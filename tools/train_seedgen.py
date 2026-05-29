"""Fine-tune a small local model (LoRA) as a fuzzer-seed generator.

Specialized purpose: harness source (+ bug context) -> format-valid input seed
(hex). Base model from the local HF cache (no download). Trains on the dataset
built by eval/cybergym/build_seedgen_dataset.py.

Run:
    python3 tools/train_seedgen.py \
        --train run-logs/seedgen/train.jsonl \
        --eval  run-logs/seedgen/train-eval.jsonl \
        --base Qwen/Qwen2.5-3B-Instruct \
        --out  run-logs/seedgen/qwen3b-lora --epochs 3
"""
from __future__ import annotations

import argparse
from pathlib import Path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", type=Path, required=True)
    ap.add_argument("--eval", type=Path, default=None)
    ap.add_argument("--base", type=str, default="Qwen/Qwen2.5-3B-Instruct")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--epochs", type=float, default=3.0)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--bs", type=int, default=8)
    ap.add_argument("--grad-accum", type=int, default=2)
    ap.add_argument("--max-len", type=int, default=2048)
    ap.add_argument("--gpu", type=int, default=0)
    args = ap.parse_args(argv)

    import os
    os.environ["CUDA_VISIBLE_DEVICES"] = str(args.gpu)
    import torch
    from datasets import load_dataset
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from peft import LoraConfig
    from trl import SFTTrainer, SFTConfig

    files = {"train": str(args.train)}
    if args.eval and args.eval.exists():
        files["eval"] = str(args.eval)
    ds = load_dataset("json", data_files=files)

    tok = AutoTokenizer.from_pretrained(args.base)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(
        args.base, torch_dtype=torch.bfloat16, attn_implementation="eager")

    peft_config = LoraConfig(
        r=16, lora_alpha=32, lora_dropout=0.05, bias="none",
        task_type="CAUSAL_LM", target_modules="all-linear")

    cfg_kw = dict(
        output_dir=str(args.out),
        per_device_train_batch_size=args.bs,
        gradient_accumulation_steps=args.grad_accum,
        num_train_epochs=args.epochs,
        learning_rate=args.lr,
        bf16=True,
        logging_steps=10,
        save_strategy="epoch",
        gradient_checkpointing=True,
        report_to="none",
        warmup_ratio=0.03,
        lr_scheduler_type="cosine",
    )
    # trl renamed max_seq_length -> max_length across versions; try both.
    try:
        cfg = SFTConfig(max_length=args.max_len, packing=False, **cfg_kw)
    except TypeError:
        cfg = SFTConfig(max_seq_length=args.max_len, packing=False, **cfg_kw)

    trainer = SFTTrainer(
        model=model, args=cfg,
        train_dataset=ds["train"],
        eval_dataset=ds.get("eval"),
        peft_config=peft_config,
        processing_class=tok,
    )
    trainer.train()
    trainer.save_model(str(args.out))
    tok.save_pretrained(str(args.out))
    print(f"saved LoRA adapter -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
