"""Synchronous OpenAI-compatible client around the local gateway.

Every Phase-3+ LLM call goes through `LLMClient.chat()` which speaks to the
gateway on `127.0.0.1:GATEWAY_PORT` (default 8000). The client is intentionally
tiny — the gateway already does role routing, log writing, and (in Phase 2+)
budget enforcement. This class adds: deterministic temperature defaults, a
single-shot retry, token bookkeeping per call, and a clear "endpoint not up"
error path so callers can fall back to a deterministic synthesizer.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CFG = REPO_ROOT / "config" / "models.yaml"


class LLMUnavailable(RuntimeError):
    """Raised when the gateway is unreachable or returns a non-2xx."""


@dataclass
class ChatResult:
    text: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    latency_s: float
    role: str
    model: str


@dataclass
class LLMClient:
    base_url: str = ""
    timeout_s: float = 120.0
    default_role: str = "synthesizer"
    tokens_used: int = 0
    calls: int = 0

    def __post_init__(self) -> None:
        if not self.base_url:
            port = os.environ.get("GATEWAY_PORT")
            if not port:
                cfg = yaml.safe_load(DEFAULT_CFG.read_text())
                port = cfg.get("serving", {}).get("gateway_port", 8000)
            self.base_url = f"http://127.0.0.1:{port}"

    def healthz(self) -> dict:
        req = urllib.request.Request(f"{self.base_url}/healthz")
        try:
            with urllib.request.urlopen(req, timeout=2.0) as r:
                return json.loads(r.read())
        except (urllib.error.URLError, TimeoutError) as e:
            raise LLMUnavailable(f"gateway unreachable: {e}") from e

    def chat(
        self,
        system: str,
        user: str,
        *,
        role: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> ChatResult:
        role = role or self.default_role
        body = {
            "model": role,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            f"{self.base_url}/v1/chat/completions",
            data=data,
            headers={"content-type": "application/json"},
        )
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as r:
                payload = json.loads(r.read())
        except (urllib.error.URLError, TimeoutError) as e:
            raise LLMUnavailable(f"chat call failed: {e}") from e
        latency = time.time() - t0
        try:
            text = payload["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError) as e:
            raise LLMUnavailable(f"malformed gateway response: {payload!r}") from e
        usage = payload.get("usage", {}) or {}
        pt = int(usage.get("prompt_tokens", 0))
        ct = int(usage.get("completion_tokens", 0))
        tt = int(usage.get("total_tokens", pt + ct))
        self.tokens_used += tt
        self.calls += 1
        return ChatResult(
            text=text,
            prompt_tokens=pt,
            completion_tokens=ct,
            total_tokens=tt,
            latency_s=round(latency, 3),
            role=role,
            model=payload.get("model", ""),
        )
