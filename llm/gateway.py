"""OpenAI-compatible gateway in front of vLLM replicas.

All agent/LLM calls in this repo go through one internal gateway (PLAN §1), so
model choice and routing are swappable behind a config. The gateway:

  * exposes `/v1/chat/completions` and `/v1/completions` matching the OpenAI
    schema (vLLM already speaks it; we just proxy);
  * routes by *role* — the caller asks for "synthesizer" or "router" in the
    `model` field, and the gateway rewrites it to the actual underlying model
    id before forwarding to a replica selected round-robin;
  * records token usage to a JSONL file under run-logs/ so the metrics harness
    (Phase 0.5) and the budget enforcer (Phase 2) can read a single canonical
    stream.

It does NOT yet enforce caps — that goes live in Phase 2 alongside the per-
hypothesis cost model. The wiring is already here so the call site never
changes.
"""
from __future__ import annotations
import asyncio
import itertools
import json
import os
import time
from pathlib import Path
from typing import Any

import httpx
import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = REPO_ROOT / "config" / "models.yaml"
LOG_DIR = REPO_ROOT / "run-logs"
LOG_DIR.mkdir(exist_ok=True)


def _load_config(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text())


class Router:
    """Maps role -> list of (model_id, base_url) replica endpoints."""

    def __init__(self, cfg: dict[str, Any]) -> None:
        self.cfg = cfg
        self.replicas: dict[str, list[tuple[str, str]]] = {}
        profile = os.environ.get("VERI_PROFILE") or cfg.get("serving", {}).get("profile", "production")
        self.profile = profile
        if profile == "smoke":
            s = cfg["smoke"]
            url = f"http://127.0.0.1:{s['port']}"
            # In smoke profile both roles resolve to the same replica.
            self.replicas["synthesizer"] = [(s["model"], url)]
            self.replicas["router"] = [(s["model"], url)]
        elif profile == "cpu":
            s = cfg["cpu"]
            url = f"http://127.0.0.1:{s['port']}"
            # CPU profile: ollama backend, both roles share one dense model.
            self.replicas["synthesizer"] = [(s["model"], url)]
            self.replicas["router"] = [(s["model"], url)]
        else:
            for role, r in cfg.get("roles", {}).items():
                self.replicas[role] = [
                    (r["model"], f"http://127.0.0.1:{rep['port']}")
                    for rep in r["replicas"]
                ]
        self._rr = {role: itertools.cycle(reps) for role, reps in self.replicas.items() if reps}

    def pick(self, role: str) -> tuple[str, str]:
        if role not in self._rr:
            raise HTTPException(404, f"unknown role: {role!r} (have {list(self.replicas)})")
        return next(self._rr[role])


def _resolve_role(model_field: str, router: Router) -> tuple[str, str]:
    """Caller may pass `synthesizer` / `router` (role) or a concrete model id.

    Concrete ids are forwarded only if they match a known role's model.
    """
    if model_field in router.replicas:
        return router.pick(model_field)
    for role, reps in router.replicas.items():
        for model_id, url in reps:
            if model_id == model_field:
                return router.pick(role)
    raise HTTPException(404, f"no replica for {model_field!r}")


def _log_usage(record: dict[str, Any]) -> None:
    """Append one JSON line per request to run-logs/llm-gateway.jsonl."""
    fp = LOG_DIR / "llm-gateway.jsonl"
    with fp.open("a") as f:
        f.write(json.dumps(record) + "\n")


def create_app(config_path: Path | None = None) -> FastAPI:
    cfg = _load_config(config_path or DEFAULT_CONFIG)
    router = Router(cfg)
    client = httpx.AsyncClient(timeout=600.0)
    app = FastAPI()

    @app.get("/healthz")
    async def health() -> dict[str, Any]:
        # Probe each backend's /health.
        status = {}
        health_path = "/health"
        if router.profile == "cpu":
            health_path = cfg.get("cpu", {}).get("backend_health_path", "/api/version")
        async def probe(role: str, url: str):
            try:
                r = await client.get(f"{url}{health_path}", timeout=2.0)
                return role, url, r.status_code
            except Exception as e:
                return role, url, f"err: {e.__class__.__name__}"
        results = await asyncio.gather(*[
            probe(role, url) for role, reps in router.replicas.items() for _, url in reps
        ])
        for role, url, st in results:
            status.setdefault(role, []).append({"url": url, "status": st})
        active_profile = os.environ.get("VERI_PROFILE") or cfg.get("serving", {}).get("profile")
        return {"backends": status, "profile": active_profile}

    @app.get("/v1/models")
    async def list_models() -> dict[str, Any]:
        # Expose roles as virtual model ids so OpenAI clients can list them.
        data = []
        for role, reps in router.replicas.items():
            for model_id, _ in reps:
                data.append({"id": role, "object": "model", "owned_by": "touchstone",
                             "underlying": model_id})
                break
        return {"object": "list", "data": data}

    async def _forward(request: Request, path: str) -> Any:
        body = await request.json()
        requested_model = body.get("model", "synthesizer")
        underlying, url = _resolve_role(requested_model, router)
        body["model"] = underlying
        t0 = time.time()
        try:
            r = await client.post(f"{url}{path}", json=body)
        except httpx.RequestError as e:
            raise HTTPException(502, f"upstream unreachable: {e}")
        latency = time.time() - t0
        try:
            payload = r.json()
        except Exception:
            payload = {"raw": r.text}
        usage = payload.get("usage") if isinstance(payload, dict) else None
        _log_usage({
            "ts": time.time(),
            "path": path,
            "role": requested_model,
            "underlying": underlying,
            "upstream": url,
            "status": r.status_code,
            "latency_s": round(latency, 3),
            "usage": usage,
        })
        return JSONResponse(payload, status_code=r.status_code)

    @app.post("/v1/chat/completions")
    async def chat(request: Request):
        return await _forward(request, "/v1/chat/completions")

    @app.post("/v1/completions")
    async def completions(request: Request):
        return await _forward(request, "/v1/completions")

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("GATEWAY_PORT") or
               _load_config(DEFAULT_CONFIG)["serving"]["gateway_port"])
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
