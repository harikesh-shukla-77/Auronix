#!/usr/bin/env python3
"""Benchmark local Ollama models (Qwen 3B vs Qwen 7B vs Dolphin) for decode tokens/sec on Apple Silicon."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from typing import Any

import httpx

DEFAULT_MODELS = ("qwen2.5:3b", "qwen2.5:7b", "dolphin-uncensored:latest")
DEFAULT_PROMPT = (
    "Write a concise Python function to compute Fibonacci numbers iteratively with type hints. "
    "Return only clean code."
)


def benchmark_model(
    model: str,
    *,
    ollama_url: str = "http://localhost:11434",
    prompt: str = DEFAULT_PROMPT,
    runs: int = 2,
    timeout: float = 120.0,
) -> dict[str, Any]:
    """Measure average eval tokens/sec and first-response latency for one Ollama model."""
    url = f"{ollama_url.rstrip('/')}/api/generate"
    tok_per_sec: list[float] = []
    latencies_ms: list[float] = []
    eval_counts: list[int] = []

    for _ in range(max(1, runs)):
        t0 = time.perf_counter()
        try:
            resp = httpx.post(
                url,
                json={"model": model, "prompt": prompt, "stream": False},
                timeout=timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            return {"model": model, "ok": False, "error": str(exc)}

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        eval_count = int(data.get("eval_count") or len(str(data.get("response", "")).split()) or 0)
        eval_ns = float(data.get("eval_duration") or 0.0)
        tps = (eval_count / (eval_ns / 1e9)) if eval_ns > 0 else (eval_count / max(0.001, elapsed_ms / 1000.0))
        tok_per_sec.append(tps)
        latencies_ms.append(elapsed_ms)
        eval_counts.append(eval_count)

    return {
        "model": model,
        "ok": True,
        "runs": len(tok_per_sec),
        "avg_tokens_per_sec": round(statistics.mean(tok_per_sec), 2),
        "avg_latency_ms": round(statistics.mean(latencies_ms), 1),
        "avg_eval_tokens": int(round(statistics.mean(eval_counts))),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark local Ollama models on Apple Silicon.")
    parser.add_argument("--url", default="http://localhost:11434", help="Ollama base URL")
    parser.add_argument("--models", nargs="+", default=list(DEFAULT_MODELS), help="Models to benchmark")
    parser.add_argument("--runs", type=int, default=2, help="Number of iterations per model")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of table")
    args = parser.parse_args(argv)

    results = [
        benchmark_model(model, ollama_url=args.url, runs=args.runs)
        for model in args.models
    ]

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"{'Model':<28} {'Status':<10} {'Tokens/s':<12} {'Latency(ms)':<14} {'Tokens'}")
        print("-" * 74)
        for r in results:
            if r["ok"]:
                print(
                    f"{r['model']:<28} {'OK':<10} {r['avg_tokens_per_sec']:<12.2f} "
                    f"{r['avg_latency_ms']:<14.1f} {r['avg_eval_tokens']}"
                )
            else:
                print(f"{r['model']:<28} {'FAIL':<10} {'-':<12} {'-':<14} {r['error']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

