#!/usr/bin/env python3
"""
Measure Ollama chat latency under different parallel request counts.

The script sends a fixed number of prompts to the specified Ollama endpoint
using thread-based concurrency (1, 2, 3, 4 workers by default) and reports
latency / throughput statistics for each setting. The default model is
``DeepSeek-R1:1.5b``.

Note: Ollama model names are case-sensitive. Use 'ollama list' to check exact names.
"""
from __future__ import annotations

import argparse
import math
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable, List

try:
    import requests
except ImportError:
    print("❌ requests 라이브러리가 필요합니다: pip install requests")
    sys.exit(1)


DEFAULT_PROMPT = (
    "다음 C 코드가 왜 위험한지 한 문장으로 설명해주세요.\n"
    "\n"
    "void process(char *input) {\n"
    "    char buf[16];\n"
    "    strcpy(buf, input);\n"
    "}\n"
)


@dataclass
class RequestStat:
    idx: int
    elapsed: float
    success: bool
    error: str | None = None


def build_payload(model: str, prompt: str, api: str) -> dict:
    """Construct the Ollama payload for the requested API."""
    if api == "chat":
        return {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        }
    return {
        "model": model,
        "prompt": prompt,
        "stream": False,
    }


def run_single_request(
    idx: int,
    endpoint: str,
    payload: dict,
    timeout: float,
    api: str,
) -> RequestStat:
    """Send a single request to Ollama and capture latency."""
    start = time.perf_counter()
    try:
        response = requests.post(
            endpoint,
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        # Accessing the content verifies response integrity but we ignore the text.
        if api == "chat":
            message = data.get("message", {})
            if not isinstance(message, dict) or "content" not in message:
                raise ValueError("응답 본문에 message.content 가 없습니다.")
        else:
            if "response" not in data:
                raise ValueError("응답 본문에 response 필드가 없습니다.")
    except Exception as exc:
        elapsed = time.perf_counter() - start
        error_msg = str(exc)
        if api == "chat" and hasattr(requests, "exceptions"):
            http_error = (
                isinstance(exc, requests.exceptions.HTTPError)
                and getattr(exc, "response", None) is not None
                and exc.response.status_code == 404
            )
            if http_error:
                error_msg += " - /api/chat 엔드포인트가 비활성화된 Ollama 버전 같습니다. --api generate 로 다시 시도하세요."
        return RequestStat(idx=idx, elapsed=elapsed, success=False, error=error_msg)
    elapsed = time.perf_counter() - start
    return RequestStat(idx=idx, elapsed=elapsed, success=True)


def percentile(values: Iterable[float], pct: float) -> float | None:
    """Return percentile using linear interpolation."""
    data = sorted(values)
    if not data:
        return None
    k = (len(data) - 1) * (pct / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return data[int(k)]
    return data[f] + (data[c] - data[f]) * (k - f)


def benchmark_concurrency(
    concurrency: int,
    endpoint: str,
    model: str,
    prompt: str,
    requests_per_level: int,
    timeout: float,
    api: str,
) -> dict:
    """Execute the benchmark for a single concurrency level."""
    print(f"\n{'=' * 70}")
    print(f"🔁 동시 요청 수: {concurrency}")
    print(f"{'-' * 70}")
    print(
        f"요청 횟수: {requests_per_level}, 모델: {model}, "
        f"엔드포인트: {endpoint} (API: {api})"
    )

    payload = build_payload(model, prompt, api)
    results: List[RequestStat] = []

    start_wall = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [
            executor.submit(run_single_request, idx, endpoint, payload, timeout, api)
            for idx in range(1, requests_per_level + 1)
        ]
        for future in as_completed(futures):
            stat = future.result()
            results.append(stat)
            status = "✅ 성공" if stat.success else "❌ 실패"
            print(f"[{status}] 요청 #{stat.idx:02d} - {stat.elapsed:.2f}초", end="")
            if stat.error:
                print(f" (오류: {stat.error})")
            else:
                print()
    wall_time = time.perf_counter() - start_wall

    successes = [r for r in results if r.success]
    failures = [r for r in results if not r.success]
    latencies = [r.elapsed for r in successes]

    avg_latency = sum(latencies) / len(latencies) if latencies else None
    p95 = percentile(latencies, 95) if latencies else None

    throughput = (
        len(successes) / wall_time if wall_time > 0 and successes else 0.0
    )

    print(f"\n총 소요 시간: {wall_time:.2f}초")
    print(f"성공: {len(successes)} / 실패: {len(failures)}")
    if avg_latency is not None:
        print(f"평균 지연 시간: {avg_latency:.2f}초")
    if p95 is not None:
        print(f"95퍼센타일 지연 시간: {p95:.2f}초")
    print(f"처리량: {throughput:.3f} 요청/초")

    return {
        "concurrency": concurrency,
        "wall_time": wall_time,
        "successes": len(successes),
        "failures": len(failures),
        "avg_latency": avg_latency,
        "p95_latency": p95,
        "throughput": throughput,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ollama deepseek-r1 병렬 처리 벤치마크 도구"
    )
    parser.add_argument(
        "--endpoint",
        help="Ollama API 엔드포인트 (예: http://127.0.0.1:11434/api/generate)",
    )
    parser.add_argument(
        "--model",
        default="DeepSeek-R1:1.5b",
        help="벤치마크할 모델 이름 (대소문자 정확히 입력)",
    )
    parser.add_argument(
        "--requests",
        type=int,
        default=32,
        help="각 동시성 수준에서 보낼 총 요청 수",
    )
    parser.add_argument(
        "--levels",
        type=int,
        nargs="+",
        default=[1, 4, 8],
        help="테스트할 동시 요청 수 목록",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="각 요청 타임아웃 (초)",
    )
    parser.add_argument(
        "--prompt",
        default=DEFAULT_PROMPT,
        help="테스트에 사용할 프롬프트 (기본값은 간단한 C 예제)",
    )
    parser.add_argument(
        "--api",
        choices=["chat", "generate"],
        default="chat",
        help="Ollama API 타입 선택 (chat 또는 generate)",
    )
    return parser.parse_args()


def print_summary(results: List[dict]) -> None:
    print(f"\n{'=' * 70}")
    print("📊 동시성 수준별 요약")
    print(f"{'=' * 70}")
    print(
        f"{'동시성':>6} | {'성공':>4} | {'실패':>4} | {'총시간(초)':>11} | "
        f"{'평균지연(초)':>12} | {'P95(초)':>8} | {'처리량(req/s)':>16}"
    )
    print("-" * 70)
    for item in results:
        avg = f"{item['avg_latency']:.2f}" if item["avg_latency"] is not None else "-"
        p95 = f"{item['p95_latency']:.2f}" if item["p95_latency"] is not None else "-"
        print(
            f"{item['concurrency']:>6} | "
            f"{item['successes']:>4} | "
            f"{item['failures']:>4} | "
            f"{item['wall_time']:>11.2f} | "
            f"{avg:>12} | "
            f"{p95:>8} | "
            f"{item['throughput']:>16.3f}"
        )


def main() -> None:
    args = parse_args()
    if not args.endpoint:
        if args.api == "chat":
            args.endpoint = "http://127.0.0.1:11434/api/chat"
        else:
            args.endpoint = "http://127.0.0.1:11434/api/generate"

    results = []
    for level in args.levels:
        if level < 1:
            print(f"⚠️  동시성 수준 {level} 은(는) 무시합니다. 1 이상의 값을 사용하세요.")
            continue
        results.append(
            benchmark_concurrency(
                concurrency=level,
                endpoint=args.endpoint,
                model=args.model,
                prompt=args.prompt,
                requests_per_level=args.requests,
                timeout=args.timeout,
                api=args.api,
            )
        )
    if results:
        print_summary(results)


if __name__ == "__main__":
    main()
