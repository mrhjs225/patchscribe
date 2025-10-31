#!/usr/bin/env python3
"""
LLM 속도 벤치마크 스크립트
Ollama 로컬 엔드포인트 응답 시간 측정 도구
"""
import sys
import time
from pathlib import Path

try:
    import requests
except ImportError:
    print("❌ requests 라이브러리가 필요합니다: pip install requests")
    sys.exit(1)


def benchmark_ollama(endpoint: str, model: str, label: str, num_requests: int = 10) -> dict:
    """
    Ollama API로 벤치마크를 수행합니다.
    
    Args:
        endpoint: Ollama API 엔드포인트 (예: http://127.0.0.1:11434/api/generate)
        model: 모델 이름 (예: deepseek-r1:1.5b)
        label: 표시 이름 (예: "로컬")
        num_requests: 요청 횟수
        
    Returns:
        벤치마크 결과 딕셔너리
    """
    print(f"\n{'='*60}")
    print(f"벤치마킹: {label} - {model}")
    print(f"{'='*60}")
    print(f"엔드포인트: {endpoint}")
    
    # 간단한 테스트 프롬프트
    test_prompt = """다음 C 코드의 버퍼 오버플로우 취약점을 간단히 설명하세요:

void process_data(char *input) {
    char buffer[10];
    strcpy(buffer, input);
}

한 문장으로 답변해주세요."""
    
    times = []
    responses = []
    
    print(f"\n{num_requests}번의 요청을 보내는 중...\n")
    
    for i in range(num_requests):
        try:
            start_time = time.time()
            
            # Ollama API 호출
            response = requests.post(
                endpoint,
                headers={"Content-Type": "application/json"},
                json={
                    "model": model,
                    "prompt": test_prompt,
                    "stream": False
                },
                timeout=120
            )
            response.raise_for_status()
            
            elapsed = time.time() - start_time
            data = response.json()
            
            # 응답 텍스트 추출
            response_text = data.get("response", "")
            
            times.append(elapsed)
            responses.append(response_text)
            
            print(f"  요청 #{i+1:2d}: {elapsed:.2f}초 - "
                  f"응답 길이: {len(response_text)}자")
            
        except Exception as e:
            elapsed = time.time() - start_time
            print(f"  요청 #{i+1:2d}: ❌ 실패 ({elapsed:.2f}초) - {str(e)}")
            times.append(None)
            responses.append(None)
    
    # 성공한 요청만 필터링
    successful_times = [t for t in times if t is not None]
    
    if not successful_times:
        print(f"\n❌ 모든 요청이 실패했습니다.")
        return None
    
    # 통계 계산
    total_time = sum(successful_times)
    avg_time = total_time / len(successful_times)
    min_time = min(successful_times)
    max_time = max(successful_times)
    success_rate = len(successful_times) / num_requests * 100
    
    results = {
        "label": label,
        "endpoint": endpoint,
        "model": model,
        "num_requests": num_requests,
        "successful_requests": len(successful_times),
        "success_rate": success_rate,
        "total_time": total_time,
        "avg_time": avg_time,
        "min_time": min_time,
        "max_time": max_time,
        "times": successful_times,
    }
    
    # 결과 출력
    print(f"\n{'─'*60}")
    print(f"📊 결과 요약:")
    print(f"{'─'*60}")
    print(f"  성공률:        {success_rate:.1f}% ({len(successful_times)}/{num_requests})")
    print(f"  총 소요 시간:  {total_time:.2f}초")
    print(f"  평균 응답 시간: {avg_time:.2f}초")
    print(f"  최소 응답 시간: {min_time:.2f}초")
    print(f"  최대 응답 시간: {max_time:.2f}초")
    
    # 첫 번째 응답 샘플 출력
    first_response = next((r for r in responses if r), None)
    if first_response:
        print(f"\n  샘플 응답 (첫 150자):")
        print(f"  {first_response[:150]}...")
    
    return results


def main():
    """메인 벤치마크 실행"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="로컬 Ollama 속도 벤치마크 (동일 모델 반복 측정)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예제:
  # 기본 설정으로 실행 (각 10번씩, deepseek-r1:1.5b)
  python scripts/benchmark_llm_speed.py
  
  # 요청 횟수 변경
  python scripts/benchmark_llm_speed.py --num-requests 20
  
  # 다른 모델 사용
  python scripts/benchmark_llm_speed.py --model llama3.2:1b
  
  # 응답 횟수와 모델을 조정
  python scripts/benchmark_llm_speed.py --num-requests 5 --model llama3.2:1b
        """
    )
    
    parser.add_argument(
        "--num-requests", "-n",
        type=int,
        default=10,
        help="각 엔드포인트에 보낼 요청 횟수 (기본값: 10)"
    )
    parser.add_argument(
        "--model", "-m",
        default="deepseek-r1:1.5b",
        help="테스트할 모델 이름 (기본값: deepseek-r1:1.5b)"
    )
    parser.add_argument(
        "--local-endpoint",
        default="http://127.0.0.1:11434/api/generate",
        help="로컬 Ollama 엔드포인트 (기본값: http://127.0.0.1:11434/api/generate)"
    )
    
    args = parser.parse_args()
    
    print("\n🚀 Ollama 속도 벤치마크 시작")
    print(f"{'='*70}")
    print(f"   모델: {args.model}")
    print(f"   요청 횟수: {args.num_requests}회")
    print(f"{'='*70}")
    print(f"\n📍 테스트 대상:")
    print(f"   - 로컬 Ollama:  {args.local_endpoint}")
    
    print(f"\n{'='*70}")
    print(f"로컬 Ollama 벤치마크 준비")
    print(f"{'='*70}")
    print(f"💡 로컬 Ollama 서버가 실행 중인지 확인하세요:")
    print(f"   $ ollama serve")
    print(f"   $ ollama list  # {args.model} 모델이 있는지 확인")
    print(f"   $ ollama pull {args.model}  # 없으면 다운로드")
    input("\n   준비되면 Enter를 누르세요...")
    
    local_results = benchmark_ollama(
        args.local_endpoint,
        args.model,
        "로컬 Ollama",
        args.num_requests
    )
    
    if local_results:
        print(f"\n✅ 로컬 Ollama 벤치마크가 완료되었습니다.")
    else:
        print(f"\n❌ 로컬 Ollama 벤치마크에 실패했습니다.")
    
    print(f"\n{'='*70}")
    if local_results:
        print("✅ 벤치마크 완료!")
    else:
        print("⚠️ 벤치마크를 완료하지 못했습니다.")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
