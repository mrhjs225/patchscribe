# PatchScribe 전체 실험 워크플로우

논문의 모든 RQ(Research Questions)를 검증하기 위한 완전한 실험 실행 가이드입니다.

## 📋 목차

1. [환경 설정](#1-환경-설정)
2. [데이터셋 준비](#2-데이터셋-준비)
3. [RQ1: Theory-Guided Generation](#3-rq1-theory-guided-generation)
4. [RQ2: Dual Verification Effectiveness](#4-rq2-dual-verification-effectiveness)
5. [RQ3: Scalability and Performance](#5-rq3-scalability-and-performance)
6. [RQ4: Explanation Quality](#6-rq4-explanation-quality)
7. [결과 분석 및 시각화](#7-결과-분석-및-시각화)
8. [문제 해결](#8-문제-해결)

---

## 1. 환경 설정

### 1.1 Python 환경 확인
```bash
# Python 3.8 이상 확인
python3 --version

# 필요한 패키지 설치 (requirements.txt가 있다면)
pip install -r requirements.txt

# 또는 개별 설치
pip install tree-sitter tqdm psutil
```

### 1.2 외부 도구 설치 (선택 사항)
```bash
# Symbolic verification을 위한 도구 (V2에 필요)
# KLEE (선택)
sudo apt-get install klee

# Clang (컴파일용)
sudo apt-get install clang

# GCC (exploit testing용, V1에 필요)
sudo apt-get install gcc
```

### 1.3 환경 변수 설정
```bash
# LLM 설정 (로컬 모델 사용 시)
export PATCHSCRIBE_LLM_PROVIDER=ollama
export PATCHSCRIBE_LLM_MODEL=llama3.2:1b
export PATCHSCRIBE_LLM_ENDPOINT=http://localhost:11434

# 또는 OpenAI 사용 시
# export PATCHSCRIBE_LLM_PROVIDER=openai
# export PATCHSCRIBE_LLM_MODEL=gpt-4
# export OPENAI_API_KEY=your_api_key_here
```

---

## 2. 데이터셋 준비

### 2.1 데이터셋 확인
```bash
# Zeroday repair 데이터셋이 있는지 확인
ls -la datasets/zeroday_repair/

# 케이스 개수 확인
python3 -c "
from patchscribe.dataset import load_cases
cases = load_cases('zeroday')
print(f'Total cases: {len(cases)}')
for i, case in enumerate(cases[:3], 1):
    print(f'{i}. {case[\"id\"]} - {case[\"cwe_id\"]}')
"
```

**예상 출력:**
```
Total cases: 10
1. CWE-125___CVE-2024-25116.c___1-64___13.c - CWE-125
2. CWE-125___CVE-2024-29489.c___1-59___5.c - CWE-125
3. CWE-190___CVE-2024-26130.c___1-98___56.c - CWE-190
```

### 2.2 결과 디렉토리 생성
```bash
# 모든 결과를 저장할 디렉토리 생성
mkdir -p results/{raw_results,rq_analysis,incomplete_patches,verification_ablation,figures}
```

---

## 3. RQ1: Theory-Guided Generation

**목표**: C1 (baseline) vs C2 (vague hints) vs C3 (pre-hoc) vs C4 (full PatchScribe) 비교

### 3.1 전체 평가 실행 (C1-C4 모두)

```bash
# 전체 조건 실행 (시간이 오래 걸림: ~30-60분)
python3 scripts/run_full_evaluation.py zeroday \
    --conditions c1 c2 c3 c4 \
    --limit 10 \
    --output results/evaluation_full \
    --llm-provider ollama \
    --llm-model llama3.2:1b

# 또는 빠른 테스트 (3개 케이스만)
python3 scripts/run_full_evaluation.py zeroday \
    --conditions c1 c2 c3 c4 \
    --limit 3 \
    --output results/evaluation_test
```

**예상 출력:**
```
================================================================================
PATCHSCRIBE RQ EVALUATION
================================================================================
Dataset: zeroday
Output: results/evaluation_full
Conditions: ['c1', 'c2', 'c3', 'c4']
...
✅ EVALUATION COMPLETE
```

### 3.2 개별 조건 실행 (선택)

필요시 개별 조건만 재실행할 수 있습니다:

```bash
# C1만 실행 (Baseline: post-hoc, no formal guidance)
python3 scripts/run_full_evaluation.py zeroday \
    --conditions c1 \
    --limit 10 \
    --output results/evaluation_c1

# C4만 실행 (Full PatchScribe)
python3 scripts/run_full_evaluation.py zeroday \
    --conditions c4 \
    --limit 10 \
    --output results/evaluation_c4
```

### 3.3 RQ1 결과 확인

```bash
# 결과 파일 확인
ls -lh results/evaluation_full/raw_results/

# 각 조건의 성공률 빠르게 확인
for file in results/evaluation_full/raw_results/*_results.json; do
    echo "=== $(basename $file) ==="
    python3 -c "
import json
with open('$file') as f:
    data = json.load(f)
    metrics = data.get('metrics', {})
    print(f\"Success rate: {metrics.get('success_rate', 0):.1%}\")
    print(f\"Ground truth match: {metrics.get('ground_truth_match_rate', 0):.1%}\")
    print(f\"First attempt success: {metrics.get('first_attempt_success_rate', 0):.1%}\")
    print(f\"AST similarity: {metrics.get('avg_ast_overall_similarity', 0):.1%}\")
"
done
```

---

## 4. RQ2: Dual Verification Effectiveness

**목표**: V1 (exploit-only) vs V2 (symbolic) vs V3 (consistency) vs V4 (triple) 비교

### 4.1 불완전 패치 생성

```bash
# 단계 1: 각 취약점에 대해 2-3개의 불완전 패치 생성
python3 scripts/inject_incomplete_patches.py \
    --dataset zeroday \
    --limit 10 \
    --output results/incomplete_patches

# 결과 확인
cat results/incomplete_patches/incomplete_patches_zeroday.json | python3 -m json.tool | head -50
```

**예상 출력:**
```
Loading zeroday dataset...
Loaded 10 cases

Generating incomplete patches for: CWE-125___CVE-2024-25116.c___1-64___13.c
  Generated 3 incomplete patches:
    - ..._incomplete_1: tautology_check
    - ..._incomplete_2: insufficient_validation
    - ..._incomplete_3: wrong_location

✅ Saved incomplete patches to: results/incomplete_patches/incomplete_patches_zeroday.json
   Total cases: 10
   Total incomplete patches: 30
```

### 4.2 검증 방법 비교 실험 (V1-V4)

```bash
# 단계 2: V1, V2, V3, V4 모두 실행하여 비교
# 주의: 시간이 오래 걸릴 수 있음 (~1-2시간)
python3 scripts/run_verification_ablation.py \
    --dataset zeroday \
    --limit 10 \
    --incomplete-patches results/incomplete_patches/incomplete_patches_zeroday.json \
    --output results/verification_ablation

# 빠른 테스트 (2개 케이스만)
python3 scripts/run_verification_ablation.py \
    --dataset zeroday \
    --limit 2 \
    --incomplete-patches results/incomplete_patches/incomplete_patches_zeroday.json \
    --output results/verification_ablation_test
```

**예상 출력:**
```
================================================================================
Testing case: CWE-125___CVE-2024-25116.c___1-64___13.c
  Testing incomplete patch: ..._incomplete_1
    Running V1 (exploit-only)...
      Detected: True
    Running V2 (symbolic-only)...
      Detected: True
    Running V3 (consistency-only)...
      Detected: True
    Running V4 (triple verification)...
      Detected: True

================================================================================
PRECISION/RECALL ANALYSIS
================================================================================

V1:
  Detected incomplete: 18/30
  Precision: 60.00%
  Recall: 60.00%
  Avg execution time: 2.34s

V2:
  Detected incomplete: 22/30
  Precision: 73.33%
  Recall: 73.33%
  Avg execution time: 15.67s

V3:
  Detected incomplete: 25/30
  Precision: 83.33%
  Recall: 83.33%
  Avg execution time: 8.45s

V4:
  Detected incomplete: 27/30
  Precision: 90.00%
  Recall: 90.00%
  Avg execution time: 24.12s
```

### 4.3 RQ2 결과 분석

```bash
# Precision/Recall 요약
python3 -c "
import json
with open('results/verification_ablation/verification_ablation_zeroday.json') as f:
    data = json.load(f)

print('Verification Method Comparison:')
print('='*60)
for method in ['V1', 'V2', 'V3', 'V4']:
    results = data.get(method, [])
    if results:
        detected = sum(1 for r in results if r['detected_incomplete'])
        total = len(results)
        avg_time = sum(r['execution_time'] for r in results) / len(results)

        print(f'{method}:')
        print(f'  Detection rate: {detected}/{total} ({detected/total:.1%})')
        print(f'  Avg time: {avg_time:.2f}s')
        print()
"
```

---

## 5. RQ3: Scalability and Performance

**목표**: 코드 복잡도별 성능 측정

RQ3는 이미 RQ1 평가에 포함되어 있습니다 (performance profiling).

### 5.1 성능 데이터 추출

```bash
# C4 (full PatchScribe) 결과에서 성능 메트릭 추출
python3 scripts/run_rq_analysis.py \
    results/evaluation_full/raw_results/full_patchscribe_c4_results.json \
    -o results/rq_analysis/rq3_performance.json
```

### 5.2 RQ3 결과 확인

```bash
# 복잡도별 성능 요약
python3 -c "
import json
with open('results/rq_analysis/rq3_performance.json') as f:
    data = json.load(f)

rq3 = data.get('rq3_scalability_performance', [])
print('Performance by Code Complexity:')
print('='*60)
for result in rq3:
    print(f\"Complexity: {result['complexity_level']}\")
    print(f\"  Cases: {result['case_count']}\")
    print(f\"  Avg iterations: {result['avg_iterations']:.1f}\")
    if result.get('avg_total_time'):
        print(f\"  Avg total time: {result['avg_total_time']:.2f}s\")
        print(f\"  Avg phase 1 (formalization): {result.get('avg_phase1_time', 0):.2f}s\")
        print(f\"  Avg phase 2 (generation): {result.get('avg_phase2_time', 0):.2f}s\")
        print(f\"  Avg phase 3 (verification): {result.get('avg_phase3_time', 0):.2f}s\")
    print()
"
```

---

## 6. RQ4: Explanation Quality

**목표**: Explanation 품질 평가 (자동 + 수동)

### 6.1 Explanation 메트릭 자동 평가

RQ4도 RQ1 평가에 이미 포함되어 있습니다.

```bash
# C4 결과에서 explanation 메트릭 추출
python3 scripts/run_rq_analysis.py \
    results/evaluation_full/raw_results/full_patchscribe_c4_results.json \
    -o results/rq_analysis/rq4_explanation.json
```

### 6.2 Blind Evaluation 생성 (수동 평가용)

```bash
# 전문가 리뷰를 위한 blind evaluation 파일 생성
python3 scripts/generate_blind_explanations.py \
    results/evaluation_full/raw_results/full_patchscribe_c4_results.json \
    --output results/blind_evaluation

# 생성된 파일 확인
ls -lh results/blind_evaluation/
```

### 6.3 RQ4 결과 확인

```bash
# Explanation 품질 메트릭 요약
python3 -c "
import json
with open('results/rq_analysis/rq4_explanation.json') as f:
    data = json.load(f)

rq4 = data.get('rq4_explanation_quality', [])
print('Explanation Quality Metrics:')
print('='*60)
for result in rq4:
    print(f\"Type: {result['explanation_type']}\")
    print(f\"  Checklist coverage: {result['checklist_coverage']:.1%}\")
    if result.get('avg_accuracy_score', 0) > 0:
        print(f\"  Accuracy score: {result['avg_accuracy_score']:.2f}/5\")
        print(f\"  Clarity score: {result['avg_clarity_score']:.2f}/5\")
        print(f\"  Causality score: {result['avg_causality_score']:.2f}/5\")
    print()
"
```

---

## 7. 결과 분석 및 시각화

### 7.1 모든 RQ에 대한 종합 분석

```bash
# 각 조건(C1-C4)에 대해 RQ 분석 실행
for condition in baseline_c1 vague_hints_c2 prehoc_c3 full_patchscribe_c4; do
    if [ -f "results/evaluation_full/raw_results/${condition}_results.json" ]; then
        echo "Analyzing $condition..."
        python3 scripts/run_rq_analysis.py \
            "results/evaluation_full/raw_results/${condition}_results.json" \
            -o "results/rq_analysis/rq_analysis_${condition}.json"
    fi
done

# 비교 분석 생성
python3 scripts/run_rq_analysis.py \
    results/evaluation_full/raw_results/ \
    -o results/rq_analysis/comparative_analysis.json
```

### 7.2 최종 보고서 확인

```bash
# 자동 생성된 markdown 보고서 확인
cat results/evaluation_full/EVALUATION_REPORT.md

# 각 RQ의 markdown 보고서
ls results/rq_analysis/*.md
```

### 7.3 주요 메트릭 요약 출력

```bash
# 전체 결과를 하나의 테이블로 요약
python3 << 'EOF'
import json
from pathlib import Path

conditions = {
    'C1 (Baseline)': 'baseline_c1_results.json',
    'C2 (Vague Hints)': 'vague_hints_c2_results.json',
    'C3 (Pre-hoc)': 'prehoc_c3_results.json',
    'C4 (Full PatchScribe)': 'full_patchscribe_c4_results.json'
}

print("="*80)
print("FINAL RESULTS SUMMARY - ALL RQs")
print("="*80)
print()

print("RQ1: Theory-Guided Generation Effectiveness")
print("-"*80)
print(f"{'Condition':<25} {'Success':<10} {'1st Attempt':<12} {'Ground Truth':<13} {'AST Sim':<10}")
print("-"*80)

for name, filename in conditions.items():
    filepath = Path(f'results/evaluation_full/raw_results/{filename}')
    if filepath.exists():
        with open(filepath) as f:
            data = json.load(f)
            metrics = data.get('metrics', {})
            success = metrics.get('success_rate', 0)
            first_attempt = metrics.get('first_attempt_success_rate', 0)
            ground_truth = metrics.get('ground_truth_match_rate', 0)
            ast_sim = metrics.get('avg_ast_overall_similarity', 0)
            print(f"{name:<25} {success:>8.1%} {first_attempt:>10.1%} {ground_truth:>11.1%} {ast_sim:>8.1%}")

print()
print("RQ2: Dual Verification Effectiveness")
print("-"*80)

verification_file = Path('results/verification_ablation/verification_ablation_zeroday.json')
if verification_file.exists():
    with open(verification_file) as f:
        data = json.load(f)
        print(f"{'Method':<15} {'Detection Rate':<20} {'Avg Time':<15}")
        print("-"*80)
        for method in ['V1', 'V2', 'V3', 'V4']:
            results = data.get(method, [])
            if results:
                detected = sum(1 for r in results if r['detected_incomplete'])
                total = len(results)
                avg_time = sum(r['execution_time'] for r in results) / len(results)
                print(f"{method:<15} {detected}/{total} ({detected/total:.1%})"[:35].ljust(35) + f"{avg_time:.2f}s")

print()
print("RQ3: Scalability and Performance (C4)")
print("-"*80)

c4_analysis = Path('results/rq_analysis/rq_analysis_full_patchscribe_c4.json')
if c4_analysis.exists():
    with open(c4_analysis) as f:
        data = json.load(f)
        rq3 = data.get('rq3_scalability_performance', [])
        print(f"{'Complexity':<15} {'Cases':<8} {'Avg Time':<12} {'Iterations':<12}")
        print("-"*80)
        for result in rq3:
            complexity = result['complexity_level']
            cases = result['case_count']
            avg_time = result.get('avg_total_time', 0)
            iterations = result['avg_iterations']
            print(f"{complexity:<15} {cases:<8} {avg_time:>8.2f}s   {iterations:>8.1f}")

print()
print("="*80)
print("All experiments completed successfully!")
print("="*80)
EOF
```

---

## 8. 문제 해결

### 8.1 일반적인 오류

#### LLM 연결 오류
```bash
# Ollama가 실행 중인지 확인
curl http://localhost:11434/api/tags

# Ollama 시작
ollama serve

# 모델 다운로드
ollama pull llama3.2:1b
```

#### 메모리 부족
```bash
# 병렬 처리 제한 (순차 실행)
python3 scripts/run_full_evaluation.py zeroday \
    --conditions c4 \
    --limit 5 \
    --max-workers 1  # 순차 실행
```

#### 데이터셋 없음
```bash
# 데이터셋 경로 확인
ls -la datasets/zeroday_repair/

# 없다면 README에서 데이터셋 다운로드 방법 확인
cat README.md | grep -A 10 "dataset"
```

### 8.2 부분 재실행

실험 중 일부가 실패한 경우:

```bash
# 특정 조건만 재실행
python3 scripts/run_full_evaluation.py zeroday \
    --conditions c4 \
    --limit 10 \
    --output results/evaluation_full

# 특정 검증 방법만 재실행 (수동으로 스크립트 수정 필요)
# run_verification_ablation.py에서 원하는 메서드만 실행하도록 수정
```

### 8.3 결과 검증

```bash
# 생성된 모든 결과 파일 확인
find results/ -name "*.json" -type f | sort

# 각 파일의 케이스 수 확인
for file in results/evaluation_full/raw_results/*_results.json; do
    cases=$(python3 -c "import json; data=json.load(open('$file')); print(len(data.get('cases', [])))")
    echo "$(basename $file): $cases cases"
done
```

---

## 9. 빠른 전체 실행 스크립트

모든 실험을 한 번에 실행하려면:

```bash
#!/bin/bash
# run_all_experiments.sh

set -e  # 오류 시 중단

echo "Starting full experimental pipeline..."

# 1. Environment check
echo "Step 1: Checking environment..."
python3 --version
python3 -c "from patchscribe.dataset import load_cases; print('✅ PatchScribe module OK')"

# 2. RQ1: Full evaluation
echo "Step 2: Running RQ1 evaluation (C1-C4)..."
python3 scripts/run_full_evaluation.py zeroday \
    --conditions c1 c2 c3 c4 \
    --limit 10 \
    --output results/evaluation_full

# 3. RQ2: Incomplete patches
echo "Step 3: Generating incomplete patches for RQ2..."
python3 scripts/inject_incomplete_patches.py \
    --dataset zeroday \
    --limit 10 \
    --output results/incomplete_patches

# 4. RQ2: Verification ablation
echo "Step 4: Running verification ablation (V1-V4)..."
python3 scripts/run_verification_ablation.py \
    --dataset zeroday \
    --limit 10 \
    --incomplete-patches results/incomplete_patches/incomplete_patches_zeroday.json \
    --output results/verification_ablation

# 5. RQ Analysis
echo "Step 5: Running RQ analysis..."
for condition in baseline_c1 vague_hints_c2 prehoc_c3 full_patchscribe_c4; do
    if [ -f "results/evaluation_full/raw_results/${condition}_results.json" ]; then
        python3 scripts/run_rq_analysis.py \
            "results/evaluation_full/raw_results/${condition}_results.json" \
            -o "results/rq_analysis/rq_analysis_${condition}.json"
    fi
done

# 6. Generate summary
echo "Step 6: Generating final summary..."
cat results/evaluation_full/EVALUATION_REPORT.md

echo ""
echo "✅ All experiments completed successfully!"
echo "Results are in: results/"
echo ""
echo "Key files:"
echo "  - results/evaluation_full/EVALUATION_REPORT.md"
echo "  - results/rq_analysis/*.json"
echo "  - results/verification_ablation/verification_ablation_zeroday.json"
```

실행:
```bash
chmod +x run_all_experiments.sh
./run_all_experiments.sh 2>&1 | tee experiment_log.txt
```

---

## 10. 예상 실행 시간

| 단계 | 케이스 수 | 예상 시간 | 설명 |
|------|----------|----------|------|
| RQ1 - C1 (Baseline) | 10 | ~10분 | No formal guidance |
| RQ1 - C2 (Vague Hints) | 10 | ~12분 | Informal prompts |
| RQ1 - C3 (Pre-hoc) | 10 | ~15분 | E_bug without verification |
| RQ1 - C4 (Full) | 10 | ~20분 | Full PatchScribe |
| **RQ1 Total** | **10** | **~60분** | **모든 조건** |
| RQ2 - Incomplete patches | 10 | ~2분 | 패치 생성 |
| RQ2 - V1-V4 ablation | 30 patches | ~90분 | 모든 검증 방법 |
| **RQ2 Total** | **10+30** | **~90분** | **검증 비교** |
| RQ3 - Analysis | N/A | ~2분 | RQ1에 포함 |
| RQ4 - Analysis | N/A | ~2분 | RQ1에 포함 |
| **Grand Total** | **10 cases** | **~2.5-3시간** | **전체 실험** |

*참고: 시간은 하드웨어와 LLM 속도에 따라 달라집니다.*

---

## 11. 결과 파일 구조

```
results/
├── evaluation_full/
│   ├── raw_results/
│   │   ├── baseline_c1_results.json           # RQ1: C1 결과
│   │   ├── vague_hints_c2_results.json        # RQ1: C2 결과
│   │   ├── prehoc_c3_results.json             # RQ1: C3 결과
│   │   └── full_patchscribe_c4_results.json   # RQ1: C4 결과
│   ├── rq_analysis/
│   │   └── (RQ별 분석 결과)
│   └── EVALUATION_REPORT.md                   # 최종 보고서
├── incomplete_patches/
│   └── incomplete_patches_zeroday.json        # RQ2: 불완전 패치
├── verification_ablation/
│   └── verification_ablation_zeroday.json     # RQ2: V1-V4 비교
├── rq_analysis/
│   ├── rq_analysis_baseline_c1.json
│   ├── rq_analysis_full_patchscribe_c4.json
│   └── comparative_analysis.json              # 모든 조건 비교
└── blind_evaluation/
    └── (수동 평가용 파일들)
```

---

## 요약: 핵심 명령어만

```bash
# 1. 전체 평가 (RQ1, RQ3, RQ4)
python3 scripts/run_full_evaluation.py zeroday --conditions c1 c2 c3 c4 --limit 10

# 2. 불완전 패치 생성 (RQ2)
python3 scripts/inject_incomplete_patches.py --dataset zeroday --limit 10

# 3. 검증 비교 (RQ2)
python3 scripts/run_verification_ablation.py --dataset zeroday --limit 10 \
    --incomplete-patches results/incomplete_patches/incomplete_patches_zeroday.json

# 4. 결과 분석
python3 scripts/run_rq_analysis.py results/evaluation_full/raw_results/full_patchscribe_c4_results.json

# 5. 보고서 확인
cat results/evaluation_full/EVALUATION_REPORT.md
```

**완료!** 🎉
