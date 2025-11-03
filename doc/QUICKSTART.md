# PatchScribe 빠른 시작 가이드

## 📚 전체 실험 실행하기

논문의 모든 RQ(Research Questions)를 검증하기 위한 완전한 가이드입니다.

---

## 🚀 가장 빠른 시작 (30초)

### 옵션 1: 빠른 테스트 (10분)
```bash
# 3개 케이스만으로 파이프라인이 동작하는지 테스트
./quick_test.sh
```

### 옵션 2: 전체 실험 (2-3시간)
```bash
# 10개 케이스로 모든 RQ 실험 실행
./run_all_experiments.sh 2>&1 | tee experiment_log.txt
```

---

## 📖 상세 가이드

### 1️⃣ 환경 준비

```bash
# Python 버전 확인 (3.8 이상 필요)
python3 --version

# LLM 설정 (로컬 모델 사용 시)
export PATCHSCRIBE_LLM_PROVIDER=ollama
export PATCHSCRIBE_LLM_MODEL=llama3.2:1b

# Ollama 시작 및 모델 다운로드
ollama serve  # 별도 터미널에서
ollama pull llama3.2:1b
```

### 2️⃣ 단계별 실행

#### Step 1: RQ1 - Theory-Guided Generation (60분)
```bash
# C1, C2, C3, C4 모든 조건 평가
python3 scripts/run_full_evaluation.py zeroday \
    --conditions c1 c2 c3 c4 \
    --limit 10 \
    --output results/evaluation_full
```

#### Step 2: RQ2 - Incomplete Patches 생성 (2분)
```bash
# 각 취약점당 2-3개의 불완전 패치 생성
python3 scripts/inject_incomplete_patches.py \
    --dataset zeroday \
    --limit 10 \
    --output results/incomplete_patches
```

#### Step 3: RQ2 - Verification Ablation (90분)
```bash
# V1, V2, V3, V4 검증 방법 비교
python3 scripts/run_verification_ablation.py \
    --dataset zeroday \
    --limit 10 \
    --incomplete-patches results/incomplete_patches/incomplete_patches_zeroday.json \
    --output results/verification_ablation
```

#### Step 4: 결과 분석
```bash
# 각 조건에 대한 RQ 분석
python3 scripts/run_rq_analysis.py \
    results/evaluation_full/raw_results/full_patchscribe_c4_results.json \
    -o results/rq_analysis/rq_analysis.json

# 최종 보고서 확인
cat results/evaluation_full/EVALUATION_REPORT.md
```

---

## 📊 결과 확인

### 빠른 요약
```bash
# 모든 조건의 성공률 확인
for file in results/evaluation_full/raw_results/*_results.json; do
    echo "=== $(basename $file) ==="
    python3 -c "
import json
with open('$file') as f:
    data = json.load(f)
    print(f\"Success rate: {data['metrics']['success_rate']:.1%}\")
"
done
```

### 상세 결과 위치
```
results/
├── evaluation_full/
│   ├── raw_results/              # RQ1 결과 (C1-C4)
│   └── EVALUATION_REPORT.md      # 최종 요약 보고서
├── incomplete_patches/           # RQ2 불완전 패치
├── verification_ablation/        # RQ2 V1-V4 비교
└── rq_analysis/                  # 모든 RQ 분석
```

---

## 🎯 예상 결과 (논문 기준)

### RQ1: Theory-Guided Generation
| 조건 | 성공률 | 설명 |
|------|--------|------|
| C1 (Baseline) | ~30% | Post-hoc, no formal guidance |
| C2 (Vague Hints) | ~40% | Informal prompts |
| C3 (Pre-hoc) | ~50% | E_bug without verification |
| C4 (Full) | ~70% | E_bug + triple verification |

### RQ2: Dual Verification
| 방법 | Precision | Recall |
|------|-----------|--------|
| V1 (Exploit-only) | ~60% | ~50% |
| V2 (Symbolic-only) | ~75% | ~70% |
| V3 (Consistency-only) | ~85% | ~75% |
| V4 (Triple) | ~90% | ~80% |

### RQ3: Performance
| 복잡도 | 평균 시간 |
|--------|----------|
| Simple (<50 LoC) | ~120s |
| Medium (50-100) | ~160s |
| Complex (>100) | ~240s |

---

## 🔧 문제 해결

### LLM 연결 오류
```bash
# Ollama 상태 확인
curl http://localhost:11434/api/tags

# 모델이 없으면 다운로드
ollama pull llama3.2:1b
```

### 메모리 부족
```bash
# 순차 실행으로 변경
python3 scripts/run_full_evaluation.py zeroday \
    --conditions c4 \
    --limit 5 \
    --max-workers 1
```

### 데이터셋 없음
```bash
# 데이터셋 확인
ls -la datasets/zeroday_repair/

# 케이스 수 확인
python3 -c "from patchscribe.dataset import load_cases; print(len(load_cases('zeroday')))"
```

---

## 📋 Quick Reference - Research Questions

### RQ1: Theory-Guided Generation Effectiveness
**질문**: 사전 형식 명세(E_bug)가 더 정확한 패치를 생성하는가?

**실행**:
```bash
python3 scripts/run_full_evaluation.py zeroday --conditions c1 c2 c3 c4 --limit 10
```

**측정 지표**:
- Triple verification rate (삼중 검증 통과율)
- Ground truth similarity (실제 패치 유사도)
- First attempt success rate (첫 시도 성공률)

### RQ2: Dual Verification Effectiveness
**질문**: 이중 설명(E_bug ↔ E_patch) + 일관성 검증이 불완전 패치를 탐지하는가?

**실행**:
```bash
python3 scripts/run_full_evaluation.py zeroday --conditions c4 --limit 10
```

**측정 지표**:
- Incomplete patches caught (불완전 패치 탐지 수)
- Consistency violation breakdown (일관성 위반 유형)

### RQ3: Scalability and Performance
**질문**: 3단계 워크플로우의 시간 오버헤드는?

**측정 지표**:
- Phase 1/2/3 time (단계별 시간)
- Total time (목표: <3분)
- Peak memory usage

### RQ4: Explanation Quality
**질문**: 이중 설명이 개발자에게 유용한 인사이트를 제공하는가?

**측정 지표**:
- Checklist coverage (자동)
- Expert quality scores (GPT 기반)

---

## 📚 더 많은 정보

- **전체 워크플로우**: [EXPERIMENT_WORKFLOW.md](EXPERIMENT_WORKFLOW.md)
- **데이터셋 가이드**: [DATASET_GUIDE.md](DATASET_GUIDE.md)
- **RQ 평가 가이드**: [RQ_EVALUATION_GUIDE.md](RQ_EVALUATION_GUIDE.md)
- **RQ2 전문 가이드**: [RQ2_EVALUATION_GUIDE.md](RQ2_EVALUATION_GUIDE.md)
- **분산 실행**: [DISTRIBUTED_GUIDE.md](DISTRIBUTED_GUIDE.md)
- **성능 튜닝**: [PERFORMANCE_TUNING.md](PERFORMANCE_TUNING.md)

---

## 💡 핵심 명령어만 보기

### 단일 서버
```bash
# 1. 빠른 테스트
./quick_test.sh

# 2. 전체 실험
./run_all_experiments.sh

# 3. 개별 실행
python3 scripts/run_full_evaluation.py zeroday --conditions c1 c2 c3 c4 --limit 10
python3 scripts/inject_incomplete_patches.py --dataset zeroday --limit 10
python3 scripts/run_verification_ablation.py --dataset zeroday --limit 10 \
    --incomplete-patches results/incomplete_patches/incomplete_patches_zeroday.json

# 4. 결과 확인
cat results/evaluation_full/EVALUATION_REPORT.md
```

### 여러 서버 (분산 실행) ⚡

```bash
# 1. 각 서버에서 실행 (모든 모델 × 모든 조건 C1-C4 자동 실행)
# Server 0:
python3 scripts/run_distributed.py 0 4 20 zeroday

# Server 1:
python3 scripts/run_distributed.py 1 4 20 zeroday

# Server 2:
python3 scripts/run_distributed.py 2 4 20 zeroday

# Server 3:
python3 scripts/run_distributed.py 3 4 20 zeroday

# 2. 결과 수집 (중앙 서버)
scp -r user@server0:~/patchscribe/results/server0 results/
scp -r user@server1:~/patchscribe/results/server1 results/
scp -r user@server2:~/patchscribe/results/server2 results/
scp -r user@server3:~/patchscribe/results/server3 results/

# 3. 결과 병합
python3 scripts/aggregate_results.py --mode merge --results-dir results --output results/merged

# 4. RQ 분석 (모델별로)
python3 scripts/run_rq_analysis.py results/merged/llama3.2:1b/c4_merged_results.json
python3 scripts/run_rq_analysis.py results/merged/llama3.2:3b/c4_merged_results.json
python3 scripts/run_rq_analysis.py results/merged/qwen2.5-coder:7b/c4_merged_results.json
```

**참고**:
- 테스트할 모델 리스트는 `--models` 옵션으로 지정 가능 (기본값: gemma3:4b, qwen3:4b, deepseek-r1:7b, llama3.2:3b)
- 각 서버는 할당된 데이터에 대해 모든 모델과 조건을 자동으로 실험

**상세 가이드**: [DISTRIBUTED_GUIDE.md](DISTRIBUTED_GUIDE.md) 참고

---

**완료!** 🎉 질문이 있으시면 이슈를 등록해주세요.
