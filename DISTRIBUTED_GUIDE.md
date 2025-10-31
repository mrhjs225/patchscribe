# 분산 실험 가이드

여러 서버에서 데이터를 나눠서 실험하고 결과를 병합하는 가이드입니다.

---

## 📋 개요

### 핵심 개념
- **각 서버는 할당된 데이터만 처리**
- **모든 조건(C1-C4)을 자동으로 실험**
- **결과를 중앙에서 병합**

### 예시: 4대 서버, 20개 케이스
```
Server 0: Cases 0-4   (5개) → C1, C2, C3, C4 모두 실험
Server 1: Cases 5-9   (5개) → C1, C2, C3, C4 모두 실험
Server 2: Cases 10-14 (5개) → C1, C2, C3, C4 모두 실험
Server 3: Cases 15-19 (5개) → C1, C2, C3, C4 모두 실험
```

### 성능 향상
- **단일 서버**: 20개 × 8분 = 160분
- **4대 서버**: 5개 × 8분 = 40분 (**4배 빠름!**)

---

## 🚀 사용법

### 1단계: 데이터셋 크기 확인

```bash
# 데이터셋에 몇 개의 케이스가 있는지 확인
python3 -c "
from patchscribe.dataset import load_cases
cases = load_cases('zeroday')
print(f'Total cases: {len(cases)}')
"
```

### 2단계: 각 서버에서 실행

모든 서버에서 **동일한 명령어**를 실행하되, **SERVER_ID만 다르게** 지정합니다.

```bash
# 문법
./run_server.sh <SERVER_ID> <NUM_SERVERS> <TOTAL_CASES> [DATASET]
```

#### 예시: 4대 서버, 20개 케이스

**Server 0 (148):**
```bash
./run_server.sh 0 4 20 zeroday
```

**Server 1 (selab2):**
```bash
./run_server.sh 1 4 20 zeroday
```

**Server 2 (soty):**
```bash
./run_server.sh 2 4 20 zeroday
```

**Server 3 (central):**
```bash
./run_server.sh 3 4 20 zeroday
```

### 3단계: 결과 수집

각 서버의 `results/server<ID>/` 디렉토리를 중앙 서버로 복사:

```bash
# 중앙 서버에서 실행
mkdir -p results

# 각 서버에서 복사
scp -r user@148:~/patchscribe/results/server0 results/
scp -r user@selab2:~/patchscribe/results/server1 results/
scp -r user@soty:~/patchscribe/results/server2 results/
scp -r user@central:~/patchscribe/results/server3 results/
```

또는 **공유 스토리지 사용**:
```bash
# 각 서버가 NFS 마운트된 공유 디렉토리에 직접 저장
# 별도 복사 불필요
```

### 4단계: 결과 병합

```bash
# 중앙 서버에서 실행
python3 scripts/merge_results.py --results-dir results --output results/merged
```

**출력 예시:**
```
================================================================================
MERGING RESULTS FROM ALL SERVERS
================================================================================

Merging condition: c1
  Reading: c1_server0_results.json
    Added 5 cases
  Reading: c1_server1_results.json
    Added 5 cases
  Reading: c1_server2_results.json
    Added 5 cases
  Reading: c1_server3_results.json
    Added 5 cases
  ✅ c1: 20 cases, success rate: 35.0%

Merging condition: c2
  ...

✅ MERGE COMPLETE
Results saved to: results/merged/
```

### 5단계: RQ 분석

```bash
# 각 조건별 분석
python3 scripts/run_rq_analysis.py \
    results/merged/c1_merged_results.json \
    -o results/analysis/rq_c1.json

python3 scripts/run_rq_analysis.py \
    results/merged/c2_merged_results.json \
    -o results/analysis/rq_c2.json

python3 scripts/run_rq_analysis.py \
    results/merged/c3_merged_results.json \
    -o results/analysis/rq_c3.json

python3 scripts/run_rq_analysis.py \
    results/merged/c4_merged_results.json \
    -o results/analysis/rq_c4.json
```

---

## 📁 결과 파일 구조

```
results/
├── server0/
│   ├── assigned_cases.json
│   ├── c1_server0_results.json
│   ├── c2_server0_results.json
│   ├── c3_server0_results.json
│   ├── c4_server0_results.json
│   └── incomplete_patches_server0.json
├── server1/
│   └── (동일 구조)
├── server2/
│   └── (동일 구조)
├── server3/
│   └── (동일 구조)
└── merged/
    ├── c1_merged_results.json          ← 모든 서버 C1 결과 병합
    ├── c2_merged_results.json          ← 모든 서버 C2 결과 병합
    ├── c3_merged_results.json          ← 모든 서버 C3 결과 병합
    ├── c4_merged_results.json          ← 모든 서버 C4 결과 병합
    └── incomplete_patches_merged.json  ← 모든 불완전 패치 병합
```

---

## 🔧 고급 활용

### SSH를 통한 자동 실행

```bash
#!/bin/bash
# run_all_servers.sh

SERVERS=("148" "selab2" "soty" "central")
TOTAL_CASES=20

for i in "${!SERVERS[@]}"; do
    SERVER=${SERVERS[$i]}
    echo "Starting Server $i on $SERVER..."

    ssh user@$SERVER "cd ~/patchscribe && \
        nohup ./run_server.sh $i ${#SERVERS[@]} $TOTAL_CASES zeroday \
        > server${i}.log 2>&1 &"
done

echo "All servers started. Monitor with:"
echo "  ssh user@SERVER 'tail -f ~/patchscribe/server*.log'"
```

### 진행 상황 모니터링

```bash
# 각 서버의 진행 상황 확인
ssh user@148 "cd ~/patchscribe && ls -lh results/server0/*.json | wc -l"

# 예상: 5개 파일 (c1, c2, c3, c4, incomplete_patches)
```

### 부분 결과 확인

```bash
# 일부 서버만 완료된 경우에도 병합 가능
python3 scripts/merge_results.py --results-dir results --output results/partial

# 나중에 나머지 서버 결과를 추가하여 재병합
```

---

## ⚠️ 주의사항

### 1. 환경 일치
모든 서버에서 **동일한 환경** 필요:
- Python 버전
- LLM 모델 (Ollama)
- 동일한 코드베이스

```bash
# 각 서버에서 확인
python3 --version
ollama list
git rev-parse HEAD  # 동일한 commit 확인
```

### 2. 케이스 수 정확히 입력
`TOTAL_CASES`는 **실제 데이터셋 크기**와 일치해야 함:
```bash
# 잘못된 예
./run_server.sh 0 4 30 zeroday  # 실제로는 20개인데 30 입력

# 올바른 예
TOTAL=$(python3 -c "from patchscribe.dataset import load_cases; print(len(load_cases('zeroday')))")
./run_server.sh 0 4 $TOTAL zeroday
```

### 3. 중복 실행 방지
같은 SERVER_ID로 두 번 실행하지 않도록 주의

---

## 🐛 문제 해결

### 한 서버가 실패한 경우

```bash
# 실패한 서버만 재실행
# Server 1이 실패했다면:
ssh user@selab2 "cd ~/patchscribe && ./run_server.sh 1 4 20 zeroday"

# 완료 후 전체 재병합
python3 scripts/merge_results.py
```

### 결과 검증

```bash
# 병합된 케이스 수 확인
python3 << 'EOF'
import json
from pathlib import Path

for condition in ['c1', 'c2', 'c3', 'c4']:
    file = Path(f'results/merged/{condition}_merged_results.json')
    if file.exists():
        with open(file) as f:
            data = json.load(f)
        print(f"{condition}: {len(data['cases'])} cases")
EOF
```

---

## 📊 성능 비교

| 케이스 수 | 단일 서버 | 2대 서버 | 4대 서버 |
|----------|----------|---------|---------|
| 10개 | 80분 | 40분 | 20분 |
| 20개 | 160분 | 80분 | 40분 |
| 50개 | 400분 | 200분 | 100분 |

---

## 요약

```bash
# 1. 각 서버 실행 (SERVER_ID만 변경)
./run_server.sh 0 4 20 zeroday  # Server 0
./run_server.sh 1 4 20 zeroday  # Server 1
./run_server.sh 2 4 20 zeroday  # Server 2
./run_server.sh 3 4 20 zeroday  # Server 3

# 2. 결과 수집 (중앙 서버)
scp -r user@server*:~/patchscribe/results/server* results/

# 3. 병합
python3 scripts/merge_results.py

# 4. 분석
python3 scripts/run_rq_analysis.py results/merged/c4_merged_results.json
```

**완료!** 🚀
