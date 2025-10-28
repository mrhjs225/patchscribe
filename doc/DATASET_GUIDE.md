# 데이터셋 사용 가이드

## 내장 데이터셋

PatchScribe는 두 가지 내장 데이터셋을 제공합니다:

### 1. POC 데이터셋 (`poc`)
- 3개의 간단한 테스트 케이스
- 개발 및 디버깅용
- 빠른 실행 (~1-2분)

### 2. Zeroday Repair 데이터셋 (`zeroday`)
- 실제 2024 CVE 사례들
- 총 100+ 케이스
- 다양한 CWE 타입:
  - CWE-125: Out-of-bounds read
  - CWE-190: Integer overflow
  - CWE-401: Memory leak
  - CWE-457: Uninitialized variable
  - CWE-476: NULL pointer dereference
  - CWE-787: Out-of-bounds write

## 데이터셋 형식

모든 케이스는 다음 필드를 포함해야 합니다:

```json
{
  "id": "case_identifier",
  "source": "vulnerable C code",
  "vuln_line": 10,
  "cwe_id": "CWE-125",
  "signature": "vulnerable line or description",
  "expected_success": true,
  "ground_truth": "patched code (optional)",
  "cve_id": "CVE-2024-xxxxx (optional)"
}
```

### 필수 필드
- `id`: 고유 식별자
- `source`: 취약한 소스 코드 (문자열)
- `vuln_line`: 취약점이 있는 라인 번호 (1-based)
- `cwe_id`: CWE 식별자 (예: "CWE-125")
- `signature`: 취약점 시그니처
- `expected_success`: 패치 성공 예상 여부

### 선택적 필드
- `ground_truth`: 실제 CVE 패치 코드 (비교용)
- `cve_id`: CVE 식별자
- `metadata`: 추가 메타데이터

## 사용 방법

### Quick Eval 스크립트

```bash
# 내장 샘플 케이스
python scripts/quick_eval.py

# POC 데이터셋 (3 cases)
python scripts/quick_eval.py poc

# Zeroday 데이터셋 (처음 3 cases만)
python scripts/quick_eval.py zeroday

# JSON 파일
python scripts/quick_eval.py path/to/dataset.json
```

### Full Evaluation 스크립트

```bash
# Zeroday 데이터셋 전체
python scripts/run_full_evaluation.py zeroday -o results/full

# POC 데이터셋
python scripts/run_full_evaluation.py poc -o results/poc

# JSON 파일
python scripts/run_full_evaluation.py dataset.json -o results/custom

# 디렉토리 (zeroday_repair 구조)
python scripts/run_full_evaluation.py datasets/zeroday_repair/ -o results/dir
```

### Python API

```python
from patchscribe.dataset import load_cases

# POC 데이터셋 로드
cases = load_cases(dataset='poc')

# Zeroday 데이터셋 로드 (전체)
cases = load_cases(dataset='zeroday')

# 처음 5개만 로드
cases = load_cases(dataset='zeroday', limit=5)

# 케이스 확인
for case in cases:
    print(f"ID: {case['id']}")
    print(f"CWE: {case['cwe_id']}")
    print(f"Lines: {len(case['source'].splitlines())}")
```

## 커스텀 데이터셋 생성

### JSON 파일 형식

```json
[
  {
    "id": "custom_001",
    "source": "int func() {\n  char buf[10];\n  gets(buf);\n  return 0;\n}",
    "vuln_line": 3,
    "cwe_id": "CWE-120",
    "signature": "gets(buf)",
    "expected_success": true,
    "ground_truth": "int func() {\n  char buf[10];\n  fgets(buf, 10, stdin);\n  return 0;\n}"
  }
]
```

### 디렉토리 구조 (Zeroday 형식)

```
custom_dataset/
├── CWE-XXX___issue-name___1-50___10.c/
│   ├── vul.c      # 취약한 코드
│   └── nonvul.c   # 패치된 코드
└── CWE-YYY___another-issue___1-30___5.c/
    ├── vul.c
    └── nonvul.c
```

디렉토리명 형식: `CWE-ID___CVE-ID___line-range___vuln-line.c`

## 데이터셋 통계

### Zeroday Repair 데이터셋

```bash
# 통계 확인
python -c "
from patchscribe.dataset import load_cases
from collections import Counter

cases = load_cases(dataset='zeroday')
cwes = Counter(c['cwe_id'] for c in cases)

print(f'Total cases: {len(cases)}')
print(f'\\nCWE distribution:')
for cwe, count in cwes.most_common():
    print(f'  {cwe}: {count} cases')

# 코드 복잡도
lines = [len(c['source'].splitlines()) for c in cases]
print(f'\\nCode complexity:')
print(f'  Min lines: {min(lines)}')
print(f'  Max lines: {max(lines)}')
print(f'  Avg lines: {sum(lines)/len(lines):.1f}')
"
```

예상 출력:
```
Total cases: 100+

CWE distribution:
  CWE-476: 25 cases
  CWE-125: 20 cases
  CWE-787: 15 cases
  CWE-401: 12 cases
  ...

Code complexity:
  Min lines: 7
  Max lines: 517
  Avg lines: 65.3
```

## 트러블슈팅

### "Dataset not found"
```bash
# 경로 확인
ls -la datasets/zeroday_repair/

# 내장 데이터셋 사용
python scripts/quick_eval.py zeroday
```

### "Invalid dataset format"
케이스 JSON이 올바른 형식인지 확인:
- 필수 필드 모두 포함
- `source`는 문자열
- `vuln_line`은 숫자

### 데이터셋 검증
```python
from patchscribe.dataset import load_cases

# 데이터 로드 및 검증
cases = load_cases(dataset='your_dataset')

for case in cases:
    # 필수 필드 확인
    assert 'id' in case
    assert 'source' in case
    assert 'vuln_line' in case
    assert 'cwe_id' in case
    
    # 타입 확인
    assert isinstance(case['source'], str)
    assert isinstance(case['vuln_line'], int)
    
    print(f"✓ {case['id']}")

print(f"\n✅ All {len(cases)} cases valid")
```
