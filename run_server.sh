#!/bin/bash
# PatchScribe 분산 실험 실행 스크립트
# 각 서버가 할당된 데이터에 대해 모든 조건(C1-C4)을 실험

set -e

# 설정
SERVER_ID=${1}
NUM_SERVERS=${2}
TOTAL_CASES=${3}
DATASET=${4:-zeroday}

if [ -z "$SERVER_ID" ] || [ -z "$NUM_SERVERS" ] || [ -z "$TOTAL_CASES" ]; then
    echo "Usage: $0 <SERVER_ID> <NUM_SERVERS> <TOTAL_CASES> [DATASET]"
    echo ""
    echo "Example:"
    echo "  $0 0 4 20 zeroday"
    echo ""
    echo "Arguments:"
    echo "  SERVER_ID    : This server's ID (0, 1, 2, ...)"
    echo "  NUM_SERVERS  : Total number of servers"
    echo "  TOTAL_CASES  : Total number of cases in dataset"
    echo "  DATASET      : Dataset name (default: zeroday)"
    exit 1
fi

echo "========================================"
echo "  PatchScribe Server $SERVER_ID"
echo "========================================"
echo "Total servers: $NUM_SERVERS"
echo "Total cases: $TOTAL_CASES"
echo "Dataset: $DATASET"
echo ""

# 케이스 할당 계산
cases_per_server=$((TOTAL_CASES / NUM_SERVERS))
remainder=$((TOTAL_CASES % NUM_SERVERS))

if [ $SERVER_ID -lt $remainder ]; then
    start_index=$((SERVER_ID * (cases_per_server + 1)))
    count=$((cases_per_server + 1))
else
    start_index=$((remainder * (cases_per_server + 1) + (SERVER_ID - remainder) * cases_per_server))
    count=$cases_per_server
fi

end_index=$((start_index + count - 1))

echo "This server processes:"
echo "  Cases: $start_index to $end_index ($count cases)"
echo ""

# 출력 디렉토리
OUTPUT_DIR="results/server${SERVER_ID}"
mkdir -p $OUTPUT_DIR

# 할당된 케이스 추출
echo "Extracting assigned cases..."
python3 << EOF
from patchscribe.dataset import load_cases
import json

all_cases = load_cases('$DATASET')
assigned_cases = all_cases[$start_index:$start_index+$count]

print(f"Assigned: {len(assigned_cases)} cases")

with open('$OUTPUT_DIR/assigned_cases.json', 'w') as f:
    json.dump(assigned_cases, f, indent=2)
EOF

echo ""
echo "========================================"
echo "  Running All Conditions (C1-C4)"
echo "========================================"

# 모든 조건 실행
for CONDITION in c1 c2 c3 c4; do
    echo ""
    echo ">>> Starting Condition: $CONDITION"

    # 조건별 설정
    case $CONDITION in
        c1) STRATEGY="only_natural"; CONSISTENCY="False" ;;
        c2) STRATEGY="natural"; CONSISTENCY="False" ;;
        c3) STRATEGY="formal"; CONSISTENCY="False" ;;
        c4) STRATEGY="formal"; CONSISTENCY="True" ;;
    esac

    # 평가 실행
    python3 << EOF
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path.cwd()))

from patchscribe.pipeline import PatchScribePipeline
from patchscribe.evaluation import Evaluator

# 할당된 케이스 로드
with open('$OUTPUT_DIR/assigned_cases.json', 'r') as f:
    cases = json.load(f)

print(f"Running $CONDITION on {len(cases)} cases...")

# 파이프라인 설정
enable_consistency = $CONSISTENCY == "True"
pipeline = PatchScribePipeline(
    strategy='$STRATEGY',
    explain_mode='both',
    enable_consistency_check=enable_consistency,
    enable_performance_profiling=True
)

# 평가 실행
evaluator = Evaluator(pipeline=pipeline)
report = evaluator.run(cases)

# 결과 저장
output_file = Path('$OUTPUT_DIR/${CONDITION}_server${SERVER_ID}_results.json')
output_file.parent.mkdir(parents=True, exist_ok=True)

with open(output_file, 'w') as f:
    json.dump(report.as_dict(), f, indent=2)

print(f"✅ $CONDITION complete: Success rate {report.metrics.get('success_rate', 0):.1%}")
EOF

    echo "✅ Condition $CONDITION completed"
done

echo ""
echo "========================================"
echo "  Generating Incomplete Patches (RQ2)"
echo "========================================"

python3 << EOF
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path.cwd()))

from scripts.inject_incomplete_patches import IncompletePatchGenerator

with open('$OUTPUT_DIR/assigned_cases.json', 'r') as f:
    cases = json.load(f)

print(f"Generating incomplete patches for {len(cases)} cases...")

all_patches = {}
for case in cases:
    case_id = case['id']
    generator = IncompletePatchGenerator(case)
    patches = generator.generate_incomplete_patches()

    all_patches[case_id] = [
        {
            'patch_id': p.patch_id,
            'case_id': p.case_id,
            'patched_code': p.patched_code,
            'incompleteness_type': p.incompleteness_type,
            'description': p.description,
            'why_incomplete': p.why_incomplete,
            'should_be_caught_by': p.should_be_caught_by
        }
        for p in patches
    ]

output_file = Path('$OUTPUT_DIR/incomplete_patches_server${SERVER_ID}.json')
with open(output_file, 'w') as f:
    json.dump(all_patches, f, indent=2)

print(f"✅ Generated {sum(len(p) for p in all_patches.values())} incomplete patches")
EOF

echo ""
echo "========================================"
echo "  ✅ Server $SERVER_ID Complete!"
echo "========================================"
echo ""
echo "Results saved to: $OUTPUT_DIR/"
echo ""
echo "Files generated:"
ls -lh $OUTPUT_DIR/*.json
echo ""
echo "Next: Merge results on central server"
echo "  python3 scripts/merge_results.py"
