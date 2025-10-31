#!/bin/bash
# Quick Test Script - 빠른 테스트용 (3개 케이스만)
# 전체 파이프라인이 동작하는지 빠르게 확인

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}  PatchScribe Quick Test${NC}"
echo -e "${BLUE}================================${NC}"
echo ""
echo "Testing with 3 cases (estimated time: ~10 minutes)"
echo ""

# Test 1: RQ1 - Only C4
echo -e "${GREEN}Test 1: RQ1 - Full PatchScribe (C4)${NC}"
python3 scripts/run_full_evaluation.py zeroday \
    --conditions c4 \
    --limit 3 \
    --output results/quick_test

# Test 2: RQ2 - Incomplete patches
echo -e "${GREEN}Test 2: RQ2 - Generate incomplete patches${NC}"
python3 scripts/inject_incomplete_patches.py \
    --dataset zeroday \
    --limit 2 \
    --output results/quick_test_incomplete

# Test 3: AST similarity
echo -e "${GREEN}Test 3: AST similarity calculation${NC}"
python3 -c "
from patchscribe.ast_similarity import calculate_ast_similarity

code1 = 'int main() { char buf[10]; strcpy(buf, input); }'
code2 = 'int main() { char buf[10]; if(strlen(input)<10) strcpy(buf, input); }'

result = calculate_ast_similarity(code1, code2)
print(f'✅ AST similarity: {result.overall_similarity:.2%}')
"

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  ✅ Quick Test Passed!${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo "Results: results/quick_test/"
echo ""
echo "To run full experiments: ./run_all_experiments.sh"
