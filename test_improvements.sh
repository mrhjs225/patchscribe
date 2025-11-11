#!/bin/bash
# 개선 사항 빠른 테스트 스크립트

set -e

echo "=========================================="
echo "PatchScribe 개선 사항 테스트"
echo "=========================================="
echo ""

# 가상환경 확인
if [ ! -d ".venv" ]; then
    echo "❌ 가상환경이 없습니다. 먼저 생성하세요:"
    echo "   python -m venv .venv"
    echo "   source .venv/bin/activate"
    echo "   pip install -r requirements.txt"
    exit 1
fi

# 결과 디렉토리 생성
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="results/test_improvements_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

echo "📁 결과 저장 위치: $OUTPUT_DIR"
echo ""

# 테스트 케이스 수 설정
LIMIT=5

echo "🧪 테스트 1: ExtractFix C3 성능 확인 (이전 급락 문제)"
echo "   - 이전: 8.3% success rate"
echo "   - 목표: 15%+ 달성"
echo ""

source .venv/bin/activate

python scripts/run_experiment.py \
  --dataset extractfix \
  --conditions c3 \
  --limit $LIMIT \
  --output "$OUTPUT_DIR/extractfix_c3" \
  2>&1 | tee "$OUTPUT_DIR/extractfix_c3.log"

echo ""
echo "✅ ExtractFix C3 테스트 완료"
echo ""

echo "🧪 테스트 2: ExtractFix C4 인과 경로 개선 확인"
echo "   - 이전: 13.5% success rate"
echo "   - 목표: 20%+ 달성"
echo ""

python scripts/run_experiment.py \
  --dataset extractfix \
  --conditions c4 \
  --limit $LIMIT \
  --output "$OUTPUT_DIR/extractfix_c4" \
  2>&1 | tee "$OUTPUT_DIR/extractfix_c4.log"

echo ""
echo "✅ ExtractFix C4 테스트 완료"
echo ""

echo "🧪 테스트 3: Zeroday C1 vs C4 비교 (LLM Judge 평가)"
echo "   - C1 Causality: 3.73 → 3.0 목표"
echo "   - C4 Causality: 3.94 → 4.5 목표"
echo ""

python scripts/run_experiment.py \
  --dataset zeroday \
  --conditions c1,c4 \
  --limit $LIMIT \
  --output "$OUTPUT_DIR/zeroday_comparison" \
  --enable-judge \
  2>&1 | tee "$OUTPUT_DIR/zeroday_comparison.log"

echo ""
echo "✅ Zeroday 비교 테스트 완료"
echo ""

echo "=========================================="
echo "📊 테스트 결과 요약"
echo "=========================================="
echo ""

# 결과 분석 (간단한 grep)
echo "1. ExtractFix C3 Success Rate:"
grep -E "success_rate|Success Rate" "$OUTPUT_DIR/extractfix_c3.log" | tail -1 || echo "   (로그에서 찾을 수 없음)"
echo ""

echo "2. ExtractFix C4 Success Rate:"
grep -E "success_rate|Success Rate" "$OUTPUT_DIR/extractfix_c4.log" | tail -1 || echo "   (로그에서 찾을 수 없음)"
echo ""

echo "3. LLM Judge Causality 점수:"
echo "   C1 결과:"
grep -E "causality|Causality" "$OUTPUT_DIR/zeroday_comparison.log" | grep -i "c1" | tail -1 || echo "   (로그에서 찾을 수 없음)"
echo "   C4 결과:"
grep -E "causality|Causality" "$OUTPUT_DIR/zeroday_comparison.log" | grep -i "c4" | tail -1 || echo "   (로그에서 찾을 수 없음)"
echo ""

echo "=========================================="
echo "📁 상세 결과 확인:"
echo "   $OUTPUT_DIR/"
echo ""
echo "📖 개선 사항 문서:"
echo "   IMPROVEMENTS_2025.md"
echo ""
echo "✅ 테스트 완료!"
echo "=========================================="
