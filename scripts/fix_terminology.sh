#!/bin/bash
# PatchScribe 논문 용어 통일 스크립트
# "Triple Verification" → "Multi-Stage Verification"

set -e

PAPER_FILE="doc/paper/patchscribe.tex"
BACKUP_FILE="doc/paper/patchscribe.tex.backup"

echo "🔧 PatchScribe 용어 통일 스크립트"
echo "=================================="
echo ""

# 백업 생성
if [ ! -f "$BACKUP_FILE" ]; then
    echo "📦 원본 파일 백업 중..."
    cp "$PAPER_FILE" "$BACKUP_FILE"
    echo "✅ 백업 완료: $BACKUP_FILE"
else
    echo "⚠️  백업 파일이 이미 존재합니다: $BACKUP_FILE"
    read -p "기존 백업을 덮어쓰시겠습니까? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cp "$PAPER_FILE" "$BACKUP_FILE"
        echo "✅ 백업 덮어쓰기 완료"
    fi
fi

echo ""
echo "🔍 변경 전 상태 확인..."
echo "------------------------"
echo "\"triple verification\" 출현 횟수:"
grep -c "triple verification" "$PAPER_FILE" || echo "0"
echo ""

# 수정 1: Abstract (triple verification → multi-stage checks)
echo "📝 수정 1/7: Abstract 수정..."
sed -i 's/triple verification: (1) consistency checking to ensure E_patch/dual verification by comparing E_bug and E_patch through multi-stage checks: (1) consistency checking to ensure E_patch/g' "$PAPER_FILE"

# 수정 2: Abstract (추가 설명)
sed -i 's/addresses causes identified in E_bug, (2) symbolic verification to$/addresses all causes identified in E_bug, (2) symbolic verification to/g' "$PAPER_FILE"

# 수정 3: Introduction (triple verification → dual verification through multiple stages)
echo "📝 수정 2/7: Introduction 수정..."
sed -i 's/We then perform triple verification: (1) consistency/We then perform dual verification—comparing E_bug and E_patch—through multiple stages: (1) consistency/g' "$PAPER_FILE"

# 수정 4: Phase 3 description (triple verification → multi-stage verification)
echo "📝 수정 3/7: Phase 3 설명 수정..."
sed -i 's/This triple verification$/This multi-stage verification/g' "$PAPER_FILE"

# 수정 5: Phase 3 detailed description
sed -i 's/We perform three types of$/We verify consistency between E_bug and E_patch through multi-stage/g' "$PAPER_FILE"

# 수정 6: RQ2 (triple verification → multi-stage verification)
echo "📝 수정 4/7: RQ2 수정..."
sed -i 's/Does triple verification (consistency + symbolic + completeness)/Does multi-stage verification (consistency checking + symbolic verification + completeness analysis)/g' "$PAPER_FILE"

# 수정 7: Evaluation 섹션들
echo "📝 수정 5/7: Evaluation 섹션 1 수정..."
sed -i 's/E_bug and triple verification)/E_bug and multi-stage verification)/g' "$PAPER_FILE"

echo "📝 수정 6/7: Evaluation 섹션 2 수정..."
sed -i 's/and V4 (triple verification)\./and V4 (multi-stage verification)./g' "$PAPER_FILE"

echo "📝 수정 7/7: Evaluation 섹션 3 수정..."
sed -i 's/We anticipate triple verification (V4) to$/We anticipate multi-stage verification (V4) to/g' "$PAPER_FILE"

echo ""
echo "✅ 모든 수정 완료!"
echo ""

echo "🔍 변경 후 상태 확인..."
echo "------------------------"
echo "\"triple verification\" 남은 횟수:"
grep -c "triple verification" "$PAPER_FILE" || echo "0 (모두 제거됨 ✅)"
echo ""
echo "\"multi-stage\" 출현 횟수:"
grep -c "multi-stage" "$PAPER_FILE" || echo "0"
echo ""

echo "📊 변경 사항 요약:"
echo "------------------------"
echo "\"triple verification\" → \"multi-stage verification\""
echo "\"three types of verification\" → \"multi-stage verification\""
echo ""

echo "📋 다음 단계:"
echo "1. doc/paper/patchscribe.tex 파일을 열어 수정 결과 확인"
echo "2. Introduction에 Terminology 단락 수동 추가 (doc/TERMINOLOGY_FIX.md 참조)"
echo "3. LaTeX 컴파일하여 오류 확인"
echo "4. 문제 있으면 백업 파일로 복원: cp $BACKUP_FILE $PAPER_FILE"
echo ""

echo "✨ 완료!"
