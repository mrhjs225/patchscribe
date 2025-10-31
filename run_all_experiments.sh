#!/bin/bash
# PatchScribe Full Experimental Pipeline
# 논문의 모든 RQ를 검증하기 위한 전체 실험 스크립트

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DATASET="zeroday"
LIMIT=10  # Number of cases to evaluate (use 3 for quick test)
OUTPUT_DIR="results"

echo -e "${BLUE}================================================================================${NC}"
echo -e "${BLUE}        PatchScribe Full Experimental Pipeline${NC}"
echo -e "${BLUE}================================================================================${NC}"
echo ""
echo -e "${YELLOW}Configuration:${NC}"
echo "  Dataset: $DATASET"
echo "  Limit: $LIMIT cases"
echo "  Output: $OUTPUT_DIR/"
echo ""

# Check environment
echo -e "${GREEN}Step 0: Checking environment...${NC}"
python3 --version || { echo -e "${RED}Python 3 not found!${NC}"; exit 1; }
python3 -c "from patchscribe.dataset import load_cases" || { echo -e "${RED}PatchScribe module not found!${NC}"; exit 1; }
echo -e "${GREEN}✅ Environment OK${NC}"
echo ""

# Create output directories
mkdir -p $OUTPUT_DIR/{evaluation_full,incomplete_patches,verification_ablation,rq_analysis,blind_evaluation}

# Step 1: RQ1 - Theory-Guided Generation (C1-C4)
echo -e "${GREEN}================================================================================${NC}"
echo -e "${GREEN}Step 1: RQ1 - Theory-Guided Generation (C1-C4)${NC}"
echo -e "${GREEN}================================================================================${NC}"
echo "This will evaluate all four conditions:"
echo "  C1: Baseline (post-hoc, no formal guidance)"
echo "  C2: Vague Hints (informal prompts)"
echo "  C3: Pre-hoc Guidance (E_bug without verification)"
echo "  C4: Full PatchScribe (E_bug + triple verification)"
echo ""
echo "Estimated time: ~60 minutes for $LIMIT cases"
echo ""

python3 scripts/run_full_evaluation.py $DATASET \
    --conditions c1 c2 c3 c4 \
    --limit $LIMIT \
    --output $OUTPUT_DIR/evaluation_full

echo -e "${GREEN}✅ Step 1 complete: RQ1 evaluation done${NC}"
echo ""

# Step 2: RQ2 Part 1 - Generate Incomplete Patches
echo -e "${GREEN}================================================================================${NC}"
echo -e "${GREEN}Step 2: RQ2 Part 1 - Generate Incomplete Patches${NC}"
echo -e "${GREEN}================================================================================${NC}"
echo "Generating 2-3 deliberately incomplete patches per vulnerability"
echo "Estimated time: ~2 minutes"
echo ""

python3 scripts/inject_incomplete_patches.py \
    --dataset $DATASET \
    --limit $LIMIT \
    --output $OUTPUT_DIR/incomplete_patches

echo -e "${GREEN}✅ Step 2 complete: Incomplete patches generated${NC}"
echo ""

# Step 3: RQ2 Part 2 - Verification Method Ablation (V1-V4)
echo -e "${GREEN}================================================================================${NC}"
echo -e "${GREEN}Step 3: RQ2 Part 2 - Verification Method Ablation (V1-V4)${NC}"
echo -e "${GREEN}================================================================================${NC}"
echo "Comparing four verification approaches:"
echo "  V1: Exploit-only testing"
echo "  V2: Symbolic execution only"
echo "  V3: Consistency checking only"
echo "  V4: Triple verification (full PatchScribe)"
echo ""
echo "Estimated time: ~90 minutes"
echo ""

python3 scripts/run_verification_ablation.py \
    --dataset $DATASET \
    --limit $LIMIT \
    --incomplete-patches $OUTPUT_DIR/incomplete_patches/incomplete_patches_$DATASET.json \
    --output $OUTPUT_DIR/verification_ablation

echo -e "${GREEN}✅ Step 3 complete: Verification ablation done${NC}"
echo ""

# Step 4: RQ Analysis for all conditions
echo -e "${GREEN}================================================================================${NC}"
echo -e "${GREEN}Step 4: RQ Analysis (RQ1, RQ2, RQ3, RQ4)${NC}"
echo -e "${GREEN}================================================================================${NC}"
echo "Analyzing results for all research questions..."
echo ""

for condition in baseline_c1 vague_hints_c2 prehoc_c3 full_patchscribe_c4; do
    if [ -f "$OUTPUT_DIR/evaluation_full/raw_results/${condition}_results.json" ]; then
        echo "Analyzing $condition..."
        python3 scripts/run_rq_analysis.py \
            "$OUTPUT_DIR/evaluation_full/raw_results/${condition}_results.json" \
            -o "$OUTPUT_DIR/rq_analysis/rq_analysis_${condition}.json"
    fi
done

echo -e "${GREEN}✅ Step 4 complete: RQ analysis done${NC}"
echo ""

# Step 5: Generate Summary
echo -e "${GREEN}================================================================================${NC}"
echo -e "${GREEN}Step 5: Generating Summary${NC}"
echo -e "${GREEN}================================================================================${NC}"

python3 << 'EOF'
import json
from pathlib import Path

conditions = {
    'C1 (Baseline)': 'baseline_c1_results.json',
    'C2 (Vague Hints)': 'vague_hints_c2_results.json',
    'C3 (Pre-hoc)': 'prehoc_c3_results.json',
    'C4 (Full PatchScribe)': 'full_patchscribe_c4_results.json'
}

output_dir = Path('results/evaluation_full/raw_results')

print("\n" + "="*80)
print("EXPERIMENTAL RESULTS SUMMARY")
print("="*80)
print()

# RQ1
print("RQ1: Theory-Guided Generation Effectiveness")
print("-"*80)
print(f"{'Condition':<25} {'Success':<10} {'1st Attempt':<12} {'AST Sim':<10}")
print("-"*80)

for name, filename in conditions.items():
    filepath = output_dir / filename
    if filepath.exists():
        with open(filepath) as f:
            data = json.load(f)
            metrics = data.get('metrics', {})
            success = metrics.get('success_rate', 0)
            first = metrics.get('first_attempt_success_rate', 0)
            ast_sim = metrics.get('avg_ast_overall_similarity', 0)
            print(f"{name:<25} {success:>8.1%} {first:>10.1%} {ast_sim:>8.1%}")

print()

# RQ2
print("RQ2: Dual Verification Effectiveness")
print("-"*80)
verification_file = Path('results/verification_ablation/verification_ablation_zeroday.json')
if verification_file.exists():
    with open(verification_file) as f:
        data = json.load(f)
        print(f"{'Method':<10} {'Detection Rate':<20} {'Avg Time':<10}")
        print("-"*80)
        for method in ['V1', 'V2', 'V3', 'V4']:
            results = data.get(method, [])
            if results:
                detected = sum(1 for r in results if r['detected_incomplete'])
                total = len(results)
                avg_time = sum(r['execution_time'] for r in results) / len(results)
                print(f"{method:<10} {detected}/{total} ({detected/total:.1%})"[:30].ljust(30) + f"{avg_time:>6.2f}s")

print()

# RQ3
print("RQ3: Scalability and Performance")
print("-"*80)
c4_file = Path('results/rq_analysis/rq_analysis_full_patchscribe_c4.json')
if c4_file.exists():
    with open(c4_file) as f:
        data = json.load(f)
        rq3 = data.get('rq3_scalability_performance', [])
        if rq3:
            print(f"{'Complexity':<15} {'Cases':<8} {'Avg Time':<12}")
            print("-"*80)
            for result in rq3:
                complexity = result['complexity_level']
                cases = result['case_count']
                avg_time = result.get('avg_total_time', 0)
                print(f"{complexity:<15} {cases:<8} {avg_time:>8.2f}s")

print()

# RQ4
print("RQ4: Explanation Quality")
print("-"*80)
if c4_file.exists():
    with open(c4_file) as f:
        data = json.load(f)
        rq4 = data.get('rq4_explanation_quality', [])
        if rq4:
            for result in rq4:
                print(f"Checklist coverage: {result['checklist_coverage']:.1%}")
                if result.get('avg_accuracy_score', 0) > 0:
                    print(f"Accuracy: {result['avg_accuracy_score']:.2f}/5")
                    print(f"Clarity: {result['avg_clarity_score']:.2f}/5")
                    print(f"Causality: {result['avg_causality_score']:.2f}/5")

print()
print("="*80)
EOF

echo ""
echo -e "${GREEN}================================================================================${NC}"
echo -e "${GREEN}        ✅ ALL EXPERIMENTS COMPLETED SUCCESSFULLY!${NC}"
echo -e "${GREEN}================================================================================${NC}"
echo ""
echo -e "${YELLOW}Results Location:${NC}"
echo "  📊 Main evaluation: $OUTPUT_DIR/evaluation_full/"
echo "  📈 RQ analysis: $OUTPUT_DIR/rq_analysis/"
echo "  🔬 Verification ablation: $OUTPUT_DIR/verification_ablation/"
echo "  📝 Final report: $OUTPUT_DIR/evaluation_full/EVALUATION_REPORT.md"
echo ""
echo -e "${YELLOW}Key Files:${NC}"
find $OUTPUT_DIR -name "*.json" -o -name "*.md" | head -10
echo ""
echo -e "${BLUE}Next Steps:${NC}"
echo "  1. Review: cat $OUTPUT_DIR/evaluation_full/EVALUATION_REPORT.md"
echo "  2. Analyze: Review JSON files in $OUTPUT_DIR/rq_analysis/"
echo "  3. Visualize: Create figures from the JSON data"
echo ""
echo -e "${GREEN}Experiment log saved to: experiment_log.txt${NC}"
