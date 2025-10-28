#!/bin/bash
# Multi-model evaluation script for PatchScribe
# This script runs full evaluation with multiple LLM models

set -e

# Configuration
DATASET="zeroday"  # or path to JSON file
BASE_OUTPUT_DIR="results/multi_model_evaluation"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Models to test (add or modify as needed)
MODELS=(
    "gpt-oss:20b"
    "llama3.2:1b"
    "llama3.2:3b"
)

echo "=================================="
echo "PatchScribe Multi-Model Evaluation"
echo "=================================="
echo "Dataset: $DATASET"
echo "Base output: $BASE_OUTPUT_DIR"
echo "Models: ${MODELS[@]}"
echo "Timestamp: $TIMESTAMP"
echo "=================================="
echo ""

# Create base output directory
mkdir -p "$BASE_OUTPUT_DIR"

# Run evaluation for each model
for MODEL in "${MODELS[@]}"; do
    echo "=========================================="
    echo "Starting evaluation with model: $MODEL"
    echo "=========================================="
    
    # Create model-specific output directory
    MODEL_SAFE=$(echo "$MODEL" | tr ':/' '_')
    OUTPUT_DIR="$BASE_OUTPUT_DIR/${MODEL_SAFE}_${TIMESTAMP}"
    
    echo "Output directory: $OUTPUT_DIR"
    echo ""
    
    # Run evaluation
    python scripts/run_full_evaluation.py "$DATASET" \
        --llm-provider ollama \
        --llm-model "$MODEL" \
        -o "$OUTPUT_DIR" \
        2>&1 | tee "$OUTPUT_DIR/evaluation.log"
    
    EXIT_CODE=${PIPESTATUS[0]}
    
    if [ $EXIT_CODE -eq 0 ]; then
        echo "✅ Evaluation with $MODEL completed successfully"
        echo "   Results: $OUTPUT_DIR"
    else
        echo "❌ Evaluation with $MODEL failed (exit code: $EXIT_CODE)"
        echo "   Check log: $OUTPUT_DIR/evaluation.log"
    fi
    
    echo ""
    echo "Waiting 5 seconds before next model..."
    sleep 5
done

echo "=========================================="
echo "All evaluations complete!"
echo "=========================================="
echo "Results directory: $BASE_OUTPUT_DIR"
echo ""
echo "To compare results:"
echo "  ls -la $BASE_OUTPUT_DIR/*/EVALUATION_REPORT.md"
echo ""
