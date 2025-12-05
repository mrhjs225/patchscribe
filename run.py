import argparse
import os


# os.system("python scripts/run_experiment.py --dataset zeroday --precompute-stage1")
# os.system("python scripts/run_experiment.py --dataset extractfix --precompute-stage1")


os.environ["OPENAI_MAX_OUTPUT_TOKENS"] = "none"
os.environ["ANTHROPIC_MAX_OUTPUT_TOKENS"] = "8192"
os.environ["GEMINI_MAX_OUTPUT_TOKENS"] = "none"

# quick test
os.system("python3 scripts/run_experiment.py --quick")

# Use GPT-5 only for evaluation (no voting)
os.environ["PATCHSCRIBE_JUDGE_TIMEOUT"] = "120"  # Shorter timeout for single judge

os.system("python scripts/run_experiment.py --dataset zeroday --llm-provider anthropic --models claude-haiku-4-5 --llm-concurrency 100 --parallel-conditions")
# os.system("python scripts/run_experiment.py --dataset zeroday --llm-provider gemini --models gemini-2.5-flash --llm-concurrency 200 --parallel-conditions")
# os.system("python scripts/run_experiment.py --dataset zeroday --llm-provider openai --models gpt-5-mini --llm-concurrency 400 --parallel-conditions")
 
os.system("python scripts/evaluate_results.py results/local --concurrency 100")

os.system(f"python scripts/analyze.py results/local_evaluated --models gpt-5-mini,claude-haiku-4-5,gemini-2.5-flash --all-conditions")
os.system(f"python scripts/analyze.py --unified results/local_evaluated")


os.system("python scripts/run_experiment.py --dataset extractfix --llm-provider anthropic --models claude-haiku-4-5 --llm-concurrency 100 --parallel-conditions")
# os.system("python scripts/run_experiment.py --dataset extractfix --llm-provider gemini --models gemini-2.5-flash --llm-concurrency 100 --parallel-conditions")
os.system("python scripts/run_experiment.py --dataset extractfix --llm-provider openai --models gpt-5-mini --llm-concurrency 100 --parallel-conditions")

os.system("python scripts/evaluate_results.py results/local_extractfix --concurrency 100")

os.system(f"python scripts/analyze.py results/local_extractfix_evaluated --models gpt-5-mini,claude-haiku-4-5,gemini-2.5-flash --all-conditions")
os.system(f"python scripts/analyze.py --unified results/local_extractfix_evaluated")