import argparse
import os


# os.system("python scripts/run_experiment.py --dataset zeroday --precompute-stage1")
# os.system("python scripts/run_experiment.py --dataset extractfix --precompute-stage1")


os.environ["OPENAI_MAX_OUTPUT_TOKENS"] = "none"
os.environ["ANTHROPIC_MAX_OUTPUT_TOKENS"] = "8192"
os.environ["GEMINI_MAX_OUTPUT_TOKENS"] = "none"

# Enable majority voting for manual evaluation
os.environ["PATCHSCRIBE_USE_MAJORITY_VOTING"] = "true"
os.environ["PATCHSCRIBE_JUDGE_TIMEOUT"] = "180"  # Longer timeout for 3 judges

os.system("python scripts/run_experiment.py --dataset zeroday --llm-provider anthropic --models claude-haiku-4-5 --llm-concurrency 100 --parallel-conditions --skip-judge-evaluation --output results/local")
os.system("python scripts/run_experiment.py --dataset zeroday --llm-provider gemini --models gemini-2.5-flash --llm-concurrency 200 --parallel-conditions --skip-judge-evaluation --output results/local")
os.system("python scripts/run_experiment.py --dataset zeroday --llm-provider openai --models gpt-5-mini --llm-concurrency 400 --parallel-conditions --skip-judge-evaluation --output results/local")

os.system("python scripts/evaluate_results.py results/local --single-judge --concurrency 100")

os.system(f"python scripts/analyze.py results/local_evaluated --models gpt-5-mini,claude-haiku-4-5,gemini-2.5-flash --all-conditions")
os.system(f"python scripts/analyze.py --unified results/local_evaluated")


# os.system("python scripts/run_experiment.py --dataset extractfix --llm-provider anthropic --models claude-haiku-4-5 --llm-concurrency 100 --parallel-conditions --skip-judge-evaluation --output results/local_extractfix")
# os.system("python scripts/run_experiment.py --dataset extractfix --llm-provider gemini --models gemini-2.5-flash --llm-concurrency 100 --parallel-conditions --skip-judge-evaluation --output results/local_extractfix")
# os.system("python scripts/run_experiment.py --dataset extractfix --llm-provider openai --models gpt-5-mini --llm-concurrency 100 --parallel-conditions --skip-judge-evaluation --output results/local_extractfix")

os.system("python scripts/evaluate_results.py results/local_extractfix --single-judge --concurrency 40")

os.system(f"python scripts/analyze.py results/local_extractfix_evaluated --models gpt-5-mini,claude-haiku-4-5,gemini-2.5-flash --all-conditions")
os.system(f"python scripts/analyze.py --unified results/local_extractfix_evaluated")