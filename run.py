import argparse
import os


os.system("python scripts/run_experiment.py --dataset zeroday --precompute-stage1")
os.system("python scripts/run_experiment.py --dataset extractfix --precompute-stage1")

# os.system("python scripts/run_experiment.py --dataset zeroday --llm-provider openai --models gpt-5-mini --llm-concurrency 400 --parallel-conditions --output results/local")
os.system("python scripts/run_experiment.py --dataset zeroday --llm-provider openai --models gpt-4.1-mini --llm-concurrency 400 --parallel-conditions --output results/local")
os.system("python scripts/run_experiment.py --dataset zeroday --llm-provider anthropic --models claude-haiku-4-5 --llm-concurrency 100 --parallel-conditions --output results/local")
# os.system("python scripts/run_experiment.py --dataset zeroday --llm-provider anthropic --models claude-3-5-haiku --llm-concurrency 20 --parallel-conditions --output results/local")
os.system("python scripts/run_experiment.py --dataset zeroday --llm-provider gemini --models gemini-2.5-flash --llm-concurrency 200 --parallel-conditions --output results/local")
# os.system("python scripts/run_experiment.py --dataset zeroday --llm-provider gemini --models gemini-2.0-flash --llm-concurrency 200 --parallel-conditions --output results/local")

# os.system(f"python scripts/analyze.py results/local --models gpt-5-mini,gpt-4.1-mini,claude-haiku-4-5,claude-3-5-haiku,gemini-2.5-flash,gemini-2.0-flash --all-conditions")
os.system(f"python scripts/analyze.py results/local --models gpt-4.1-mini,claude-haiku-4-5,gemini-2.5-flash --all-conditions")
os.system(f"python scripts/analyze.py --unified results/local")


# os.system("python scripts/run_experiment.py --dataset extractfix --llm-provider openai --models gpt-5-mini --llm-concurrency 100 --parallel-conditions --output results/local_extractfix")
os.system("python scripts/run_experiment.py --dataset extractfix --llm-provider openai --models gpt-4.1-mini --llm-concurrency 100 --parallel-conditions --output results/local_extractfix")
os.system("python scripts/run_experiment.py --dataset extractfix --llm-provider anthropic --models claude-haiku-4-5 --llm-concurrency 100 --parallel-conditions --output results/local_extractfix")
# os.system("python scripts/run_experiment.py --dataset extractfix --llm-provider anthropic --models claude-3-5-haiku --llm-concurrency 20 --parallel-conditions --output results/local_extractfix")
os.system("python scripts/run_experiment.py --dataset extractfix --llm-provider gemini --models gemini-2.5-flash --llm-concurrency 100 --parallel-conditions --output results/local_extractfix")
# os.system("python scripts/run_experiment.py --dataset extractfix --llm-provider gemini --models gemini-2.0-flash --llm-concurrency 100 --parallel-conditions --output results/local_extractfix")

os.system(f"python scripts/analyze.py results/local_extractfix --models gpt-4.1-mini,claude-haiku-4-5,gemini-2.5-flash --all-conditions")
os.system(f"python scripts/analyze.py --unified results/local_extractfix")
