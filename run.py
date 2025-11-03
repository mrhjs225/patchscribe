import os


os.system("python scripts/run_experiment.py --dataset zeroday --limit 1 --models qwen3-14b gemma3-12b")
# os.system("python scripts/run_experiment.py --dataset zeroday --limit 1 --models deepseek-r1-14b gpt-oss-20b")
# os.system("python scripts/analyze.py results/local --all-conditions")
# os.system("python scripts/analyze.py results/local --models llama3.2-3b --all-conditions")