import os


# os.system("python scripts/run_experiment.py --dataset zeroday --llm-provider openai  --models gpt-5-mini --llm-concurrency 100 --batch-judge --batch-size 100")
# os.system("python scripts/run_experiment.py --dataset zeroday --llm-provider anthropic  --models claude-haiku-4-5 --llm-concurrency 100 --batch-judge --batch-size 100")
# os.system("python scripts/run_experiment.py --dataset zeroday --llm-provider gemini --models gemini-2.5-flash --llm-concurrency 100 --batch-judge --batch-size 100")
# os.system("python scripts/run_experiment.py --dataset zeroday --llm-provider openai  --models gpt-5-mini --llm-concurrency 50")
# os.system("python scripts/run_experiment.py --dataset zeroday --limit 1 --models deepseek-r1:14b gpt-oss:20b")

os.system("python scripts/analyze.py results/local --models gpt-5-mini claude-haiku-4-5 gemini-2.5-flash --all-conditions")
