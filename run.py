import os
import sys
# machine_id = sys.argv[1]
# models = {"148": ["llama3.2:1b"],
#           "selab2": ["gemma3:1b", "llama3.2:1b"],
#           "soty": ["qwen3:0.6b", "deepseek-r1:1.5b"]
#           }

# os.system("python scripts/run_multi_model_evaluation.py zeroday --limit 5 --models " + " ".join(models[machine_id]))

# os.system(
#     "python scripts/run_multi_model_evaluation.py zeroday --models qwen3:14b qwen3:8b qwen3:4b qwen3:1.7b qwen3:0.6b gemma3:12b gemma3:4b gemma3:1b gemma3:270m DeepSeek-R1:14b DeepSeek-R1:8b DeepSeek-R1:7b DeepSeek-R1:1.5b Llama3.2:3b Llama3.2:1b gpt-oss:20b --provider ollama --limit 1 --conditions c1 c2 c3 c4 --output results/multi_model_smoke"
# )
os.system(
    "python scripts/run_multi_model_evaluation.py zeroday --models qwen3:0.6b --limit 1 --conditions c1 c2 c3 c4 --output results/multi_model_smoke"
)