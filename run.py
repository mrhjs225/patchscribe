import os
import sys
machine_id = sys.argv[1]
models = {"148": ["gpt-oss:20b"],
          "selab2": ["gemma3:1b", "llama3.2:1b"],
          "soty": ["qwen3:0.6b", "deepseek-r1:1.5b"]
          }

os.system("python scripts/run_multi_model_evaluation.py zeroday --limit 1 --models " + " ".join(models[machine_id]))