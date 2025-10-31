import os
import sys
machine_id = sys.argv[1]
models = {"148": ["llama3.2:1b"],
          "selab2": ["gemma3:1b", "llama3.2:1b"],
          "soty": ["qwen3:0.6b", "deepseek-r1:1.5b"]
          }

os.system("python scripts/run_multi_model_evaluation.py zeroday --limit 5 --models " + " ".join(models[machine_id]))
