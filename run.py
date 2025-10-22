import os
from time import time

BASE = (
    "python -m cpg_verify.cli "
    "--dataset zeroday "
    "--limit 20 "
    "--explain-mode both "
    "--explanation-patch-source ground_truth "
    "--format markdown "
    "--llm-provider ollama "
)
models = ["qwen3:0.6b", "deepseek-r1:1.5b", "gemma3:1b", "gpt-oss:20b", "llama3.2:1b"]
# models = ["llama3.2:1b"]
modes = ["minimal", "formal", "natural", "only_natural"]
# modes = ["formal", "natural", "only_natural"]
alias_models = []
for model in models:
    model_alias = model.split(":")[0]
    if model_alias not in alias_models:
        alias_models.append(model_alias)
    for mode in modes:
        output_file = f"results/poc/zeroday_{mode}_{model_alias}.md"
        command = f"{BASE} --llm-model {model} --strategy {mode} --output {output_file}"
        print(f"Running command: {command}")
        start_time = time()
        os.system(command)
        end_time = time()
        print(f"Finished {model} with {mode}: Total time taken: {end_time - start_time} seconds")

blind_command = (
    "python scripts/generate_blind_explanations.py "
    "--input-dir results/poc "
    "--output-dir results/poc "
    "--key-dir results/poc "
    f"--models {' '.join(alias_models)}"
)
print(f"Running command: {blind_command}")
start_time = time()
os.system(blind_command)
end_time = time()
print(f"Finished blind generation: Total time taken: {end_time - start_time} seconds")
