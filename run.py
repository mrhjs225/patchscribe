import argparse
import os


DATASET_RUNS = [
    ("zeroday", "results/local", False),
    ("extractfix", "results/local_extractfix", True),
]

MODEL_CONFIG = {
    "openai": ["gpt-5", "gpt-5-mini", "gpt-4.1", "gpt-4.1-mini"],
    "anthropic": ["claude-3-5-haiku", "claude-haiku-4-5", "claude-sonnet-4-5"],
    "gemini": ["gemini-2.5-flash", "gemini-2.0-flash"],
}

ALL_MODELS = " ".join(
    MODEL_CONFIG["openai"] + MODEL_CONFIG["anthropic"] + MODEL_CONFIG["gemini"]
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run PatchScribe experiments across datasets/models.")
    parser.add_argument(
        "--test-one",
        action="store_true",
        help="각 데이터셋에서 케이스 1개만 실행하여 빠르게 테스트합니다.",
    )
    return parser.parse_args()


def run_dataset(dataset: str, output_dir: str, force_output_flag: bool, extra_limit: str) -> None:
    for provider, models in MODEL_CONFIG.items():
        for model in models:
            cmd = (
                f"python scripts/run_experiment.py --dataset {dataset} "
                f"--llm-provider {provider} --models {model} "
                "--llm-concurrency 100 --parallel-conditions"
            )
            if extra_limit:
                cmd += f" {extra_limit}"
            if force_output_flag or output_dir != "results/local":
                cmd += f" --output {output_dir}"
            os.system(cmd)

    os.system(f"python scripts/analyze.py {output_dir} --models {ALL_MODELS} --all-conditions")
    os.system(f"python scripts/analyze.py --unified {output_dir}")


def main() -> None:
    args = parse_args()
    limit_flag = "--limit 1" if args.test_one else ""
    for dataset_name, output_path, force_output in DATASET_RUNS:
        run_dataset(dataset_name, output_path, force_output, limit_flag)


if __name__ == "__main__":
    main()
