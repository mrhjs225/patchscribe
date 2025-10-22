#!/usr/bin/env bash
set -euo pipefail

# Simple helper to pull lightweight Ollama models used for local experiments.
# Requires the Ollama daemon to be running locally (`ollama serve`).

if ! command -v ollama >/dev/null 2>&1; then
  echo "error: ollama CLI not found. Install from https://ollama.com/download" >&2
  exit 1
fi

MODELS=(
  "qwen3:0.6b"
  "DeepSeek-R1:1.5b"
  "gemma3:1b"
  "gpt-oss:20b"
  "Llama3.2:1b"
)

failed=0

for model in "${MODELS[@]}"; do
  echo "Pulling ${model}..."
  if ! ollama pull "${model}"; then
    echo "warning: failed to pull ${model}" >&2
    if [[ "${model}" == "gpt-oss:20b" ]]; then
      echo "hint: gpt-oss:20b requires a newer Ollama release; upgrade from https://ollama.com/download" >&2
    fi
    failed=1
  fi
done

if [[ "${failed}" -eq 0 ]]; then
  echo "All requested models downloaded. You can test with: ollama chat Llama3.2:1b"
else
  echo "Some models failed to download. Review the warnings above." >&2
fi

exit "${failed}"
