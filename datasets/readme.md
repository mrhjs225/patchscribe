# APPATCH: Automated Adaptive Prompting Large Language Models for Real-World Software Vulnerability Patching
To elicit LLMs to effectively reason about vulnerable code behaviors, which is essential for quality patch generation, we introduce vulnerability semantics reasoning and adaptive prompting on LLMs and instantiate the methodology as APPATCH, an automated LLM-based patching system.


## Package Structure
- `appatch.zip`: The datasets and results for the Appatch.
    - `dataset`: The dataset we collected, labeled, and for evaluating Appatch.
        - `patchdb_cvefixes_for_appatch_train`: The PatchDB+CVEFixes dataset used to generate exemplars for Appatch.
        - `zeroday_repair`: The zeroday dataset we collected for evaluation.
        - `extractfix_dataset`: The extractfix dataset we used for evaluation.
    - `results`: The results of Appatch, baselines, and the ablation studies
        - `claude3`: The results of Appatch and ablation studies using Claude 3.5 Sonnet.
            - `appatch`: The results of Appatch.
                - `zeroday`: The exemplars, generated root causes, prompts, generated patches, validations, and results for zeroday dataset.
                - `interprocedural`: The generated root causes, prompts, generated patches, validations, and results for interprocedural samples.
                - `extractfix`: The generated root causes, prompts, generated patches, validations, and results for extractfix dataset.
            - `noslice`: The results of Appatch without slicing with the same format as `appatch`.
            - `rand_exemplars`: The results of Appatch with random exemplars with the same format as `appatch`.
            - `fixed_exemplars`: The results of Appatch with manual exemplars with the same format as `appatch`.
            - `standard prompting`: The results of Appatch with direct reasoning with the same format as `appatch`.
            - `zero`: The results with standard prompting.
            - `s2`: The results with zero-shot completion.
            - `codeql_appatch`: The results of Appatch with CodeQL end-to-end experiments (fully automated).
            - `codeql_human_appatch`: The results of Appatch with CodeQL end-to-end experiments (realistic).
        - `gpt4`: The results of Appatch and ablation studies using GPT-4 with the same format as `claude3`.
        - `gemini`: The results of Appatch and ablation studies using Gemini 1.5 Pro with the same format as `claude3`.
        - `llama3`: The results of Appatch and ablation studies using Llama 3.1 with the same format as `claude3`.
        - `vulrepair`: The results of the baseline VulRepair.
        - `getafix`: The results of the baseline Getafix.
        - `codellama`: The results of Appatch using CodeLlama.
        - `codeqwen`: The results of Appatch using CodeQwen 1.5.
        - `deepseek-coder2`: The results of Appatch using DeepSeek-Coder-V2.
    - `code`: The source code for Appatch, ablated versions, baselines, as well as the usability experiments.
        - `appatch_ablated`: The source code for Appatch and its ablated versions. Switch to the LLMs you want to test and fill your keys when using them.
        - `baselines`: The source code for the traditional baselines we compared.
        - `usability_codeql`: The source code for the usability experiments with CodeQL.

## How to use

Please use the package structure to find the data and results for the corresponding contents described in the original paper. 




