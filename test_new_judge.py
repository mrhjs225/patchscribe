#!/usr/bin/env python3
"""
Test script for the new developer-centric judge prompt.
This will test the prompt with a sample explanation.
"""
import json
from patchscribe.llm import LLMClient

# Sample data from CWE-476___CVE-2024-36947.c (successful case)
vulnerability_sig = "CWE-476: NULL Pointer Dereference"

original_code = """static int __init debugfs_init(void)
{
	struct dentry *dir;

	dir = lookup_one_len_unlocked("test", NULL, 4);
	simple_recursive_removal(dir, NULL);

	return 0;
}"""

patched_code = """static int __init debugfs_init(void)
{
	struct dentry *dir;

	dir = lookup_one_len_unlocked("test", NULL, 4);
	if (IS_ERR(dir))
		return PTR_ERR(dir);
	simple_recursive_removal(dir, NULL);

	return 0;
}"""

ebug_text = """## What Caused the Vulnerability

The vulnerability occurs at **line 6** where `dir` (returned from `lookup_one_len_unlocked()`)
is passed to `simple_recursive_removal()` without checking if it's an error pointer.

The function `lookup_one_len_unlocked()` can return an ERR_PTR-encoded error value (not NULL),
which when dereferenced in `simple_recursive_removal()` causes a kernel crash.

**Trigger Condition:** When `lookup_one_len_unlocked()` fails and returns ERR_PTR(-ENOENT) or similar.

**Impact:** Kernel NULL pointer dereference leading to system crash."""

epatch_text = """## How the Patch Changes the Code

**Lines 6-7 (added):**
```c
if (IS_ERR(dir))
    return PTR_ERR(dir);
```

**Mechanism:**
The patch adds an `IS_ERR()` check immediately after `lookup_one_len_unlocked()`.
If the lookup fails (returns error pointer), the function returns early with the error code.

This prevents the error pointer from reaching `simple_recursive_removal()`, which expects
a valid dentry pointer.

**Why This Change Eliminates the Vulnerability:**
The IS_ERR() macro detects ERR_PTR-encoded values. By checking before dereferencing,
the patch blocks the causal chain: lookup failure → error pointer → dereference crash.

**Side Effects:** Function now returns error code on lookup failure instead of continuing.
Caller must handle the error return value."""

print("=" * 80)
print("Testing New Developer-Centric Judge Prompt")
print("=" * 80)

# Build the prompt
prompt = LLMClient.build_explanation_judge_prompt(
    ebug_text=ebug_text,
    epatch_text=epatch_text,
    vulnerability_signature=vulnerability_sig,
    original_code=original_code,
    patched_code=patched_code,
)

print("\n📋 GENERATED PROMPT:")
print("-" * 80)
print(prompt)
print("-" * 80)

print("\n✅ Prompt generated successfully!")
print("\nKey features of the new prompt:")
print("  • Developer-centric perspective")
print("  • 4 dimensions: Vulnerability Understanding, Patch Understanding,")
print("    Causal Connection, Actionability")
print("  • Detailed scoring criteria (1-5 scale)")
print("  • Emphasizes specificity (line numbers, code snippets)")
print("  • Penalizes vague language")
print("  • Rewards actionable insights")

print("\n" + "=" * 80)
print("Next Steps:")
print("=" * 80)
print("1. Run this prompt against GPT-5 judge to verify JSON output format")
print("2. Compare scores with old format on same explanation")
print("3. Run batch evaluation on full dataset")
print("\nTo test with actual LLM judge:")
print("  python test_new_judge.py --call-llm")
print("\n" + "=" * 80)
