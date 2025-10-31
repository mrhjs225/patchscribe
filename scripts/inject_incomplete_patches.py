#!/usr/bin/env python3
"""
Incomplete Patch Injection System for RQ2 Evaluation

Generates deliberately incomplete patches for each vulnerability to evaluate
the precision and recall of different verification methods (V1-V4).

Each vulnerability gets 2-3 incomplete patches that:
1. Block the original exploit but miss edge cases
2. Address one causal path but miss others
3. Add partial checks that don't cover all conditions
"""
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

# Add patchscribe to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from patchscribe.dataset import load_cases


@dataclass
class IncompletePatch:
    """Represents an intentionally incomplete patch"""
    patch_id: str
    case_id: str
    patched_code: str
    incompleteness_type: str
    description: str
    why_incomplete: str
    should_be_caught_by: List[str]  # List of verification methods that should catch this


class IncompletePatchGenerator:
    """Generates incomplete patches for testing verification methods"""

    def __init__(self, case: Dict):
        self.case = case
        self.case_id = case['id']
        self.source = case['source']
        self.vuln_line = case['vuln_line']
        self.cwe_id = case.get('cwe_id', '')
        self.signature = case.get('signature', '')

    def generate_incomplete_patches(self) -> List[IncompletePatch]:
        """Generate 2-3 incomplete patches based on vulnerability type"""
        patches = []

        # Strategy 1: Specific input check only (misses edge cases)
        patch1 = self._create_specific_input_check()
        if patch1:
            patches.append(patch1)

        # Strategy 2: Partial condition check (misses negatives or other paths)
        patch2 = self._create_partial_condition_check()
        if patch2:
            patches.append(patch2)

        # Strategy 3: Wrong location or incomplete guard
        patch3 = self._create_wrong_location_patch()
        if patch3:
            patches.append(patch3)

        return patches

    def _create_specific_input_check(self) -> Optional[IncompletePatch]:
        """
        Create patch that checks for specific exploit pattern only
        Example: if (len == 256) instead of if (len >= 256)
        """
        lines = self.source.splitlines()
        vuln_idx = self.vuln_line - 1

        if vuln_idx < 0 or vuln_idx >= len(lines):
            return None

        vuln_line_text = lines[vuln_idx]
        indent = self._get_indent(vuln_line_text)

        # Identify vulnerability type and add overly specific check
        if 'strcpy' in vuln_line_text or 'strcat' in vuln_line_text:
            # For buffer overflow: check exact length instead of >=
            guard = f"{indent}if (strlen(input) == 256) return -1;  // Incomplete: only checks exact 256\n"
            incomplete_type = "specific_value_check"
            why = "Checks for equality (==) instead of >= or >, misses other overflow values"
            caught_by = ["V3", "V4"]  # Consistency and triple verification

        elif 'printf' in vuln_line_text and '%' in self.signature:
            # For format string: only check for specific format specifier
            guard = f"{indent}if (strstr(input, \"%s\")) return -1;  // Incomplete: only checks %s\n"
            incomplete_type = "specific_pattern_check"
            why = "Only checks for %s format specifier, misses %n, %x, and other dangerous patterns"
            caught_by = ["V3", "V4"]

        elif 'malloc' in vuln_line_text or 'calloc' in vuln_line_text:
            # For integer overflow: only check positive values
            guard = f"{indent}if (size > INT_MAX) return NULL;  // Incomplete: misses negative overflow\n"
            incomplete_type = "positive_only_check"
            why = "Only checks positive overflow, misses negative values and wraparound"
            caught_by = ["V2", "V3", "V4"]  # Symbolic and consistency

        elif 'scanf' in vuln_line_text or 'gets' in vuln_line_text:
            # For unbounded read: limit to specific size but buffer is smaller
            guard = f"{indent}char limited[128];  // Incomplete: buffer still too small\n"
            incomplete_type = "insufficient_size_limit"
            why = "Adds size limit but the limit is still larger than the buffer size"
            caught_by = ["V2", "V3", "V4"]

        else:
            # Generic: add a check that's always true
            guard = f"{indent}if (1) {{  // Incomplete: tautology, doesn't prevent vulnerability\n"
            guard += f"{indent}    {vuln_line_text.strip()}\n"
            guard += f"{indent}}}\n"
            incomplete_type = "tautology_check"
            why = "Guard condition is always true, provides no actual protection"
            caught_by = ["V2", "V3", "V4"]
            lines[vuln_idx] = ""  # Remove original line

        # Insert guard before vulnerable line
        if 'tautology' not in incomplete_type:
            lines.insert(vuln_idx, guard)

        patched_code = '\n'.join(lines)

        return IncompletePatch(
            patch_id=f"{self.case_id}_incomplete_1",
            case_id=self.case_id,
            patched_code=patched_code,
            incompleteness_type=incomplete_type,
            description="Patch checks for specific exploit input only, misses edge cases",
            why_incomplete=why,
            should_be_caught_by=caught_by
        )

    def _create_partial_condition_check(self) -> Optional[IncompletePatch]:
        """
        Create patch that addresses one path but misses others
        Example: checks input but not when input comes from alternative source
        """
        lines = self.source.splitlines()
        vuln_idx = self.vuln_line - 1

        if vuln_idx < 0 or vuln_idx >= len(lines):
            return None

        vuln_line_text = lines[vuln_idx]
        indent = self._get_indent(vuln_line_text)

        # Add guard that only covers one branch
        if 'strcpy' in vuln_line_text or 'memcpy' in vuln_line_text:
            # Only check if input is from specific source
            guard = f"{indent}// Incomplete: only checks direct input, not processed input\n"
            guard += f"{indent}if (input != NULL && direct_input) {{\n"
            guard += f"{indent}    if (strlen(input) > sizeof(buf)) return -1;\n"
            guard += f"{indent}}}\n"
            incomplete_type = "single_path_check"
            why = "Only guards direct input path, misses processed/indirect input paths"
            caught_by = ["V3", "V4"]

        elif 'malloc' in vuln_line_text:
            # Only check one variable in multiplication
            guard = f"{indent}if (n > 1000) return NULL;  // Incomplete: doesn't check multiplier m\n"
            incomplete_type = "partial_variable_check"
            why = "Checks only one variable in size calculation (n), ignores multiplier (m)"
            caught_by = ["V2", "V3", "V4"]

        else:
            # Generic: add null check but not bounds check
            guard = f"{indent}if (input == NULL) return -1;  // Incomplete: null check only\n"
            incomplete_type = "insufficient_validation"
            why = "Only validates null pointer, doesn't check bounds or other conditions"
            caught_by = ["V3", "V4"]

        lines.insert(vuln_idx, guard)
        patched_code = '\n'.join(lines)

        return IncompletePatch(
            patch_id=f"{self.case_id}_incomplete_2",
            case_id=self.case_id,
            patched_code=patched_code,
            incompleteness_type=incomplete_type,
            description="Patch addresses one causal path but misses others",
            why_incomplete=why,
            should_be_caught_by=caught_by
        )

    def _create_wrong_location_patch(self) -> Optional[IncompletePatch]:
        """
        Create patch at wrong location or with wrong scope
        Example: check after the vulnerable operation instead of before
        """
        lines = self.source.splitlines()
        vuln_idx = self.vuln_line - 1

        if vuln_idx < 0 or vuln_idx >= len(lines):
            return None

        vuln_line_text = lines[vuln_idx]
        indent = self._get_indent(vuln_line_text)

        # Add check AFTER the vulnerable operation (too late)
        post_check = f"{indent}// Incomplete: check is after vulnerable operation\n"
        post_check += f"{indent}if (error_occurred) {{  // Too late - damage already done\n"
        post_check += f"{indent}    return -1;\n"
        post_check += f"{indent}}}\n"

        # Insert after vulnerable line (wrong location)
        lines.insert(vuln_idx + 1, post_check)
        patched_code = '\n'.join(lines)

        return IncompletePatch(
            patch_id=f"{self.case_id}_incomplete_3",
            case_id=self.case_id,
            patched_code=patched_code,
            incompleteness_type="wrong_location",
            description="Patch placed after vulnerable operation instead of before",
            why_incomplete="Validation happens after the vulnerability is exploited, not before",
            should_be_caught_by=["V2", "V3", "V4"]  # Symbolic and consistency should catch
        )

    @staticmethod
    def _get_indent(line: str) -> str:
        """Extract leading whitespace from line"""
        return line[:len(line) - len(line.lstrip())]


def generate_incomplete_patches_dataset(
    dataset: str = "zeroday",
    limit: Optional[int] = None,
    output_dir: Path = Path("results/incomplete_patches")
) -> Dict[str, List[IncompletePatch]]:
    """
    Generate incomplete patches for all cases in dataset

    Returns:
        Dictionary mapping case_id to list of incomplete patches
    """
    print(f"Loading {dataset} dataset...")
    cases = load_cases(dataset=dataset, limit=limit)
    print(f"Loaded {len(cases)} cases")

    all_incomplete_patches = {}

    for case in cases:
        case_id = case['id']
        print(f"\nGenerating incomplete patches for: {case_id}")

        generator = IncompletePatchGenerator(case)
        patches = generator.generate_incomplete_patches()

        print(f"  Generated {len(patches)} incomplete patches:")
        for patch in patches:
            print(f"    - {patch.patch_id}: {patch.incompleteness_type}")
            print(f"      Should be caught by: {', '.join(patch.should_be_caught_by)}")

        all_incomplete_patches[case_id] = patches

    # Save to file
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"incomplete_patches_{dataset}.json"

    # Convert to JSON-serializable format
    output_data = {
        case_id: [
            {
                'patch_id': p.patch_id,
                'case_id': p.case_id,
                'patched_code': p.patched_code,
                'incompleteness_type': p.incompleteness_type,
                'description': p.description,
                'why_incomplete': p.why_incomplete,
                'should_be_caught_by': p.should_be_caught_by
            }
            for p in patches
        ]
        for case_id, patches in all_incomplete_patches.items()
    }

    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)

    print(f"\n✅ Saved incomplete patches to: {output_file}")
    print(f"   Total cases: {len(all_incomplete_patches)}")
    print(f"   Total incomplete patches: {sum(len(p) for p in all_incomplete_patches.values())}")

    return all_incomplete_patches


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Generate incomplete patches for RQ2 precision/recall evaluation'
    )
    parser.add_argument(
        '--dataset',
        default='zeroday',
        help='Dataset to use (default: zeroday)'
    )
    parser.add_argument(
        '--limit',
        type=int,
        help='Limit number of cases to process'
    )
    parser.add_argument(
        '--output',
        type=Path,
        default=Path('results/incomplete_patches'),
        help='Output directory for incomplete patches'
    )

    args = parser.parse_args()

    print("="*80)
    print("INCOMPLETE PATCH GENERATION FOR RQ2 EVALUATION")
    print("="*80)
    print(f"Dataset: {args.dataset}")
    print(f"Output: {args.output}")
    if args.limit:
        print(f"Limit: {args.limit} cases")
    print("="*80)

    generate_incomplete_patches_dataset(
        dataset=args.dataset,
        limit=args.limit,
        output_dir=args.output
    )

    print("\n" + "="*80)
    print("✅ INCOMPLETE PATCH GENERATION COMPLETE")
    print("="*80)
    print("\nNext steps:")
    print("1. Run verification methods (V1-V4) on these incomplete patches")
    print("2. Calculate precision/recall for each method")
    print("3. Analyze which verification methods catch which types of incompleteness")


if __name__ == '__main__':
    main()
