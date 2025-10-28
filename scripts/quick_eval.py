#!/usr/bin/env python3
"""
Quick evaluation runner for testing PatchScribe on a small dataset.
Useful for development and quick validation.
"""
import json
import sys
from pathlib import Path

# Add patchscribe to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from patchscribe.evaluation import Evaluator
from patchscribe.pipeline import PatchScribePipeline
from patchscribe.dataset import load_cases


def create_sample_cases():
    """Create sample test cases for quick evaluation"""
    return [
        {
            "id": "sample_001",
            "source": """int process_data(char *input, int len) {
    char buffer[256];
    memcpy(buffer, input, len);  // Vulnerable: no bounds check
    return 0;
}""",
            "ground_truth": """int process_data(char *input, int len) {
    char buffer[256];
    if (len > 256) {
        return -1;  // Error: input too large
    }
    memcpy(buffer, input, len);
    return 0;
}""",
            "vuln_line": 3,
            "cwe_id": "CWE-787",
            "signature": "buffer overflow",
            "expected_success": True
        }
    ]


def main():
    """Run quick evaluation"""
    print("="*80)
    print("PATCHSCRIBE QUICK EVALUATION")
    print("="*80)
    
    # Create output directory
    output_dir = Path('results/quick_test')
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Use sample cases or load from file/dataset
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        
        # Check if it's a dataset name
        if arg in ['poc', 'zeroday']:
            print(f"Loading {arg} dataset (limit: 3 cases)...")
            cases = load_cases(dataset=arg, limit=3)
        # Otherwise treat as file path
        elif Path(arg).exists():
            dataset_path = Path(arg)
            print(f"Loading dataset from: {dataset_path}")
            with open(dataset_path, 'r') as f:
                cases = json.load(f)
        else:
            print(f"Error: Unknown dataset '{arg}' or file not found")
            print("Available datasets: 'poc', 'zeroday'")
            print("Or provide a path to a JSON file")
            sys.exit(1)
    else:
        print("Using built-in sample test cases")
        print("Tip: Use 'poc' or 'zeroday' to load real datasets")
        print("  Example: python scripts/quick_eval.py zeroday")
        cases = create_sample_cases()
    
    print(f"Test cases: {len(cases)}")
    if cases:
        print(f"First case: {cases[0].get('id', 'unknown')}")
    
    # Run with full PatchScribe configuration
    print("\nRunning PatchScribe with full features...")
    pipeline = PatchScribePipeline(
        strategy="formal",
        explain_mode="both",
        enable_consistency_check=True,
        enable_performance_profiling=True
    )
    
    evaluator = Evaluator(pipeline=pipeline)
    
    try:
        report = evaluator.run(cases)
        
        # Save results
        output_path = output_dir / 'quick_test_results.json'
        with open(output_path, 'w') as f:
            json.dump(report.as_dict(), f, indent=2)
        
        print(f"\n✅ Results saved to: {output_path}")
        
        # Print summary
        print("\n" + "="*80)
        print("SUMMARY")
        print("="*80)
        print(f"Total cases: {report.metrics['total_cases']}")
        print(f"Success rate: {report.metrics['success_rate']:.1%}")
        print(f"First attempt success: {report.metrics.get('first_attempt_success_rate', 0):.1%}")
        print(f"Consistency pass rate: {report.metrics.get('consistency_pass_rate', 0):.1%}")
        print(f"Triple verification rate: {report.metrics.get('triple_verification_pass_rate', 0):.1%}")
        
        print("\n✅ Quick evaluation complete!")
        
    except Exception as e:
        print(f"\n❌ Error during evaluation: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
