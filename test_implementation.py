#!/usr/bin/env python3
"""Test script for newly implemented features"""

from patchscribe.formal_spec import (
    FormalBugExplanation, FormalPatchExplanation, 
    VariableSpec, CodeDiff, InterventionDescription, EffectAnalysis
)
from patchscribe.consistency_checker import ConsistencyChecker
from patchscribe.performance import PerformanceProfiler

def test_formal_spec():
    """Test formal specification classes"""
    print("Testing FormalBugExplanation...")
    E_bug = FormalBugExplanation(
        formal_condition='V_bug ⟺ (x < 0)',
        variables={'x': VariableSpec(name='x', var_type='int', meaning='input value', code_location='line 1')},
        description='Buffer underflow vulnerability',
        manifestation='Negative index access',
        vulnerable_location='line 5',
        causal_paths=[],
        safety_property='∀x: x >= 0',
        intervention_options=['Add bounds check'],
        preconditions=[],
        postconditions=[],
        assertions=[]
    )
    print(f'✓ E_bug created: {E_bug.formal_condition}')
    
    print('\nTesting FormalPatchExplanation...')
    E_patch = FormalPatchExplanation(
        code_diff=CodeDiff(added_lines=[], modified_lines=[], deleted_lines=[]),
        intervention=InterventionDescription(formal='do(x = max(x, 0))', affected_variables=['x'], description='Clamp x to non-negative'),
        effect_on_Vbug=EffectAnalysis(before='V_bug ⟺ (x < 0)', after='V_bug ⟺ False', reasoning='Bounds check prevents negative values'),
        addressed_causes=['negative_input'],
        unaddressed_causes=[],
        disrupted_paths=['path_1'],
        summary='Added bounds check',
        mechanism='Clamps input to non-negative range',
        consequence='Prevents buffer underflow',
        postconditions=['x >= 0'],
        new_assertions=[]
    )
    print(f'✓ E_patch created: {E_patch.summary}')
    
    return E_bug, E_patch

def test_consistency_checker(E_bug, E_patch):
    """Test consistency checker"""
    print('\nTesting ConsistencyChecker...')
    checker = ConsistencyChecker()
    result = checker.check(E_bug, E_patch)
    print(f'✓ Consistency check completed: overall={result.overall}')
    print(f'  - Causal coverage: {result.causal_coverage.success}')
    print(f'  - Intervention validity: {result.intervention_validity.success}')
    print(f'  - Logical consistency: {result.logical_consistency.success}')
    print(f'  - Completeness: {result.completeness.success}')
    return result

def test_performance_profiler():
    """Test performance profiler"""
    print('\nTesting PerformanceProfiler...')
    profiler = PerformanceProfiler()
    profiler.start_total()
    
    with profiler.profile_phase('test_phase'):
        # Simulate some work
        result = sum([i**2 for i in range(10000)])
    
    profile = profiler.end_total(case_id='test_case', iteration_count=1)
    print(f'✓ Profiler completed: total_time={profile.total_time_seconds:.4f}s')
    if profile.peak_memory_mb:
        print(f'  - Peak memory: {profile.peak_memory_mb:.2f} MB')
    print(f'  - Phase metrics:')
    for phase_name, duration in profile.phase_breakdown.items():
        print(f'    * {phase_name}: {duration:.4f}s')
    
    return profile

if __name__ == '__main__':
    print('='*60)
    print('Testing newly implemented PatchScribe features')
    print('='*60)
    
    try:
        E_bug, E_patch = test_formal_spec()
        consistency_result = test_consistency_checker(E_bug, E_patch)
        performance_profile = test_performance_profiler()
        
        print('\n' + '='*60)
        print('✅ All tests passed!')
        print('='*60)
    except Exception as e:
        print(f'\n❌ Test failed: {e}')
        import traceback
        traceback.print_exc()
