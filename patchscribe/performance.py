"""
Performance profiling tools for measuring PatchScribe execution time and resources.
Supports RQ3: Scalability and Performance evaluation.
"""
from __future__ import annotations

import csv
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


@dataclass
class PhaseMetrics:
    """Metrics for a single phase of execution"""
    phase_name: str
    duration_seconds: float
    peak_memory_mb: float | None = None


@dataclass
class PerformanceProfile:
    """Complete performance profile for a vulnerability case"""
    case_id: str
    total_time_seconds: float
    phase_breakdown: Dict[str, float]
    iteration_count: int
    peak_memory_mb: float | None = None
    phase_memory_mb: Dict[str, float] | None = None
    code_complexity: Dict[str, object] | None = None
    llm_calls: List[Dict[str, object]] = field(default_factory=list)
    
    def as_dict(self) -> Dict[str, object]:
        result = {
            'case_id': self.case_id,
            'total_time_seconds': self.total_time_seconds,
            'phase_breakdown': self.phase_breakdown,
            'iteration_count': self.iteration_count,
        }
        if self.peak_memory_mb is not None:
            result['peak_memory_mb'] = self.peak_memory_mb
        if self.phase_memory_mb:
            result['phase_memory_mb'] = self.phase_memory_mb
        if self.code_complexity is not None:
            result['code_complexity'] = self.code_complexity
        return result


class PerformanceProfiler:
    """
    Profiles PatchScribe execution to measure time and resource usage.
    
    Usage:
        profiler = PerformanceProfiler()
        with profiler.profile_phase("phase_name"):
            # Do work
            pass
        profile = profiler.get_profile("case_id", iteration_count)
    """
    
    def __init__(self):
        self.phases: List[PhaseMetrics] = []
        self.total_start = None
        self.total_end = None
        self.process = psutil.Process() if PSUTIL_AVAILABLE else None
        self.initial_memory = None
        self.llm_calls: List[Dict[str, object]] = []
        
    def start_total(self):
        """Start timing the entire execution"""
        self.total_start = time.time()
        if self.process:
            self.initial_memory = self.process.memory_info().rss
    
    def end_total(self, case_id: str = "default", iteration_count: int = 0, code_complexity: Dict[str, object] | None = None):
        """End timing the entire execution and return profile"""
        self.total_end = time.time()
        return self.get_profile(case_id, iteration_count, code_complexity)
    
    def profile_phase(self, phase_name: str):
        """Context manager for profiling a single phase"""
        return _PhaseContext(self, phase_name)
    
    def add_phase_metrics(self, metrics: PhaseMetrics):
        """Add phase metrics manually"""
        self.phases.append(metrics)
    
    def record_llm_call(self, record: Dict[str, object]) -> None:
        """Record telemetry from an LLM request."""
        self.llm_calls.append(record)

    def get_profile(
        self,
        case_id: str,
        iteration_count: int,
        code_complexity: Dict[str, object] | None = None
    ) -> PerformanceProfile:
        """Generate complete performance profile"""
        if self.total_start is None or self.total_end is None:
            raise ValueError("Must call start_total() and end_total() before get_profile()")
        
        total_time = self.total_end - self.total_start
        phase_breakdown: Dict[str, float] = {}
        phase_memory: Dict[str, float] = {}
        for phase in self.phases:
            phase_breakdown[phase.phase_name] = phase_breakdown.get(phase.phase_name, 0.0) + phase.duration_seconds
            if phase.peak_memory_mb is not None:
                phase_memory[phase.phase_name] = max(
                    phase_memory.get(phase.phase_name, 0.0),
                    phase.peak_memory_mb,
                )
        
        peak_memory: Optional[float] = None
        if self.process and self.initial_memory is not None:
            current_memory = self.process.memory_info().rss
            peak_memory = (current_memory - self.initial_memory) / (1024 * 1024)  # MB
            if phase_memory:
                peak_memory = max(peak_memory or 0.0, max(phase_memory.values()))
        elif phase_memory:
            peak_memory = max(phase_memory.values())
        
        return PerformanceProfile(
            case_id=case_id,
            total_time_seconds=total_time,
            phase_breakdown=phase_breakdown,
            iteration_count=iteration_count,
            peak_memory_mb=peak_memory,
            phase_memory_mb=phase_memory or None,
            code_complexity=code_complexity,
            llm_calls=list(self.llm_calls),
        )
    
    def reset(self):
        """Reset profiler for next case"""
        self.phases = []
        self.total_start = None
        self.total_end = None
        self.initial_memory = None
        self.llm_calls = []


class _PhaseContext:
    """Context manager for profiling a phase"""
    
    def __init__(self, profiler: PerformanceProfiler, phase_name: str):
        self.profiler = profiler
        self.phase_name = phase_name
        self.start_time = None
        self.start_memory = None
    
    def __enter__(self):
        self.start_time = time.time()
        if self.profiler.process:
            self.start_memory = self.profiler.process.memory_info().rss
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        
        peak_memory = None
        if self.profiler.process and self.start_memory is not None:
            end_memory = self.profiler.process.memory_info().rss
            peak_memory = max(0.0, (end_memory - self.start_memory) / (1024 * 1024))
        
        metrics = PhaseMetrics(
            phase_name=self.phase_name,
            duration_seconds=duration,
            peak_memory_mb=peak_memory
        )
        self.profiler.add_phase_metrics(metrics)


def measure_code_complexity(source_code: str) -> Dict[str, object]:
    """
    Measure code complexity metrics.
    
    Returns:
        Dictionary with:
        - lines_of_code: Total lines
        - function_count: Number of functions
        - branch_count: Approximate number of branches
    """
    lines = source_code.strip().split('\n')
    loc = len(lines)
    
    # Simple heuristics
    function_count = sum(1 for line in lines if 'def ' in line or line.strip().startswith('int ') or line.strip().startswith('void '))
    branch_count = sum(1 for line in lines if 'if ' in line or 'for ' in line or 'while ' in line)
    
    return {
        'lines_of_code': loc,
        'function_count': function_count,
        'branch_count': branch_count,
    }


def categorize_complexity(loc: int) -> str:
    """Categorize code complexity by lines of code"""
    if loc < 50:
        return "simple"
    elif loc < 100:
        return "medium"
    else:
        return "complex"


def export_llm_calls_to_csv(
    profiles: List[PerformanceProfile],
    output_path: Path,
) -> None:
    """Export aggregated LLM call telemetry to CSV."""
    fieldnames = [
        "case_id",
        "model",
        "provider",
        "duration_ms",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "timestamp",
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for profile in profiles:
            for call in profile.llm_calls or []:
                row = {
                    "case_id": profile.case_id,
                    "model": call.get("model"),
                    "provider": call.get("provider"),
                    "duration_ms": f"{call.get('duration_ms', 0):.2f}",
                    "prompt_tokens": call.get("prompt_tokens"),
                    "completion_tokens": call.get("completion_tokens"),
                    "total_tokens": call.get("total_tokens"),
                    "timestamp": call.get("timestamp"),
                }
                writer.writerow(row)
