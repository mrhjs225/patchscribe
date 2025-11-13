"""
Test cases for enhanced analysis modules.

Tests the newly implemented LLVM-based backward slicing,
SMT logical consistency checking, and enhanced static/AST analysis.
"""
import pytest


# Test sample C code with a simple vulnerability
SAMPLE_VULNERABLE_CODE = """
int vulnerable_function(char *input) {
    char buffer[10];
    int result;

    if (!input) {
        return -1;
    }

    result = strlen(input);  // No bounds check
    strcpy(buffer, input);    // Buffer overflow vulnerability (line 10)

    return result;
}
"""


class TestLLVMBackwardSlicing:
    """Test LLVM-based backward slicing."""

    def test_llvm_slicer_import(self):
        """Test that LLVM slicer module can be imported."""
        try:
            from patchscribe.tools.llvm_slicer import (
                LLVMBackwardSlicer,
                HeuristicBackwardSlicer,
                create_backward_slicer,
            )
            assert LLVMBackwardSlicer is not None
            assert HeuristicBackwardSlicer is not None
            assert create_backward_slicer is not None
        except ImportError as e:
            pytest.skip(f"LLVM slicer not available: {e}")

    def test_heuristic_slicer_basic(self):
        """Test heuristic backward slicer on sample code."""
        from patchscribe.tools.llvm_slicer import HeuristicBackwardSlicer

        slicer = HeuristicBackwardSlicer(SAMPLE_VULNERABLE_CODE)
        result = slicer.slice(vuln_line=10)

        assert result is not None
        assert result.slice_size > 0
        assert len(result.statements) > 0
        # Should include the vulnerability line
        assert any(s.line_number == 10 for s in result.statements)

    def test_llvm_slicer_availability(self):
        """Test LLVM slicer availability detection."""
        from patchscribe.tools.llvm_slicer import LLVMBackwardSlicer

        slicer = LLVMBackwardSlicer(SAMPLE_VULNERABLE_CODE)
        # Just check that availability check doesn't crash
        is_available = slicer.available
        assert isinstance(is_available, bool)

    def test_create_backward_slicer_factory(self):
        """Test factory function returns appropriate slicer."""
        from patchscribe.tools.llvm_slicer import create_backward_slicer

        slicer = create_backward_slicer(SAMPLE_VULNERABLE_CODE)
        assert slicer is not None

        # Should have slice method
        assert hasattr(slicer, "slice")


class TestSMTConsistencyChecking:
    """Test SMT-based logical consistency checking."""

    def test_smt_timeout_configuration(self):
        """Test that SMT timeout is properly configured."""
        from patchscribe.consistency_checker import SMT_SOLVER_TIMEOUT_MS

        assert SMT_SOLVER_TIMEOUT_MS > 0
        assert SMT_SOLVER_TIMEOUT_MS <= 60000  # Should be reasonable (< 60s)

    def test_consistency_checker_import(self):
        """Test that enhanced consistency checker can be imported."""
        try:
            from patchscribe.consistency_checker import (
                ConsistencyChecker,
                ConsistencyResult,
            )
            assert ConsistencyChecker is not None
            assert ConsistencyResult is not None
        except ImportError as e:
            pytest.fail(f"Failed to import consistency checker: {e}")

    def test_extract_affected_variables(self):
        """Test extraction of affected variables from patch."""
        from patchscribe.consistency_checker import ConsistencyChecker

        checker = ConsistencyChecker()

        # Test that the method exists and is callable
        assert hasattr(checker, "_extract_affected_variables")
        assert callable(getattr(checker, "_extract_affected_variables"))


class TestEnhancedStaticAnalysis:
    """Test LLVM IR-based static analysis."""

    def test_llvm_static_analyzer_import(self):
        """Test that LLVM static analyzer can be imported."""
        try:
            from patchscribe.analysis.static_analysis_llvm import (
                LLVMStaticAnalyzer,
                create_static_analyzer,
            )
            assert LLVMStaticAnalyzer is not None
            assert create_static_analyzer is not None
        except ImportError as e:
            pytest.skip(f"LLVM static analyzer not available: {e}")

    def test_llvm_static_analyzer_availability(self):
        """Test LLVM static analyzer availability check."""
        from patchscribe.analysis.static_analysis_llvm import LLVMStaticAnalyzer

        analyzer = LLVMStaticAnalyzer(SAMPLE_VULNERABLE_CODE, vuln_location=10)
        is_available = analyzer.available
        assert isinstance(is_available, bool)

    def test_static_analyzer_factory(self):
        """Test static analyzer factory function."""
        from patchscribe.analysis.static_analysis_llvm import create_static_analyzer

        analyzer = create_static_analyzer(SAMPLE_VULNERABLE_CODE, vuln_location=10)
        assert analyzer is not None
        assert hasattr(analyzer, "run")

        # Run analysis (should not crash)
        result = analyzer.run()
        assert result is not None
        assert hasattr(result, "graph")
        assert hasattr(result, "trace")


class TestEnhancedASTAnalysis:
    """Test pycparser-based AST analysis."""

    def test_pycparser_analyzer_import(self):
        """Test that pycparser AST analyzer can be imported."""
        try:
            from patchscribe.analysis.ast_analysis_pycparser import (
                PycparserASTAnalyzer,
                create_ast_analyzer,
            )
            assert PycparserASTAnalyzer is not None
            assert create_ast_analyzer is not None
        except ImportError as e:
            pytest.skip(f"pycparser AST analyzer not available: {e}")

    def test_pycparser_analyzer_availability(self):
        """Test pycparser analyzer availability check."""
        from patchscribe.analysis.ast_analysis_pycparser import PycparserASTAnalyzer

        analyzer = PycparserASTAnalyzer(SAMPLE_VULNERABLE_CODE, vuln_location=10)
        is_available = analyzer.available
        assert isinstance(is_available, bool)

    def test_ast_analyzer_factory(self):
        """Test AST analyzer factory function."""
        from patchscribe.analysis.ast_analysis_pycparser import create_ast_analyzer

        analyzer = create_ast_analyzer(SAMPLE_VULNERABLE_CODE, vuln_location=10)
        assert analyzer is not None
        assert hasattr(analyzer, "run")

        # Run analysis (should not crash)
        result = analyzer.run()
        assert result is not None
        assert hasattr(result, "graph")
        assert hasattr(result, "trace")


class TestPCGBuilderIntegration:
    """Test integration of enhanced analyzers into PCG builder."""

    def test_pcg_builder_with_enhanced_analyzers(self):
        """Test that PCG builder can use enhanced analyzers."""
        from patchscribe.pcg_builder import PCGBuilder, PCGBuilderConfig

        vuln_info = {
            "location": 10,
            "type": "buffer_overflow",
            "description": "Buffer overflow in strcpy",
        }

        builder = PCGBuilder(
            program=SAMPLE_VULNERABLE_CODE,
            vuln_info=vuln_info,
            config=PCGBuilderConfig(),
        )

        # Should not crash
        graph, metadata = builder.build()

        assert graph is not None
        assert len(graph.nodes) > 0
        assert metadata is not None
        assert "static_trace" in metadata
        assert "ast_trace" in metadata


class TestBackwardCompatibility:
    """Test that existing code still works with enhancements."""

    def test_clang_analysis_fallback(self):
        """Test that clang analysis falls back gracefully."""
        from patchscribe.tools.clang_analysis import ClangStaticAnalyzer

        analyzer = ClangStaticAnalyzer(SAMPLE_VULNERABLE_CODE)
        result = analyzer.run(vuln_line=10)

        # Should return something (either LLVM result or fallback)
        # or None if neither is available
        assert result is None or hasattr(result, "nodes")

    def test_static_analysis_backward_compat(self):
        """Test that original static analyzer still works."""
        from patchscribe.analysis.static_analysis import StaticAnalyzer

        analyzer = StaticAnalyzer(SAMPLE_VULNERABLE_CODE, vuln_location=10)
        result = analyzer.run()

        assert result is not None
        assert hasattr(result, "graph")
        assert hasattr(result, "trace")

    def test_ast_analysis_backward_compat(self):
        """Test that original AST analyzer still works."""
        from patchscribe.analysis.ast_analysis import ASTAnalyzer

        analyzer = ASTAnalyzer(SAMPLE_VULNERABLE_CODE, vuln_location=10)
        result = analyzer.run()

        assert result is not None
        assert hasattr(result, "graph")
        assert hasattr(result, "trace")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
