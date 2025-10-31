"""
AST-based Code Similarity Calculation

Provides structural similarity comparison between code patches using AST analysis.
This is more accurate than text-based comparison as it understands code semantics.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

try:
    from tree_sitter import Language, Parser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False


@dataclass
class ASTSimilarityResult:
    """Result of AST-based similarity comparison"""
    structural_similarity: float  # 0.0 to 1.0
    token_similarity: float  # 0.0 to 1.0
    edit_distance: int
    matched_nodes: int
    total_nodes: int
    analysis: Dict[str, object]

    @property
    def overall_similarity(self) -> float:
        """Combined similarity score (weighted average)"""
        return 0.6 * self.structural_similarity + 0.4 * self.token_similarity


class SimpleASTSimilarityCalculator:
    """
    Fallback AST similarity calculator using regex-based parsing.

    This is used when tree-sitter is not available. It provides a reasonable
    approximation by analyzing code structure through pattern matching.
    """

    def __init__(self):
        # Patterns to extract code structure
        self.patterns = {
            'functions': re.compile(r'\b\w+\s+\w+\s*\([^)]*\)\s*\{'),
            'conditionals': re.compile(r'\b(if|else|switch)\b'),
            'loops': re.compile(r'\b(for|while|do)\b'),
            'assignments': re.compile(r'\w+\s*=\s*[^;]+;'),
            'function_calls': re.compile(r'\b\w+\s*\([^)]*\)'),
            'returns': re.compile(r'\breturn\b'),
            'variables': re.compile(r'\b(int|char|float|double|void|size_t|bool)\s+\w+'),
        }

    def calculate_similarity(
        self,
        code1: str,
        code2: str
    ) -> ASTSimilarityResult:
        """Calculate similarity between two code snippets"""

        # Extract structural features
        features1 = self._extract_features(code1)
        features2 = self._extract_features(code2)

        # Calculate structural similarity
        structural_sim = self._structural_similarity(features1, features2)

        # Calculate token similarity
        tokens1 = self._tokenize(code1)
        tokens2 = self._tokenize(code2)
        token_sim = self._token_similarity(tokens1, tokens2)

        # Calculate edit distance (simplified)
        edit_dist = self._levenshtein_distance(
            self._normalize_code(code1),
            self._normalize_code(code2)
        )

        # Count matched structural elements
        matched = sum(
            min(features1[key], features2[key])
            for key in features1.keys()
        )
        total = sum(max(features1[key], features2[key]) for key in features1.keys())

        return ASTSimilarityResult(
            structural_similarity=structural_sim,
            token_similarity=token_sim,
            edit_distance=edit_dist,
            matched_nodes=matched,
            total_nodes=total,
            analysis={
                'features1': features1,
                'features2': features2,
                'method': 'regex_based'
            }
        )

    def _extract_features(self, code: str) -> Dict[str, int]:
        """Extract structural features from code"""
        features = {}
        for feature_name, pattern in self.patterns.items():
            matches = pattern.findall(code)
            features[feature_name] = len(matches)
        return features

    def _structural_similarity(
        self,
        features1: Dict[str, int],
        features2: Dict[str, int]
    ) -> float:
        """Calculate structural similarity based on features"""
        if not features1 and not features2:
            return 1.0

        # Use Jaccard-like similarity for counts
        all_keys = set(features1.keys()) | set(features2.keys())

        intersection = sum(
            min(features1.get(key, 0), features2.get(key, 0))
            for key in all_keys
        )
        union = sum(
            max(features1.get(key, 0), features2.get(key, 0))
            for key in all_keys
        )

        return intersection / union if union > 0 else 0.0

    def _tokenize(self, code: str) -> List[str]:
        """Tokenize code into meaningful tokens"""
        # Normalize and split
        code = self._normalize_code(code)

        # Split by common delimiters
        tokens = re.findall(r'\b\w+\b|[{}();,=<>!+\-*/]', code)

        # Filter out common noise tokens
        noise = {'', ' ', '\n', '\t'}
        return [t for t in tokens if t not in noise]

    def _token_similarity(self, tokens1: List[str], tokens2: List[str]) -> float:
        """Calculate token-level similarity (Jaccard)"""
        if not tokens1 and not tokens2:
            return 1.0

        set1 = set(tokens1)
        set2 = set(tokens2)

        intersection = len(set1 & set2)
        union = len(set1 | set2)

        return intersection / union if union > 0 else 0.0

    @staticmethod
    def _normalize_code(code: str) -> str:
        """Normalize code for comparison"""
        # Remove comments
        code = re.sub(r'//.*?\n', '\n', code)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)

        # Normalize whitespace
        code = re.sub(r'\s+', ' ', code)

        return code.strip()

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate Levenshtein edit distance"""
        if len(s1) < len(s2):
            return SimpleASTSimilarityCalculator._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                # Cost of insertions, deletions, or substitutions
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]


class TreeSitterASTSimilarityCalculator:
    """
    Advanced AST similarity calculator using tree-sitter.

    Provides accurate structural comparison by parsing code into proper AST.
    """

    def __init__(self, language: str = 'c'):
        if not TREE_SITTER_AVAILABLE:
            raise ImportError("tree-sitter is not available")

        self.language = language
        # Note: In production, you'd need to build and load the language
        # For now, this is a placeholder
        self.parser = None

    def calculate_similarity(
        self,
        code1: str,
        code2: str
    ) -> ASTSimilarityResult:
        """Calculate similarity using tree-sitter AST"""
        # This would use tree-sitter to parse and compare ASTs
        # For now, fall back to simple calculator
        simple_calc = SimpleASTSimilarityCalculator()
        result = simple_calc.calculate_similarity(code1, code2)
        result.analysis['method'] = 'tree_sitter_fallback'
        return result


def calculate_ast_similarity(
    code1: str,
    code2: str,
    method: str = 'auto'
) -> ASTSimilarityResult:
    """
    Calculate AST-based similarity between two code snippets.

    Args:
        code1: First code snippet
        code2: Second code snippet
        method: 'auto', 'tree_sitter', or 'simple'

    Returns:
        ASTSimilarityResult with similarity metrics
    """
    if method == 'auto':
        if TREE_SITTER_AVAILABLE:
            method = 'tree_sitter'
        else:
            method = 'simple'

    if method == 'tree_sitter':
        try:
            calculator = TreeSitterASTSimilarityCalculator()
            return calculator.calculate_similarity(code1, code2)
        except Exception:
            # Fall back to simple if tree-sitter fails
            method = 'simple'

    # Use simple regex-based calculator
    calculator = SimpleASTSimilarityCalculator()
    return calculator.calculate_similarity(code1, code2)


def extract_patch_from_diff(diff_text: str) -> Tuple[List[str], List[str]]:
    """
    Extract added and removed lines from a unified diff.

    Returns:
        (removed_lines, added_lines)
    """
    removed = []
    added = []

    for line in diff_text.splitlines():
        if line.startswith('-') and not line.startswith('---'):
            removed.append(line[1:].strip())
        elif line.startswith('+') and not line.startswith('+++'):
            added.append(line[1:].strip())

    return removed, added


def compare_patches(
    patch1_code: str,
    patch2_code: str,
    original_code: Optional[str] = None
) -> ASTSimilarityResult:
    """
    Compare two patches, optionally considering the original code.

    This is useful for comparing a generated patch to a ground truth patch.

    Args:
        patch1_code: First patched code (or diff)
        patch2_code: Second patched code (or diff)
        original_code: Original vulnerable code (optional)

    Returns:
        ASTSimilarityResult
    """
    # If we have the original code, we can do a more sophisticated comparison
    # by looking at what each patch changed

    if original_code:
        # Extract what changed in each patch
        # This is simplified - in practice you'd use proper diff parsing
        return calculate_ast_similarity(patch1_code, patch2_code)
    else:
        # Direct comparison of patched code
        return calculate_ast_similarity(patch1_code, patch2_code)


# Convenience functions for common use cases

def is_similar_patch(
    generated_patch: str,
    ground_truth_patch: str,
    threshold: float = 0.7
) -> bool:
    """
    Check if generated patch is similar enough to ground truth.

    Args:
        generated_patch: The generated patch code
        ground_truth_patch: The ground truth patch code
        threshold: Similarity threshold (0.0 to 1.0)

    Returns:
        True if patches are similar above threshold
    """
    result = calculate_ast_similarity(generated_patch, ground_truth_patch)
    return result.overall_similarity >= threshold


def get_similarity_score(
    code1: str,
    code2: str,
    metric: str = 'overall'
) -> float:
    """
    Get a single similarity score between two code snippets.

    Args:
        code1: First code snippet
        code2: Second code snippet
        metric: 'overall', 'structural', or 'token'

    Returns:
        Similarity score (0.0 to 1.0)
    """
    result = calculate_ast_similarity(code1, code2)

    if metric == 'structural':
        return result.structural_similarity
    elif metric == 'token':
        return result.token_similarity
    else:  # overall
        return result.overall_similarity
