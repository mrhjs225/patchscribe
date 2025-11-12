"""
LLM-based patch success judge replicating manual SynEq/SemEq/Plausible evaluation.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, List, Optional

from .llm import LLMClient, LLMConfig, LLMUnavailable


@dataclass
class PatchSuccessVerdict:
    syntactic_equivalent: bool
    semantic_equivalent: bool
    plausible: bool
    reason: str = ""
    raw_response: Optional[str] = None
    judge_votes: Optional[Dict[str, Dict[str, bool]]] = None
    voting_method: Optional[str] = None

    @property
    def is_success(self) -> bool:
        return self.syntactic_equivalent or self.semantic_equivalent or self.plausible

    def as_dict(self) -> Dict[str, object]:
        result = {
            "syn_eq": self.syntactic_equivalent,
            "sem_eq": self.semantic_equivalent,
            "plausible": self.plausible,
            "reason": self.reason,
            "raw": self.raw_response,
        }
        if self.judge_votes is not None:
            result["judge_votes"] = self.judge_votes
        if self.voting_method is not None:
            result["voting_method"] = self.voting_method
        return result


class PatchSuccessJudge:
    """
    Determines whether a generated patch satisfies SynEq, SemEq, or Plausible criteria.
    Falls back to deterministic checks before consulting the LLM judge.
    Supports majority voting with multiple judges.
    """

    def __init__(self, *, use_majority_voting: bool = False, judge_models: List[str] = None) -> None:
        """
        Args:
            use_majority_voting: If True, use 3 judges with majority voting
            judge_models: List of judge models to use (default: ["gpt", "claude", "gemini"])
        """
        self.use_majority_voting = use_majority_voting
        if use_majority_voting:
            self.judge_models = judge_models or ["gpt", "claude", "gemini"]
            if len(self.judge_models) != 3:
                raise ValueError("Majority voting requires exactly 3 judges")
        else:
            self.judge_models = ["gpt"]  # Single judge (backward compatibility)

        # Create LLM clients for each judge
        self.judges = {}
        for judge_key in self.judge_models:
            judge_config = LLMConfig.from_env(for_judge=True, judge_model=judge_key)
            self.judges[judge_key] = LLMClient(judge_config)

    def evaluate(
        self,
        *,
        original_code: str,
        patched_code: str,
        ground_truth: Optional[str] = None,
        vulnerability_signature: Optional[str] = None,
        description: Optional[str] = None,
    ) -> PatchSuccessVerdict:
        patched_norm = _normalize_code(patched_code)
        if not patched_norm:
            return PatchSuccessVerdict(False, False, False, reason="Generated patch is empty.")

        syn_eq = _matches_ground_truth(patched_norm, ground_truth)
        if syn_eq:
            return PatchSuccessVerdict(
                syntactic_equivalent=True,
                semantic_equivalent=False,
                plausible=False,
                reason="Patched code exactly matches provided ground truth.",
            )

        # Check if all judges are available
        if not all(client.available() for client in self.judges.values()):
            return PatchSuccessVerdict(False, False, False, reason="One or more judges unavailable.")

        prompt = self._build_prompt(
            original_code=original_code,
            patched_code=patched_code,
            ground_truth=ground_truth,
            vulnerability_signature=vulnerability_signature,
            description=description,
        )

        # Collect votes from all judges in parallel
        all_votes = {}
        all_responses = {}

        # Parallelize judge calls using ThreadPoolExecutor
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def call_judge(judge_key: str, judge_client):
            try:
                response = judge_client._post_chat(
                    [
                        {"role": "system", "content": self._system_prompt()},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.0,
                )
                payload = self._parse_json_response(response)

                if payload is None:
                    return judge_key, {"sem_eq": False, "plausible": False, "reason": "Non-JSON response"}, response

                sem_eq = _as_bool(payload.get("semantic_equivalent") or payload.get("sem_eq"))
                plausible = _as_bool(payload.get("plausible"))
                reason = payload.get("reason") or payload.get("analysis") or payload.get("notes") or ""

                vote = {
                    "sem_eq": sem_eq,
                    "plausible": plausible,
                    "reason": reason.strip()
                }
                return judge_key, vote, response

            except LLMUnavailable as exc:
                return judge_key, {"sem_eq": False, "plausible": False, "reason": f"Judge unavailable: {exc}"}, None

        # Execute judge calls in parallel
        with ThreadPoolExecutor(max_workers=len(self.judges)) as executor:
            futures = {executor.submit(call_judge, key, client): key for key, client in self.judges.items()}

            for future in as_completed(futures):
                judge_key, vote, response = future.result()
                all_votes[judge_key] = vote
                all_responses[judge_key] = response

        # Apply voting logic
        if self.use_majority_voting:
            final_sem_eq, final_plausible, final_reason = self._apply_majority_vote(all_votes)
            voting_method = "majority"
        else:
            # Single judge (backward compatibility)
            single_vote = all_votes[self.judge_models[0]]
            final_sem_eq = single_vote.get("sem_eq", False)
            final_plausible = single_vote.get("plausible", False)
            final_reason = single_vote.get("reason", "")
            voting_method = "single"

        return PatchSuccessVerdict(
            syntactic_equivalent=False,
            semantic_equivalent=final_sem_eq,
            plausible=final_plausible,
            reason=final_reason,
            raw_response=json.dumps(all_responses),
            judge_votes=all_votes,
            voting_method=voting_method,
        )

    @staticmethod
    def _build_prompt(
        *,
        original_code: str,
        patched_code: str,
        ground_truth: Optional[str],
        vulnerability_signature: Optional[str],
        description: Optional[str],
    ) -> str:
        payload = {
            "task": "classify_patch_success",
            "definitions": {
                "SynEq": "Generated patch text is identical to the ground truth patch.",
                "SemEq": (
                    "Patch differs syntactically but enforces the same behavior as the ground truth, "
                    "fully removing the vulnerability."
                ),
                "Plausible": (
                    "Patch may have different behavior but still eliminates the vulnerability without breaking "
                    "the intended functionality of the original program."
                ),
            },
            "instructions": (
                "Decide whether the generated patch qualifies as SemEq and/or Plausible (SynEq is already determined). "
                "Focus on whether the vulnerability is addressed and whether normal functionality remains intact. "
                "Respond ONLY with JSON containing boolean fields semantic_equivalent, plausible, and a short reason."
            ),
            "context": {
                "vulnerability_signature": vulnerability_signature,
                "description": description,
            },
            "code": {
                "original_vulnerable": original_code,
                "generated_patch": patched_code,
                "ground_truth_patch": ground_truth,
            },
        }
        return json.dumps(payload, ensure_ascii=False)

    @staticmethod
    def _parse_json_response(response: str) -> Optional[Dict[str, object]]:
        response = response.strip()
        if not response:
            return None
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        # Some judges wrap JSON in commentary; extract the last object.
        buf = ""
        depth = 0
        candidates = []
        for ch in response:
            if ch == "{":
                depth += 1
            if depth:
                buf += ch
            if ch == "}":
                depth -= 1
                if depth == 0 and buf:
                    candidates.append(buf)
                    buf = ""
        for snippet in reversed(candidates):
            snippet = snippet.strip()
            if not snippet:
                continue
            try:
                return json.loads(snippet)
            except json.JSONDecodeError:
                continue
        return None

    @staticmethod
    def _system_prompt() -> str:
        return (
            "You replace a human evaluation panel for security patches. "
            "Use the provided definitions to decide if a generated patch is SemEq or Plausible. "
            "Respond strictly with JSON: {\"semantic_equivalent\": bool, \"plausible\": bool, \"reason\": \"...\"}."
        )

    @staticmethod
    def _apply_majority_vote(votes: Dict[str, Dict[str, bool]]) -> tuple[bool, bool, str]:
        """
        Apply majority voting (2 out of 3 must agree).

        Returns:
            (sem_eq, plausible, reason)
        """
        sem_eq_votes = [v.get("sem_eq", False) for v in votes.values()]
        plausible_votes = [v.get("plausible", False) for v in votes.values()]

        # Count True votes
        sem_eq_count = sum(sem_eq_votes)
        plausible_count = sum(plausible_votes)

        # Majority = at least 2 out of 3
        final_sem_eq = sem_eq_count >= 2
        final_plausible = plausible_count >= 2

        # Build reason explaining the vote
        judge_names = list(votes.keys())
        reason_parts = []

        reason_parts.append(f"SemEq votes: {sem_eq_count}/3 (majority: {final_sem_eq})")
        for judge, vote in votes.items():
            if vote.get("sem_eq"):
                reason_parts.append(f"  - {judge}: SemEq=True")

        reason_parts.append(f"Plausible votes: {plausible_count}/3 (majority: {final_plausible})")
        for judge, vote in votes.items():
            if vote.get("plausible"):
                reason_parts.append(f"  - {judge}: Plausible=True")

        # Add individual judge reasons
        reason_parts.append("\nIndividual judge reasons:")
        for judge, vote in votes.items():
            judge_reason = vote.get("reason", "No reason provided")
            reason_parts.append(f"  [{judge}] {judge_reason}")

        final_reason = "\n".join(reason_parts)

        return final_sem_eq, final_plausible, final_reason


def _normalize_code(code: Optional[str]) -> str:
    if not code:
        return ""
    return "\n".join(line.rstrip() for line in code.strip().splitlines())


def _matches_ground_truth(patched_norm: str, ground_truth: Optional[str]) -> bool:
    if not ground_truth:
        return False
    return patched_norm == _normalize_code(ground_truth)


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if not normalized:
            return False
        if normalized in {"true", "yes", "y", "1", "pass"}:
            return True
        if normalized in {"false", "no", "n", "0", "fail"}:
            return False
    return False
