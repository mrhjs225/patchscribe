# PatchScribe 용어 혼동 해소 가이드

## 📌 요약

**문제**: "Dual Verification"과 "Triple Verification"이 혼용되어 독자 혼란
**해결**: "Triple Verification" → "Multi-Stage Verification"으로 통일

---

## 🎯 권장 방안: 계층적 용어 체계

### 새로운 용어 구조

```
Phase 3: Dual Verification
  ↓ (E_bug ↔ E_patch 두 설명 간의 검증)
  ↓
Multi-Stage Verification (여러 단계의 검증)
  ├─ Stage 1: Consistency Checking (4 checks)
  ├─ Stage 2: Symbolic Verification (KLEE/angr)
  └─ Stage 3: Completeness Verification (path analysis)
```

### 핵심 원칙

1. **"Dual" = 두 설명 (E_bug, E_patch)**
2. **"Multi-Stage" = 여러 검증 단계**
3. **"Triple" 제거 = 혼란 해소**

---

## 📝 구체적 수정 사항

### 1. Introduction에 용어 정의 추가

**위치**: Introduction 섹션 초반 (line 100 근처)

**추가할 내용**:
```latex
\paragraph{Terminology.}
We refer to our approach as \emph{dual verification} because it verifies
consistency between two formal explanations: E\_bug (the formal specification
of the vulnerability's root cause) and E\_patch (the formal specification of
how the patch eliminates it). This distinguishes our work from prior approaches
that verify only the patch itself without a formal bug specification to compare
against.

Within dual verification, we employ \emph{multi-stage verification} consisting
of three complementary stages: (1) consistency checking (four sub-checks ensuring
E\_patch addresses all causes identified in E\_bug), (2) symbolic verification
(proving vulnerability unreachability via KLEE/angr), and (3) completeness
verification (ensuring all causal paths are disrupted). This multi-stage approach
provides defense-in-depth: even if one stage produces a false negative, others
can catch incomplete patches.
```

---

### 2. Abstract 수정 (line 41-43)

**Before**:
```latex
After patch generation, we perform
triple verification: (1) consistency checking to ensure E\_patch
addresses causes identified in E\_bug, (2) symbolic verification to
prove the vulnerability is unreachable, and (3) completeness checking to
ensure all causal paths are disrupted.
```

**After**:
```latex
After patch generation, we perform dual verification by comparing E\_bug
and E\_patch through multi-stage checks: (1) consistency checking to ensure
E\_patch addresses all causes identified in E\_bug, (2) symbolic verification
to prove the vulnerability is unreachable in the patched code, and
(3) completeness checking to ensure all causal paths are disrupted.
```

---

### 3. Abstract - Phase 소개 (line 44-46)

**Before**:
```latex
We outline the three-phase design
of PatchScribe (Vulnerability Formalization, Theory-Guided Patch
Generation, Dual Verification) and present an evaluation plan on recent
vulnerability repair benchmarks.
```

**After** (유지, 변경 없음):
```latex
We outline the three-phase design
of PatchScribe (Vulnerability Formalization, Theory-Guided Patch
Generation, Dual Verification) and present an evaluation plan on recent
vulnerability repair benchmarks.
```

---

### 4. Introduction 본문 (line 115)

**Before**:
```latex
is eliminated. We then perform triple verification: (1) consistency
checking between E\_bug and E\_patch (does the patch address identified
causes?), (2) symbolic verification (is the vulnerability provably
unreachable?), and (3) completeness checking (are all causal paths
disrupted?).
```

**After**:
```latex
is eliminated. We then perform dual verification—comparing E\_bug and E\_patch—
through multiple stages: (1) consistency checking (does the patch address
identified causes?), (2) symbolic verification (is the vulnerability provably
unreachable?), and (3) completeness checking (are all causal paths
disrupted?).
```

---

### 5. Phase 3 Title & Description (line 596-602)

**Before**:
```latex
\textbf{Phase 3: Dual Verification} - We perform three types of
verification: (1) \textbf{Consistency checking} to ensure the patch
explanation addresses the causes stated in the bug explanation (does
E\_patch actually handle what E\_bug identified?), (2) \textbf{Symbolic
verification} to prove the vulnerability condition is unreachable in the
patched program, and (3) \textbf{Completeness checking} to ensure all
identified causes are properly handled. This triple verification
provides stronger guarantees than prior work.
```

**After**:
```latex
\textbf{Phase 3: Dual Verification} - We verify consistency between
E\_bug and E\_patch through multi-stage verification:
(1) \textbf{Consistency Checking} to ensure E\_patch addresses the causes
identified in E\_bug (four sub-checks: causal coverage, intervention validity,
logical consistency, completeness), (2) \textbf{Symbolic Verification} to
prove the vulnerability condition is unreachable in the patched program
(using KLEE/angr), and (3) \textbf{Completeness Verification} to ensure
all causal paths are disrupted. This multi-stage verification provides
stronger guarantees than prior single-stage approaches.
```

---

### 6. RQ2 (line 1248-1250)

**Before**:
```latex
\textbf{RQ2: Dual Verification Effectiveness} -- How effective is the
dual verification framework at detecting incomplete patches? Does triple
verification (consistency + symbolic + completeness) catch cases that
```

**After**:
```latex
\textbf{RQ2: Dual Verification Effectiveness} -- How effective is dual
verification (comparing E\_bug and E\_patch) at detecting incomplete patches?
Does multi-stage verification (consistency checking + symbolic verification +
completeness analysis) catch cases that
```

---

### 7. Evaluation 섹션 (line 1289)

**Before**:
```latex
E\_bug and triple verification). Comparing C3 vs C1 isolates the effect
```

**After**:
```latex
E\_bug and multi-stage verification). Comparing C3 vs C1 isolates the effect
```

---

### 8. Evaluation 섹션 (line 1291)

**Before**:
```latex
dual verification.
```

**After** (유지, 변경 없음):
```latex
dual verification.
```

---

### 9. Evaluation 섹션 (line 1304)

**Before**:
```latex
and V4 (triple verification). The key metric is precision and recall in
```

**After**:
```latex
and V4 (multi-stage verification). The key metric is precision and recall in
```

---

### 10. Evaluation 섹션 (line 1347)

**Before**:
```latex
others identified in E\_bug. We anticipate triple verification (V4) to
```

**After**:
```latex
others identified in E\_bug. We anticipate multi-stage verification (V4) to
```

---

## 📊 변경 요약

| 위치 | Line | Before | After |
|------|------|--------|-------|
| Introduction | ~100 | (없음) | Terminology 단락 추가 |
| Abstract | 41-43 | triple verification | dual verification with multi-stage checks |
| Introduction | 115 | triple verification | dual verification through multiple stages |
| Phase 3 | 596-602 | three types / triple | multi-stage verification |
| RQ2 | 1248-1250 | triple verification | multi-stage verification |
| Evaluation | 1289 | triple verification | multi-stage verification |
| Evaluation | 1304 | triple verification | multi-stage verification |
| Evaluation | 1347 | triple verification | multi-stage verification |

**총 변경**: 7곳 수정 + 1곳 추가 = 8곳

---

## 🔍 검증 방법

수정 후 다음 명령으로 확인:

```bash
# "triple verification" 남은 것 확인
grep -n "triple verification" patchscribe.tex

# "multi-stage" 제대로 들어갔는지 확인
grep -n "multi-stage" patchscribe.tex

# "Dual Verification"이 일관되게 사용되었는지 확인
grep -n "Dual Verification" patchscribe.tex
```

**예상 결과**:
- "triple verification": 0건 (모두 제거됨)
- "multi-stage": 8건 이상
- "Dual Verification": Phase 3 제목, RQ2 등에서 일관되게 사용

---

## 💡 추가 개선 제안

### Option A: Figure 추가

Phase 3 구조를 시각화한 그림 추가:

```latex
\begin{figure}[t]
\centering
\begin{tikzpicture}
  % Phase 3 box
  \node[draw, rectangle, minimum width=8cm, minimum height=1cm] (phase3)
    {Phase 3: Dual Verification (E\_bug $\leftrightarrow$ E\_patch)};

  % Three stages
  \node[draw, rectangle, below=1cm of phase3, xshift=-2.5cm] (stage1)
    {Consistency\\Checking};
  \node[draw, rectangle, below=1cm of phase3] (stage2)
    {Symbolic\\Verification};
  \node[draw, rectangle, below=1cm of phase3, xshift=2.5cm] (stage3)
    {Completeness\\Verification};

  % Arrows
  \draw[->] (phase3) -- (stage1);
  \draw[->] (phase3) -- (stage2);
  \draw[->] (phase3) -- (stage3);

  % Details
  \node[below=0.2cm of stage1, font=\footnotesize] {4 checks};
  \node[below=0.2cm of stage2, font=\footnotesize] {KLEE/angr};
  \node[below=0.2cm of stage3, font=\footnotesize] {Path analysis};
\end{tikzpicture}
\caption{Phase 3: Dual Verification with Multi-Stage Checks}
\label{fig:dual-verification}
\end{figure}
```

### Option B: Table 추가

용어 비교 표:

```latex
\begin{table}[t]
\centering
\caption{PatchScribe Verification Terminology}
\label{tab:terminology}
\begin{tabular}{ll}
\toprule
\textbf{Term} & \textbf{Meaning} \\
\midrule
Dual Verification & Comparing E\_bug and E\_patch \\
Multi-Stage Verification & Three complementary verification stages \\
Consistency Checking & Four checks on E\_bug $\leftrightarrow$ E\_patch \\
Symbolic Verification & KLEE/angr symbolic execution \\
Completeness Verification & Causal path disruption analysis \\
\bottomrule
\end{tabular}
\end{table}
```

---

## ✅ 체크리스트

논문 수정 완료 후 확인:

- [ ] Introduction에 Terminology 단락 추가됨
- [ ] Abstract에서 "triple" → "multi-stage" 변경됨
- [ ] Introduction line 115 수정됨
- [ ] Phase 3 설명에서 "triple" → "multi-stage" 변경됨
- [ ] RQ2에서 "triple" → "multi-stage" 변경됨
- [ ] Evaluation 섹션 3곳 수정됨
- [ ] grep으로 "triple verification" 0건 확인
- [ ] 논문 전체 읽어보며 용어 일관성 확인
- [ ] (선택) Figure 또는 Table 추가
- [ ] (선택) 코드 주석 업데이트

---

## 📞 문의

수정 중 질문이나 추가 제안 사항이 있으면 언제든지 문의하세요!
