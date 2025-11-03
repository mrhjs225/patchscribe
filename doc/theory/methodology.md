# PatchScribe: Improved Methodology

## Proposed Approach (PatchScribe)

PatchScribe is a system for automated vulnerability repair that produces **formally verified dual causal explanations** for each patch. Unlike prior approaches that generate patches first and explain them post-hoc, PatchScribe follows a principled theory-guided approach: it first formalizes the vulnerability causally, uses this formalization to guide patch generation, and then verifies the consistency between the bug's root cause and the patch's intervention.

At a high level, PatchScribe operates in three phases:

**Phase 1: Vulnerability Formalization** - We analyze the vulnerable program to build a Program Causal Graph (PCG) and derive a Structural Causal Model (SCM). From the SCM, we generate a **formal vulnerability specification** that precisely characterizes the conditions under which the vulnerability manifests. This specification serves as both a verification target and guidance for patch generation.

**Phase 2: Theory-Guided Patch Generation** - Armed with the formal vulnerability specification, we prompt an LLM to generate a patch. Critically, the LLM receives not vague hints but a precise formal description of what conditions cause the vulnerability and what the patch must achieve. After patch generation, we analyze how the patch intervenes on the causal model and generate a **formal patch explanation** describing the intervention.

**Phase 3: Dual Verification** - We perform three types of verification: (1) **Consistency checking** to ensure the patch explanation addresses the causes stated in the bug explanation, (2) **Symbolic verification** to prove the vulnerability condition is unreachable in the patched program, and (3) **Completeness checking** to ensure all identified causes are properly handled.

This approach ensures that patches are not only verified to work, but that we understand and can formally prove *why* they work in terms of the causal structure of the vulnerability.

---

## Phase 1: Vulnerability Formalization

### Step 1.1: Program Causal Graph Construction

**Input:** Vulnerable program P, vulnerability indicator (e.g., crash location, CVE description, PoC exploit)

**Process:** We construct a Program Causal Graph (PCG) that captures the causal relationships leading to the vulnerability. The PCG is a directed graph G = (V, E) where:

- **Nodes (V):** Represent program predicates and events relevant to the vulnerability:
  - Condition nodes: Truth values of conditionals (e.g., "len > buffer_size")
  - State nodes: Variable properties (e.g., "ptr is NULL", "input is unsanitized")
  - Event nodes: Program operations (e.g., "buffer write at line L", "function call to memcpy")
  - Special node V_bug: Represents the vulnerability manifestation

- **Edges (E):** Represent causal influence:
  - An edge u → v indicates that node u causally contributes to v in the vulnerability context
  - Includes both data dependencies (value flows) and control dependencies (execution paths)

**Construction Method:**

1. **Backward Slicing:** Starting from V_bug, perform backward static slicing to identify all program elements that can influence whether the vulnerability occurs

2. **Dependency Analysis:**
   - Control dependencies: Identify branches that guard the path to V_bug
   - Data dependencies: Track how tainted inputs or critical values flow to V_bug
   - Missing check identification: Detect absence of security checks (e.g., bounds checks, null checks, sanitization)

3. **Causal Refinement:** Transform dependencies into causal relationships by determining which conditions are *necessary* or *sufficient* for V_bug:
   - If V_bug requires passing through branch condition C, then C is a cause
   - If V_bug requires certain data properties (e.g., "len > N"), those properties are causes
   - Absence of checks (e.g., "no bounds check performed") are represented as causal nodes

**Output:** PCG G = (V, E) with V_bug as the sink node and causal factors as source/intermediate nodes

**Example:** For a buffer overflow vulnerability:
```
Nodes:
  - C_input: "User controls input length"
  - C_large: "len > buffer_size"  
  - C_nocheck: "No bounds check before copy"
  - E_copy: "memcpy execution at line 42"
  - V_bug: "Buffer overflow occurs"

Edges:
  C_input → C_large (user input determines length)
  C_large → V_bug (large length causes overflow)
  C_nocheck → V_bug (absence of check allows overflow)
  E_copy → V_bug (overflow manifests during copy)
```

### Step 1.2: Structural Causal Model Derivation

**Input:** PCG G = (V, E)

**Process:** We formalize the PCG as a Structural Causal Model (SCM) M = (U, V, F, P(U)) where:

- **U = {U₁, ..., Uₖ}:** Exogenous variables (external inputs, environment)
  - User inputs (e.g., input data, length parameters)
  - External state (e.g., file system state, network conditions)

- **V = {V₁, ..., Vₙ}:** Endogenous variables (program-internal states)
  - Boolean variables for conditions (e.g., Check_performed ∈ {0,1})
  - Boolean/state variables for events (e.g., V_bug ∈ {0,1})
  - Numeric variables for values (e.g., len ∈ ℕ)

- **F = {f₁, ..., fₙ}:** Structural equations defining each Vᵢ
  - Each fᵢ: Parents(Vᵢ) → Range(Vᵢ)
  - Captures how parent variables determine child variable
  - For V_bug, typically a conjunction of causal conditions

- **P(U):** Probability distribution over exogenous variables (for our purposes, we consider all feasible values)

**Mapping from PCG:**

1. **Variable Identification:** Each PCG node becomes an SCM variable
   - Condition nodes → Boolean endogenous variables
   - Input-related nodes → Exogenous variables
   - V_bug node → V_bug endogenous variable

2. **Equation Formulation:** For each variable Vᵢ, derive fᵢ from its parents in PCG
   - If V_bug has parents C₁, C₂, ..., Cₘ in PCG, then:
     - V_bug = f_bug(C₁, C₂, ..., Cₘ)
   - Typically conjunction: V_bug = C₁ ∧ C₂ ∧ ... ∧ Cₘ (all conditions must hold)
   - Or disjunction: V_bug = C₁ ∨ C₂ ∨ ... ∨ Cₘ (any condition triggers)

3. **Intervention Framework:** The SCM enables reasoning about interventions
   - An intervention do(Vᵢ = v) represents setting Vᵢ to value v
   - This models patches as causal interventions on the program
   - We can reason: "If we intervene do(Check = true), does V_bug become false?"

**Output:** SCM M capturing the formal causal structure of the vulnerability

**Example:** For the buffer overflow:
```
Exogenous:
  U = {user_input} (user provides input)

Endogenous:
  len = length(user_input)
  Large = (len > buffer_size)
  Check = check_performed  (0 = no check, 1 = check exists)
  V_overflow = overflow_occurs

Structural Equations:
  len := length(user_input)
  Large := (len > buffer_size)
  Check := 0  (originally, no check in vulnerable code)
  V_overflow := Large ∧ (¬Check)
  
Interpretation:
  Overflow occurs when length exceeds buffer size AND no check exists
```

### Step 1.3: Formal Bug Specification Generation ⭐ NEW

**Input:** SCM M, vulnerable program P

**Process:** Generate a formal, machine-checkable specification of the vulnerability:

1. **Identify Vulnerability Variable:** Locate V_bug in the SCM

2. **Extract Causal Condition:** From V_bug's structural equation f_bug, extract the formal condition:
   - φ_bug(X₁, ..., Xₙ) such that V_bug = true ⟺ φ_bug(X₁, ..., Xₙ) is satisfied
   - This is typically a logical formula (conjunction, disjunction, etc.)

3. **Map to Source Code:** For each variable Xᵢ in φ_bug:
   - Identify corresponding code location(s)
   - Specify where and when the condition is evaluated
   - Note: "absence of check" is mapped to "no conditional on path to vulnerable operation"

4. **Formulate Fix Requirement:** Specify what a correct patch must achieve:
   - Safety property: ∀ feasible inputs U, V_bug(U) = false
   - Causal property: For all execution paths, φ_bug cannot be satisfied
   - Intervention options: List which variables can be intervened upon to falsify φ_bug

5. **Generate Dual Representations:**
   - **Formal:** Mathematical/logical expression of vulnerability condition
   - **Natural Language:** Human-readable description mapping formal terms to code
   - **Verification Assertions:** Properties that can be checked by verification tools

**Output:** Formal Bug Explanation E_bug containing:

```python
E_bug = {
    # Formal specification
    "formal_condition": "V_bug ⟺ φ(X₁, ..., Xₙ)",
    "variables": {
        "X₁": {"type": bool, "meaning": "...", "code_location": "..."},
        ...
    },
    
    # Natural language description
    "description": "The vulnerability occurs when [conditions] at [locations]",
    "manifestation": "This causes [impact] at line L",
    
    # Code mapping
    "vulnerable_location": "line L, function F",
    "causal_paths": ["path 1: condition C₁ → ... → V_bug", ...],
    
    # Fix requirements
    "safety_property": "∀inputs: ¬V_bug(inputs)",
    "intervention_options": [
        "Option 1: Ensure ¬X₁ (by adding check/validation)",
        "Option 2: Ensure ¬X₂ (by changing computation)",
        ...
    ],
    
    # Verification artifacts
    "preconditions": ["assumptions about program state"],
    "postconditions": ["V_bug must be unreachable"],
    "assertions": ["assert(¬φ) at line L"]
}
```

**Example Output for Buffer Overflow:**

```python
E_bug = {
    "formal_condition": "V_overflow ⟺ (len > buffer_size) ∧ (¬Check)",
    
    "variables": {
        "len": {
            "type": "integer",
            "meaning": "Length of user input",
            "code_location": "computed from user_input at line 15"
        },
        "buffer_size": {
            "type": "constant",
            "meaning": "Allocated buffer capacity",
            "code_location": "BUFFER_SIZE = 256"
        },
        "Check": {
            "type": "boolean",
            "meaning": "Whether bounds check is performed",
            "code_location": "ABSENT: no check before line 42"
        }
    },
    
    "description": 
        "Buffer overflow occurs when the input length (len) exceeds the "
        "buffer capacity (256 bytes) AND no bounds check is performed before "
        "the memcpy operation.",
    
    "manifestation": 
        "At line 42, memcpy writes beyond the allocated buffer when both "
        "conditions hold, leading to memory corruption.",
    
    "vulnerable_location": "line 42: memcpy(buffer, input, len)",
    
    "causal_paths": [
        "user_input → len → (len > 256) → V_overflow",
        "absence of bounds check → ¬Check → V_overflow"
    ],
    
    "safety_property": 
        "∀user_input: ¬V_overflow(user_input)",
    
    "intervention_options": [
        "Option 1: Add bounds check (set Check = true) before memcpy",
        "Option 2: Ensure len ≤ buffer_size (clamp len value)",
        "Option 3: Use safe function (e.g., memcpy_s with size limit)"
    ],
    
    "preconditions": [
        "user_input can be arbitrary (attacker-controlled)",
        "buffer is allocated with size 256",
        "execution reaches line 42"
    ],
    
    "postconditions": [
        "line 42 is unreachable when len > 256",
        "OR len ≤ 256 when line 42 is reached"
    ],
    
    "assertions": [
        "assert(len <= 256) at line 41 (before memcpy)",
        "assert(unreachable(line 42) when len > 256)"
    ]
}
```

**Key Innovation:** This step transforms the implicit causal model (PCG/SCM) into an **explicit, formal specification** that can be:
1. Fed to the LLM for precise guidance
2. Used to verify patch correctness
3. Checked for consistency with the patch explanation
4. Shared with developers as documentation

---

## Phase 2: Theory-Guided Patch Generation

### Step 2.1: Formal Prompt Construction

**Input:** Vulnerable program P, Formal Bug Explanation E_bug

**Process:** Construct a structured prompt that provides the LLM with formal guidance:

**Prompt Template:**
```
You are fixing a security vulnerability in the following code:

[VULNERABLE CODE]
{source code with line numbers}

[FORMAL VULNERABILITY SPECIFICATION]
Vulnerability Type: {vulnerability class, e.g., "Buffer Overflow (CWE-120)"}

The vulnerability is formally characterized as follows:
{E_bug.formal_condition}

Where:
{for each variable in E_bug.variables:
  - Variable: {meaning}, Location: {code_location}}

Description:
{E_bug.description}

This vulnerability manifests at: {E_bug.vulnerable_location}
Impact: {E_bug.manifestation}

[CAUSAL ANALYSIS]
The vulnerability occurs through the following causal paths:
{E_bug.causal_paths}

[PATCH REQUIREMENTS]
Your patch must satisfy the following safety property:
{E_bug.safety_property}

To achieve this, you can intervene by:
{E_bug.intervention_options}

[VERIFICATION PROPERTIES]
After patching, the following must hold:
Preconditions: {E_bug.preconditions}
Postconditions: {E_bug.postconditions}

[INSTRUCTIONS]
Generate a patch that:
1. Eliminates the vulnerability by making the formal condition unsatisfiable
2. Preserves the intended functionality of the code
3. Introduces minimal code changes
4. Includes clear comments explaining the fix

Provide the complete patched function.
```

**Example Prompt for Buffer Overflow:**
```
You are fixing a security vulnerability in the following code:

[VULNERABLE CODE]
15: int process_input(char *user_input) {
16:     char buffer[256];
17:     int len = strlen(user_input);
18:     // No check here!
42:     memcpy(buffer, user_input, len);
43:     return process(buffer);
44: }

[FORMAL VULNERABILITY SPECIFICATION]
Vulnerability Type: Buffer Overflow (CWE-120)

The vulnerability is formally characterized as:
  V_overflow ⟺ (len > 256) ∧ (¬Check)

Where:
  - len: Length of user input, computed at line 17
  - 256: Buffer capacity (BUFFER_SIZE)
  - Check: Bounds check before memcpy (currently ABSENT)

Description:
Buffer overflow occurs when input length exceeds 256 bytes AND no bounds 
check is performed before the memcpy operation.

This vulnerability manifests at: line 42: memcpy(buffer, user_input, len)
Impact: Memory corruption when len > 256

[CAUSAL ANALYSIS]
The vulnerability occurs through the following causal paths:
  1. user_input → len → (len > 256) → V_overflow
  2. absence of bounds check → ¬Check → V_overflow

[PATCH REQUIREMENTS]
Your patch must satisfy: ∀user_input: ¬V_overflow(user_input)

To achieve this, you can intervene by:
  Option 1: Add bounds check (set Check = true) before line 42
  Option 2: Ensure len ≤ 256 (clamp len value)
  Option 3: Use safe function (memcpy_s with size check)

[VERIFICATION PROPERTIES]
After patching, the following must hold:
Preconditions:
  - user_input can be arbitrary (attacker-controlled)
  - buffer allocated with size 256
Postconditions:
  - line 42 unreachable when len > 256, OR
  - len ≤ 256 when line 42 is reached

[INSTRUCTIONS]
Generate a patch that makes the formal condition (len > 256) ∧ (¬Check) 
unsatisfiable by ensuring Check = true or len ≤ 256.
```

**Output:** Formal prompt for LLM with precise vulnerability specification

### Step 2.2: LLM Patch Generation

**Input:** Vulnerable program P, Formal prompt from Step 2.1

**Process:**
1. Send the formal prompt to the LLM (e.g., GPT-4, Claude, specialized code model)
2. Parse the LLM's response to extract the patched code
3. Apply the patch to produce candidate patched program P'

**Output:** Candidate patched program P'

**Example LLM Output:**
```c
int process_input(char *user_input) {
    char buffer[256];
    int len = strlen(user_input);
    
    // PATCH: Add bounds check to prevent overflow
    if (len > 256) {
        fprintf(stderr, "Input too large, truncating\n");
        len = 256;  // Clamp to buffer size
    }
    
    memcpy(buffer, user_input, len);
    return process(buffer);
}
```

### Step 2.3: Patch Explanation Generation ⭐ NEW

**Input:** Original program P, Patched program P', SCM M, Bug Explanation E_bug

**Process:** Analyze how the patch intervenes on the causal model and generate a formal explanation:

1. **Identify Code Changes:**
   - Perform syntactic diff between P and P'
   - Locate added/modified/deleted lines
   - Categorize changes: new conditionals, modified computations, added checks, etc.

2. **Map Changes to SCM Variables:**
   - For each code change, identify which SCM variable(s) it affects
   - Example: Adding "if (len > 256)" affects the Check variable
   - Example: "len = 256" affects the len variable

3. **Formulate Intervention:**
   - Express the patch as a causal intervention in SCM notation
   - Intervention do(Vᵢ = v) means "set variable Vᵢ to value v"
   - Example: do(Check = true) for adding a bounds check
   - Example: do(len = min(len, 256)) for clamping length

4. **Compute Effect on V_bug:**
   - Using the SCM structural equations, determine how the intervention affects V_bug
   - Substitute the intervened values into the equation for V_bug
   - Simplify to show V_bug becomes false (or remains false)

5. **Analyze Causal Paths:**
   - Which causal paths from E_bug are disrupted by the patch?
   - Which causes in E_bug are addressed vs. ignored?
   - Are there residual causes that could still trigger V_bug?

6. **Generate Explanation:**
   - **Formal:** Mathematical expression of the intervention and its effect
   - **Natural Language:** Human-readable description
   - **Verification Properties:** Assertions that must hold in P'

**Output:** Formal Patch Explanation E_patch

```python
E_patch = {
    # Code changes
    "code_diff": {
        "added_lines": [{"line": L, "code": "..."}],
        "modified_lines": [...],
        "deleted_lines": [...]
    },
    
    # Causal intervention
    "intervention": {
        "formal": "do(Variable = value)",
        "affected_variables": ["Variable₁", "Variable₂", ...],
        "description": "The patch sets [variable] to [value] by [mechanism]"
    },
    
    # Effect on vulnerability
    "effect_on_Vbug": {
        "before": "V_bug = φ(X₁, ..., Xₙ)",
        "after": "V_bug = φ'(X₁, ..., Xₙ) = false",
        "reasoning": "Because [intervention], the condition [φ] is now unsatisfiable"
    },
    
    # Causal path analysis
    "addressed_causes": ["Cause₁", "Cause₂", ...],
    "unaddressed_causes": ["Cause₃", ...],  # Should be empty or justified
    "disrupted_paths": ["path 1: intervention breaks link X → Y", ...],
    
    # Natural language
    "summary": "The patch [action] which ensures [property]",
    "mechanism": "Specifically, [detailed explanation]",
    "consequence": "As a result, the vulnerability cannot manifest because [reason]",
    
    # Verification properties
    "postconditions": [
        "Property P₁ holds at location L₁",
        "V_bug is unreachable under all inputs"
    ],
    "new_assertions": [
        "assert(P₁) at line L₁",
        ...
    ]
}
```

**Example for Buffer Overflow Patch:**

```python
E_patch = {
    "code_diff": {
        "added_lines": [
            {"line": 19, "code": "if (len > 256) {"},
            {"line": 20, "code": "    len = 256;"},
            {"line": 21, "code": "}"}
        ]
    },
    
    "intervention": {
        "formal": "do(len = min(len, 256))",
        "affected_variables": ["len"],
        "description": 
            "The patch clamps len to a maximum of 256 by adding a conditional "
            "that reduces len when it exceeds the buffer size"
    },
    
    "effect_on_Vbug": {
        "before": "V_overflow = (len > 256) ∧ (¬Check)",
        "after": "V_overflow = (256 > 256) ∧ (¬Check) = false ∧ (¬Check) = false",
        "reasoning": 
            "With the intervention do(len = min(len, 256)), the value of len "
            "at line 42 is guaranteed to be ≤ 256. Therefore, (len > 256) is "
            "always false, making the entire conjunction false."
    },
    
    "addressed_causes": ["len > 256"],
    "unaddressed_causes": [],
    "disrupted_paths": [
        "user_input → len → (len > 256) → V_overflow: "
        "The path is broken because len is now bounded by 256"
    ],
    
    "summary": 
        "The patch prevents buffer overflow by clamping the input length to "
        "the buffer capacity",
    
    "mechanism": 
        "At line 19-21, the patch adds a conditional check. If the computed "
        "length exceeds 256 bytes, it is reduced to exactly 256. This ensures "
        "that when memcpy executes at line 42, the copy size never exceeds "
        "the buffer allocation.",
    
    "consequence": 
        "As a result, the vulnerability condition (len > 256) ∧ (¬Check) can "
        "never be satisfied because len ≤ 256 is now guaranteed. The buffer "
        "overflow cannot occur.",
    
    "postconditions": [
        "len ≤ 256 at line 42 (before memcpy)",
        "V_overflow is unreachable for all user inputs"
    ],
    
    "new_assertions": [
        "assert(len <= 256) at line 22 (after clamping, before memcpy)"
    ]
}
```

**Key Advantage:** By generating separate bug and patch explanations, we can now **verify their consistency** - does the patch actually address the identified cause?

---

## Phase 3: Dual Verification

Phase 3 performs three complementary types of verification to ensure both correctness and explanation validity.

### Step 3.1: Consistency Verification ⭐ NEW

**Input:** Bug Explanation E_bug, Patch Explanation E_patch

**Purpose:** Verify that the patch explanation is consistent with and addresses the bug explanation

**Checks:**

**Check 1: Causal Coverage**
```
For each cause Cᵢ identified in E_bug:
    Is Cᵢ ∈ E_patch.addressed_causes?
    
If any Cᵢ ∉ addressed_causes:
    If Cᵢ ∈ E_patch.unaddressed_causes with justification:
        Verify justification (e.g., "Cᵢ is not attackable")
    Else:
        FAIL: Patch does not address cause Cᵢ
```

**Example:**
```
E_bug identifies causes: [(len > 256), ¬Check]
E_patch addresses: [len > 256] by clamping

Check: Is ¬Check addressed?
Answer: Not directly, but justified because len is now safe
Verdict: PASS (with justification)
```

**Check 2: Intervention Validity**
```
E_patch claims intervention: do(Variable = value)

Verify in code diff:
    1. Is there code that sets Variable to value?
    2. Is this on all paths to V_bug location?
    3. Can the intervention be bypassed?

If intervention is not properly implemented:
    FAIL: Patch explanation claims intervention that doesn't exist
```

**Example:**
```
E_patch claims: do(len = min(len, 256))
Code diff shows: if (len > 256) len = 256;

Verify:
    ✓ This implements min(len, 256)
    ✓ Occurs before line 42 on all paths
    ✓ Cannot be bypassed
Verdict: PASS
```

**Check 3: Logical Consistency**
```
E_bug: V_bug ⟺ φ_bug(X₁, ..., Xₙ)
E_patch: After intervention, V_bug = φ'_bug = false

Verify using logic solver:
    Substitute E_patch.intervention into φ_bug
    Simplify the resulting expression
    Check if result is logically false

If φ'_bug ≠ false:
    FAIL: Patch does not logically eliminate V_bug
```

**Example:**
```
E_bug: V_overflow = (len > 256) ∧ (¬Check)
E_patch: do(len = min(len, 256))

Substitute:
    V_overflow = (min(len, 256) > 256) ∧ (¬Check)
                = (256 > 256) ∧ (¬Check)    [worst case: len was ∞]
                = false ∧ (¬Check)
                = false

Verdict: PASS (V_overflow is logically false)
```

**Check 4: Completeness**
```
For each causal path P in E_bug:
    Is P ∈ E_patch.disrupted_paths?
    
If any path is not disrupted:
    Generate test case exercising that path
    If V_bug is reachable via that path in P':
        FAIL: Patch is incomplete
```

**Output:** Consistency report indicating PASS or FAIL with specific reasons

### Step 3.2: Symbolic Verification

**Input:** Patched program P', Bug Explanation E_bug, Patch Explanation E_patch

**Purpose:** Use program analysis tools to verify that V_bug is unreachable in P'

**Method 1: Symbolic Execution**

```
1. Load patched program P' into symbolic executor (e.g., KLEE, angr)

2. Set initial constraints from E_bug.preconditions:
   - Mark user-controlled inputs as symbolic
   - Assume attacker capabilities (e.g., arbitrary input values)

3. Add path constraint from E_bug.formal_condition:
   - Assume φ_bug(X₁, ..., Xₙ) is satisfiable
   - This represents the "vulnerability trigger condition"

4. Attempt to reach E_bug.vulnerable_location:
   - Symbolically execute all paths
   - Check if any path can satisfy φ_bug and reach the vulnerable operation

5. Result:
   - If path found: FAIL (counterexample: vulnerability still reachable)
   - If no path found: PASS (vulnerability provably unreachable)
   - If timeout: INCONCLUSIVE (require manual review)
```

**Example:**
```python
# Symbolic execution setup for buffer overflow

# 1. Make user_input symbolic
user_input = symbolic_value("user_input", string)

# 2. Add precondition: user can provide arbitrary input
assume(len(user_input) >= 0)  # any length possible

# 3. Add bug condition: try to trigger overflow
assume(len(user_input) > 256)  # E_bug says this causes overflow

# 4. Execute P' and try to reach line 42 with len > 256
result = symbolic_execute(patched_process_input, user_input)

# 5. Check if line 42 is reachable with len > 256
if result.can_reach(line=42, constraint="len > 256"):
    print("FAIL: Overflow still possible with input:", result.counterexample)
else:
    print("PASS: Overflow provably prevented")
```

**Method 2: Assertion Injection**

```
1. Instrument P' with assertions from E_patch.new_assertions:
   For each assertion A:
       Insert "assert(A)" at specified location in P'

2. Run bounded model checker (e.g., CBMC) or verifier:
   Try to find execution that violates any assertion

3. Result:
   - If assertion violated: FAIL (patch doesn't guarantee safety)
   - If all assertions hold: PASS (safety properties verified)
```

**Example:**
```c
int process_input_instrumented(char *user_input) {
    char buffer[256];
    int len = strlen(user_input);
    
    if (len > 256) {
        len = 256;
    }
    
    // Assertion from E_patch
    assert(len <= 256);  // Must hold before memcpy
    
    memcpy(buffer, user_input, len);
    return process(buffer);
}

// Run CBMC
// $ cbmc process_input_instrumented.c --unwind 10
// If CBMC finds no violation: PASS
```

**Method 3: SMT Solving**

```
1. Extract verification condition (VC) from E_patch.postconditions:
   VC = "For all valid inputs, vulnerability condition is false"
   
2. Formulate as SMT formula:
   ∀ inputs in ValidInputs: ¬φ_bug(inputs)
   
3. Negate and check satisfiability:
   ∃ inputs: φ_bug(inputs) is satisfiable?
   
4. Result:
   - If SAT: FAIL (found counterexample)
   - If UNSAT: PASS (no violation possible)
```

**Output:** Verification report indicating whether V_bug is provably unreachable

### Step 3.3: Regression and New Bug Detection

**Input:** Original program P, Patched program P'

**Purpose:** Ensure the patch doesn't break functionality or introduce new vulnerabilities

**Method 1: Test Suite Execution**
```
If test suite available:
    Run all tests on P'
    Compare results with P's test results
    
    If new test failures:
        WARN: Potential functionality regression
        Analyze: Does patch over-restrict valid inputs?
```

**Method 2: Fuzzing with Sanitizers**
```
1. Instrument P' with sanitizers:
   - AddressSanitizer (ASan): memory errors
   - UndefinedBehaviorSanitizer (UBSan): undefined behavior
   - MemorySanitizer (MSan): uninitialized memory

2. Fuzz P' with diverse inputs:
   - Valid inputs (should process normally)
   - Invalid inputs (should be rejected safely)
   - Edge cases (boundary values)

3. Monitor for sanitizer reports:
   If new errors detected:
       FAIL: Patch introduced new bug
       Report: Type and location of new bug
```

**Method 3: Differential Testing**
```
For the same set of inputs:
    Run P and P' side-by-side
    Compare outputs (except for rejected malicious inputs)
    
If outputs differ on valid inputs:
    WARN: Behavioral change detected
    Require manual review
```

**Output:** Regression report indicating any functional issues or new bugs

### Step 3.4: Verification Summary

After all checks, generate a comprehensive verification report:

```python
verification_report = {
    "consistency_check": {
        "status": "PASS" | "FAIL",
        "causal_coverage": "all causes addressed",
        "intervention_validity": "intervention properly implemented",
        "logical_consistency": "V_bug logically eliminated",
        "completeness": "all causal paths disrupted"
    },
    
    "symbolic_verification": {
        "status": "PASS" | "FAIL" | "INCONCLUSIVE",
        "method": "KLEE symbolic execution",
        "result": "V_bug unreachable under all inputs",
        "execution_time": "45 seconds",
        "paths_explored": 1247
    },
    
    "regression_check": {
        "status": "PASS" | "WARN",
        "test_results": "127/127 tests passed",
        "fuzzing": "no new crashes in 10M executions",
        "sanitizer_reports": "clean"
    },
    
    "overall_verdict": "VERIFIED" | "FAILED" | "REQUIRES_REVIEW",
    "confidence": "HIGH" | "MEDIUM" | "LOW"
}
```

### Step 3.5: Iterative Refinement

If verification fails:

```
1. Analyze failure mode:
   - Consistency failure → patch doesn't address stated cause
   - Symbolic verification failure → counterexample found
   - Regression failure → functionality broken

2. Generate feedback for LLM:
   If consistency failure:
       "Your patch addressed [X] but ignored [Y]. 
        E_bug requires addressing both.
        Revise to also handle [Y]."
   
   If counterexample found:
       "Symbolic execution found input [counterexample] that still triggers
        vulnerability via path [P]. Your patch is incomplete.
        Ensure path [P] is also protected."
   
   If regression:
       "Patch broke test [T]. The change at [location] is too restrictive.
        Revise to allow valid input [I] while still blocking vulnerability."

3. Return to Step 2.1 with enhanced prompt including failure information

4. Repeat until verification passes or max iterations reached
```

**Output:** Either a verified patch with dual explanations, or failure report with detailed diagnostics

---

## Complete Workflow Example

Let's trace a complete example to show all components working together:

### Example: CVE-2024-XXXX Buffer Overflow

**Vulnerable Code:**
```c
void handle_request(char *request) {
    char buffer[512];
    int len = strlen(request);
    memcpy(buffer, request, len);  // Line 42: VULNERABLE
    process_buffer(buffer);
}
```

### Phase 1 Output:

**E_bug:**
```
{
    "formal_condition": "V_overflow ⟺ (len > 512) ∧ (¬Check)",
    
    "description": 
        "Buffer overflow occurs when request length exceeds 512 bytes AND "
        "no bounds check is performed before memcpy at line 42",
    
    "intervention_options": [
        "Option 1: Add bounds check before memcpy (set Check = true)",
        "Option 2: Clamp len to 512 (ensure len ≤ 512)",
        "Option 3: Use strncpy with size limit"
    ],
    
    "safety_property": "∀request: ¬V_overflow(request)"
}
```

### Phase 2 Output:

**Patched Code:**
```c
void handle_request(char *request) {
    char buffer[512];
    int len = strlen(request);
    
    // PATCH: Bounds check
    if (len > sizeof(buffer)) {
        fprintf(stderr, "Request too large\n");
        return;  // Reject oversized requests
    }
    
    memcpy(buffer, request, len);
    process_buffer(buffer);
}
```

**E_patch:**
```
{
    "intervention": {
        "formal": "do(Check = true)",
        "description": "Patch adds bounds check that exits function when len > 512"
    },
    
    "effect_on_Vbug": {
        "before": "V_overflow = (len > 512) ∧ (¬Check)",
        "after": "V_overflow = (len > 512) ∧ (¬true) = (len > 512) ∧ false = false",
        "reasoning": "Check variable is now true, making conjunction false"
    },
    
    "addressed_causes": ["¬Check"],
    "disrupted_paths": [
        "user_input → len → (len > 512) → V_overflow: "
        "Path blocked because function exits when len > 512"
    ]
}
```

### Phase 3 Verification:

**Consistency Check:**
```
✓ Causal Coverage: ¬Check is addressed by adding check
✓ Intervention Validity: Code adds "if (len > sizeof(buffer)) return"
✓ Logical Consistency: V_overflow = false after do(Check = true)
✓ Completeness: Both causes [(len > 512), ¬Check] handled
   - ¬Check: directly addressed by new check
   - len > 512: function exits, so line 42 unreachable when len > 512

Result: PASS
```

**Symbolic Verification:**
```python
# Setup
request = symbolic_string("request")
assume(len(request) > 512)  # Try to trigger overflow

# Execute patched function
result = symbolic_execute(handle_request_patched, request)

# Check if line 42 reachable
if result.can_reach(line=42):
    print("FAIL")
else:
    print("PASS: Line 42 unreachable when len > 512")

Result: PASS (early return prevents reaching line 42)
```

**Regression Check:**
```
Test Suite: 45/45 tests pass
Fuzzing: 10M inputs, no crashes
Sanitizers: Clean

Result: PASS
```

**Final Verdict:** 
```
✅ VERIFIED
Confidence: HIGH
Certificate: {E_bug, E_patch, verification_report}
```

---

## Key Innovations Summary

This improved methodology provides several key innovations over the current draft:

1. **Pre-hoc vs Post-hoc:** Formal bug specification is generated BEFORE patching, enabling theory-guided generation rather than post-hoc rationalization

2. **Dual Explanations:** Separate formal explanations for bug cause and patch effect, enabling consistency checking

3. **Stronger LLM Guidance:** LLM receives precise formal specification (e.g., "V_bug = (len > N) ∧ (¬Check)") rather than vague hints

4. **Consistency Verification:** New checking layer to ensure patch explanation addresses bug explanation

5. **Completeness Analysis:** Explicit checking that all identified causes are handled

6. **Theory-Guided Generation:** The formal model drives patch generation, not just verification

This transforms PatchScribe from a "patch verification tool" into a "theory-guided patch generation and verification framework" - a much stronger contribution for a top-tier security conference.