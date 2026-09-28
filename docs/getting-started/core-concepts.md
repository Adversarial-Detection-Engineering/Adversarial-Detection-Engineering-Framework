# Core Concepts

Essential terminology and concepts for understanding the ADE Framework.

## Detection Rule Components

### Detection Rule
A repeatedly running hypothesis test that examines records (logs, telemetry, events) against a set of conditions.

**Components:**
- **Scope:** Human-readable purpose (description, MITRE mappings, metadata)
- **Detection Logic:** Machine-readable implementation (query, conditions, filters, schedule)

### Scope
The **intended purpose** of a detection rule. Includes:
- Rule description
- MITRE ATT&CK technique mappings
- Author notes and references
- Any metadata describing *what* the rule aims to detect

**Example:**
> "Detect when PowerShell scripts download files from the internet"

### Detection Logic
The **actual implementation** that performs the hypothesis test. Includes:
- Query syntax (KQL, EQL, SQL, etc.)
- Field conditions and filters
- Boolean logic (AND/OR/NOT)
- Schedule, lookback period, aggregations
- Suppression rules

**Example:**
```yaml
Data|contains: '.DownloadFile('
OR
Data|contains: '.DownloadString('
```

## Hypothesis Testing Framework

### Null Hypothesis (H₀)
Conditions are **not met** → Record is benign (negative)

### Alternative Hypothesis (H₁)
Conditions **are met** → Record is suspicious (positive)

**Decision:**
- If conditions met: Reject H₀ → **Predicted Positive** (alert fired)
- If conditions not met: Fail to reject H₀ → **Predicted Negative** (no alert)

### Confusion Matrix

|  | **Actually Malicious** | **Actually Benign** |
|:--|:--:|:--:|
| **Alert Fired** | True Positive ✅ | False Positive ⚠️ |
| **No Alert** | **False Negative** 🚨 | True Negative ✅ |

**ADE focuses on:** False Negatives (missed detections)

## Detection Logic Bugs

### Bug Definition
A **flaw, error, or fault** in detection logic that causes unexpected, incorrect, or unintended behavior.

### False Negative Generating Bug
A bug exists when **both** conditions are satisfied:
1. Attacker behavior/action falls within the detection rule's **scope**, AND
2. The **detection logic** didn't capture this behavior during the hypothesis test

**Result:** Record is classified as **benign (negative)** but its ground truth is **True Positive** → **False Negative**

### Rule Bypass
When there is **prior knowledge** of a bug in detection logic, coupled with a working method to produce a False Negative by abusing this bug.

**Components:**
- Known bug in detection logic
- Reproducible technique to exploit the bug
- Results in **no detection** for in-scope malicious activity

## ADE Taxonomy Categories

### ADE1: Reformatting in Actions
**Attacker manipulates** the format/representation of data being logged.

**Core mechanism:** String matching on attacker-controlled fields

**Example:** `"Download" + "File"` bypasses detection for `.DownloadFile(`

### ADE2: Omit Alternatives
**Rule author omits** alternative methods that achieve the same malicious outcome.

**Core mechanism:** Incomplete enumeration of techniques within scope

**Example:** Only detecting `curl`, missing `wget`, `Invoke-WebRequest`, BITS

### ADE3: Context Development
**Attacker shapes contextual data** that detection logic depends on.

**Core mechanism:** Preparatory actions that poison aggregations, timing, or process metadata (including spoofed parent lineage), or data volume that pushes a record past a query-engine limit

**Example:** Cloning `/usr/bin/wget` to `/tmp/foo` bypasses process name checks

### ADE4: Logic Manipulation
**Attacker exploits Boolean logic flaws** in detection conditions.

**Core mechanism:** Manipulating inputs to flip AND/OR/NOT evaluations, or conditions that silently fail because a field is misnamed, unavailable, or null

**Example:** De Morgan's Law violations allowing negation inversion

## Key Terms

### Ground Truth
The **actual** classification of an event:
- **Ground Truth Positive:** Event is actually malicious
- **Ground Truth Negative:** Event is actually benign

Independent of what the detection rule decides.

### Predicted Classification
What the **detection rule** determines:
- **Predicted Positive:** Rule fires an alert
- **Predicted Negative:** Rule does not fire

May or may not match ground truth.

### Hypothesis Test
The evaluation of conditions specified in detection logic to determine if the Null Hypothesis should be rejected.

**Process:**
1. Ingest record (log/event/telemetry)
2. Apply detection logic conditions
3. Evaluate Boolean result
4. Reject H₀ (alert) or Fail to reject H₀ (no alert)

### Scope Mismatch
When detection logic **does not fully implement** the intended scope, creating coverage gaps.

**Example:**
- **Scope:** "Detect file downloads via PowerShell"
- **Logic:** Only checks for `.DownloadFile(`
- **Mismatch:** Omits `.DownloadString(`, `Invoke-WebRequest`, etc.

### Robust Detection
Detection logic that:
- ✅ Minimizes reliance on mutable indicators
- ✅ Focuses on behavioral patterns
- ✅ Accounts for technique variations
- ✅ Tested against known bypasses

**vs. Threat Intelligence Detection:**
- ⚠️ Specific to known malware/campaigns
- ⚠️ Relies on exact indicators (filenames, hashes, strings)
- ⚠️ Short-lived effectiveness

## Behavioral Concepts

### Behavioral Steering
Attacker adapts activity by **stacking multiple rule bypasses** during a kill chain.

**Impact:**
- No longer a single point of failure
- Multiple blind spots create evasion pathway
- Defenders lose contextual understanding (no alerts from multiple stages)

**Example:**
1. Bypass initial access detection (ADE2-01)
2. Bypass persistence detection (ADE3-01)
3. Bypass lateral movement detection (ADE1-01)
4. Complete kill chain without triggering any alerts

### Evasion
Undetected malicious activity due to bug abuse.

**Impact:**
- Rule never fires
- Defenders falsely believe coverage exists
- Attackers operate in blind spot

### Context Development
Attacker takes **preparatory steps** to manipulate contextual data that detection logic relies on.

**Differs from primary evasion:**
- Not changing the malicious action itself
- Shaping the surrounding environment/context
- Often appears benign until malicious action occurs

**Example:**
1. Clone binary (preparatory, seems benign)
2. Use cloned binary for malicious action (in-scope, but not detected)

## Detection Engineering Lifecycle Integration

### Where ADE Fits

**Traditional Phases:**
1. Design → Create detection rule
2. Deploy → Put into production
3. Operate → Monitor alerts
4. **Improve** → **← ADE applies here**

**ADE Enhancement:**
- **Design Phase:** Apply ADE during rule creation
- **Pre-deployment:** Test for known bug classes
- **Improvement Phase:** Systematically identify and fix bugs
- **Documentation:** Record known limitations

## Comparison to Related Frameworks

| Framework | ADE Relationship |
|:----------|:-----------------|
| **MITRE ATT&CK** | ADE explains *why detection fails* for ATT&CK techniques |
| **MITRE CAR** | ADE provides bug taxonomy for CAR analytics |
| **Sigma/YARA** | ADE analyzes *semantic bugs* regardless of syntax |
| **Detection Engineering Lifecycle** | ADE is the *reasoning framework* for improvement phase |

## Success Criteria

**A detection rule is ADE-hardened when:**

- ✅ All ADE taxonomy categories have been evaluated
- ✅ Known bypasses have been tested
- ✅ Bugs have been fixed or documented as limitations
- ✅ Rule focuses on behavioral patterns over exact matches
- ✅ Regular re-evaluation scheduled as threats evolve

## Practical Application

**Before deploying a rule, ask:**

1. **ADE1:** Can attackers manipulate strings I'm matching?
2. **ADE2:** Have I enumerated ALL methods that achieve this outcome?
3. **ADE3:** Can attackers shape context (process names, timing, aggregations, parent lineage)? Can data volume push the record past a join, subsearch, group, or sort limit?
4. **ADE4:** Are my Boolean logic conditions sound? Any De Morgan's Law issues? Does every field exist and populate on every backend the rule runs on?

**If unsure on any:** Apply full ADE analysis before deployment.

## Next Steps

**Now that you understand core concepts:**

1. **[Quick Start Guide](quick-start.md)** - Apply ADE to a real detection rule
2. **[Taxonomy Overview](../taxonomy/overview.md)** - Explore all bug categories
3. **[Bug Likelihood Test](../guides/bug-likelihood-test.md)** - Quick assessment tool

**Deep dive by category:**
- [ADE1 - Reformatting in Actions](../taxonomy/ade1-reformatting-in-actions.md)
- [ADE2 - Omit Alternatives](../taxonomy/ade2-omit-alternatives.md)
- [ADE3 - Context Development](../taxonomy/ade3-context-development.md)
- [ADE4 - Logic Manipulation](../taxonomy/ade4-logic-manipulation.md)

---

**Questions?**
- [Introduction](introduction.md) - ADE overview
- [Examples](../../examples/) - Real-world bug analysis
- [Theory](../theory/detection-logic-bugs.md) - Formal foundations
