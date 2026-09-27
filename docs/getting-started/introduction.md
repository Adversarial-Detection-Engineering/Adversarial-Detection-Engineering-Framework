# Introduction to Adversarial Detection Engineering (ADE)

## What Is ADE?

**Adversarial Detection Engineering (ADE)** is the discipline of reasoning about **False Negatives in detection rules on a per-rule basis**. These False Negatives result from **Detection Logic Bugs** - mismatches between what a detection rule is *intended* to identify and how its logic *actually* implements that intention.

## The Problem ADE Solves

### Traditional Detection Engineering Approach

**React to failures:**
1. Deploy detection rule
2. Wait for real-world attack
3. Discover False Negative
4. Fix the rule
5. Repeat

**Problem:** Attackers have already bypassed your defenses.

### ADE Framework Approach

**Proactive analysis:**
1. Write detection rule
2. **Apply ADE taxonomy** to identify potential logic bugs
3. **Test bypasses** before deployment
4. **Fix bugs** preemptively
5. Deploy hardened rule

**Advantage:** Get ahead of False Negatives before threat actors abuse them.

## Core Concept: Detection Logic Bugs

### What Is a Detection Logic Bug?

A **Detection Logic Bug** is a flaw in detection rule logic that causes the rule to miss malicious activity that falls within its intended scope.

**Components:**
- **Scope:** What the rule is *intended* to detect (documented in description, MITRE ATT&CK mappings, etc.)
- **Detection Logic:** The *actual implementation* (query, conditions, filters)
- **Bug:** When scope and logic don't align, creating blind spots

### Example

**Rule Intent (Scope):**
> "Detect when PowerShell downloads a file from the internet"

**Detection Logic:**
```yaml
detection:
    condition: Data|contains: '.DownloadFile('
```

**Bug:**
The logic only checks for the exact substring `.DownloadFile(`, but PowerShell allows:
- String concatenation: `"Download" + "File"`
- Reflection: `GetType().InvokeMember("DownloadFile", ...)`
- Alternative methods: `.DownloadString(`, `Invoke-WebRequest`, etc.

**Result:** Attacker can download files using methods within scope but outside detection logic → **False Negative**

## How ADE Mirrors Attacker Thinking

ADE embeds an **attacker's mental model** into detection engineering:

**Attacker question:** *"How can I achieve my objective without triggering this detection?"*

**ADE question:** *"What variations would cause this rule's detection logic to miss what it was intended to catch?"*

Both ask the same fundamental question from different perspectives.

## The ADE Framework Components

### 1. Theory Foundation

[Detection Logic Bug Theory](../theory/detection-logic-bugs.md) provides:
- Formal definitions of detection rules, scope, and logic
- Hypothesis testing framework for detections
- Theory of how bugs create False Negatives
- Concept of Rule Bypasses

### 2. Formal Taxonomy

[Detection Logic Bug Taxonomy](../taxonomy/overview.md) classifies bugs into **4 major categories** and **15 subcategories**:

```
🌳 ADE1 – Reformatting in Actions
    ├─ ADE1-01 Substring Manipulation
    └─ ADE1-02 Normalization Asymmetry

🌳 ADE2 – Omit Alternatives
    ├─ ADE2-01 Method/Binary
    ├─ ADE2-02 Versioning
    ├─ ADE2-03 Locations
    └─ ADE2-04 File Types

🌳 ADE3 – Context Development
    ├─ ADE3-01 Process Cloning
    ├─ ADE3-02 Aggregation Hijacking
    ├─ ADE3-03 Timing and Scheduling
    ├─ ADE3-04 Event Fragmentation
    └─ ADE3-05 Lineage Spoofing

🌳 ADE4 – Logic Manipulation
    ├─ ADE4-01 Gate Inversion
    ├─ ADE4-02 Conjunction Inversion
    ├─ ADE4-03 Incorrect Expression
    └─ ADE4-04 Field Mismapping & Semantics
```

### 3. Real-World Examples

Each taxonomy category includes **concrete examples** of bugs found in:
- [Sigma](https://github.com/SigmaHQ/sigma) rules
- [Microsoft Sentinel](https://github.com/Azure/Azure-Sentinel) analytics
- [Elastic Security](https://github.com/elastic/detection-rules) SIEM & EDR rules

### 4. Practical Tools

[Bug Likelihood Test](../guides/bug-likelihood-test.md): Quick checklist to assess whether a rule likely contains ADE-class bugs

## Who Should Use ADE?

### Detection Engineers
- **Proactively** identify logic weaknesses before deployment
- **Systematically** review existing detection rules
- **Document** known limitations and coverage gaps
- **Prioritize** rule improvements based on bug severity

### Security Researchers
- **Formalize** bypass techniques with structured taxonomy
- **Contribute** new bug categories as they're discovered
- **Analyze** vendor detection capabilities objectively

### Red Teams
- **Understand** detection logic weaknesses to test blue team capabilities
- **Develop** realistic evasion scenarios for exercises
- **Provide** actionable feedback to detection engineers

### SOC/Threat Hunters
- **Investigate** why attacks weren't detected
- **Identify** coverage gaps in existing tooling
- **Recommend** rule improvements based on ADE analysis

## What Makes ADE Unique?

**Compared to existing frameworks:**

| Framework | Focus | ADE Unique Value |
|:----------|:------|:----------------|
| MITRE ATT&CK | Attack techniques | ADE: Logic-level **why detections fail** for each technique |
| MITRE CAR | Detection analytics | ADE: Formal **bug taxonomy** for analytics |
| Detection Engineering Lifecycle | Process/workflow | ADE: **Improvement phase** reasoning framework |
| Sigma/YARA Rules | Rule syntax | ADE: **Semantic bug analysis** across all query languages |

**ADE is the only framework** that:
1. ✅ Provides formal theory of detection logic bugs
2. ✅ Creates comprehensive taxonomy of bug classes
3. ✅ Documents reproducible bypasses with concrete examples
4. ✅ Enables proactive False Negative reasoning

## Quick Start

**New to ADE? Start here:**

1. **[Core Concepts](core-concepts.md)** - Understand fundamental terminology
2. **[Quick Start Guide](quick-start.md)** - Apply ADE to your first detection rule
3. **[Taxonomy Overview](../taxonomy/overview.md)** - Explore the bug categories
4. **[Examples](../../examples/)** - See real-world bugs and bypasses

## ADE in Practice

### Before ADE
```
Rule: Detect PowerShell downloads
Logic: CommandLine contains "DownloadFile"
Result: Deployed → Bypassed by string concatenation → Incident → Fix
```

### With ADE
```
Rule: Detect PowerShell downloads
Logic: CommandLine contains "DownloadFile"
ADE Analysis:
  - ADE1-01: Substring manipulation possible
  - ADE2-01: Alternative methods/binaries (DownloadString, Invoke-WebRequest)
Testing: Bypass confirmed with string concatenation
Fix: Use behavioral detection (network + file write + process context)
Result: Deployed hardened rule → No known bypasses
```

## Success Metrics

**ADE helps you:**
- ⬇️ **Reduce** False Negative rate in production detections
- ⬆️ **Increase** attacker cost of evasion
- 📊 **Measure** detection quality objectively
- 🎯 **Prioritize** rule improvements systematically
- 📝 **Document** known limitations transparently

## Next Steps

**Continue learning:**
- [Core Concepts →](core-concepts.md) - Master ADE terminology
- [Quick Start →](quick-start.md) - Apply ADE to a detection rule
- [Bug Likelihood Test →](../guides/bug-likelihood-test.md) - Rapid rule assessment

**Explore the taxonomy:**
- [ADE1 - Reformatting in Actions](../taxonomy/ade1-reformatting-in-actions.md)
- [ADE2 - Omit Alternatives](../taxonomy/ade2-omit-alternatives.md)
- [ADE3 - Context Development](../taxonomy/ade3-context-development.md)
- [ADE4 - Logic Manipulation](../taxonomy/ade4-logic-manipulation.md)

---

**Questions? Feedback?**
- Report issues: [GitHub Issues](https://github.com/NikolasBielski/Adversarial-Detection-Engineering-Framework/issues)
- Contribute: See [CONTRIBUTING.md](../../CONTRIBUTING.md)
