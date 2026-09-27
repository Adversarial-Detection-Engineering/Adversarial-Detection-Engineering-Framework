# Detection Logic Bug Taxonomy

The following classes are for bugs found in multiple rulesets (see below table). The taxonomy will continue to grow and expand as more are found.

Rulesets currently informing the taxonomy:

| Integration/Record Source | SIGMA    | Microsoft Sentinel | Elastic Security SIEM | Elastic Security Endgame EDR |
|:-----------------------|:---------|:------------|:------------|:------------|
| AWS (CloudTrail)                        | ❌  | ❌           | ❌                      | ❌                            |
| Windows PowerShell Script Block Logging | ❌  | ❌           | ❌                      | ❌                            |
| Linux                                  | ❌  | ✅           | ❌                      | ❌                            |
| Azure                                  | 🟡 TBC | ❌          | ❌                      | N/A                           |
| O365                                   | 🟡 TBC | 🟡 TBC          | ❌                      | N/A                           |
| LLM                                    | 🟡 TBC | 🟡 TBC          | ❌                      | N/A                           |
| macOS                                  | 🟡 TBC | 🟡 TBC          | ❌                      | ❌                            |
| Okta                                   | 🟡 TBC | 🟡 TBC          | ❌                      | N/A                           |
---
✅ = Unaffected (No logic bugs found)
❌ = Affected  (Logic bugs found)
🟡 TBC = To Be Confirmed (Unassessed) 


Other solutions and their rulesets have not yet been reviewed as part of creating the Detection Logic Bug taxonomy. The taxonomy is subject to expand based on newly seen examples, so is considered a living taxonomy.

## ADE Detection Logic Bug Taxonomy

The full taxonomy consists of 4 categories, and 15 sub-categories
- Each category is given a label, such as ADE1, ADE2, ...., ADE4.
- Subcategories are labels with their subcategory number. E.g ADE1-02, ADE3-03 This is for mappings to rules.

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

## Category Summaries

### [ADE1 - Reformatting in Actions](ade1-reformatting-in-actions.md)

Reformatting in Actions occurs when a detection rule relies on **string match conditions**, and an attacker can manipulate the collected logs such that the match fails. This has been widely exploited by threat actors for years and still appears in modern SIEM rules.

**Subcategory:**
- **[ADE1-01 Substring Manipulation](ade1-reformatting-in-actions.md#ade1-01-substring-manipulation)**: Attacker alters or obfuscates input data to bypass substring matches
- **[ADE1-02 Normalization Asymmetry](ade1-reformatting-in-actions.md#ade1-02-normalization-asymmetry)**: Attacker leverages inconsistent normalization across detection branches so that logically identical entities fail equality checks


---

### [ADE2 - Omit Alternatives](ade2-omit-alternatives.md)

An alternative method/binary, version, location, or file type is available within the attack scope, but has been omitted from the detection logic, resulting in a False Negative.

**Subcategories:**
- **[ADE2-01 Method/Binary](ade2-omit-alternatives.md#ade2-01-omit-alternatives---methodbinary)**: Alternative methods/binaries achieving same effect are omitted
- **[ADE2-02 Versioning](ade2-omit-alternatives.md#ade2-02-omit-alternatives---versioning)**: Software/OS version differences not accounted for
- **[ADE2-03 Locations](ade2-omit-alternatives.md#ade2-03-omit-alternatives---locations)**: Alternative file paths or locations ignored
- **[ADE2-04 File Types](ade2-omit-alternatives.md#ade2-04-omit-alternatives---file-type)**: Alternative file extensions/formats omitted

---

### [ADE3 - Context Development](ade3-context-development.md)

Attacker takes additional steps to **manipulate or poison contextual data** used by detection logic, causing in-scope activity to bypass rule conditions. Rather than changing the primary action, the attacker shapes the surrounding context.

**Subcategories:**
- **[ADE3-01 Process Cloning](ade3-context-development.md#ade3-01-context-development---process-cloning)**: Clone/rename binaries to bypass process name checks
- **[ADE3-02 Aggregation Hijacking](ade3-context-development.md#ade3-02-context-development---aggregation-hijacking)**: Influence aggregations, thresholds, or baselines
- **[ADE3-03 Timing and Scheduling](ade3-context-development.md#ade3-03-context-development---timing-and-scheduling)**: Space actions to avoid time-based constraints
- **[ADE3-04 Event Fragmentation](ade3-context-development.md#ade3-04-context-development---event-fragmentation)**: Shell operators split commands across multiple events
- **[ADE3-05 Lineage Spoofing](ade3-context-development.md#ade3-05-context-development---lineage-spoofing)**: Falsify the logged parent process that parent-child rules and exclusions trust

---

### [ADE4 - Logic Manipulation](ade4-logic-manipulation.md)

Attacker analyzes detection logic as Boolean conditions and manipulates inputs or filters to invert, bypass, or neutralize the rule outcome.

**Subcategories:**
- **[ADE4-01 Gate Inversion](ade4-logic-manipulation.md#ade4-01-logic-manipulation---gate-inversion)**: Exploit NOT clauses and De Morgan's Law violations
- **[ADE4-02 Conjunction Inversion](ade4-logic-manipulation.md#ade4-02-logic-manipulation---conjunction-inversion)**: Flip AND conditions with poisoned data
- **[ADE4-03 Incorrect Expression](ade4-logic-manipulation.md#ade4-03-logic-manipulation---incorrect-expression)**: Logic construction errors (AND vs OR)
- **[ADE4-04 Field Mismapping & Semantics](ade4-logic-manipulation.md#ade4-04-logic-manipulation---field-mismapping--semantics)**: Wrong, unavailable, or misunderstood fields make conditions silently fail or invert

---

## Quick Reference

**By Attack Vector:**
- String manipulation → ADE1-01
- Missing methods/binaries → ADE2-01
- Version drift → ADE2-02
- Process renaming → ADE3-01
- Threshold evasion → ADE3-02
- Timing manipulation → ADE3-03
- Piped commands → ADE3-04
- Parent PID spoofing → ADE3-05
- Logic flaws → ADE4
- Field name/availability drift across sources or backends → ADE4-04

**By Detection Pattern:**
- `contains` on cmdline → ADE1-01, ADE3-04
- `join` on query logic → ADE1-02, ADE3-02
- Process name checks → ADE3-01
- Method-specific queries → ADE2-01, ADE2-02
- File paths → ADE2-03
- File extensions → ADE2-04
- Thresholds/counts → ADE3-02
- Sequence rules → ADE3-03
- Multiple `NOT` → ADE4-01
- Parent process checks (`ParentImage`, `process.parent.*`) → ADE3-05
- Sysmon-only fields (`OriginalFileName`), multi-backend Sigma, `not filter` on optional fields → ADE4-04
