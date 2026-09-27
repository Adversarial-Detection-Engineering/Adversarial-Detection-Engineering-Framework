# ADE4 - Logic Manipulation

Logic Manipulation occurs when an attacker analyzes detection logic as Boolean conditions and manipulates inputs or filters to invert, bypass, or neutralize the rule outcome.

Attackers assess detection rule logic as **Boolean Algebra** and undertake additional steps to force the chain of Boolean tests to flip the output value, resulting in no hits.

It is common to see a Logic Manipulation bug in a detection rule along with another bug from a different category, as every logic manipulation requires another bug to invert or skip detection logic.

## Subcategories

### ADE4-01: Logic Manipulation - Gate Inversion

**Definition:** Gate inversion occurs when the detection rule includes a NOT clause (negation) which looks for data values that are mutable by the attacker through insertion of poisoned data prior to the record being generated. It often appears in rule exceptions or filters, where this bug, coupled with another bug, results in an "inversion" of the cumulative Boolean outcome of the rule.

**Most cases occur when:** The detection rule author didn't consider that multiple negations can be simplified using [De Morgan's Laws](https://en.wikipedia.org/wiki/De_Morgan%27s_laws).

**De Morgan's Laws:**
```
NOT A AND NOT B  ⟺  NOT (A OR B)
NOT A OR NOT B   ⟺  NOT (A AND B)
```

**Common Pattern:**
```yaml
detection:
    selection:
        suspicious_activity: true
    filter1:
        not field1: "value1"
    filter2:
        not field2: "value2"
    condition: selection and not filter1 and not filter2
```

**Simplifies to:**
```yaml
condition: selection and not (filter1 or filter2)
```

**Attack:** If attacker can insert `value1` OR `value2`, the entire condition becomes False.

---

### ADE4-02: Logic Manipulation - Conjunction Inversion

**Definition:** Conjunction inversion bugs occur when conjunction conditions (AND) within the rule look for data values vulnerable to manipulation by the attacker through insertion of poisoned data prior to record generation. Often appears when detection rules are updated to include a conjuncted condition that can be easily flipped by an attacker with the assumed privilege level needed to perform the in-scope activity.

**Example:** Creating poisoned data to fill an array at rule execution time, which if non-empty gets evaluated as benign due to a filter.

**Common Pattern:**
```yaml
condition: suspicious_activity AND not (field contains "safe_string")
```

**Attack:** Attacker adds "safe_string" to malicious payload to flip the conjunction.

---

### ADE4-03: Logic Manipulation - Incorrect Expression

**Definition:** Incorrect Expression occurs when detection logic has been crafted in a way that the interpreted query would rarely create hits. This occurs when a detection rule uses incorrect choices between negations, conjunctions, or disjunctions.

**Why it happens:**
- Lack of adversarial emulation
- No testing with generated data before production deployment
- Logic construction errors (AND vs OR confusion)

**Result:** The rule is ineffective by design, not due to attacker action.

**Common Mistakes:**
- Using AND when OR is required
- Negating privileged accounts in non-privilege-escalation rules
- Requiring mutually exclusive conditions

---

### ADE4-04: Logic Manipulation - Field Mismapping & Semantics

**Definition:** Field Mismapping & Semantics occurs when detection logic references fields incorrectly — the wrong name, a field that is unavailable in the log source actually reaching the rule, or a field whose semantics the author misunderstood. The query does not error; it evaluates against a missing or wrong value and silently fails to match, or, inside a negated filter, inverts the rule outcome.

**Why it happens:**
- A single Sigma rule transpiles to many backends, each with its own field names, case handling, and null semantics
- Rules are validated against one reference source (usually Sysmon) and deployed where fields differ
- Field availability depends on the deployed telemetry and its configuration, not on the rule text

**Result:** Like ADE4-03, often no attacker action is required — the rule is broken on arrival for part of the fleet. An attacker only needs to land where the depended-upon field is not collected.

**Three failure modes:**

1. **Field-Name Mismatch Across Backends** — right field, wrong spelling or case for the target backend
   - `CommandLine` vs `commandline` / `command_line` / `process.command_line`
   - `TargetFilename` (what Sysmon emits) vs `TargetFileName`
   - Sysmon field names used against Security 4688, where the command line lives in `Process Command Line`
   - Transpiles clean, matches nothing; zero hits look identical to "no attacks happened"

2. **Unavailable Field — Silent Match Failure** — right name, but not populated in the source that reaches the rule
   - `OriginalFileName` is present in Sysmon Event ID 1, absent from Security 4688 and many EDR tables
   - `CommandLine` is absent from 4688 unless command-line process auditing is enabled
   - `ParentImage` is not carried by PowerShell Script Block Logging (Event ID 4104)
   - The deployed Sysmon configuration decides which event IDs and fields exist at all
   - Truncated command lines move deep substrings out of view

3. **Absent Field Inverts a Filter Clause** — a missing field inside `not filter` flips the outcome (the ADE4-04 ∩ ADE4-01 case)
   - Authors reason in two-valued Boolean logic; backends may run three-valued logic where `NOT null` is `null`, not `true`
   - Depending on backend null-handling, the exclusion either silently disables itself (**false positives**, the rule gets muted) or swallows every match (**false negatives**)
   - The same Sigma source can fail in opposite directions on two SIEMs

**Semantic confusion:** `SubjectUserName` (the actor) vs `TargetUserName` (the account acted upon) in Windows Security logs — matching the wrong one inverts who the rule is about.

## Examples

### Real-World Detection Logic Bugs

**ADE4-01 - Gate Inversion:**
1. **[PowerShell Audio Capture - Sentinel String Bypass](../../examples/ade4/powershell-audio-capture-gate-inversion.md)**
   - Add sentinel strings to bypass negation filter
   - Platform: Windows PowerShell Script Block Logging (Elastic Security)

2. **[Windows BITS - De Morgan's Laws Gate Inversion](../../examples/ade4/bits-gate-inversion.md)**
   - Filename length >30 inverts entire negation chain
   - Platform: Windows (Elastic Endgame EDR)
   - **Note:** Same rule also demonstrates ADE2-04 and ADE3-02 bugs

**ADE4-03 - Incorrect Expression:**

1. **[Suspicious Shell Script - curl AND wget](../../examples/ade4/shell-script-incorrect-expression.md)**
   - Requires both `curl` AND `wget` in same command line
   - Real attacks use one OR the other
   - Platform: Linux Syslog (Microsoft Sentinel)

## Detection Rule Patterns Vulnerable to ADE4

### ADE4-01 Patterns (Gate Inversion)

**Multiple negations:**
```yaml
not condition1 and not condition2 and not condition3
```

**Should be simplified:**
```yaml
not (condition1 or condition2 or condition3)
```

**Negations on attacker-controlled fields:**
```yaml
not (field contains "bypass_string")  # Attacker can insert this
```

### ADE4-02 Patterns (Conjunction Inversion)

**Filters on mutable data:**
```yaml
suspicious_action and not (
    script_content contains "legitimate_tool_signature"
)
```

**Array/list evaluations:**
```yaml
array is not empty and array does not contain "poison_value"
```

### ADE4-03 Patterns (Incorrect Expression)

**AND when OR is needed:**
```yaml
cmdline has "curl" and cmdline has "wget"  # Unlikely both present
```

**Should be:**
```yaml
cmdline has "curl" or cmdline has "wget"
```

**Excluding privileged accounts from non-privesc rules:**
```yaml
suspicious_action and not (user in ("root", "SYSTEM", "Administrator"))
```

### ADE4-04 Patterns (Field Mismapping & Semantics)

**Non-canonical field spelling:**
```yaml
Commandline|contains: '-enc'   # 'Commandline', not 'CommandLine'
```

**Source-specific field without a pinned log source:**
```yaml
logsource:
    category: process_creation
    product: windows            # not pinned to service: sysmon
detection:
    selection:
        OriginalFileName: 'CertUtil.exe'   # null on 4688 and many EDR tables
```

**Negated filter on an optional field:**
```yaml
filter:
    ParentImage|endswith: '\explorer.exe'   # may be absent
condition: selection and not filter
```

**Hardened negation — only exclude when the field is present:**
```yaml
filter_benign_parent:
    ParentImage|endswith: '\explorer.exe'
filter_parent_present:
    ParentImage|exists: true
condition: selection and not (filter_benign_parent and filter_parent_present)
```

## 🚨 Risk of Negating Privileged Accounts

**Critical Issue:** Many detection rules negate privileged accounts (root, SYSTEM, Administrator) to reduce noise from standard administrative activity.

**Problem:** This only makes sense for **privilege escalation** detections. For initial access, persistence, lateral movement, and other tactics, privileged account activity **must** be monitored.

### Why This Is Dangerous

**Recent CVEs demonstrating unauthenticated RCE as root/SYSTEM:**

#### 2025 Examples

**🚨 [CVE-2025-20281 / CVE-2025-20337 – Cisco ISE](https://nvd.nist.gov/vuln/detail/CVE-2025-20337)**
- Unauthenticated remote code execution as **root**
- No credentials required
- Actively exploited by APTs in mid-2025

**🚨 [CVE-2025-59287 – Microsoft WSUS](https://nvd.nist.gov/vuln/detail/CVE-2025-59287)**
- Unauthenticated RCE with **SYSTEM-equivalent** privileges
- Windows Server Update Services component

**🚨 [CVE-2025-46811 — SUSE Manager Missing Authorization](https://www.suse.com/security/cve/CVE-2025-46811.html)**
- Unauthenticated RCE as **root**
- Root privileges on SUSE Manager server and managed clients

**🚨 [CVE-2025-32463 — sudo chroot privilege escalation](https://www.upwind.io/feed/cve-2025-32463-critical-sudo-chroot-privilege-escalation-flaw)**
- Local flaw allowing any unprivileged user to escalate to **root**
- Actively bypassed (added to security advisories)

#### 2024 Examples

**🚨 [CVE-2024-6387 — OpenSSH "regreSSHion"](https://nvd.nist.gov/vuln/detail/cve-2024-6387)**
- Critical unauthenticated RCE in OpenSSH server
- Leads to **root shell** / full system takeover

**🚨 [CVE-2024-1086 — Linux kernel netfilter privilege escalation](https://nvd.nist.gov/vuln/detail/CVE-2024-1086)**
- Use-after-free in netfilter subsystem
- PoCs published leading to **root** privilege

### Impact

**Detection rules that exclude root/SYSTEM will miss:**
- ✗ Unauthenticated RCE exploits gaining immediate root access
- ✗ Privilege escalation exploits where attacker already has root
- ✗ Initial access via vulnerable services running as SYSTEM
- ✗ Persistence mechanisms installed at system level
- ✗ Lateral movement using elevated credentials

### When Negating Privileged Accounts Is Acceptable

**ONLY for privilege escalation detections:**
```yaml
# Detecting privilege escalation to root
rule: detect_privesc_to_root
scope: "Activity indicating escalation FROM lower privilege TO root"
logic: user.previous != "root" and user.current == "root"
```

**NOT acceptable for:**
- Initial access detections
- Persistence mechanisms
- Lateral movement
- Defense evasion
- Credential access
- Collection/Exfiltration

## Testing Your Rules

**Quick Test Questions:**

**For ADE4-01 (Gate Inversion):**
- ✅ Do you have multiple `not` conditions chained with AND?
- ✅ Can these be simplified using De Morgan's Laws?
- ✅ Do your negations check attacker-controlled fields?
- ✅ Could an attacker insert data to flip the negation?

**For ADE4-02 (Conjunction Inversion):**
- ✅ Do you have AND conditions on mutable fields?
- ✅ Could an attacker add data to make the condition False?
- ✅ Are you checking array emptiness with attacker-influenced data?

**For ADE4-03 (Incorrect Expression):**
- ✅ Have you tested your rule with real-world attack samples?
- ✅ Did you validate that the Boolean logic matches your intent?
- ✅ Are you using AND where OR is needed (or vice versa)?
- ✅ Are you excluding privileged accounts in non-privesc rules?

**For ADE4-04 (Field Mismapping & Semantics):**
- ✅ Have you read the **transpiled** query (SPL/KQL/ES|QL/Lucene) and confirmed every field exists in that schema?
- ✅ Does the rule depend on a field only some sources populate (e.g., `OriginalFileName`, `CommandLine` on 4688) without pinning `logsource.service`?
- ✅ Does a `not filter` reference a field that can be absent on any target segment?
- ✅ Has the rule fired on an atomic test on **each** backend it is deployed to?

If you answered "yes" to any of these, your rule likely has an ADE4 vulnerability.

## Related Bug Categories

ADE4 often appears alongside:
- **ADE1-01 (Substring Manipulation):** String manipulation used to flip negations
- **ADE3-02 (Aggregation Hijacking):** Manipulated aggregations flip Boolean gates
- **ADE2 (Omit Alternatives):** Logic errors compound with missing alternatives
- **ADE3-05 (Lineage Spoofing):** Spoofed parent fields flip parent-based exclusions (ADE4-01 / ADE4-02)
- **ADE2-02 (Versioning):** Product or log-source version changes can rename or remove fields a rule depends on (ADE4-04)

## Logic Testing Framework

**Before deploying any rule:**

1. **Draw truth table** for your Boolean conditions
2. **Enumerate all input combinations** that should trigger
3. **Test with real attack samples** (not just theoretical)
4. **Apply De Morgan's Laws** to simplify negations
5. **Validate privileged account assumptions** match rule scope
6. **Add field presence** as an input to the truth table (`field present` / `field absent`) for every negated condition, per target backend
