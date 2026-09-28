# Mitigation Strategies

This document provides comprehensive guidance for mitigating Adversarial Detection Engineering (ADE) vulnerabilities in detection rules.
---

## Overview

Adversarial Detection Engineering bugs arise when detection rules fail to account for alternative representations, execution methods, or logical variations that adversaries can exploit. Effective mitigation requires a multi-layered approach combining robust telemetry, comprehensive logic, and defense-in-depth strategies.

## General Principles

1. **Assume Adversarial Thinking**: Threat actors actively test and bypass detection rules. Design rules with bypass resistance in mind.
2. **Prioritize Immutable Indicators**: Focus on telemetry and indicators that adversaries cannot easily manipulate.
3. **Test Your Rules**: Use the ADE framework to identify potential bypasses before deployment.
4. **Layer Your Defenses**: No single rule is perfect. Use multiple complementary rules to cover different attack variations.
5. **Monitor Rule Effectiveness**: Track true positive and false negative rates to identify potential bypasses in production.

---

## Robust Telemetry Collection

### Use Immutable or Hard-to-Manipulate Telemetry Sources

**Problem**: Many detection rules rely on easily manipulated fields like process command lines, which adversaries can obfuscate or split across multiple events.

**Solution**: Prioritize telemetry sources that capture immutable or outcome-based indicators.

#### Example: File Download Detection

**Vulnerable Approach**: Detecting downloads by monitoring for browser process command lines containing URLs or by looking for processes like `curl.exe` or `wget.exe`.

**Robust Approach**: Ingest **Sysmon Event ID 15 (FileCreateStreamHash)** which logs when files are created with alternate data streams, including the `Zone.Identifier` stream that Windows uses to mark files downloaded from the internet.

```yaml
# Robust download detection using Sysmon Event ID 15
detection:
  selection:
    EventID: 15
    Contents|contains: 'ZoneId=3'  # Zone 3 = Internet
  condition: selection
```

**Why This Works**:
- Sysmon Event ID 15 captures the actual outcome (file marked as downloaded) rather than the process that performed the download
- The `Zone.Identifier` alternate data stream is set by Windows at the OS level and is consistent across download methods
- Adversaries cannot easily suppress or manipulate this telemetry without elevated privileges or kernel-level access
- **Category**: This falls under **Robust Collection Configuration** as it selects a more reliable data source

**Limitations to Consider**:
- Requires Sysmon configuration to include Event ID 15
- May generate high volume on file servers or systems with frequent downloads
- Does not capture downloads that bypass the Windows attachment manager (e.g., certain archive extractions, some network shares)

---

## String Representation Attacks

**Bug Type**: Reformatting and substring manipulation - exploiting how detection rules parse and match string patterns.

### Mitigation 1: Account for Whitespace Variations

**Problem**: Detection rules that rely on exact spacing (e.g., `" set "`) can be bypassed by:
- Enclosing parameters in quotes: `"set"` instead of ` set `
- Using tab characters: `` `t `` instead of space
- Using multiple spaces or mixed whitespace

#### Example Bypass - Space-Based Detection

**Vulnerable Condition**:
```yaml
detection:
  selection:
    CommandLine|contains: ' set '  # Hardcoded spaces
```

**Bypass Techniques**:
1. **Quote Enclosure**: `wmic useraccount where name='user' "set" passwordexpires=false`
2. **Tab Characters**: ``Start-Process "7zr.exe" -ArgumentList "`tu`ttest.zip`t*png`t`"-p`"test"``
3. **Multiple Spaces**: `wmic useraccount  set  passwordexpires`

**Hardened Condition**:
```yaml
detection:
  selection:
    CommandLine|re: '\bset\b'
  condition: selection
```

**Best Practice**: Use regex patterns that match the largest amount of possible variations under the commandLine field.

### Mitigation 2: RTL Consideration

**Problem**: Detection rules that match on exact binary names can be bypassed using:
- Right-to-Left (RTL) override characters (U+202E) that reverse the display of text

#### Example Bypass - RTL Character Injection

**Vulnerable Rule**:
```yaml
detection:
  selection:
    Image|endswith: '\malicious.exe'
```

**Bypass**: Create a directory with an injected RTL character, place the binary in that folder, and execute it. The logged "process_name" field will show the process name/path as reversed or jumbled - depends on ingestion method.

**Hardened Rule**:
```yaml
<TODO>
```

**Best Practices**:
1. **Prioritize Behavioral Detection**: Focus on what the process does (network connections, file modifications, registry changes) rather than just its name
2. **Use Hash-Based Detection**: Where applicable, match on file hashes (Sysmon Event ID 1 includes hashes) or use the field "OriginalFilename"
3. **Check for Unicode Anomalies**: Flag processes with RTL override characters or other unusual Unicode in paths

### Mitigation 3: Defense-in-Depth Rules for String Manipulation

**Strategy**: Create specific "canary" rules that detect common evasion techniques themselves.

**Example Rules**:
```yaml
# Detect RTL override characters in process execution
detection:
  selection_img:
    Image|contains: '\u202E'
  selection_cmd:
    CommandLine|contains: '\u202E'
  condition: any of selection_*
```

---

## Missing Alternatives

**Bug Type**: Omitting alternative methods, values, or execution paths that achieve the same malicious outcome.

### Mitigation 1: Enumerate All Functional Alternatives

**Problem**: Detection rules that check for specific string values miss functionally equivalent alternatives.

#### Example: Boolean Value Alternatives

**Vulnerable Rule**:
```yaml
detection:
  selection:
    Image|endswith: '\wmic.exe'
    CommandLine|contains|all:
      - 'useraccount'
      - 'set'
      - 'passwordexpires'
      - 'false'  # Only checks for "false"
  condition: selection
```

**Bypass**: Use `passwordexpires=0` instead of `passwordexpires=false` (both disable password expiration in WMIC).

**Hardened Rule**:
```yaml
detection:
  selection:
    Image|endswith: '\wmic.exe'
    CommandLine|contains|all:
      - 'useraccount'
      - 'set'
      - 'passwordexpires'
  password_disabled:
    CommandLine|contains:
      - 'false'
      - '0'
  condition: selection and password_disabled
```

**Best Practice**: Research the command syntax thoroughly to identify all value representations. For boolean parameters, check for:
- `true`/`false`
- `1`/`0`
- `yes`/`no`
- `on`/`off`
- `enabled`/`disabled`

**Best Practice**:
- Design rules with boolean replacements in mind

### Mitigation 3: Cover All Binary Alternatives

**Problem**: Focusing on one binary (e.g., `curl.exe`) misses alternatives (`wget.exe`, `certutil.exe`, PowerShell, BitsTransfer, etc.).

**Best Practice**: Create detection families that cover entire categories:
- File download tools: curl, wget, certutil, bitsadmin, PowerShell cmdlets, .NET classes
- Script interpreters: powershell.exe, pwsh.exe, cmd.exe, wscript.exe, cscript.exe, mshta.exe
- Compression tools: 7z.exe, zip.exe, tar.exe, expand.exe, extrac32.exe, makecab.exe

---

## Context Development Attacks

**Bug Type**: Attacks that manipulate the execution context to evade detection rules that assume specific parent processes, user contexts, or environmental conditions.

### Mitigation 1: Validate Full Process Ancestry

**Problem**: Rules that only check the immediate parent process miss deeper process tree manipulation.

**Best Practice**:
```yaml
detection:
  selection:
    Image|endswith: '\powershell.exe'
    # Check multiple levels of ancestry if available
    ParentImage|endswith:
      - '\cmd.exe'
      - '\wscript.exe'
    # Or check grandparent in systems that support it
    # GrandparentImage|endswith: '\suspicious.exe'
  condition: selection
```

### Mitigation 2: Fragmentation

**Problem**: Detection rules focusing on direct process execution miss indirect execution methods like piping, redirection, or alternative binaries.

#### Example: WMIC Piping Bypass

**Vulnerable Rule**:
```yaml
detection:
  selection:
    Image|endswith: '\wmic.exe'
    CommandLine|contains|all:
      - 'useraccount'
      - 'set'
      - 'passwordexpires'
  condition: selection
```

**Bypass**:
```cmd
echo /interactive:off useraccount where name='user' set passwordexpires=false | wmic
```

**What Happens**:
- **Event 1**: Process creation of `wmic.exe` with empty command line (only receiving piped input)
- **Event 2**: Process creation of `cmd.exe` with command line containing `echo /interactive:off useraccount where name='user' set passwordexpires=false`

The malicious WMIC command never appears in the WMIC process command line - it's passed via stdin.

**Hardened Approach**:
```yaml
# Instead of fixing all vulnerable rules - this rule acts as a "defense-in-depth" alternative that catches the entire blindspot
detection:
  selection:
    Image|endswith: '\cmd.exe'
    CommandLine|contains|all:
     - 'echo'
     - '/s'
     - '/d'
     - '/c'
  condition: selection
```

### Mitigation 3: Don't Treat Reported Parent Lineage as Ground Truth

**Problem**: Parent PID spoofing (ADE3-05) lets an attacker choose the parent recorded for a new process. Rules that alert on a suspicious parent miss, and rules that exclude a benign parent can be satisfied on purpose.

**Best Practice**:
1. **Use a source that records the real creator**: ETW `Microsoft-Windows-Kernel-Process` exposes the true caller in `EventHeader.ProcessId`; some EDRs surface it separately (e.g., Elastic Defend `process.parent.Ext.real.pid`). Alert when the real creator and the reported parent differ.
2. **Never exclude on parent alone**: pair parent-based exclusions with fields the attacker cannot choose at process creation, or drop the exclusion and tune instead.
3. **Keep a behavioral rule for the child**: detect what the child process does, so a spoofed parent removes context but not coverage.
4. **Validate cross-source signals in a lab**: confirm what each source (Sysmon, Security 4688, ETW, EDR) records under spoofing before building a correlation on it.

### Mitigation 4: Keep Bounded Operators on the Rare Side

**Problem**: A join, subsearch, group table, or sort holds a bounded working set (ADE3-06). When volume exceeds the limit the set is truncated without an error, and the record the rule needed is dropped.

**Best Practice**:
1. **Put the rare set in the bounded operator**: the subsearch or subquery should return the few records the rule is about (e.g., the suspicious processes), and the high-volume source should be the streamed, unbounded side.
2. **Prefer streaming correlation over `join`**: in Splunk, OR both sources into one search and correlate with `stats ... by <key>`; in LogScale, use `selfJoinFilter()` (it has no false negatives, but admits some false-positive keys, so gate the result on both sides being present). A `groupBy()` keyed per process is not an escape hatch — at estate scale it hits the group limit instead.
3. **Raise limits explicitly where the engine allows it**: `limit=max` on LogScale `groupBy()`, `limit=` on LogScale `join()`, `sort 0` in Splunk. Where a hard maximum exists (LogScale `join()`: 200,000), reduce the input instead.
4. **Never apply a rarity filter after a top-N limit**: a group table that keeps the highest-value groups drops the rare ones first.
5. **Probe for truncation**: count the bounded side alone over the rule's window, and re-run the rule constrained to a single host. If a match appears only when constrained, the rule is truncating.

---

## Logic Manipulation

**Bug Type**: Exploiting flawed logical operators, condition ordering, or incomplete logic chains in detection rules.

### Mitigation 1: Review Boolean Logic Carefully

**Problem**: Incorrect use of AND/OR operators creates logical loopholes.

**Best Practice**:
- Use explicit grouping with parentheses
- Test logic tables with all combinations
- Prefer positive detection (what MUST be present) over negative detection (what must NOT be present)

**Example**:
```yaml
# Vulnerable
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-enc'
  filter:
    User: 'SYSTEM'
  condition: selection and not filter  # Can be bypassed by running as different user

# Better
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-enc'
  suspicious_user:
    User|contains:
      - 'Administrator'
      - 'Guest'
    # Explicit list rather than negation
  condition: selection and suspicious_user
```

### Mitigation 2: Avoid Overly Specific Filters

**Problem**: Allowlists that are too granular create easy bypass opportunities.

**Best Practice**:
- Keep filters minimal and well-justified
- Regularly review filter effectiveness
- Consider removing filters and tuning instead

### Mitigation 3: Verify Fields Against the Deployed Telemetry

**Problem**: A misnamed, unavailable, or absent field (ADE4-04) does not error — the condition silently matches nothing, or inverts a negated filter.

**Best Practice**:
- **Review the transpiled query**, not the Sigma source, on every target backend
- **Pin `logsource.service`** when a rule depends on a source-specific field (e.g., `OriginalFileName` is Sysmon-only)
- **OR in a fallback** for sources without the field (e.g., `OriginalFileName` or `Image|endswith`)
- **Guard every negated optional field** with a presence check so absence cannot flip the outcome:

```yaml
detection:
  selection:
    Image|endswith: '\rundll32.exe'
  filter_benign_parent:
    ParentImage|endswith: '\explorer.exe'
  filter_parent_present:
    ParentImage|exists: true
  condition: selection and not (filter_benign_parent and filter_parent_present)
```

- **Probe field population** per fleet segment; a field that is always null on a segment means the rule is blind there
- **Replay an atomic test** per backend, and flag rules that have never fired since deployment for review

---

## Defense-in-Depth Strategies

### Layer 1: Robust Telemetry Foundation
- Deploy comprehensive logging
- Ingest immutable indicators

### Layer 2: Primary Detection Rules
- Behavior-based rules targeting attacker objectives
- Cover major attack techniques per MITRE ATT&CK
- Test against known bypasses using ADE framework

### Layer 3: Evasion Detection Rules
- Specific rules detecting common bypass techniques:
  - RTL override characters in process names and commandLine
  - Suspicious quote patterns in command lines
  - Tab character usage in command lines
  - Empty command lines for typically verbose processes (e.g., WMIC without args, expand with correlation)
  - Piping patterns that split detection logic
  - Whitespace manipulation patterns

### Layer 4: Anomaly Detection
- Baseline normal process behaviors
- Flag deviations from typical execution patterns
- Monitor for unusual parent-child relationships, and for mismatches between reported and real parent

### Layer 5: Threat Hunting
- Proactive searches for bypass variations
- Regular rule validation against new techniques
- Community intelligence integration (e.g., new LOLBAS techniques)

---

## Testing Your Mitigations

### ADE Testing Methodology

1. **Identify Rule Intent**: What attacker behavior are you trying to detect?
2. **List Detection Assumptions**: What must be true for the rule to fire?
3. **Brainstorm Alternatives**: How else could the attacker achieve the same outcome?
4. **Test Bypass Attempts**: Actually test each alternative in a lab
5. **Update Rules**: Incorporate findings into rule logic
6. **Document Limitations**: Be honest about what the rule cannot detect
7. **Store True Positive Data**: Store the True Positive data for future DaC pipeline verification
8. **Repeat**: Adversaries evolve - continuously test and improve

### Example Testing Template

```markdown
## Rule: Detect WMIC Password Expiration Disable

**Intent**: Detect when WMIC is used to disable password expiration on user accounts

**Detection Logic**:
- Process: wmic.exe
- CommandLine contains: useraccount, set, passwordexpires, false

**Known Bypasses**:
1. ✅ Use 0 instead of false - MITIGATED (added to rule)
2. ✅ Pipe command via echo - MITIGATED (created companion rule)
3. ✅ Use tabs instead of spaces - MITIGATED (changed to regex)
4. ⚠️ Use PowerShell WMI cmdlets instead - PARTIAL (separate rule exists but may need correlation)
5. ❌ Direct registry modification - NOT COVERED (need new rule for registry-based password policy changes)

**Testing Date**: 2026-02-08
**Next Review**: 2026-05-08
```

---

## Continuous Improvement

Detection engineering is an ongoing process:

1. **Monitor Production Detections**: Track rule effectiveness and false negative indicators
2. **Integrate Threat Intelligence**: New bypass techniques emerge regularly
3. **Collaborate**: Share findings with the community and learn from others
4. **Automate Testing**: Build automated bypass testing into your CI/CD pipeline
5. **Use This Framework**: Regularly apply ADE taxonomy to your rule base

---

**Contributing**: If you discover new mitigation strategies or bypass techniques, please contribute back to this framework via pull request or issue submission.
