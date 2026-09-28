# ADE3 - Context Development

Context Development bugs occur when an attacker takes additional steps to **manipulate or poison contextual data** used by the detection logic, causing in-scope activity to bypass rule conditions.

Rather than changing the primary malicious action, the attacker shapes the **surrounding context** that the rule relies on.

## Subcategories

### ADE3-01: Context Development - Process Cloning

**Definition:** Detection logic relies on **string-based identification of a process or binary**, while implicitly assuming the attacker cannot clone or rename binaries. If the attacker has sufficient privileges to duplicate and rename a binary, they can execute identical behavior under a different process name, resulting in a False Negative.

**Common Scenarios:**
- Linux: `cp /usr/bin/wget /tmp/foo` → Use `/tmp/foo` for malicious download
- Windows: Copy legitimate binary to user-writable location
- Any process name-based detection without hash/signature validation

**Why It Works:**
- Cloned binary has identical functionality
- File hash remains the same
- Only the process name field changes in logs
- Many detection rules only check `process.name` or `Image` fields

---

### ADE3-02: Context Development - Aggregation Hijacking

**Definition:** Detection logic relies on **aggregated values** that an attacker can influence or precondition.

**Common Patterns:**
- **Threshold-based rules:** "Alert if >10 failed logins" → Attacker stays at 9
- **"Newly seen" logic:** "Alert on first-time process" → Attacker runs benign version first
- **UEBA entity grouping:** `source.ip:user.name` → Attacker matches existing baseline
- **File size/name length aggregations:** Attacker manipulates to stay within expected ranges

**Examples:**
- Aggregations over file sizes, file name lengths, or counts
- UEBA-style entities (e.g., `source.ip:user.name`)
- "New terms" rules that group by abstract fields
- Threshold-based logic with attacker-visible counters

**Attack Pattern:**
1. Attacker reconnaissance: Observe current baselines/thresholds
2. Preparatory activity: Pre-condition aggregation buckets
3. Malicious action: Execute within established baseline → No alert

---

### ADE3-03: Context Development - Timing and Scheduling

**Definition:** Detection logic relies on **time-based assumptions**, such as execution frequency, duration, or inter-event timing. By spacing, batching, or scheduling actions to avoid inclusion within rule execution windows or aggregation periods, an attacker can bypass detection without changing the underlying behavior.

**Common Patterns:**
- **Sequence rules with maxspan:** `maxspan=1m` → Attacker waits >1 minute between steps
- **File age checks:** "Alert if file <500s old" → Attacker waits 501 seconds
- **Lookback periods:** "Check last 15 days" → Attacker waits 16 days
- **Rate limiting:** "Alert if >5 per minute" → Attacker does 4/minute

**Attack Pattern:**
1. Identify time constraints in detection logic
2. Space malicious actions to fall outside time windows
3. Achieve same outcome without triggering temporal thresholds

---

### ADE3-04: Context Development - Event Fragmentation

**Definition:** Detection logic relies on **multi-substring matching** (using `|all`, `contains|all`, or multiple `AND` conditions) while assuming all required substrings will appear in a single process creation event. However, shell operators like `|` and `&` cause commands to be split into multiple separate process creation events, preventing the detection logic from matching, resulting in a False Negative.

**Why This Happens:**
- Operating systems fragment piped commands at the OS level
- Each command in a pipe generates a separate process creation event
- No single event contains all the substrings the rule expects

**Result:** In-scope malicious activity bypasses detection without the attacker needing to know the rule exists. This is **unintentional evasion** - a natural consequence of OS behavior.

**Related Research:**
- [Detection Pitfalls by Daniel Koifman](https://detect.fyi/detection-pitfalls-you-might-be-sleeping-on-52b5a3d9a0c8)
- [Unintentional Evasion: Command Line Logging Gaps by Kostas](https://detect.fyi/unintentional-evasion-investigating-how-cmd-fragmentation-hampers-detection-response-e5d7b465758e)

---

### ADE3-05: Context Development - Lineage Spoofing

**Definition:** Detection logic relies on the **parent-process relationship** (e.g., "PowerShell spawned by Word is suspicious") while assuming the logged parent is truthful. Using a documented Windows API (`CreateProcess` with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`), an attacker assigns an arbitrary parent to the process they create. The event is still generated, but the parent fields the rule trusts (`ParentImage`, `ParentProcessId`, `ParentCommandLine`, `process.parent.*`) are poisoned, resulting in a False Negative.

**Common Scenarios:**
- Parent-child rules: "alert if `cmd.exe`/`powershell.exe` is spawned by `outlook.exe`" → attacker spoofs the parent to `explorer.exe`
- Parent-based exclusions: "ignore `rundll32.exe` launched by `explorer.exe`" → attacker spoofs exactly the excluded parent
- Allowlist-style rules: "alert if `cmd.exe` is NOT spawned by `explorer.exe`" → attacker spoofs the expected parent
- Blending into the process tree by parenting to long-lived processes (`explorer.exe`, `svchost.exe`)

**Why It Works:**
- The telemetry exists and the event fires; only a contextual field has been falsified
- Process-creation telemetry such as Sysmon Event ID 1 records the spoofed parent in `ParentProcessId`, `ParentImage`, and `ParentCommandLine`
- The technique is built into common C2 tooling (e.g., Cobalt Strike's `ppid` command), so it costs the attacker nothing (MITRE ATT&CK [T1134.004](https://attack.mitre.org/techniques/T1134/004/))
- Rules treat parent lineage as ground truth for both alerting and exclusion

**Where the truth still lives:**
- ETW `Microsoft-Windows-Kernel-Process` process-start events: the `EventHeader.ProcessId` is the real creator, while the payload's parent PID is the spoofed one
- EDR telemetry that exposes the real creator separately, e.g., Elastic Defend's `process.parent.Ext.real.pid`
- Windows Security Event 4688 `Creator Process ID` / `Creator Process Name` is commonly used as a cross-check source ([MITRE ATT&CK detection guidance](https://attack.mitre.org/techniques/T1134/004/)); validate in your lab what it records under spoofing before relying on it as ground truth

**Relationship to ADE4:** Parent-based filter exclusions are directly exploitable through lineage spoofing. When the spoofed parent is the excluded value, this is ADE3-05 feeding [ADE4-01 Gate Inversion](ade4-logic-manipulation.md#ade4-01-logic-manipulation---gate-inversion) / [ADE4-02 Conjunction Inversion](ade4-logic-manipulation.md#ade4-02-logic-manipulation---conjunction-inversion).

---

### ADE3-06: Context Development - Limit Saturation

**Definition:** Detection logic relies on a query operator that holds a **bounded working set** — a join or subsearch, a group table, a sort, or a per-key match count — while assuming the operator evaluates every record in scope. When the volume reaching that operator exceeds its limit, the engine truncates the set, and the in-scope record is discarded before the rule's conditions ever evaluate it, resulting in a False Negative.

**Common Scenarios:**
- Splunk `join`: the right-side subsearch is capped at 50,000 rows and 60 seconds by default, and `max=1` joins each main result to at most one subsearch row. Other subsearches are capped at 10,000 results / 60 seconds
- CrowdStrike LogScale `join()`: the subquery is capped by `limit` (default 100,000, maximum 200,000), and `max=1` keeps one subquery row per join key
- LogScale `groupBy()`: 20,000 groups by default (`limit=max` raises it to the `GroupMaxLimit`, 1,000,000 by default). When the limit is exceeded, it keeps the top-N groups by value
- `sort` defaults: Splunk returns 10,000 results unless given `0`; LogScale `sort()` returns 200 unless given a `limit`

**Why It Works:**
- Truncation is not an error: the search completes, and at most a warning banner or job-log message records it — which nobody reads on a scheduled rule
- The limit is spent on **everything** that reaches the operator, not on the records the rule cares about. A subsearch filtered only by event type spends its budget on noise
- Volume grows on its own: a rule validated in a lab or a small tenant degrades silently as the estate grows. Like ADE3-04, this is **unintentional evasion**
- Where the operator keeps the top-N by value (LogScale `groupBy()`), low-count groups are dropped first — exactly the rare groups a rarity or first-seen rule is looking for

**Adversarial use — cap flooding:** An attacker who can generate records on the bounded side of the operator can push its volume past the limit on purpose. A burst of connections to many distinct destinations inflates a network-traffic subsearch; thousands of distinct low-count groups (randomized paths, names, or arguments) inflate a group table. The malicious action is unchanged — only the surrounding volume is shaped.

**Distinguishing it from related bugs:**
- **ADE3-02 Aggregation Hijacking** manipulates the *value* an aggregation computes (a count stays under a threshold). Limit Saturation decides whether the record is *in* the aggregation at all
- **ADE1-02 Normalization Asymmetry** also produces an empty join, but because the keys differ. Under Limit Saturation the keys match and the row was never retained. To tell them apart, constrain the bounded side to a single host and re-run: if the match appears, the cause is truncation
- **ADE4-04 Unavailable Field** covers telemetry ceilings (a command line truncated at collection). ADE3-06 is a query-engine ceiling on rows, groups, or keys

## Examples

### Real-World Detection Logic Bugs

**ADE3-01 - Process Cloning:**
1. **[Wget Download to Tmp - Process Cloning](../../examples/ade3/process-cloning-wget.md)**
   - Clone `/usr/bin/wget` → Use cloned binary
   - Platform: Linux (Sysmon for Linux)

2. **[Cat Network Activity - Process Cloning](../../examples/ade3/process-cloning-cat.md)**
   - Clone `/bin/cat` → Use for TCP/UDP exfiltration via `/dev/tcp`
   - Platform: Linux (Elastic Endgame)

3. **[AWS CLI Custom Endpoint - Process Cloning](../../examples/ade3/process-cloning-aws-cli.md)**
   - Clone `/usr/bin/aws` → Use with malicious endpoints
   - Platform: Linux process events

**ADE3-02 - Aggregation Hijacking:**

4. **[Windows BITS Filename Length Manipulation](../../examples/ade3/bits-filename-manipulation.md)**
   - Use filename >30 characters to bypass length-based exclusions
   - Platform: Windows (Elastic Endgame EDR)
   - **Note:** Same rule also demonstrates ADE2-04 and ADE4-01 bugs

5. **[AWS CLI New Terms Aggregation Hijacking](../../examples/ade3/aws-cli-new-terms-hijacking.md)**
   - Hijack `host.id` aggregation baseline
   - Platform: Linux (Elastic Security new_terms rule)

6. **[Remote Access Tool New Terms Hijacking](../../examples/ade3/rat-new-terms-hijacking.md)**
   - RAT execution aggregated by `host.id` only
   - Platform: Windows (Elastic Security new_terms rule)

**ADE3-03 - Timing and Scheduling:**

7. **[Outlook COM Collection - Multiple Timing Bugs](../../examples/ade3/outlook-com-timing-bugs.md)**
   - Contains 4 bugs: ADE3-01, ADE3-02, ADE3-03 (2 timing bugs)
   - File age bypass (>500 seconds) + sequence maxspan bypass (>60 seconds)
   - Platform: Windows (Elastic Endgame EDR)

**ADE3-04 - Event Fragmentation:**

8. **[LSASS Process Reconnaissance - Event Fragmentation](../../examples/ade3/event-fragmentation.md)**
   - Command: `tasklist | findstr lsass`
   - Fragmented across multiple process creation events
   - Platform: Windows Event ID 4688

**ADE3-06 - Limit Saturation:**

9. **[Rundll32 with No Command Line Arguments with Network - Limit Saturation](../../examples/ade3/limit-saturation-splunk-join.md)**
   - `join` subsearch returns every network flow in the estate, grouped by 20 fields including `src_port` and `bytes`
   - Platform: Splunk ESCU (production)

10. **[Windows WinLogon with Public Network Connection](https://github.com/splunk/security_content/blob/develop/detections/endpoint/windows_winlogon_with_public_network_connection.yml)**
    - `join` subsearch returns every public connection in the estate by `process_id`, `dest`, and `dest_port`, where the rule needs only winlogon's
    - Platform: Splunk ESCU (production)

11. **[Log4Shell JNDI Payload Injection with Outbound Connection](https://github.com/splunk/security_content/blob/develop/detections/web/log4shell_jndi_payload_injection_with_outbound_connection.yml)**
    - `join` subsearch returns every destination in `Network_Traffic`; the rule needs only the hosts named in JNDI payloads
    - Platform: Splunk ESCU (production)

12. **[Hunt PDB File Paths in Reflective .NET Module Loads](https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/Hunt%20PBD%20File%20Paths%20in%20Reflective%20.net%20Module%20Loads.md)**
    - `groupBy([FileName, FilePath])` with no `limit` (default 20,000, top-N by value retained), followed by a rarity filter `test(uniqueEndpoints<5)` — the rare groups are the first dropped
    - Platform: CrowdStrike LogScale (community hunting query)

13. **[Process Events - Identify Low Port Bindings](https://github.com/CrowdStrike/logscale-community-content/blob/main/Log-Sources/CrowdStrike/FLTR/crowdstrike-fltrcore/src/queries/ProcessEvents-IdentifyLowPortBindings.yaml)**
    - `join()` subquery is every `NetworkListenIP4` with `LocalPort<1024` in the estate over 7 days; already set to `limit=200000`, the hard maximum, so it cannot be raised further
    - Platform: CrowdStrike LogScale (FLTR package query)

## Detection Rule Patterns Vulnerable to ADE3

### ADE3-01 Patterns

**Process name-only matching:**
```yaml
Image|endswith: '/wget'
process.name: "powershell.exe"
```

### ADE3-02 Patterns

**Threshold rules:**
```
count > 10
length(field) > 30
```

**New terms rules:**
```yaml
type: "new_terms"
field: "host.id"  # Too abstract
```

**Time-based baselines:**
```
not seen in last 15 days
```

### ADE3-03 Patterns

**Sequence rules:**
```yaml
sequence by host.id with maxspan=1m
```

**File age checks:**
```
file.created < 500 seconds ago
```

**Aggregation windows:**
```
bucket_span: "5m"
lookback: "now-9m"
```

### ADE3-04 Patterns

**Multi-substring matching:**
```yaml
CommandLine|contains|all:
    - 'string1'
    - 'string2'
    - 'string3'
```

**With:**
- Shell operators: `|`, `&`, `&&`, `||`
- Piped commands
- Chained execution

### ADE3-05 Patterns

**Parent-child matching:**
```yaml
Image|endswith: '\powershell.exe'
ParentImage|endswith: '\winword.exe'
```

**Parent-based exclusions:**
```yaml
filter:
    ParentImage|endswith: '\explorer.exe'
condition: selection and not filter
```

**Parent fields as ground truth:**
```
process.parent.name == "outlook.exe"
ParentProcessId / ParentCommandLine used for alerting or suppression
```

### ADE3-06 Patterns

**Bounded subsearch/subquery on the high-volume side:**
```spl
| join process_id [
    | tstats count FROM datamodel=Network_Traffic.All_Traffic
      WHERE All_Traffic.dest_port != 0
      BY All_Traffic.process_id All_Traffic.dest All_Traffic.dest_port ]
```
```
| join({#event_simpleName=NetworkListenIP4 LocalPort<1024}, field=TargetProcessId, key=ContextProcessId, limit=200000)
```

**Group table with no explicit limit, followed by a rarity filter:**
```
| groupBy([FileName, FilePath], function=count(aid, distinct=true, as=uniqueEndpoints))
| test(uniqueEndpoints<5)
```

**Sort without a count:**
```
| sort - count          (Splunk: 10,000 results)
| sort(count)           (LogScale: 200 rows)
```

## Why Context Development Is Powerful

**Key Insight:** ADE3 bugs often don't require the attacker to know detection rules exist.

**ADE3-01:** Process cloning is a natural privilege escalation/evasion technique
**ADE3-02:** Attackers naturally do reconnaissance before attacking
**ADE3-03:** Operational security naturally involves timing spacing
**ADE3-04:** Piped commands are **standard shell usage** - not intentional evasion
**ADE3-05:** Parent PID spoofing is a **built-in feature of common C2 frameworks** - one flag, not a bespoke evasion
**ADE3-06:** Data volume **grows on its own** - rules degrade as the estate grows, and noise speeds it up

## Related Bug Categories

ADE3 often appears alongside:
- **ADE1-01 (Substring Manipulation):** Context manipulation often involves string changes
- **ADE1-02 (Normalization Asymmetry):** Both produce empty joins - ADE1-02 because the keys differ, ADE3-06 because the matching row was truncated
- **ADE2-01 (Omit Alternatives - Method/Binary):** Cloned binaries are "alternative" execution methods
- **ADE4-01 (Gate Inversion):** Timing/aggregation manipulation can flip Boolean gates
- **ADE4-01 / ADE4-02 (Gate / Conjunction Inversion):** Lineage spoofing (ADE3-05) poisons parent fields used in exclusion filters

## Testing Your Rules

**Quick Test Questions:**

**For ADE3-01:**
- ✅ Does your rule only check process names, not hashes/signatures?
- ✅ Can the target binary be copied by users with expected privileges?
- ✅ Would renaming the binary bypass detection?

**For ADE3-02:**
- ✅ Can an attacker see current aggregation baselines?
- ✅ Are thresholds/counts visible to compromised accounts?
- ✅ Could preparatory "benign" activity poison aggregations?

**For ADE3-03:**
- ✅ Does your rule have hard-coded time windows (maxspan, lookback)?
- ✅ Could an attacker wait out the time constraint?
- ✅ Are file age checks based on attacker-controllable timestamps?

**For ADE3-04:**
- ✅ Does your rule use multi-substring matching (`contains|all`)?
- ✅ Are you matching against command-line fields?
- ✅ Could shell operators fragment the command?

**For ADE3-05:**
- ✅ Does your rule alert on, or exclude by, the parent process (`ParentImage`, `process.parent.*`)?
- ✅ Can the attacker create processes with a chosen parent at the assumed privilege level?
- ✅ Does your telemetry expose the real creator (ETW event header, EDR real-parent field), or only the reported parent?

**For ADE3-06:**
- ✅ Does your rule use a `join`, a subsearch, a group-by over high-cardinality keys, or a `sort`?
- ✅ Is the bounded side filtered only by event type, rather than narrowed toward the records the rule needs?
- ✅ Could the volume on that side exceed the engine's default limit in your largest environment and search window?
- ✅ Does a rarity or threshold filter run *after* a group limit that keeps only the top-N?

If you answered "yes" to any category's questions, your rule likely has an ADE3 vulnerability.
