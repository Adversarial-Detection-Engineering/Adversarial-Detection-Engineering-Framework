# ADE3-02 Example: AWS CLI New Terms Aggregation Hijacking

**Bug Category:** ADE3-02 Context Development - Aggregation Hijacking

## Original Rule

**Source:** [Elastic Security - AWS CLI Command with Custom Endpoint URL](https://github.com/elastic/detection-rules/blob/main/rules/linux/command_and_control_aws_cli_endpoint_url_used.toml)

**Description:** Searches for use of AWS CLI with a `--endpoint-url` argument, which allows users to specify a custom endpoint URL for AWS services. The action can be leveraged by attackers to redirect API requests to malicious endpoints for C2 or exfiltration.

```SQL
query = '''
host.os.type:"linux" and event.category:"process" and
event.action:("exec" or "exec_event" or "executed" or "process_started" or "ProcessRollup2") and
process.name:"aws" and process.args:"--endpoint-url"
'''
```

**Rule Type:** New Terms

```yaml
type = "new_terms"
timestamp_override = "event.ingested"

[rule.new_terms]
field = "new_terms_fields"
value = ["host.id"]

[[rule.new_terms.history_window_start]]
field = "history_window_start"
value = "now-3d"
```

## Detection Logic Analysis

**How it works:**

At every rule execution, the last 3 days worth of data is grouped per `host.id`. When the current scheduled runtime output is not observed in that historical data, it outputs a hit with the `host.id` as the term in the alert.

**Intent:** Flag first-time use of `aws` with custom endpoints on a host.

**Bug:** The aggregation uses only `host.id`, which is too abstract and can be hijacked.

## The Bug: ADE3-02 Context Development - Aggregation Hijacking

**Definition:** Detection logic relies on aggregated values that an attacker can influence or precondition.

**In this case:**
- Rule groups by `host.id` only (all users bundled together)
- Attacker can perform reconnaissance to determine if `aws --endpoint-url` has been used in the last 3 days
- If found, repeat usage will aggregate into existing baseline → No alert

**Key Issue:** New terms aggregation hijacking is **context-dependent** and not guaranteed every time.

## False Negative Situations

### Scenario 1: Existing history of `aws` usage

#### Non-root user compromise

A **non-root user** (compromised account trying to run `aws` illegitimately) can:

1. Check bash history:
   ```bash
   cat ~/.bash_history | grep aws
   ```

2. If output shows recent `aws` use with `--endpoint-url` and history isn't flushed, attacker may hijack the aggregation

**Limitation:** Non-root can only see their own bash history, not other users.

**Outcome:** Not a definite False Negative, but possible if:
- `host.id` aggregation includes all users
- No output from user history
- `aws` is already installed

#### Root user compromise

With **root**, the context is different:

1. **Logging must be enabled** for logs to reach the detection rule
2. Root can view:
   - All EXECVE messages in last 3 days (via `journalctl`)
   - Information in `/proc/*` pointing to `aws`
   - Shell usage of all users

3. **Attack pattern:**
   - Search logs for previous `aws --endpoint-url` usage
   - If found within last 3 days, repeat usage will be aggregated into existing baseline
   - No alert generated

**This is ADE3-02 Context Development - Aggregation Hijacking:**
- Attacker develops context to abuse bug in detection logic
- Bug: New terms field list too abstract (`host.id` only)

### Scenario 2: When `aws` doesn't exist

If the host doesn't have AWS CLI pre-installed:

**Attack chain (behavioral steering):**

1. Use ADE3-01 (Process Cloning) to clone/copy `wget` or `curl`
2. Bypass wget/curl detection rules to download files
3. Extract AWS CLI into compromised account's home directory (no root needed)
4. `chmod +x` the user-owned binary
5. Generate seemingly legitimate `aws` usage with bogus endpoint:
   ```bash
   ./aws s3 ls --endpoint-url https://configsnapshot-s3-endpoint.TARGETS_LEGIT_DOMAIN.com
   ```
   - Or even `--endpoint-url 8.8.8.8` (doesn't need to work)

6. Hope SOC incorrectly triages as False Positive (seeing customer's legitimate domain)
7. Wait for triage outcome
8. If triaged as FP, repeat malicious usage → aggregated into baseline

**This is "Behavioral Steering":**
- Attacker stacks multiple detection rule bugs during kill chain
- Mentioned in [Detection Logic Bug Theory](https://github.com/Adversarial-Detection-Engineering/Adversarial-Detection-Engineering-Framework/blob/main/docs/theory/detection-logic-bugs.md)

## Important Caveats

### Not guaranteed every time

In **ADE3-02 Context Development - Aggregation Hijacking**, if the bug relates to new terms aggregation:

- **Not always guaranteed** to be abused
- **Highly dependent** on context of resources
- This is why it's called "context development"

### The bug is in the design

**Bug:** Detection logic relies on too few terms for aggregation

**Assumes:** Each entity being aggregated doesn't have lower-level uniqueness that could reduce False Negatives

**Fix:** Include additional fields:
```yaml
# Instead of just host.id
new_terms_fields: ["host.id", "user.name", "process.args"]
```

### "But root can disable logging"

**Correct**, but:
- Drop in heartbeat/logging should trigger immediate SOC alert
- MITRE ATT&CK TTPs for logging disablement exist ([T1548](https://attack.mitre.org/techniques/T1548))
- Detection logic bug cannot be abused without logs
- Disabling logging **bypasses search** (not detection logic)
- ADE formalizes **bugs in detection logic**, not bypass techniques outside detection

## Impact

**False Negative:** Attacker with compromised account can:
- Perform reconnaissance on host to check for previous `aws` usage
- If found, hijack aggregation by repeating pattern
- Use custom endpoints for C2/exfiltration without triggering alert

**Context-dependent:** Requires:
- Previous `aws --endpoint-url` usage within 3-day window
- OR ability to generate false positive to poison baseline

## Related Bugs

This rule also contains:

**ADE3-01:** Process Cloning ([see example](process-cloning-aws-cli.md))
- `process.name` is mutable
- Attacker can clone `aws` binary to different name

---

**Related Documentation:**
- [ADE3 Context Development](../../docs/taxonomy/ade3-context-development.md)
- [ADE3-01 Process Cloning Example](process-cloning-aws-cli.md)
- [Detection Logic Bug Theory](../../docs/theory/detection-logic-bugs.md)
