# ADE1 - Reformatting in Actions

Reformatting in Actions occurs when a detection rule relies on **string match conditions**, and an attacker can manipulate the collected logs such that the match fails.

This has been widely exploited by threat actors for years and still appears in modern SIEM rules.

## Subcategories

### ADE1-01: Substring Manipulation

**Definition:** When detection logic relies on substring matches, an attacker can alter or obfuscate the input data so that the hypothesis conditions are not met, resulting in a False Negative.

**Common Scenarios:**
- Command-line argument obfuscation
- Method/function name manipulation
- Filename or path string modification
- Registry key/value name changes
- Any attacker-controlled string field in logs

**Why It's a Bug:** Detection logic assumes attackers will use exact, unmodified strings. In reality, most string-based indicators can be trivially obfuscated through:
- String concatenation
- Variable substitution
- Encoding/escaping
- Case manipulation
- Whitespace insertion
- Token splitting

### ADE1-02: Normalization Asymmetry

**Definition:** When different branches of detection logic apply inconsistent normalization or parsing to the same field, resulting in logically identical values failing to correlate, producing a False Negative.

**Common Scenarios:**
- Joining on differently transformed UPNs or usernames
- Case normalization applied on only one side of a join
- GUID stripping applied inconsistently
- Domain suffix trimming in one pipeline but not another
- Regex extraction logic that differs between correlated events
- Comparing raw vs parsed JSON fields

**Why It's a Bug:** Detection logic assumes both sides of a comparison represent the same canonical value. When transformations differ prior to join or normalization the equality breaks.
- Multiple extraction methods for the same field
- Join failures (inner join)
- Mutable identifiers used as correlation keys
- Lack of canonicalization function reuse


## Examples

### Real-World Detection Logic Bugs

1. **[PowerShell Download Bypass](../../examples/ade1/powershell-download-bypass.md)**
   - Rule: Sigma - Suspicious PowerShell Download
   - Technique: Method name obfuscation via string concatenation
   - Platforms: Windows PowerShell Script Block Logging
   - ADE Category: ADE1-01 – Substring Manipulation

2. **[Triple Cross eBPF Rootkit Persistence](../../examples/ade1/triple-cross-rootkit.md)**
   - Rule: Sigma - Triple Cross eBPF Rootkit Default Persistence
   - Technique: Filename modification
   - Platform: Linux file events
   - ADE Category: ADE1-01 – Substring Manipulation

3. **[Get-NetTCPConnection Obfuscation](../../examples/ade1/get-nettcpconnection.md)**
   - Rule: Sigma - Use Get-NetTCPConnection
   - Technique: PowerShell command name concatenation
   - Platform: Windows process creation (Event ID 4688)
   - ADE Category: ADE1-01 – Substring Manipulation

4. **[AccountCreatedandDeletedinShortTimeframe.md](../../examples/ade1/AccountCreatedandDeletedinShortTimeframe.md)**
   - Rule: Kusto - AccountCreatedandDeletedinShortTimeframe
   - Technique: Inconsistent UPN normalization (GUID prefix stripping asymmetry)
   - Platform: Azure AD / Entra ID AuditLogs
   - ADE Category: ADE1-02 – Normalization Asymmetry

## Detection Rule Patterns Vulnerable to ADE1-01

**String matching operators that create risk:**
- `contains: 'exact_string'`
- `startswith: 'prefix'`
- `endswith: 'suffix'`
- Exact equality: `field: 'value'`

**When combined with attacker-controlled fields:**
- Command-line arguments
- Process names
- File names/paths
- Registry keys/values
- Script block content
- PowerShell cmdlet names
- URL paths
- Environment variables

## Related Bug Categories

ADE1-01 often appears alongside:
- **ADE2-01 (Omit Alternatives - Method/Binary):** Missing alternative methods that could achieve the same outcome
- **ADE4-01 (Logic Manipulation - Gate Inversion):** String manipulation used to flip negation conditions


## Detection Rule Patterns Vulnerable to ADE1-02

**Correlation patterns that create risk:**
- `join kind=inner on <string_field>`
- Correlation on mutable identifiers (UPN, email, displayName)
- Regex extraction applied in only one branch
- `trim()`, `replace()`, or `split()` used asymmetrically
- `tolower()` / `toupper()` applied on one side of comparison
- Partial JSON parsing vs full object parsing
- Comparing raw vs transformed values
- Multi-table joins without canonicalization layer

**When combined with normalization differences across pipelines:**
- Add vs Delete user events
- Sign-in vs Audit log correlation
- Cloud vs on-prem identity formats
- Guest vs member account naming formats
- Pre- and post-enrichment fields
- Parsed vs original log columns
- Legacy vs new schema versions

## Related Bug Categories

ADE1-02 often appears alongside:
- **ADE1-01 (Reformatting in Actions - Substring Manipulation)**
- **ADE3-03 (Context Development - Timing and Schedulling):** where Normalization Asymmetry occurs on the joining of current batch data to historics, the rule likely includes a timing or scheduling bug.

## Testing Your Rules

**Quick Test Questions:**
- Does your rule rely on exact string matches in attacker-controlled fields?
- Can the matched string be split across variables or concatenated?
- Are there encoding schemes (Base64, hex, URL encoding) that could bypass the match?
- Would case changes or whitespace insertion break detection?
- Do both sides of every join apply identical normalization to the join key?
- Are you joining on a mutable field (UPN, email, displayName) instead of an immutable ID?
- Are regex extractions different between correlated event types?
- Could two logically identical identities serialize differently across tables?
- Are guest / external / legacy account formats handled consistently?
- Are you parsing JSON in one pipeline but using raw strings in another?

If you answered "yes" to any of these, your rule likely has an ADE1 vulnerability.