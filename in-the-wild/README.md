# In-the-Wild Detection Bypasses

A catalog of threat actors observed using detection bypass techniques in real intrusions, mapped to ADE Detection Logic Bugs.

## Why this exists

Most ADE examples and DLE entries are constructed: someone reads a detection rule, finds the assumption it makes, and shows input that breaks it. That is the point of ADE, getting ahead of False Negatives before threat actors find them.

Sometimes a threat actor gets there first. Public threat reports occasionally show operators shaping their commands to slip past a known detection pattern. These cases are rare, and they are the strongest evidence that ADE bug classes are exploited in practice, not only in theory. This catalog collects them so they are not lost inside long malware write-ups.

## ADE vs DLE vs In-the-Wild

- **ADE (Detection Bugs Theory and Taxonomy)**  
  A taxonomy of detection logic bug classes (similar to CWE).

- **DLE (Detection Logic Exposures)**  
  Instance-level documentation of how a specific detection rule is bypassed due to an ADE weakness (similar to CVE).

- **In-the-Wild (ITW)**  
  A threat actor observed using a bypass technique in a real intrusion (similar to [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)).

An ITW entry does not need a named rule. Threat reports usually describe the evasion generically ("exact-string detections for msiexec /package do not match") rather than naming the rule that missed. When a public rule is confirmed to be affected, the ITW entry links to the matching DLE through `related_dle`.

## Inclusion criteria

An entry needs:
- A public report describing the activity as observed in a real intrusion. Proofs of concept, red team tool defaults, and lab demonstrations belong in [DLE](../dle/README.md) or the examples instead.
- The observed command, script, or artifact, quoted from the report with indicators defanged.
- A mapping to at least one ADE subcategory.
- Reasonable evidence that the technique was used to avoid detection, rather than being incidental formatting.

## Entry structure

Each entry is a YAML file named by its ID and contains:

- **id** (e.g. ITW-2026-00001, by year of first public report)
- **title**
- **related_ade** (e.g. ADE1-01 – Substring Manipulation)
- **technique_description** (what the attacker did and why detections miss it)
- **observed_command** (quoted from the source, defanged) — or **observed_artifact** when the technique has no distinguishing command line (a spoofed parent, a direct API/COM call)
- **unicode_blocks** (optional, for character-substitution techniques: the Unicode blocks the substituted characters come from, so detections can target the range)
- **assumption_violated** (the detection assumption the technique breaks)
- **observed** (malware family, actor or `unattributed`, delivery, first report date, sources)
- **reproduction** (whether the bypass was reproduced, how, and when: `confirmed`, `not_reproduced`, or `untested`)
- **related_dle** (DLE entries for public rules confirmed to be affected)
- **logsource** and **mitre_attack**
- **credit**
- **notes** (optional mitigations and context)

## Entries

| ID | Technique | ADE | Malware / Actor | Reported | Reproduced |
|:---|:----------|:----|:----------------|:---------|:-----------|
| [ITW-2026-00001](./ITW-2026-00001.yaml) | msiexec `/package` switch written with Unicode modifier letters | ADE1-01 | Azure30 / unattributed | 2026-10-09 | Confirmed |
| [ITW-2026-00002](./ITW-2026-00002.yaml) | regsvr32 `/i:` argument obfuscated with carets and quotes | ADE1-01 | APT32 | 2017-06-30 | — |
| [ITW-2026-00003](./ITW-2026-00003.yaml) | PowerShell command kept off the command line via env var + StdIn | ADE1-01 | FIN8 | 2017-06-30 | — |
| [ITW-2026-00004](./ITW-2026-00004.yaml) | cmd.exe character-replacement + string concatenation in a LNK | ADE1-01 | FIN7 | 2017-06-30 | — |
| [ITW-2026-00005](./ITW-2026-00005.yaml) | Mixed-case msiexec / explorer / http in commands | ADE1-01 | Raspberry Robin | 2022-05-05 | — |
| [ITW-2026-00006](./ITW-2026-00006.yaml) | Parent process spoofed to explorer.exe via UpdateProcThreadAttribute | ADE3-05 | Ursnif | 2022-12-22 | — |
| [ITW-2026-00007](./ITW-2026-00007.yaml) | Shadow-copy deletion through a COM interface instead of vssadmin | ADE2-01 | Hello ransomware | 2022-09-20 | — |

## Disclaimer
⚠️ Important: This catalog is intended solely for defensive security research, detection engineering, and risk assessment. Its purpose is to help defenders identify, reason about, and remediate weaknesses in detection logic and security monitoring systems.

Users are solely responsible for ensuring that their use complies with all applicable laws, regulations, and authorization requirements. The authors and collaborators assume no liability for misuse, damage, or harm resulting from use of this framework.

Authorization Required: Always obtain explicit written authorization before testing detections, systems, or controls outside environments you own or operate.

No Warranty: This framework is provided "as is," without warranty of any kind, express or implied.
