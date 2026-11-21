# Detection Logic Exposures (DLE)

[![Author](https://img.shields.io/badge/Author-Nikolas_Bielski-blue)](https://github.com/NikolasBielski)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/Adversarial-Detection-Engineering/Adversarial-Detection-Engineering-Framework)](https://github.com/Adversarial-Detection-Engineering/Adversarial-Detection-Engineering-Framework/commits/main)
[![GitHub License](https://img.shields.io/github/license/Adversarial-Detection-Engineering/Adversarial-Detection-Engineering-Framework)](https://github.com/Adversarial-Detection-Engineering/Adversarial-Detection-Engineering-Framework/blob/main/LICENSE)

A catalog of real-world detection rule bypasses arising from ADE Detection Logic Bugs.

## Why this exists

Detection rules fail for repeatable, structural reasons. These reasons are found in the [Adversarial Detection Engineering framework (ADE)](https://github.com/Adversarial-Detection-Engineering/Adversarial-Detection-Engineering-Framework/) as 12 bug categories.

Today, those failures are discussed informally as “evasion,” “edge cases,” or “bypasses,” but they are rarely documented in a consistent, reusable way. 

DLE exists to record **concrete real-world bypasses of detection rules** and map them to **known detection logic weakness classes (ADEs)**, in a way similar to [CVEs](https://www.cve.org/).

## ADE vs DLE

This project distinguishes between two layers:

- **ADE (Detection Bugs Theory and Taxonomy)**  
  A taxonomy of detection logic bug classes (similar to CWE).

- **DLE (Detection Logic Exposures)**  
  Instance-level documentation of how a specific detection rule is bypassed due to an ADE weakness (similar to CVE). Submitted and reviewed bypasses get assigned a DLE identifier with public recognition.

## What a DLE is

A DLE documents and tracks:
- A specific detection rule or logic pattern
- The ADE bug(s) it exhibits
- How that weakness allows the rule to be bypassed
- The impact on detection outcomes
- Instructions to patch
- Credit to the submitter

A DLE does **not**:
- Describe a software vulnerability
- Provide exploit payloads
- Assign risk scores
- Attribute blame to vendors or teams

## DLE entry structure

Each DLE entry contains:

- **DLE ID** (e.g. DLE-2026-00001)
- **Related ADE** (e.g. ADE3-03 – Timing & Scheduling, ADE2-02 - Versioning)
- **Affected detection logic** (the specific rule)
- **Bypass description** (how the rule is bypassed)
- **Credit** (how the rule is bypassed)
- **Assumption violated** (what root causes contributed the bugs)
- **Likelihood** (the likelihood of bypass)
- **Complexity** (the complexity of bypass)
- **Impact** (the impact of bypass)
- **Risk** (the impact of bypass)
- **Notes / mitigations** (optional)


DLE is intended to evolve through real-world detection engineering experience and constructive disagreement.


## Entries

| ID | Related ADE | Affected detection logic | Platform |
|:---|:------------|:-------------------------|:---------|
| [DLE-2026-00001](./2026/DLE-2026-00001.yaml) | ADE1-01 | Use Get-NetTCPConnection | Windows |
| [DLE-2026-00002](./2026/DLE-2026-00002.yaml) | ADE1-01, ADE2-01 | Suspicious PowerShell Download | Windows |
| [DLE-2026-00003](./2026/DLE-2026-00003.yaml) | ADE1-01 | Triple Cross eBPF Rootkit Default Persistence | Linux |
| [DLE-2026-00004](./2026/DLE-2026-00004.yaml) | ADE2-01, ADE2-02 | Changes to Internet Facing AWS RDS Database Instances | AWS |
| [DLE-2026-00005](./2026/DLE-2026-00005.yaml) | ADE2-04, ADE3-02, ADE4-01 | Ingress Transfer via Windows BITS | Windows |
| [DLE-2026-00006](./2026/DLE-2026-00006.yaml) | ADE3-02, ADE3-01 | AWS CLI Command with Custom Endpoint URL | Linux |
| [DLE-2026-00007](./2026/DLE-2026-00007.yaml) | ADE3-02 | AWS CLI Command with Custom Endpoint URL | Linux |
| [DLE-2026-00008](./2026/DLE-2026-00008.yaml) | ADE3-02, ADE4-01 | Ingress Transfer via Windows BITS | Windows |
| [DLE-2026-00009](./2026/DLE-2026-00009.yaml) | ADE3-01, ADE3-02, ADE3-03 | Collection Email Outlook Mailbox Via COM | Windows |
| [DLE-2026-00010](./2026/DLE-2026-00010.yaml) | ADE3-01 | AWS CLI Command with Custom Endpoint URL | Linux |
| [DLE-2026-00011](./2026/DLE-2026-00011.yaml) | ADE3-01 | Network Activity Detected via cat | Linux |
| [DLE-2026-00012](./2026/DLE-2026-00012.yaml) | ADE3-01 | Wget Creating Files in Tmp Directory | Linux |
| [DLE-2026-00013](./2026/DLE-2026-00013.yaml) | ADE3-02, ADE3-01 | First Time Seen Commonly Abused Remote Access Tool Execution | Windows |
| [DLE-2026-00014](./2026/DLE-2026-00014.yaml) | ADE4-01, ADE3-02, ADE2-04 | Ingress Transfer via Windows BITS | Windows |
| [DLE-2026-00015](./2026/DLE-2026-00015.yaml) | ADE4-01 | PowerShell Suspicious Script with Audio Capture Capabilities | Windows |
| [DLE-2026-00016](./2026/DLE-2026-00016.yaml) | ADE4-03 | Suspicious Shell Script Detected | Linux |

## Disclaimer
⚠️ Important: DLE is intended solely for defensive security research, detection engineering, and risk assessment. Its purpose is to help defenders identify, reason about, and remediate weaknesses in detection logic and security monitoring systems.

Users are solely responsible for ensuring that their use complies with all applicable laws, regulations, and authorization requirements. The authors and collaborators assume no liability for misuse, damage, or harm resulting from use of this framework.

Authorization Required: Always obtain explicit written authorization before testing detections, systems, or controls outside environments you own or operate.

Responsible Disclosure: Examples are provided with responsible disclosure considerations. Detection rules and monitoring content are generally out of scope for vendor vulnerability disclosure and bug bounty programs.

No Warranty: This framework is provided "as is," without warranty of any kind, express or implied.

## Why no CVSS?

DLE does not include CVSS scores because they are not applicable to detection logic bypasses.  
CVSS was designed to rate the intrinsic severity of software vulnerabilities, considering exploitability and impact on system confidentiality, integrity, and availability.  

Detection Logic Exposures (DLEs), by contrast, document how detection rules fail due to ADE weaknesses. Their impact is highly contextual: the same bypass may be critical in one environment and negligible in another. Assigning a static numerical severity would be misleading, distract from ADE and DLE mission, and could encourage misinterpretation or misuse.  

By omitting CVSS, DLE remains focused on understanding, documenting, and mitigating detection logic weaknesses rather than providing prescriptive risk rankings.
