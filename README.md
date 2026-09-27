# Adversarial Detection Engineering (ADE) Framework

[![Author](https://img.shields.io/badge/Author-Nikolas_Bielski-blue)](https://github.com/NikolasBielski)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/NikolasBielski/Adversarial-Detection-Engineering-Framework)](https://github.com/NikolasBielski/Adversarial-Detection-Engineering-Framework/commits/main)
[![GitHub License](https://img.shields.io/github/license/NikolasBielski/Adversarial-Detection-Engineering-Framework)](https://github.com/NikolasBielski/Adversarial-Detection-Engineering-Framework/blob/main/LICENSE)

**Get ahead of False Negatives** by understanding how detection logic fails before threat actors abuse it.

Check out the website: [https://adeframework.org/](https://adeframework.org/)

## What Is ADE?

Adversarial Detection Engineering (ADE) is the discipline of reasoning about **False Negatives in detection rules**. The ADE Framework provides a modern open-source formalization of **Detection Logic Bugs** - mismatches between what a detection rule *intends* to detect and what it *actually* detects.

### The ADE Advantage

Instead of waiting for real-world False Negatives, detection engineers can proactively ask:

> *"What variations would cause this rule's detection logic to miss what it was intended to catch?"*

This adversarial line of reasoning mirrors how threat actors can abuse weaknesses in detection logic.

## Key Features

- ✅ **Identify reproducible detection logic bugs** and map them to formal ADE categories
- ✅ **Embed an attacker's mental model** into how detection logic is designed and reviewed
- ✅ **Expose structural weaknesses** in rules used for hunts or production MDR tooling (SIEM, XDR, EDR)
- ✅ **Equip security teams** with actionable detection logic bug intelligence
- ✅ **Get ahead of False Negatives** before threat actors discover and exploit them

## ADE Purpose

The purpose of ADE is not to force perfection in design, although that is an ideal goal - but to raise awareness and track limitations, even if intentional:
- ADE is not about demanding perfect detection rules; it is about making the risk of false-negatives visible.
- Many rules intentionally contain limitations due to scope, signal quality, or operational constraints, and these may still be mapped to ADE bug types without being “wrong.”
- ADE provides a shared way to document, accept, mitigate, or compensate for those risks across a ruleset, rather than judging individual rules in isolation.

## ADE link to Detection Logic Exposures (DLE)

- ADE supplies a canonical taxonomy and bug classes for detection logic bugs.
- [DLE](https://github.com/NikolasBielski/Adversarial-Detection-Engineering-Framework/tree/main/dle) provides a recognized list of publically disclosed bypasses with ADE mappings. 

## Quick Start

**New to ADE?** Start here:

1. **[Introduction](docs/getting-started/introduction.md)** - Understand what ADE is and why it matters
2. **[Core Concepts](docs/getting-started/core-concepts.md)** - Learn the foundational terminology
3. **[Quick Start Guide](docs/getting-started/quick-start.md)** - Apply ADE to your first detection rule
4. **[Bug Likelihood Test](docs/guides/bug-likelihood-test.md)** - Quick checklist to assess rules for bugs

**Ready to dive deep?**

- [Detection Logic Bug Theory](docs/theory/detection-logic-bugs.md) - Formal foundations
- [Taxonomy Overview](docs/taxonomy/overview.md) - All bug categories
- [Examples](examples/) - Real-world examples

## ADE Detection Logic Bug Taxonomy

The framework identifies **4 major categories** and **15 subcategories** of detection logic bugs:

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

**[→ Explore the Full Taxonomy](docs/taxonomy/overview.md)**

## What the Framework Provides

### 1. Theory of Detection Logic Bugs

[Formal definitions](docs/theory/detection-logic-bugs.md) and theoretical foundation:
- What constitutes a detection logic bug
- How bugs create False Negatives
- Relationship between scope and detection logic
- Concept of Rule Bypasses

### 2. Formal Bug Taxonomy

[Comprehensive classification](docs/taxonomy/overview.md) with clear terminology:
- 4 major categories
- 15 detailed subcategories
- Consistent labeling system (ADE1-01, ADE2-01, etc.)
- Mapping to real-world detection rules

### 3. Real-World Examples

Concrete examples from production rulesets:
- **[Sigma](https://github.com/SigmaHQ/sigma)** detection rules
- **[Microsoft Sentinel](https://github.com/Azure/Azure-Sentinel)** analytics
- **[Elastic Security](https://github.com/elastic/detection-rules)** SIEM & EDR rules

**Example Categories:**
- [ADE1 Examples](examples/ade1/) - String manipulation bypasses
- [ADE2 Examples](examples/ade2/) - Omitted alternatives
- [ADE3 Examples](examples/ade3/) - Context development
- [ADE4 Examples](examples/ade4/) - Logic manipulation

### 4. Practical Tools

- **[Bug Likelihood Test](docs/guides/bug-likelihood-test.md)** - Quick pre-analysis checklist
- **[Quick Start Guide](docs/getting-started/quick-start.md)** - Step-by-step application process

## How ADE Complements Existing Frameworks

ADE integrates with and enhances existing detection engineering practices:

| Framework | Focus | ADE Integration |
|:----------|:------|:----------------|
| **[MITRE ATT&CK](https://attack.mitre.org/)** | Attack techniques & tactics | ADE explains *why* detection fails for ATT&CK techniques |
| **[MITRE CAR](https://car.mitre.org/)** | Detection analytics repository | ADE provides bug taxonomy for CAR analytics |
| **[Detection Engineering Lifecycle](https://github.com/Ke0xes/Detection-Engineering-Framework)** | Engineering workflow phases | ADE is the reasoning framework for the **Improvement Phase** |
| **Sigma/YARA/KQL** | Rule syntax & formatting | ADE analyzes *semantic logic bugs* across all query languages |

**ADE's unique value:** Formal logic-level classification of False Negative causes

## Maintainers

- [Nikolas Bielski](https://www.linkedin.com/in/nikbielski/) - Framework author & lead maintainer
- [Daniel Koifman](https://www.linkedin.com/in/koifman-daniel/) - Co-maintainer

## Contributing

We welcome contributions! Areas of active development include:

### High Priority

- **Static Analyzer Development** - Tools to analyze detection rules for potential logic bugs
  - Designed for Detection-as-Code CI/CD pipelines
  - IDE integration support

- **Bug Repository Expansion** - Curated collection of identified bugs
  - Cross-platform rule analysis
  - Vendor ruleset assessment
  - Community-submitted bypasses

### General Contributions

- Documentation improvements
- New examples from additional vendors/platforms
- Taxonomy refinement based on emerging techniques
- Testing frameworks and validation tools

**[See CONTRIBUTING.md for details →](CONTRIBUTING.md)**

## Use Cases

### For Detection Engineers

1. **Pre-deployment review** - Apply ADE taxonomy before deploying new rules
2. **Systematic improvement** - Audit existing rules using the Bug Likelihood Test
3. **Documentation** - Record known limitations when bugs can't be immediately fixed
4. **Prioritization** - Focus efforts on high-severity bugs

### For Security Researchers

1. **Formalize bypasses** - Map discovered evasions to ADE categories
2. **Contribute discoveries** - Expand taxonomy with new bug classes
3. **Vendor analysis** - Objectively assess detection capabilities

### For Red Teams

1. **Realistic testing** - Use ADE to test blue team detection capabilities
2. **Actionable feedback** - Provide structured bypass intelligence
3. **Training scenarios** - Develop detection evasion exercises

### For SOC/Threat Hunters

1. **Root cause analysis** - Understand why attacks weren't detected
2. **Coverage assessment** - Identify gaps in monitoring
3. **Vendor evaluation** - Test tooling against ADE taxonomy

## Roadmap

**Planned developments:**

- 🔨 **Static Analysis Tooling** - Automated bug detection for CI/CD
- 📚 **Expanded Bug Repository** - Community-driven collection

## License

| Characteristic               | Value       |
|------------------------------|-------------|
| Based on                     | [MIT license](https://opensource.org/licenses/MIT) |
| Distribution                 | Yes         |
| Modification                 | Yes         |
| Private Use                  | Yes         |
| Commercial Use               | Yes         |
| Liability                    | No          |
| Warranty                     | No          |
| License and Copyright Notice | Yes         |
| Author Attribution           | Required    |

## Disclaimer

⚠️ **Important:** This framework is intended solely for **defensive security research**, detection engineering, and risk assessment. Its purpose is to help defenders identify, reason about, and remediate weaknesses in detection logic and security monitoring systems.

Users are solely responsible for ensuring that their use complies with all applicable laws, regulations, and authorization requirements. The authors and collaborators assume no liability for misuse, damage, or harm resulting from use of this framework.

**Authorization Required:** Always obtain explicit written authorization before testing detections, systems, or controls outside environments you own or operate.

**Responsible Disclosure:** Examples are provided with responsible disclosure considerations. Detection rules and monitoring content are generally out of scope for vendor vulnerability disclosure and bug bounty programs.

**No Warranty:** This framework is provided "as is," without warranty of any kind, express or implied.

## Contact

- GitHub Issues: [Report bugs or request features](https://github.com/NikolasBielski/Adversarial-Detection-Engineering-Framework/issues)
- LinkedIn: [Nikolas Bielski](https://www.linkedin.com/in/nikbielski/) | [Daniel Koifman](https://www.linkedin.com/in/koifman-daniel/)

