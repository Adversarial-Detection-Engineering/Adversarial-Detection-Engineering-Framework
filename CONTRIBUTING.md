# Contributing to the ADE Framework

Thank you for your interest in contributing to the Adversarial Detection Engineering (ADE) Framework! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Contribution Workflow](#contribution-workflow)
- [Style Guidelines](#style-guidelines)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Enhancements](#suggesting-enhancements)

## Code of Conduct

This project is committed to providing a welcoming and inclusive environment. Please be respectful and professional in all interactions.

## How Can I Contribute?

### High-Priority Contributions

#### 1. Static Analyzer Development

Help build tools to automatically detect detection logic bugs:

**What we need:**
- Parsers for detection rule languages (Sigma, KQL, EQL, SPL, etc.)
- AST-based analysis to identify ADE bug patterns
- CI/CD pipeline integration
- IDE plugins for real-time analysis

**Tech stack suggestions:**
- Python (rule parsing, analysis logic)
- Tree-sitter grammars for query languages
- GitHub Actions/GitLab CI integration
- VS Code extension API

#### 2. Bug Repository Expansion

Identify and document new detection logic bugs:

**What we need:**
- Analysis of additional vendor rulesets
- Testing against new platforms (macOS, cloud platforms, containers)
- Community-discovered bypasses
- Cross-platform bug patterns

**Platforms to analyze:**
- CrowdStrike Falcon
- SentinelOne
- Splunk Enterprise Security
- Chronicle SIEM
- Open-source tools (Wazuh, OSSEC, Suricata)

### General Contributions

#### Documentation

- Improve clarity of existing documentation
- Fix typos and formatting issues
- Add diagrams and visualizations
- Translate documentation to other languages
- Create video tutorials or presentations

#### Examples

- Add new real-world bug examples
- Improve existing example documentation
- Create proof-of-concept bypasses
- Document mitigation strategies

#### Taxonomy

- Propose new bug categories
- Refine existing category definitions
- Add cross-references between categories
- Map bugs to MITRE ATT&CK techniques

#### Testing

- Develop testing frameworks for detection rules
- Create test cases for known bugs
- Build validation tools
- Automated regression testing

## Contribution Workflow

### 1. Fork the Repository

```bash
git clone https://github.com/[your-username]/Adversarial-Detection-Engineering-Framework.git
cd Adversarial-Detection-Engineering-Framework
```

### 2. Create a Branch

Use descriptive branch names:

```bash
# For new features
git checkout -b feature/add-ade5-category

# For bug fixes
git checkout -b fix/broken-link-in-docs

# For examples
git checkout -b example/splunk-ade2-01

# For documentation
git checkout -b docs/improve-quick-start
```

### 3. Make Your Changes

Follow the [Style Guidelines](#style-guidelines) below.

### 4. Test Your Changes

- **Documentation:** Verify all links work and markdown renders correctly
- **Examples:** Test bypasses and ensure they're reproducible
- **Code:** Run linters and tests if applicable

### 5. Commit Your Changes

Write clear commit messages:

```bash
git commit -m "Add ADE2-01 example for Splunk correlation search

- Document omitted API alternative in user authentication rule
- Include reproducible bypass technique
- Add mitigation recommendations"
```

### 6. Push and Create Pull Request

```bash
git push origin your-branch-name
```

Then create a Pull Request on GitHub with:
- **Title:** Clear, concise description of changes
- **Description:** Detailed explanation of what and why
- **Related Issues:** Reference any related issues (#123)
- **Testing:** Describe how you tested your changes

## Style Guidelines

### Markdown Documentation

**File naming:**
- Use lowercase with hyphens: `detection-logic-bugs.md`
- Be descriptive: `ade1-powershell-download-bypass.md`

**Structure:**
- Use clear heading hierarchy (# → ## → ###)
- Include navigation links at bottom of pages
- Add a table of contents for long documents
- Use code blocks with language specifiers

**Example:**
````markdown
# Title

Brief introduction.

## Section 1

Content here.

## Section 2

More content.

---

**Navigation:**
- [← Previous Page](prev.md)
- [Next Page →](next.md)
````

### Example Documentation

All examples should follow this structure:

````markdown
# [ADE Category] Example: [Brief Description]

**Bug Category:** ADE#-## [Category Name]

## Original Rule

**Source:** [Link to original rule]

**Description:** [What the rule intends to detect]

```[language]
[Original detection logic]
```

## The Bug

[Explanation of the detection logic bug]

## Bypass

### [Bypass Name]

```[language]
[Bypass code/technique]
```

**Result:** [What happens when bypass is used]

## Impact

[Description of False Negative impact]

---

**Related Documentation:**
- [Link to taxonomy page]
- [Link to theory page]
````

### Code Contributions

**Python:**
- Follow PEP 8 style guide
- Use type hints
- Include docstrings
- Add unit tests

**JavaScript/TypeScript:**
- Follow Airbnb style guide
- Use ESLint
- Include JSDoc comments
- Add unit tests

### Taxonomy Contributions

When proposing new bug categories:

1. **Provide formal definition**
2. **Include at least 3 real-world examples**
3. **Show reproducible bypasses**
4. **Explain detection patterns vulnerable to the bug**
5. **Suggest mitigation strategies**
6. **Map to existing ADE categories if overlapping**

## Reporting Bugs

### Security Vulnerabilities

**Do NOT** open public issues for security vulnerabilities in the framework itself.

Contact maintainers privately:
- Nikolas Bielski: [LinkedIn](https://www.linkedin.com/in/nikbielski/)
- Daniel Koifman: [LinkedIn](https://www.linkedin.com/in/koifman-daniel/)

### Non-Security Bugs

Open a GitHub issue with:

**Title:** Clear, concise bug description

**Content:**
- **Description:** What's wrong?
- **Steps to Reproduce:** How to trigger the bug
- **Expected Behavior:** What should happen
- **Actual Behavior:** What actually happens
- **Environment:** OS, browser, tools used
- **Screenshots:** If applicable

## Suggesting Enhancements

Open a GitHub issue with:

**Title:** `[Enhancement] Your idea`

**Content:**
- **Problem:** What problem does this solve?
- **Proposed Solution:** Your suggested approach
- **Alternatives:** Other approaches you considered
- **Additional Context:** Mockups, examples, references

## Example Contributions

### Adding a New Bug Example

1. **Identify the bug:** Find a detection rule with a logic bug
2. **Categorize:** Map to ADE taxonomy (ADE1-01, ADE2-01, etc.)
3. **Test bypass:** Create reproducible False Negative
4. **Document:**
   - Create file in `examples/ade#/`
   - Follow example template
   - Link from taxonomy page
5. **Submit PR:** Include testing evidence

### Improving Documentation

1. **Identify issue:** Typo, unclear explanation, broken link
2. **Fix:** Make targeted improvements
3. **Test:** Verify links and rendering
4. **Submit PR:** Explain what you fixed and why

### Proposing New Taxonomy Category

1. **Research:** Ensure it's not covered by existing categories
2. **Document:**
   - Formal definition
   - Multiple real-world examples
   - Mitigation strategies
3. **Discuss:** Open issue to discuss before PR
4. **Submit PR:** After community feedback

## Recognition

Contributors will be recognized in:
- GitHub contributors list
- Release notes for significant contributions
- Potential co-authorship for major additions

## Questions?

- **General questions:** Open a GitHub Discussion
- **Bug reports:** Open a GitHub Issue
- **Private inquiries:** Contact maintainers via LinkedIn

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to the ADE Framework!**

We appreciate your efforts to improve detection engineering and help defenders get ahead of threats.
