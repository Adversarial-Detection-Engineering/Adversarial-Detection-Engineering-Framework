# ADE3-04 Example: Event Fragmentation - LSASS Process Reconnaissance

**Bug Category:** ADE3-04 Context Development - Event Fragmentation

## Pseudo-Code Example

**Rule Intent:** Detect attempts to identify or enumerate the LSASS (Local Security Authority Subsystem Service) process on Windows systems.

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        Image|endswith: '\cmd.exe'
    selection_findstr:
        CommandLine|contains|all:
            - 'tasklist'
            - 'findstr'
            - 'lsass'
    condition: all of selection_*
```

## The Bug

**Detection logic expects:** A single process creation event containing all three substrings: `tasklist`, `findstr`, and `lsass`

**Reality:** Shell operators (`|`, `&`, `&&`, `||`) **fragment commands** into **multiple separate process creation events** at the OS level.

**Implicit assumption:** All command components appear in a single event

**What actually happens:** Each part of a piped command generates a distinct event

## Command Fragmentation Behavior

### Expected Command
```cmd
tasklist | findstr "lsass"
```

### Actual Process Creation Events

**Event 1:**
```
Image: C:\Windows\System32\tasklist.exe
CommandLine: tasklist
```

**Event 2:**
```
Image: C:\Windows\System32\findstr.exe
CommandLine: findstr "lsass"
```

## Detection Logic Evaluation

**Rule requires:**
```yaml
CommandLine|contains|all:
    - 'tasklist'    ✓ (Event 1)
    - 'findstr'     ✓ (Event 2)
    - 'lsass'       ✓ (Event 2)
```

**Problem:** No single event contains all three substrings simultaneously

- Event 1: `tasklist` → Contains "tasklist" only
- Event 2: `findstr "lsass"` → Contains "findstr" and "lsass" only

**Result:** `CommandLine|contains|all` = **False** for all events → **False Negative**

## Why This Happens

### Windows Command Processing

When you execute:
```cmd
tasklist | findstr lsass
```

Windows shell:
1. Spawns `tasklist.exe` (writes to stdout)
2. Spawns `findstr.exe` (reads from stdin)
3. Each spawn = separate Event ID 4688 (process creation)

### Shell Operators That Fragment

All of these cause command fragmentation:

**Pipe:**
```cmd
command1 | command2
```

**Background execution:**
```cmd
command1 & command2
```

**Conditional execution:**
```cmd
command1 && command2
command1 || command2
```

## Caveat: a wrapping cmd.exe carries the whole pipe

The False Negative above assumes each stage is its own top-level process. If the pipe is launched as a single quoted argument — `cmd.exe /c "tasklist | findstr lsass"` — the **wrapping `cmd.exe`** process has the entire pipe on its own `CommandLine`, so a rule scoped to `cmd.exe` with `contains|all` *would* match that one event. The fragmentation gap holds when there is no such wrapping parent: the pipe typed at an interactive shell (the shell is already running; its own command line is just `cmd.exe`), or each stage launched separately. State the launch context when writing or testing the rule, and prefer per-child detection plus parent correlation so both shapes are covered.

## Related Research

- [Detection Pitfalls by Daniel Koifman](https://detect.fyi/detection-pitfalls-you-might-be-sleeping-on-52b5a3d9a0c8)
- [Unintentional Evasion: Command Line Logging Gaps by Kostas](https://detect.fyi/unintentional-evasion-investigating-how-cmd-fragmentation-hampers-detection-response-e5d7b465758e)

## Impact

**False Negative:** In-scope malicious activity (LSASS process enumeration) bypasses detection without the attacker needing to know the rule exists.

**Critical insight:** This isn't deliberate evasion - it's **unintentional** bypass caused by how operating systems process shell commands.

## Vulnerable Detection Patterns

**Any rule using multi-substring matching:**

**Sigma:**
```yaml
CommandLine|contains|all:
    - 'string1'
    - 'string2'
    - 'string3'
```

**KQL:**
```kql
CommandLine has_all ("string1", "string2", "string3")
```

---

**Related Documentation:**
- [ADE3 Context Development](../../docs/taxonomy/ade3-context-development.md)
- [Detection Logic Bug Theory](../../docs/theory/detection-logic-bugs.md)
