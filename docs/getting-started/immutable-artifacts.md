# The Detection Engineer's Secret Weapon: Immutable Artifacts

Immutable artifacts are the unchangeable traces that attackers *must* leave behind to accomplish their objectives. They're the behavioral fingerprints that persist regardless of which tool is used, what the binary is named, or how cleverly the command line is obfuscated.

Think of it this way: An attacker can rename their executable, encode their commands, or even write their own custom tooling. But they cannot change the fundamental system-level operations required to achieve their goal.

**Mutable artifacts** (what many detections focus on):
- Process names (`psexec.exe`, `mimikatz.exe`)
- File paths (`C:\Windows\Temp\bad.exe`)
- Command-line strings (`-enc`, `-noprofile`)
- File hashes
- Known tool signatures

**Immutable artifacts** (what resilient detections target):
- Registry modifications that must occur
- API calls that must be made
- File system operations that must happen
- Network connections that must be established
- Permission changes that must be applied

The difference? Mutable artifacts are *controlled by the attacker*. Immutable artifacts are *required by the technique itself*.

## The Mindset Shift: From Lists to Graphs

John Lambert once said: "Defenders think in lists. Attackers think in graphs. As long as this is true, attackers win."

When we build detections around tool names and signatures, we're thinking in lists. We're saying: "If I see X, Y, or Z, then alert." But attackers don't work from a list - they navigate a graph of possibilities, constantly finding new paths to the same destination.

To truly defend, we need to shift our focus from *how* attackers do something to *what must happen* for them to succeed. This is where immutable artifacts become your north star.

## Real-World Examples

Let's see what this looks like in practice.

### Example 1: Windows Service Creation

**The Old Way (Mutable Detection):**
```
Alert if process = "sc.exe" AND command_line contains "create"
```

This works great... until the attacker:
- Renames `sc.exe` to `svcmanager.exe`
- Uses PowerShell's `New-Service` cmdlet instead
- Leverages WMI to create the service
- Writes a custom binary that calls Win32 APIs directly

**The New Way (Immutable Artifact):**

No matter which method an attacker uses to create a Windows service, they *must* create a registry key under:
```
HKLM\SYSTEM\CurrentControlSet\Services\[ServiceName]
```

This registry operation is unavoidable. It's baked into how Windows services work. By detecting registry modifications in this location (with SACL auditing enabled), you catch every technique - past, present, and future (hopefully!).

**Detection logic:**
```
Alert when:
  - Registry key created under HKLM\SYSTEM\CurrentControlSet\Services\*
  - Exclude accordingly
```

Yes, this requires more telemetry. Yes, it generates more data. But it catches *everything*.

### Example 2: Enabling Remote Desktop Protocol (RDP)

**The Old Way:**
```
Alert if process = "reg.exe" AND command_line contains "fDenyTSConnections"
```

Again, this misses:
- PowerShell registry modifications
- WMI/WMIC-based changes
- Custom scripts

**The New Way (Immutable Artifact):**

To enable RDP on Windows, the registry value `HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections` *must* be set to `0`. This is non-negotiable.

Here's what Metasploit does:
```ruby
reg_key = 'HKLM\System\CurrentControlSet\Control\Terminal Server'
registry_setvaldata(reg_key, 'fDenyTSConnections', 0, 'REG_DWORD')
```

Here's what WMIC does:
```cmd
wmic /node:localhost rdtoggle where ServerName='%COMPUTERNAME%' call SetAllowTSConnections 1
```

Different tools, different syntax—but both produce the exact same registry modification. That registry change is your immutable artifact.

**Detection logic:**
```
Alert when:
  - Registry value "fDenyTSConnections" is set to 0
  - In key: HKLM\System\CurrentControlSet\Control\Terminal Server
  - Exclude accordingly
```

### Example 3: Encoded PowerShell

Consider this very popular detection:
```
Alert if:
  - process_name = "powershell.exe"
  - command_line contains "-encodedcommand" OR "-enc"
```

Immediate issues:
- `pwsh.exe` (PowerShell Core) is missing
- `encodedcommand` can be changed to [at least 75 distinct spellings (prefix abbreviations, `-`/`/`, three Unicode dash prefixes, and the `-ec` alias)](https://detect.fyi/detection-pitfalls-you-might-be-sleeping-on-52b5a3d9a0c8)


## How to Find Immutable Artifacts

Discovering immutable artifacts requires going deeper than signature databases:

### 1. Study the Tool's Source Code
Don't just run Mimikatz - read its code. Understand what API calls it makes, what registry keys it touches, what memory operations it performs. The answers are in the implementation (which also can be changed by an attacker, to some extent).

### 2. Use Process Monitor (Procmon)
Execute the technique in a safe environment and watch *everything* it does:
- Registry operations
- File system activity
- Network connections
- Process/thread creation

The operations that occur *every single time*, regardless of how you invoke the technique - those are your immutable artifacts.

### 3. Test All Known Variations
For any given technique, there are usually multiple tools and methods:
- Native Windows utilities
- PowerShell cmdlets
- WMI/WMIC commands
- .NET Framework methods
- Custom binaries

Run them all. Find the common denominators. Those commonalities are what you should detect.

### 4. Reference MITRE ATT&CK Data Sources
MITRE's framework includes "Data Sources" for each technique. These hint at the telemetry sources that can capture immutable artifacts:
- For T1543.003 (Windows Service): Process Creation, Windows Registry, File Monitoring
- For T1021.001 (RDP): Network Traffic, Logon Session, Windows Registry

These aren't just suggestions - they're your roadmap to durable detection.

## Practical Dos and Don'ts

### DO:
✅ Use tools like Procmon to trace actual system changes  
✅ Account for *all* parameter variations (PowerShell's `-EncodedCommand` has at least 75 valid abbreviations!)  
✅ Test detections with adversary emulation frameworks (Atomic Red Team, Caldera)  
✅ Reference methodologies like MITRE's "Summiting the Pyramid"  
✅ Continuously validate assumptions with real telemetry  

### DON'T:
❌ Blindly trust public detection databases without testing  
❌ Rely solely on process names or command-line strings  
❌ Assume "well-known" rules are good enough  
❌ Forget to tune for your specific environment  
❌ Build detections without understanding the underlying technique  

## The Learning Journey

You won't master this overnight. Progressive learning is the only path forward.

When I started:
- I detected based on process names
- Then I moved to command-line patterns
- Then I realized those were still mutable
- Finally, I learned to trace tools back to their system-level impact

Each step required unlearning old habits and embracing uncertainty. For example:
- Did you know some commands aren't logged in Event ID 4688?
- Did you know using the pipe (`|`) character in CMD can split a single command into multiple log entries?

There's always more to learn. But that's the beauty of immutable artifacts - they force you to truly understand the systems you're protecting.

## The Philosophy

Detection engineering isn't about writing more rules. It's about writing *better* rules.

A detection anchored in immutable artifacts doesn't care:
- What the binary is named
- How the command is obfuscated
- Whether the attacker uses a public tool or custom malware

It only cares about one thing: **Did the technique occur?**

This is the difference between brittle detections that break with every new tool release and resilient detections that work for years.

## Your Challenge

Take one of your existing detections - preferably one you're proud of - and ask yourself:

1. What is this detection actually targeting? The tool or the technique?
2. If an attacker renamed the binary, would my detection still fire?
3. What *must* happen at the system level for this technique to succeed?
4. Am I detecting the wrapping paper or the gift inside?

Then, go deeper. Use Procmon. Read the tool's source code. Test variations. Find the immutable artifacts.

And build a detection that will still work five years from now.

---

## The Immutable Artifacts Manifesto

🎯 **Detect intent, not syntax**  
🔒 **Anchor logic in system-level operations, not tool names**  
📉 **Accept that good detection requires good telemetry**  
🧠 **Understand the system before protecting it**  
🧰 **Test everything - especially the "standard" rules**  
🧭 **Map to behavior, not branding**  
🔍 **Every detection is a hypothesis; validate with telemetry**  
🛠️ **Build detections that will matter when TTPs evolve**

---

**Remember:** Attackers will always find new tools. But the laws of the operating system don't usually change. Focus on what can't be hidden, and you'll build detections that actually last.
