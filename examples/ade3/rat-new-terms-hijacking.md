# ADE3-02 Example: Remote Access Tool New Terms Hijacking

**Bug Category:** ADE3-02 Context Development - Aggregation Hijacking

## Original Rule

**Source:** [Elastic Security - First Time Seen Commonly Abused Remote Access Tool Execution](https://github.com/elastic/detection-rules/blob/f6e79944f2fd0ad680cb2e68fd249c8b6d722ec8/rules/windows/command_and_control_new_terms_commonly_abused_rat_execution.toml)

**Description:** This Elastic Security New Terms rule searches for cases when a process is started whose name or code signature resembles commonly abused RATs (Remote Access Tools), indicating the host has not seen this RAT process started before within the last 15 days.

```SQL
query = '''
host.os.type: "windows" and

   event.category: "process" and event.type : "start" and

    (
    process.code_signature.subject_name : (
        TeamViewer* or "NetSupport Ltd" or "GlavSoft" or "LogMeIn, Inc." or "Ammyy LLC" or
        "Nanosystems S.r.l." or "Remote Utilities LLC" or "ShowMyPC" or "Splashtop Inc." or
        "Yakhnovets Denis Aleksandrovich IP" or "Pro Softnet Corporation" or "BeamYourScreen GmbH" or
        "RealVNC" or "uvnc" or "SAFIB") or

    process.name.caseless : (
        "teamviewer.exe" or "apc_Admin.exe" or "apc_host.exe" or "SupremoHelper.exe" or "rfusclient.exe" or
        "spclink.exe" or "smpcview.exe" or "ROMServer.exe" or "strwinclt.exe" or "RPCSuite.exe" or "RemotePCDesktop.exe" or
        "RemotePCService.exe" or "tvn.exe" or "LMIIgnition.exe" or "B4-Service.exe" or "Mikogo-Service.exe" or "AnyDesk.exe" or
        "Splashtop-streamer.exe" or AA_v*.exe or "rutserv.exe" or "rutview.exe" or "vncserver.exe" or "vncviewer.exe" or
        "tvnserver.exe" or "tvnviewer.exe" or "winvnc.exe" or "RemoteDesktopManager.exe" or "LogMeIn.exe" or ScreenConnect*.exe or
        "RemotePC.exe" or "r_server.exe" or "radmin.exe" or "ROMServer.exe" or "ROMViewer.exe" or "DWRCC.exe" or "AeroAdmin.exe" or
        "ISLLightClient.exe" or "ISLLight.exe" or "AteraAgent.exe" or "SRService.exe")
	) and

	not (process.pe.original_file_name : ("G2M.exe" or "Updater.exe" or "powershell.exe") and process.code_signature.subject_name : "LogMeIn, Inc.")
'''

...

[rule.new_terms]
field = "new_terms_fields"
value = ["host.id"]
[[rule.new_terms.history_window_start]]
field = "history_window_start"
value = "now-15d"
```

## Detection Logic Analysis

**How it works:**

- Rule searches for processes matching RAT signatures or process names
- Groups results by `host.id` only
- Alerts when RAT execution is seen for first time in last 15 days

**Intent:** Detect first-time execution of potentially malicious remote access tools.

**Bug:** New terms aggregation uses only `host.id`, bundling all accounts into single terms bucket.

## The Bug: ADE3-02 Context Development - Aggregation Hijacking

**Definition:** Detection logic relies on aggregated values that an attacker can influence or precondition.

**In this case:**
- The new term is `host.id` (all accounts bundled into single instance)
- Attacker can perform reconnaissance to check if RAT has been used in last 15 days
- If found, repeat usage aggregates into existing baseline → No alert

## False Negatives - Context Requirements

For context to be developed into a False Negative, the following must match:

### Reconnaissance Capabilities

**Non-local admin user can:**
- View processes available in SYSTEM owned directories to see if RAT is installed
- Read contents in `%APPDATA%\Microsoft\Windows\Recent\` in their own account (not others)
- Check `.lnk` files to determine when existing RAT was last run
- If less than 15 days → can bypass due to new term period

**Admin can:**
- Read all users' `%APPDATA%\Microsoft\Windows\Recent\`
- View all installed programs
- Access full process list
- Check system-wide recent items

### Attack Pattern

**Step 1:** Compromised user account performs reconnaissance

```powershell
# Check if RAT is installed
Get-Process | Where-Object {$_.Name -match "teamviewer|anydesk|vnc|logmein"}

# Check recent items for RAT execution
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent\*.lnk" |
    Where-Object {$_.Name -match "TeamViewer|AnyDesk"}

# Or for admin - check all users
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*.lnk" |
    Where-Object {$_.Name -match "TeamViewer|AnyDesk"}
```

**Step 2:** If RAT usage found within 15 days

- Attacker uses same RAT
- Execution aggregates into existing `host.id` baseline
- No alert generated

**Step 3:** If no recent RAT usage

- Attacker cannot bypass via aggregation hijacking
- Must use alternative bypass (process cloning, see below)

## Additional Bug: ADE3-01 Process Cloning

**Critical difference in detection logic:**

```SQL
process.code_signature.subject_name : (...)  # Immutable - robust
process.name.caseless : (...)                 # Mutable - vulnerable
```

**`process.name.caseless`:**
- Takes the name of the executable actually ran
- Renamed copy would have its new name here
- This indicates a potential **ADE3-01 Process Cloning** bug

**Attack:**
1. Download legitimate TeamViewer installer
2. Rename to `legitapp.exe`
3. Execute → `process.name.caseless: "legitapp.exe"`
4. Bypass detection

**Note:** Code signature check would still match if binary is signed, but unsigned/self-signed RATs bypass both checks.

## Impact

**Aggregation hijacking (ADE3-02):**
- Requires RAT usage in last 15 days
- Attacker must have reconnaissance capabilities
- Context-dependent bypass

**Process cloning (ADE3-01):**
- Works regardless of history
- Only requires renaming binary
- Bypasses `process.name.caseless` check
- Unsigned/untrusted RATs evade both checks

## Why This Matters

**Common attack scenario:**

1. Attacker gains initial access (phishing, exploit)
2. Needs persistent remote access
3. Deploys RAT (TeamViewer, AnyDesk, etc.)
4. Before deployment, checks if RAT already in use
5. If yes → use same tool → bypass detection
6. If no → rename binary → bypass via process cloning

**Result:** Multiple bypass paths, both leveraging detection logic bugs.

---

**Related Documentation:**
- [ADE3 Context Development](../../docs/taxonomy/ade3-context-development.md)
- [ADE3-01 Process Cloning](../../docs/taxonomy/ade3-context-development.md#ade3-01-context-development---process-cloning)
- [Detection Logic Bug Theory](../../docs/theory/detection-logic-bugs.md)
