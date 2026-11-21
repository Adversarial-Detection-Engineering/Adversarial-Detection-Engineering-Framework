# ADE1-02 Example: Account Created and Deleted in Short Timeframe (Normalization Asymmetry)

**Bug Category:** ADE1-02 Reformatting in Actions - Normalization Asymmetry

## Original Rule

**Source:** [Kusto - Account Created and Deleted in Short Timeframe](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/AccountCreatedandDeletedinShortTimeframe.yaml)

```yaml
id: bb616d82-108f-47d3-9dec-9652ea0d3bf6
name: Account Created and Deleted in Short Timeframe
description: |
  'Search for user principal name (UPN) events. Look for accounts created and then deleted in under 24 hours. Attackers may create an account for their use, and then remove the account when no longer needed.
  Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-user-accounts#short-lived-account'
severity: High
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
queryFrequency: 1h
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
status: Available
tactics:
  - InitialAccess
relevantTechniques:
  - T1078.004
tags:
  - AADSecOpsGuide
query: |
  let queryfrequency = 1h;
  let queryperiod = 1d;
  AuditLogs
  | where TimeGenerated > ago(queryfrequency)
  | where OperationName =~ "Delete user"
  | mv-apply TargetResource = TargetResources on 
    (
        where TargetResource.type == "User"
        | extend TargetUserPrincipalName = extract(@'([a-f0-9]{32})?(.*)', 2, tostring(TargetResource.userPrincipalName))
    )
  | extend DeletedByApp = tostring(InitiatedBy.app.displayName),
  DeletedByAppServicePrincipalId = tostring(InitiatedBy.app.servicePrincipalId),
  DeletedByUserPrincipalName = tostring(InitiatedBy.user.userPrincipalName),
  DeletedByAadUserId = tostring(InitiatedBy.user.id),
  DeletedByIPAddress = tostring(InitiatedBy.user.ipAddress)
  | project Deletion_TimeGenerated = TimeGenerated, TargetUserPrincipalName, DeletedByApp, DeletedByAppServicePrincipalId, DeletedByUserPrincipalName, DeletedByAadUserId, DeletedByIPAddress, 
  Deletion_AdditionalDetails = AdditionalDetails, Deletion_InitiatedBy = InitiatedBy, Deletion_TargetResources = TargetResources
  | join kind=inner (
      AuditLogs
      | where TimeGenerated > ago(queryperiod)
      | where OperationName =~ "Add user"      
      | mv-apply TargetResource = TargetResources on 
        (
            where TargetResource.type == "User"
            | extend TargetUserPrincipalName = trim(@'"',tostring(TargetResource.userPrincipalName))
        )
      | project-rename Creation_TimeGenerated = TimeGenerated
  ) on TargetUserPrincipalName
  | extend TimeDelta = Deletion_TimeGenerated - Creation_TimeGenerated
  | where  TimeDelta between (time(0s) .. queryperiod)
  | extend CreatedByApp = tostring(InitiatedBy.app.displayName),
  CreatedByAppServicePrincipalId = tostring(InitiatedBy.app.servicePrincipalId),
  CreatedByUserPrincipalName = tostring(InitiatedBy.user.userPrincipalName),
  CreatedByAadUserId = tostring(InitiatedBy.user.id),
  CreatedByIPAddress = tostring(InitiatedBy.user.ipAddress)
  | project Creation_TimeGenerated, Deletion_TimeGenerated, TimeDelta, TargetUserPrincipalName, DeletedByApp, DeletedByAppServicePrincipalId, DeletedByUserPrincipalName, DeletedByAadUserId, DeletedByIPAddress, 
  CreatedByApp, CreatedByAppServicePrincipalId, CreatedByUserPrincipalName, CreatedByAadUserId, CreatedByIPAddress, Creation_AdditionalDetails = AdditionalDetails, Creation_InitiatedBy = InitiatedBy, Creation_TargetResources = TargetResources, Deletion_AdditionalDetails, Deletion_InitiatedBy, Deletion_TargetResources
  | extend TargetName = tostring(split(TargetUserPrincipalName,'@',0)[0]), TargetUPNSuffix = tostring(split(TargetUserPrincipalName,'@',1)[0])
  | extend CreatedByName = tostring(split(CreatedByUserPrincipalName,'@',0)[0]), CreatedByUPNSuffix = tostring(split(CreatedByUserPrincipalName,'@',1)[0])
  | extend DeletedByName = tostring(split(DeletedByUserPrincipalName,'@',0)[0]), DeletedByUPNSuffix = tostring(split(DeletedByUserPrincipalName,'@',1)[0])
entityMappings: # ... truncated ... #
version: 1.1.0
kind: Scheduled
```

## The Bug

There is an inconsistency in how User Principal Names (UPNs) are extracted for 'Add user' versus 'Delete user' operations, particularly for guest accounts, which can lead to a failure in joining the creation and deletion events. That failure can be abused by an attacker to bypass detection.

## Log Source Context

- **Logsource category:** `AuditLogs` in EntraID = OperationName `Add User` and `Delete User`
- **Logged fields:** `TargetUserPrincipalName`, `CreatedByUserPrincipalName`, etc.
- **Vulnerable field:** `TargetUserPrincipalName` post formatting prior to key use in inner join.

## Bypass

### UPN Normalization Asymmetry Breaks the Inner Join

The detection logic uses different methods to extract the TargetUserPrincipalName for 'Add user' and 'Delete user' operations, leading to potential mismatches that prevent the inner join from correlating events. Specifically, for 'Add user', it uses trim(@'\"', tostring(TargetResource.userPrincipalName)), which retains the full UPN string. For 'Delete user', it uses extract(@'([a-f0-9]{32})?(.*)', 2, tostring(TargetResource.userPrincipalName)), which is designed to strip an optional GUID prefix (common in guest account UPNs) and capture the remainder. If a guest account is created with a UPN like GUID#EXT#user@domain.com, the 'Add user' extraction will yield the full string including the GUID, while the 'Delete user' extraction will yield only #EXT#user@domain.com. This inconsistency causes the TargetUserPrincipalName values to differ, breaking the inner join and allowing the activity to go undetected.

## Impact

False Negative: Account Created and Deleted in Short Timeframe succeeds without detection as inner join fails.

---

**Related Documentation:**
- [ADE1 Reformatting in Actions](../../docs/taxonomy/ade1-reformatting-in-actions.md)
- [Detection Logic Bug Theory](../../docs/theory/detection-logic-bugs.md)
- [MITRE ATT&CK T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
