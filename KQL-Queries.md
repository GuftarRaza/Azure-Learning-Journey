# Microsoft Sentinel & Defender Hunting Queries

## Universal Search Across Tables

Search any IOC (IP, filename, hash, username, UPN, etc.) across all tables.

```kusto
search "Anything <IP>, <FileName>, <Filehashes>, <Username>, <UPN>, <any string>"
| where TimeGenerated >= ago(30d)
| distinct $table
```

---

# Identity & User Investigation

## User Information Lookup

```kusto
IdentityInfo
| where TimeGenerated >= ago(30d)
| where * has "TargetString"
| project AccountDisplayName, AccountUPN, GroupMembership, AssignedRoles, JobTitle, Department
```

## User Sign-in Summary by IP

```kusto
SigninLogs
| where TimeGenerated >= ago(30d)
| where UserPrincipalName contains "Paste UPN here"
| summarize count() by IPAddress, Location
```

## IP Address Usage Summary

```kusto
SigninLogs
| where TimeGenerated >= ago(30d)
| where IPAddress contains "Paste IP here"
| summarize count() by UserDisplayName, UserPrincipalName
```

## User Sign-in Timeline

```kusto
SigninLogs
| where TimeGenerated >= ago(30d)
| where UserPrincipalName contains "Paste UPN here"
| distinct TimeGenerated, IPAddress, Location
```

## Users Seen From an IP

```kusto
SigninLogs
| where TimeGenerated >= ago(30d)
| where IPAddress contains "Paste IP here"
| distinct TimeGenerated, UserDisplayName, UserPrincipalName
```

## Interactive and Non-Interactive Sign-ins

```kusto
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated >= ago(30d)
| project TimeGenerated, IPAddress, UserPrincipalName, ResultType, ResultDescription,
          DeviceDetail_string, AppDisplayName, AuthenticationRequirement,
          UserAgent, AutonomousSystemNumber, Location
```

## User Authentication Details

```kusto
SigninLogs
| where UserPrincipalName contains "Paste UPN here"
| project TimeGenerated, ResultType, Identity, UserPrincipalName,
          IPAddress, Location, AuthenticationDetails, DeviceDetail
```

## Sign-ins From Specific IP

```kusto
SigninLogs
| where IPAddress == "Paste IP here"
| project-reorder TimeGenerated, IPAddress, UserPrincipalName
```

## Non-Interactive Sign-ins From Specific IP

```kusto
AADNonInteractiveUserSignInLogs
| where IPAddress == "Paste IP here"
| distinct UserPrincipalName, IPAddress
| project-reorder IPAddress, UserPrincipalName
```

---

# User Agent & Device Analysis

## User Agent Statistics

```kusto
SigninLogs
| where UserPrincipalName contains "Paste UPN here"
| where TimeGenerated >= ago(30d)
| extend browser_ = tostring(DeviceDetail.browser)
| extend operatingSystem_ = tostring(DeviceDetail.operatingSystem)
| extend state_ = tostring(LocationDetails.state)
| extend city_ = tostring(LocationDetails.city)
| extend country_ = tostring(LocationDetails.countryOrRegion)
| extend SystemName_ = tostring(DeviceDetail.displayName)
| project TimeGenerated, city_, state_, country_,
          ResourceDisplayName, SystemName_, AppDisplayName,
          browser_, operatingSystem_, UserAgent,
          IPAddress, AuthenticationRequirement,
          ResultType, ResultDescription, MfaDetail
| summarize count() by UserAgent, ResultType, ResultDescription
```

## Full User Authentication Investigation

```kusto
SigninLogs
| where TimeGenerated >= ago(30d)
| where UserPrincipalName contains "Paste UPN here"
| project TimeGenerated, Identity, IPAddress, Location,
          AlternateSignInName, ResultType, ResultDescription,
          DeviceDetail, UserAgent, AppDisplayName,
          AuthenticationDetails, MfaDetail,
          AuthenticationRequirement,
          ConditionalAccessPolicies,
          ConditionalAccessStatus,
          NetworkLocationDetails,
          RiskDetail,
          RiskEventTypes,
          RiskEventTypes_V2,
          RiskLevel
```

## Authentication Method Analysis

```kusto
SigninLogs
| where UserPrincipalName contains "Paste UPN here"
| where TimeGenerated > ago(60d)
| extend browser_ = tostring(DeviceDetail.browser)
| extend operatingSystem_ = tostring(DeviceDetail.operatingSystem)
| extend state_ = tostring(LocationDetails.state)
| extend city_ = tostring(LocationDetails.city)
| extend country_ = tostring(LocationDetails.countryOrRegion)
| extend device_ = tostring(DeviceDetail.displayName)
| extend authenticationStepResultDetail_ =
    tostring(parse_json(AuthenticationDetails)[1].authenticationStepResultDetail)
| extend authenticationMethod_ =
    tostring(parse_json(AuthenticationDetails)[1].authenticationMethod)
| project TimeGenerated, IPAddress, city_, state_, country_,
          ResourceDisplayName, SystemName_, AppDisplayName,
          browser_, operatingSystem_, UserAgent,
          AuthenticationRequirement,
          authenticationStepResultDetail_,
          authenticationMethod_,
          ResultType, ResultDescription
| sort by TimeGenerated
```

---

# Email Investigations

## Network Message ID Investigation

```kusto
union EmailEvents, EmailUrlInfo, EmailAttachmentInfo
| where TimeGenerated >= ago(30d)
| where NetworkMessageId contains "Paste Network Message ID here"
| project TimeGenerated, RecipientEmailAddress, Subject,
          SenderDisplayName, SenderFromAddress,
          SenderFromDomain, SenderIPv4,
          UrlCount, AttachmentCount,
          Url, FileName, FileType
```

## Full Email Investigation

```kusto
let NetworkMsgId = "Paste Network Message ID here";

EmailEvents
| where NetworkMessageId has NetworkMsgId and TimeGenerated > ago(3d)
| join kind=leftouter (
    EmailUrlInfo
    | where NetworkMessageId has NetworkMsgId
) on NetworkMessageId
| join kind=leftouter (
    EmailAttachmentInfo
    | where NetworkMessageId has NetworkMsgId
) on NetworkMessageId
| join kind=leftouter (
    UrlClickEvents
    | where NetworkMessageId has NetworkMsgId
    | project ActionType, urlclicked = Url, NetworkMessageId
) on NetworkMessageId
| distinct TimeGenerated,
           RecipientEmailAddress,
           SenderFromAddress,
           SenderDisplayName,
           Subject,
           AttachmentCount,
           DeliveryAction,
           DeliveryLocation,
           Url,
           UrlCount,
           ActionType,
           urlclicked,
           AuthenticationDetails,
           FileName,
           FileSize,
           FileType,
           SHA256,
           SenderIPv4,
           InternetMessageId,
           SenderMailFromAddress
```

---

# File Hash Investigation

## SHA256 Investigation Across Defender Tables

```kusto
let fileSha256 = "Paste SHA256 Here";

let AttachmentInfo =
    EmailAttachmentInfo
    | extend Activity = "Attachment Info"
    | where SHA256 =~ fileSha256;

let DeviceEvents =
    DeviceEvents
    | where SHA256 =~ fileSha256;

let FileEvents =
    DeviceFileEvents
    | extend Activity = "Device File Event"
    | where SHA256 =~ fileSha256;

union AttachmentInfo, FileEvents, DeviceEvents
| invoke FileProfile()
| summarize by SHA256,
               DeviceName,
               RecipientEmailAddress,
               FileName,
               FileType,
               FileSize,
               ActionType,
               FolderPath,
               InitiatingProcessAccountUpn,
               InitiatingProcessFileName,
               DeviceId,
               SHA1,
               NetworkMessageId,
               GlobalPrevalence,
               SignatureState,
               IsExecutable,
               Publisher,
               SoftwareName,
               ThreatName
| sort by RecipientEmailAddress asc, DeviceName asc
```

---

# URL Investigation

## URL Click Analysis

```kusto
UrlClickEvents
| where TimeGenerated >= ago(30d)
| where Url contains "Paste URL here"
```

## URL Search Across Multiple Tables

```kusto
union UrlClickEvents, DeviceEvents, DeviceProcessEvents
| where TimeGenerated >= ago(30d)
| where * has "Paste URL here"
```

## Successful Phishing Clicks

```kusto
UrlClickEvents
| where ActionType == "ClickAllowed"
    or IsClickedThrough == "True"
| where Url has "Paste URL here"
| project TimeGenerated,
          ActionType,
          Url,
          IPAddress,
          ThreatTypes,
          IsClickedThrough,
          AccountUpn
```

---

# Office 365 Activity

## Mail Items Accessed

```kusto
OfficeActivity
| where TimeGenerated >= ago(30d)
| where Operation contains "MailItemsAccessed"
| where MailboxOwnerUPN contains "Paste UPN here"
```

## Mail Related Operations

```kusto
OfficeActivity
| where Operation contains "mail"
```

## List Available Operations

```kusto
OfficeActivity
| distinct Operation
```

---

# Device & Infrastructure Monitoring

## Host Heartbeat

```kusto
Heartbeat
| where TimeGenerated >= ago(30d)
| where Computer == "AddIPorHostname"
| summarize count() by bin(TimeGenerated, 1d)
```

## Latest Heartbeat

```kusto
Heartbeat
| where TimeGenerated >= ago(30d)
| where Computer == "AddIPorHostname"
| summarize arg_max(TimeGenerated, *) by Computer
| sort by TimeGenerated desc
```

## Linux Syslog Activity

```kusto
Syslog
| where Computer contains "AddIPorHostname"
```

## Successful Logons

```kusto
SecurityEvent
| where Computer has "AddIPorHostname"
| where EventID == "4624"
| distinct Account, IpAddress
```

---

# Identity Query Monitoring

## LDAP Queries

```kusto
IdentityQueryEvents
| where TimeGenerated >= ago(48h)
| where ActionType contains "LDAP"
| where IPAddress contains "10.100.1.4"
| project TimeGenerated,
          ActionType,
          Query,
          QueryTarget,
          IPAddress,
          DestinationDeviceName,
          TargetAccountUpn
| sort by TimeGenerated
```
