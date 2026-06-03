# Microsoft Defender / Sentinel Hunting Queries

## Generic Search

```kusto
search "indicator"
| where TimeGenerated >= ago(30d)
| distinct $table
```

---

## 👤 Identity Investigation

### Identity Information

```kusto
IdentityInfo
| where TimeGenerated >= ago(30d)
| where * has "value"
| project AccountDisplayName, AccountUPN, GroupMembership, AssignedRoles, JobTitle, Department
```

### User Sign-in Baseline

```kusto
SigninLogs
| where TimeGenerated >= ago(30d)
| where UserPrincipalName contains "UPN"
| summarize count() by IPAddress, Location
```

### IP Usage Across Users

```kusto
SigninLogs
| where TimeGenerated >= ago(30d)
| where IPAddress contains "IP"
| summarize count() by UserDisplayName, UserPrincipalName
```

### Combined Sign-ins

```kusto
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated >= ago(30d)
```

---

## 📧 Email Investigation

### Email Investigation

```kusto
union EmailEvents, EmailUrlInfo, EmailAttachmentInfo
| where TimeGenerated >= ago(30d)
| where NetworkMessageId contains "ID"
```

### Email Metadata

```kusto
EmailEvents
| where NetworkMessageId has "ID"
| project TimeGenerated, DeliveryLocation, SenderDisplayName, SenderFromAddress, Subject, RecipientEmailAddress
```

### Email Access Tracking

```kusto
OfficeActivity
| where TimeGenerated >= ago(30d)
| where * has "InternetMessageId"
```

---

## 🦠 File Hash Hunting

```kusto
let fileSha256 = "HASH";

let AttachmentInfo =
    EmailAttachmentInfo
    | where SHA256 =~ fileSha256;

let DeviceEventsTable =
    DeviceEvents
    | where SHA256 =~ fileSha256;

let FileEvents =
    DeviceFileEvents
    | where SHA256 =~ fileSha256;

union AttachmentInfo, FileEvents, DeviceEventsTable
| invoke FileProfile()
| summarize by SHA256, DeviceName, RecipientEmailAddress, FileName, ActionType
```

---

## 🌐 URL Investigation

### URL Investigation

```kusto
UrlClickEvents
| where TimeGenerated >= ago(30d)
| where Url contains "URL"
```

### Deep URL Investigation

```kusto
union UrlClickEvents, DeviceEvents, DeviceProcessEvents
| where TimeGenerated >= ago(30d)
| where * has "URL"
```

---

## 🎣 Phishing Investigation

### Phishing Detection

```kusto
UrlClickEvents
| where ActionType == "ClickAllowed" or IsClickedThrough == "True"
| where Url has "URL"
| project TimeGenerated, Url, AccountUpn, IPAddress
```

### Phish Click Summary

```kusto
UrlClickEvents
| where ActionType == "ClickAllowed"
| where ThreatTypes has "Phish"
| summarize by ReportId, AccountUpn, NetworkMessageId
```

---

## 🏢 Office Activity

### Available Operations

```kusto
OfficeActivity
| distinct Operation
```

### Mail Operations

```kusto
OfficeActivity
| where Operation contains "mail"
```

### Deletion Monitoring

```kusto
OfficeActivity
| where * has "value"
| where Operation contains "delete"
```

---

## ☁️ Cloud Activity

### Cloud Deletions

```kusto
CloudAppEvents
| where * has "value"
| where ActionType contains "delete"
```

### Tenant Allow/Block List Expiry

```kusto
CloudAppEvents
| where ActionType contains "TenantAllowBlockListItemExpiry"
| extend entity = tostring(parse_json(RawEventData.EntityData.Entity))
| extend expiry = tostring(parse_json(RawEventData.EntityData.Expiry))
```

---

## 🔑 LDAP / Brute Force Investigation

```kusto
IdentityQueryEvents
| where TimeGenerated >= ago(48h)
| where ActionType contains "LDAP"
| where IPAddress contains "IP"
| project TimeGenerated, Query, TargetAccountUpn
```

---

## 🌍 Advanced Sign-in Analysis

```kusto
SigninLogs
| where UserPrincipalName contains "UPN"
| where TimeGenerated > ago(60d)
| extend browser_ = tostring(DeviceDetail.browser)
| extend operatingSystem_ = tostring(DeviceDetail.operatingSystem)
| extend city_ = tostring(LocationDetails.city)
| extend country_ = tostring(LocationDetails.countryOrRegion)
| project TimeGenerated, IPAddress, city_, country_, browser_, ResultType
```

---

## 📱 User Agent Analysis

```kusto
union SigninLogs, AADNonInteractiveUserSignInLogs
| where UserPrincipalName contains "UPN"
| where UserAgent contains "agent"
| summarize count() by UserAgent
```

---

## 📩 Proofpoint Investigation

```kusto
union ProofPointTAPMessagesDelivered_CL,
      ProofPointTAPMessagesBlocked_CL,
      ProofPointTAPClicksPermitted_CL,
      ProofPointTAPClicksBlocked_CL
| where TimeGenerated >= ago(90d)
| where senderIP_s contains "IP"
```

---

## 🖥️ RDP Investigation

### RDP Logon Investigation

```kusto
DeviceLogonEvents
| where TimeGenerated >= ago(14d)
| where DeviceId contains "deviceID"
| where AccountName contains "Admin"
| where RemoteDeviceName contains "hostname"
```

### RDP Device Hunt

```kusto
DeviceEvents
| where TimeGenerated >= ago(30d)
| where * has "hostname"
```
