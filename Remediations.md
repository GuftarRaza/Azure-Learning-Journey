# 🛡️ MXDR Remediation Actions Master Playbook

When running a Microsoft-centric Managed Extended Detection and Response (MXDR) service, you are looking at a unified radar screen. If an attack drops in, you can strike back across every single asset type being monitored: **Endpoints, Identities, Email, Cloud Apps, and Data**.

Below is the master matrix of all remediation actions available within Microsoft Defender XDR and Microsoft Sentinel, categorized by asset type and operational intent.

---

## 🖥️ 1. Endpoints & Devices (Defender for Endpoint)

When a laptop, desktop, or server is compromised, the primary objective is to arrest lateral movement and stop malware from spreading across the network.

* **Isolate Device**
    * *Action:* Cuts off all network communication for the machine except its direct outbound line to Microsoft Defender.
    * *Impact:* The attacker instantly loses remote access/C2 capabilities, but SOC analysts retain the ability to run scripts, collect forensic artifacts, or investigate.
* **Restrict App Execution**
    * *Action:* Forces the operating system to only execute software explicitly signed by Microsoft.
    * *Impact:* Instantly halts unauthorized malware payloads, ransomware binaries, or secondary hacking tools from executing.
* **Run Antivirus Scan**
    * *Action:* Remotely triggers a full, background Windows Defender antivirus scan.
    * *Impact:* Locates, identifies, and quarantines hidden payloads or secondary artifacts left in storage.
* **Stop and Quarantine Process**
    * *Action:* Targets a specific malicious process identified by its Process ID (PID) or file hash (e.g., a masqueraded `lsass.exe`).
    * *Impact:* Kills the live thread and locks down the underlying file system binary so it cannot be re-executed.
* **Live Response**
    * *Action:* Establishes a secure, remote command-line interface (CLI) terminal session to the live target machine.
    * *Impact:* Empowers analysts to manually delete registry keys, pull volatile memory/files for triage, or deploy custom PowerShell remediation tools.

---

## 🆔 2. Identities & User Accounts (Defender for Identity / Entra ID)

Focuses on identity containment to stop an adversary from leveraging compromised or stolen credentials to navigate across cloud infrastructure or local Active Directory domains.

* **Block Sign-in (Disable Account)**
    * *Action:* Freezes the account status inside Entra ID / Active Directory.
    * *Impact:* Completely prevents any new authentication requests or login attempts from succeeding.
* **Revoke Active Sessions**
    * *Action:* Destroys all active access tokens and refresh tokens associated with the identity across the tenant.
    * *Impact:* Instantly boots the attacker out of live connected applications (Outlook, Teams, Azure Portal, SharePoint).
* **Confirm User Compromised**
    * *Action:* Flags the user identity status as "High Risk" within Entra ID Identity Protection.
    * *Impact:* Triggers automated conditional access guardrails, such as forcing an immediate password reset or step-up authentication.
* **Reset Password**
    * *Action:* Enforces an immediate credential rotation, invalidating the current password hash.

---

## 📧 3. Email & Collaboration (Defender for Office 365)

When phishing campaigns land or an internal account becomes compromised and begins transmitting malicious links internally, analysts remediate data directly within the cloud mailboxes.

* **Soft Delete / Hard Delete Email**
    * *Action:* Removes malicious messages directly from user mailboxes.
        * *Soft Delete:* Moves the item to the hidden *Recoverable Items* folder (removing it from user visibility).
        * *Hard Delete:* Permanently purges the message from the entire database cluster.
* **Move to Junk / Quarantine**
    * *Action:* Pulls the email from the inbox and routes it to a secure sandbox containment area.
    * *Impact:* Isolates the content so end-users cannot interact with malicious hyper-links or embedded attachments.
* **ZAP (Zero-hour Auto Purge)**
    * *Action:* Retroactive machine-learning strike applied automatically across the tenant.
    * *Impact:* If a weaponized URL or attachment is discovered *after* delivery, ZAP hunts through all customer mailboxes and silently yanks the message out of sight.

---

## ☁️ 4. Cloud Apps & SaaS Data (Defender for Cloud Apps)

Provides cross-tenant data governance and security control over third-party SaaS environments (e.g., Salesforce, Box, AWS) integrated into the corporate identity footprint.

* **Suspend SaaS User**
    * *Action:* Generates a temporary lock on the user's specific application profile inside the connected third-party app.
    * *Impact:* Stops access to the target SaaS application even if the primary Microsoft session remains intact.
* **File Quarantine**
    * *Action:* Automatically removes malware-infected files or documents violating regulatory/compliance rules (PII/SPI) from public cloud storage.
    * *Impact:* Isolates the file to a secure directory, neutralizing unauthorized public sharing exposure.
* **Inherit Microsoft Information Protection (MIP) Labels**
    * *Action:* Retroactively applies strict data encryption policies to a target document based on discovery rules.
    * *Impact:* Requires explicit identity permissions to decode the file, protecting the data payload even if it has already been exfiltrated or downloaded to an unmanaged asset.

---

## 🤖 5. Automated Remediation (AIR & Sentinel SOAR)

Remediation workflows can be shifted away from manual analyst clicks into native machine-speed automated loops using two distinct layers:

### ⚡ AIR (Automated Investigation and Response)
Built natively into the Microsoft Defender XDR platform. When a verified alert triggers on an asset, AIR spins up an automated investigation playbook in the background. It analyzes related files, processes, and network connections across your endpoints, determines a verdict, and presents a remediation action for approval—or executes it autonomously if configured for Full Automation.

### 🛠️ Microsoft Sentinel Playbooks (SOAR via Logic Apps)
Your enterprise-wide security orchestration and automation engine. Playbooks are custom-built to handle complex cross-platform workflows within seconds. 

> 💡 **Example Scenario:** If a high-severity alert fires indicating a VIP user is compromised, a Sentinel playbook can simultaneously isolate their endpoint via Defender, revoke their active cloud tokens via Entra ID, and block the malicious source IP address on your Azure Firewall or third-party gateway—all in under 5 seconds.
