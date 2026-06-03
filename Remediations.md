When you are running a Microsoft-centric MXDR service, you are looking at a unified radar screen. If an attack drops in, you can strike back across every single asset type being monitored (Endpoints, Identities, Email, Cloud Apps, and Data).
​Here is the master list of all remediation actions available to you in Microsoft Defender XDR and Sentinel, broken down by asset type.
​1. Endpoints & Devices (Defender for Endpoint)
​When a laptop, desktop, or server is compromised, your goal is to stop it from spreading malware across the network (lateral movement).
​Isolate Device: Cuts off all network communication for the machine except its direct line to Microsoft Defender. The attacker loses remote access, but you can still run scripts or investigate.
​Restrict App Execution: Forces the operating system to only run software signed by Microsoft. This instantly stops unauthorized malware, ransomware scripts, or hacking tools from running.
​Run Antivirus Scan: Remotely kicks off a full Windows Defender background scan to find and quarantine hidden payloads.
​Stop and Quarantine Process: If you see a specific malicious process running (e.g., a fake lsass.exe), you can kill the process and lock the file down so it can't run again.
​Live Response: Opens a secure, remote command-line interface (CLI) to the machine. This allows you to manually delete registry keys, pull files for analysis, or run custom remediation scripts.
​2. Identities & User Accounts (Defender for Identity / Entra ID)
​As we touched on, this is about stopping an attacker from using stolen credentials to navigate the cloud or local domain.
​Block Sign-in (Disable Account): Freezes the account so no new logins can occur.
​Revoke Active Sessions: Kicks the user/attacker out of all active apps (Outlook, Teams, Azure portal) immediately by destroying their active access tokens.
​Confirm User Compromised: Bumps the account to "High Risk," triggering automated guardrails (like forcing an immediate password reset via Conditional Access).
​Reset Password: Forces an immediate credential rotation.
​3. Email & Collaboration (Defender for Office 365)
​If a phishing campaign hits or an internal account starts blasting out malicious links, you remediate the data directly inside the mailboxes.
​Soft Delete / Hard Delete Email: Removals of malicious emails directly from the user's inbox. "Soft delete" moves it to the Recoverable Items folder (hidden from the user); "Hard delete" purges it permanently.
​Move to Junk / Quarantine: Shakes the email out of the inbox and drops it into a secure quarantine container where the user can't click the links.
​ZAP (Zero-hour Auto Purge): An automated retroactive strike. If an email was delivered hours ago, but Microsoft just discovered the link inside it is malicious, ZAP will automatically hunt through all customer mailboxes and yank that email out out of sight.
​4. Cloud Apps & SaaS Data (Defender for Cloud Apps)
​This handles data governance and third-party SaaS apps (like Salesforce, Box, or AWS) that hook into your environment.
​Suspend SaaS User: Temporarily locks the user out of a specific third-party cloud app (not just their Microsoft account).
​File Quarantine: If a user uploads a malware-infected file or a document containing sensitive corporate data (PII/SPI) to a public cloud share, you can pull it out of circulation and lock it down.
​Inherit Microsoft Information Protection (MIP) Labels: Automatically encrypts a file retroactively, requiring proper identity permissions to open it, even if it has already been downloaded.
​5. Automated Remediation (AIR & Sentinel SOAR)
​As an MXDR provider, you don't always do these manually. You have two levels of automation doing this for you:
​AIR (Automated Investigation and Response): Built directly into Defender. If a known malware alert fires on an endpoint, AIR automatically builds a "playbook" in the background, investigates related files, and asks you to approve the remediation (or does it automatically if you have it set to full automation).
​Microsoft Sentinel Playbooks (Logic Apps): Your custom orchestration engine. If you want a specific trigger (like a high-severity alert from a specific VIP user) to simultaneously isolate their laptop, revoke their cloud sessions, and block the attacker's IP on the Azure Firewall, a Sentinel playbook handles all three across different asset groups in under 5 seconds.
