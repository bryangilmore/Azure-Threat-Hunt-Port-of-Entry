# Port of Entry – Azure / Microsoft 365 Defender Threat Hunt

This repository documents my end-to-end threat hunt of the **“Port of Entry”** scenario from The Cyber Range using **Microsoft Defender for Endpoint Advanced Hunting** (KQL).

The goal of the lab is to investigate the compromise of **Azuki Import/Export** by the threat group **“JADE SPIDER”**, identify the full attack chain, and map findings to **MITRE ATT&CK**.

---

## Skills demonstrated

This project showcases several core blue-team and SOC skills:

- **Threat hunting in Microsoft Defender for Endpoint**
  - Pivoting across `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, and `DeviceRegistryEvents`
  - Building stepwise hunts that follow the full attack lifecycle

- **Kusto Query Language (KQL)**
  - Writing focused, filter-heavy queries for logon analysis, process tracing, network connections, file activity, and registry changes
  - Using projections, string searches, and ordering to surface key evidence quickly

- **Incident reconstruction & timeline building**
  - Tracing attacker actions from initial access through discovery, persistence, credential theft, collection, exfiltration, anti-forensics, and lateral movement
  - Correlating events across multiple tables and artifacts

- **MITRE ATT&CK mapping**
  - Aligning observed behaviors with ATT&CK techniques (e.g., T1133, T1105, T1053.005, T1003.001, T1567, T1070.001)
  - Presenting findings in a way that supports detection engineering and reporting

- **SOC-style documentation**
  - Clean separation of **queries** and **screenshots**
  - Clear narrative describing what each query finds and why it matters
  - Professional write-up suitable for an investigation report or portfolio

---

## Scenario summary

- **Victim:** Azuki Import/Export (small logistics / import–export company)
- **Key host:** `AZUKI-SL` (IT admin workstation)
- **Threat actor:** JADE SPIDER – financially motivated, targeting logistics companies
- **Initial symptom:** Competitor undercuts a 6-year contract; Azuki’s contracts and pricing data appear on underground forums
- **Data source:** Microsoft Defender for Endpoint tables (Advanced Hunting)

High-level attack flow:

1. Initial access via exposed Remote Desktop.
2. Discovery and staging of tools in a hidden folder.
3. Defense evasion using Windows Defender exclusions.
4. Ingress tool transfer with `certutil.exe`.
5. Persistence with a scheduled task.
6. Command & control over HTTPS.
7. Credential dumping from LSASS.
8. Collection and compression of data.
9. Exfiltration to Discord.
10. Anti-forensics and impact: log clearing + new local admin.
11. Lateral movement to another host via RDP.

---

## MITRE ATT&CK mapping

| Phase | Flags | Technique | ID | Evidence |
|------|-------|-----------|----|----------|
| Initial Access | 1–2 | External Remote Services | **T1133** | RDP logon from public IP `88.97.178.12` to `AZUKI-SL` using `kenji.sato`. |
| Discovery | 3 | System Network Configuration Discovery | **T1016** | `arp.exe -a` used to enumerate local network neighbours. |
| Defense Evasion | 4–6 | Impair Defenses: Disable or Modify Tools | **T1562.001** | Windows Defender extension and path exclusions added for attacker tools and temp folders. |
| Defense Evasion | 4 | Hide Artifacts: File/Path Exclusions | **T1564.012** | Malware staged in `C:\ProgramData\WindowsCache\`. |
| Command & Control / Ingress | 7, 10–11 | Ingress Tool Transfer | **T1105** | `certutil.exe` downloads payloads into `C:\ProgramData\WindowsCache\` which then beacon to the C2 server. |
| Persistence | 8–9 | Scheduled Task/Job: Scheduled Task | **T1053.005** | “Windows Update Check” scheduled task configured to run `C:\ProgramData\WindowsCache\svchost.exe`. |
| Credential Access | 12–13 | OS Credential Dumping: LSASS Memory | **T1003.001** | `mm.exe` executes `sekurlsa::logonpasswords` against LSASS. |
| Collection | 14 | Archive Collected Data | **T1560** | `export-data.zip` created in the staging directory. |
| Exfiltration | 15 | Exfiltration Over Web Service | **T1567** | `curl.exe` uploads data to `discord.com` over HTTPS. |
| Defense Evasion / Anti-forensics | 16 | Clear Windows Event Logs | **T1070.001** | `wevtutil.exe cl Security` used to clear the Security log. |
| Persistence / Impact | 17 | Create Account: Local Account | **T1136.001** | Local account `support` created and added to privileged group(s). |
| Execution | 18 | Command and Scripting Interpreter: PowerShell | **T1059.001** | Malicious script `wupdate.ps1` used to automate the attack chain. |
| Lateral Movement | 19–20 | Remote Services (RDP) / Use Alternate Authentication Material | **T1021.001 / T1550** | `cmdkey.exe` stores credentials, then `mstsc.exe /v:10.1.0.188` initiates RDP to a secondary host. |

---

## Files

- **`/queries`** – plain-text KQL used in Defender Advanced Hunting for each phase.  
- **`/screenshots`** – Advanced Hunting result views showing the query and key evidence used to answer each flag.

---

## Phase-by-phase walkthrough

### 1. Initial access (Flags 1 & 2)

- **Query:** `queries/01_initial_access_logon.txt`  
- **Screenshot:** `screenshots/01_initial_access_logon.png`  

This query pivots on `DeviceLogonEvents` for the host `AZUKI-SL` and surfaces RDP logons.  
From the results:

- **RemoteIP:** `88.97.178.12` → source of the RDP connection  
- **AccountName:** `kenji.sato` → compromised user identity  

These answer Flags 1 and 2 and support **T1133 External Remote Services**.

---

### 2. Discovery & staging (Flags 3 & 4)

- **Network discovery:** `queries/02_discovery_arp.txt`  
  - Shows `arp.exe -a` executed after initial access.  
  - This reflects **T1016 System Network Configuration Discovery**.

- **Staging directory:** `queries/03_staging_directory.txt`  
  - Tracks creation and use of `C:\ProgramData\WindowsCache\` as the primary malware staging area.  

Screenshots:

- `screenshots/02_discovery_arp.png`  
- `screenshots/03_staging_directory.png`

---

### 3. Defender exclusions (Flags 5 & 6)

- **Extension exclusions:** `queries/04a_defender_extension_exclusions.txt`  
  - `DeviceRegistryEvents` filtered on `Windows Defender\Exclusions\Extensions` show multiple file extensions (.bat, .ps1, .exe, etc.) being excluded.

- **Path exclusions:** `queries/04b_defender_path_exclusions.txt`  
  - Similar filter for `Windows Defender\Exclusions\Paths`, revealing a temp directory being excluded from scanning.

Screenshots:

- `screenshots/04a_defender_extension_exclusions.png`  
- `screenshots/04b_defender_path_exclusions.png`  

This behavior maps to **T1562.001 Impair Defenses: Disable or Modify Tools** and demonstrates how the attacker attempted to blind AV before running their tools.

---

### 4. Download utility & scheduled task (Flags 7, 8 & 9)

- **Ingress tool transfer (certutil):**  
  `queries/05a_certutil_downloads_to_windowscache.txt`  
  - `DeviceProcessEvents` search for `FileName == "certutil.exe"` with URLs and an output path under `C:\ProgramData\WindowsCache\`.

- **Scheduled task persistence:**  
  `queries/05b_scheduled_task_persistence.txt`  
  - `schtasks.exe /create` defining task `"Windows Update Check"` with `/tr C:\ProgramData\WindowsCache\svchost.exe`.

Screenshots:

- `screenshots/05a_certutil_downloads_to_windowscache.png`  
- `screenshots/05b_scheduled_task_persistence.png`

These support **T1105 Ingress Tool Transfer** and **T1053.005 Scheduled Task**.

---

### 5. C2 traffic (Flags 10 & 11)

- **Query:** `queries/06_c2_traffic_from_windowscache.txt`  
- **Screenshot:** `screenshots/06_c2_traffic_from_windowscache.png`

The query pivots on `DeviceNetworkEvents`, focusing on processes running from `C:\ProgramData\WindowsCache\`.  

From the results:

- **RemoteIP:** `78.141.196.6`  
- **RemotePort:** `443`  

This identifies the C2 endpoint and protocol for Flags 10 and 11.

---

### 6. Credential dumping (Flags 12 & 13)

- **Query:** `queries/07_cred_dumping_mm_sekurlsa_logonpasswords.txt`  
- **Screenshot:** `screenshots/07_cred_dumping.png`

This hunt over `DeviceProcessEvents` isolates:

- `FileName == "mm.exe"`  
- `ProcessCommandLine` containing `sekurlsa::logonpasswords`

Together, they confirm LSASS credential dumping consistent with **T1003.001 OS Credential Dumping: LSASS Memory**.

---

### 7. Collection & exfiltration (Flags 14 & 15)

- **Archive creation:**  
  `queries/08a_archive_export_data.txt`  
  - `DeviceFileEvents` shows `export-data.zip` created in `C:\ProgramData\WindowsCache\`.

- **Exfil over Discord:**  
  `queries/08b_exfil_discord.txt`  
  - `DeviceNetworkEvents` shows `curl.exe` making HTTPS requests to `discord.com`, coinciding with the ZIP creation.

Screenshots:

- `screenshots/08a_archive_export_data.png`  
- `screenshots/08b_exfil_discord.png`

These demonstrate **T1560 Archive Collected Data** and **T1567 Exfiltration Over Web Service**.

---

### 8. Anti-forensics & backdoor account (Flags 16 & 17)

- **Log clearing:**  
  `queries/09a_log_clearing_wevtuil.txt`  
  - Shows `wevtutil.exe cl Security`, clearing the Windows Security log (**T1070.001**).

- **Backdoor account:**  
  `queries/09b_backdoor_account_support.txt`  
  - `DeviceEvents` entry with `ActionType == "UserAccountCreated"` and `AccountName == "support"` – a hidden persistence pathway (**T1136.001**).

Screenshots:

- `screenshots/09a_log_clearing_wevtuil.png`  
- `screenshots/09b_backdoor_account_support.png`

---

### 9. Malicious script (Flag 18)

- **Query:** `queries/10_malicious_script_wupdate.txt`  
- **Screenshot:** `screenshots/10_malicious_script_wupdate.png`

This query locates creation and/or execution of the script `wupdate.ps1`, used to orchestrate parts of the attack using **PowerShell** (**T1059.001**).

---

### 10. Lateral movement (Flags 19 & 20)

- **Query:** `queries/11_lateral_movement_cmdkey_mstsc.txt`  
- **Screenshot:** `screenshots/11_lateral_movement.png`

The results clearly show:

- `cmdkey.exe /generic:10.1.0.188 ...`  
- followed by `mstsc.exe /v:10.1.0.188`

This pattern indicates credential staging with `cmdkey` and RDP-based lateral movement with `mstsc`, matching **T1550 Use Alternate Authentication Material** and **T1021.001 Remote Services (RDP)**.
