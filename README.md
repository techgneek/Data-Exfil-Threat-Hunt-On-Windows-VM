# 🚨 Threat Hunt Investigation: Data Exfiltration By Disgruntled Employee 

**Author:** James Moore  \
**Date:** April 13, 2025  \
**Lab Type:** Threat Hunting / Data Exfiltration / MITRE ATT&CK Mapping  \

---

## :bookmark_tabs: Overview
This lab simulates a real-world threat hunting scenario involving a disgruntled employee suspected of malicious insider behavior. After being placed on a performance improvement plan (PIP), the employee was subsequently terminated. Concerns were raised that they may have attempted to steal proprietary company data from their corporate-assigned endpoint. This investigation uses Microsoft Defender for Endpoint (MDE) telemetry, KQL queries, and MITRE ATT&CK mapping to uncover potential data exfiltration activities involving unauthorized file archiving and suspicious PowerShell execution.

---

## :world_map: Incident Summary
The VM `win10vm` showed repeated ZIP file creation and manipulation activity. Further investigation revealed the use of `7z.exe` to compress data and `powershell.exe` to rename and move files into a hidden backup folder—signs of possible data staging.

**File creation event showing `employee-data-20250413.zip`**

<img width="640" alt="Screen Shot 2025-04-13 at 9 56 01 PM" src="https://github.com/user-attachments/assets/f0d83945-f51e-4d66-ae18-ff13d748ac24" />

---

## :mag_right: Investigation Timeline & KQL Queries

### 1. Detect ZIP Archive Activity
```kql
DeviceFileEvents
| where DeviceName == "win10vm"
| where FileName endswith ".zip"
| order by Timestamp desc
```
**Repeated ZIP creation logs**

<img width="640" alt="Screen Shot 2025-04-13 at 9 56 01 PM" src="https://github.com/user-attachments/assets/f0d83945-f51e-4d66-ae18-ff13d748ac24" />

### 2. Trace the Process Behind Archive Creation
```kql
let VMName = "win10vm";
let specificTime = datetime(2025-04-14T00:50:11.5715803Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, FolderPath
```
**PowerShell invoking 7z.exe**

<img width="640" alt="Screen Shot 2025-04-14 at 9 23 11 AM" src="https://github.com/user-attachments/assets/c21e49a6-07a7-4cb9-9324-439c308f85ac" />

### 3. Check for Exfiltration Evidence
```kql
DeviceFileEvents
| where DeviceName == "win10vm"
| where FileName endswith ".zip"
| where RequestAccountName == "Cyberlab123"
| order by Timestamp desc 
//| project Timestamp, DeviceName, ActionType, FileName, FolderPath, PreviousFileName, InitiatingProcessFileName, InitiatingProcessCommandLine
```
**No data exfiltration but evidence of potential Data-Staging**

<img width="640" alt="Screen Shot 2025-04-14 at 10 43 04 PM" src="https://github.com/user-attachments/assets/e1691781-5a73-4db1-bdf3-52b296f9a8c5" />

---

## :shield: Conclusion
The user account `Cyberlab123` installed 7-Zip via PowerShell, created a ZIP archive of what appears to be employee data, and moved it to a hidden folder. Although no direct data exfiltration was observed, the behavior is strongly consistent with data staging and insider threat patterns.

---

## :bulb: Recommendations
- Enforce PowerShell script restrictions via AppLocker
- Block unauthorized archive utilities like 7-Zip
- Enable NSG outbound filtering on critical assets
- Implement Sentinel and Defender alerts for abnormal file handling

---

## :memo: MITRE ATT&CK Mapping
| Tactic             | Technique                                     | ID         | Description |
|--------------------|-----------------------------------------------|------------|-------------|
| Execution          | Command and Scripting Interpreter: PowerShell | T1059.001  | PowerShell used to run silent install + scripts |
| Defense Evasion    | Signed Binary Proxy Execution: PowerShell     | T1218.001  | LOLBin abuse to rename/move files |
| Collection         | Archive Collected Data                        | T1560.001  | Used 7-Zip to compress internal data |
| Collection         | Local Data Staging                            | T1074.001  | Staged archive in hidden folder |
| Discovery          | File and Directory Discovery                  | T1083      | Found target files to compress |
| Collection         | Data from Local System                        | T1005      | Archived employee-related data |
| Command & Control  | Ingress Tool Transfer                         | T1105      | Downloaded 7-Zip onto the machine |
| Discovery          | Process Discovery                             | T1057      | PowerShell queried local processes |

---

## :toolbox: Lab Process Summary
### 1. **Preparation**
- Hypothesis: A user may be staging data for exfiltration using PowerShell and compression tools.

### 2. **Data Collection**
- Collected logs from Defender tables (`DeviceFileEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents`)

### 3. **Analysis**
- Discovered timed creation and renaming of archive files using suspicious processes

### 4. **Investigation**
- Identified the tools used, user account responsible, and mapped them to TTPs

### 5. **Response**
- Isolated VM, disabled account, deleted archives, and implemented alerts

### 6. **Documentation**
- Created detailed report with findings, screenshots, and mapped techniques

### 7. **Improvement**
- Hardened PowerShell controls, added NSG rules, and enhanced baseline detection with Sentinel

---

> **Created using Microsoft Defender for Endpoint, Azure Monitor, and KQL**  
> **Project by James Moore | [GitHub](https://github.com/techgneek) | [YouTube](https://youtube.com/@techgneek) | [LinkedIn](https://linkedin.com/in/jamesmoore1983)**

