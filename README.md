# Threat Hunt Report: Malicious PowerShell Execution

## Scenario Creation

### Platforms and Languages Leveraged
- **Windows 10 Virtual Machines (Microsoft Azure)**
- **EDR Platform:** Microsoft Defender for Endpoint
- **Kusto Query Language (KQL)**
- **PowerShell**

## Scenario

Management has reported unusual system behavior, including unauthorized script execution, high CPU usage, and suspicious outbound network traffic. Network logs indicate multiple outbound connections to suspicious domains, suggesting possible malware execution. Additionally, system administrators have detected unauthorized scheduled tasks running PowerShell scripts at startup. The objective is to detect any unauthorized PowerShell execution, analyze related security incidents, and mitigate potential risks. If malicious PowerShell activity is found, management will be notified.

## High-Level Malicious PowerShell Execution IoC Discovery Plan

- Check **DeviceFileEvents** for any PowerShell script (.ps1) downloads or executions.
- Check **DeviceProcessEvents** for any PowerShell executions using obfuscation or bypass techniques.
- Check **DeviceNetworkEvents** for any external connections initiated by PowerShell.
- Check **DeviceRegistryEvents** and **DeviceScheduledTaskEvents** for persistence mechanisms.

## Steps Taken

### 1. Searched the DeviceFileEvents Table

Searched for any file events involving PowerShell scripts. Discovered that user "employee" downloaded a PowerShell script named `malware.ps1` from an external source to `C:\Users\Public\malware.ps1` at `2024-11-08T22:14:48.6065231Z`.

#### Query used to locate events:
```kql
DeviceFileEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName endswith ".ps1"  
| where FolderPath contains "Users\\Public"  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

---

### 2. Searched the DeviceProcessEvents Table

Searched for PowerShell execution using `ExecutionPolicy Bypass` and `NoProfile` flags. Found that at `2024-11-08T22:16:47.4484567Z`, user "employee" executed the malicious script in hidden mode.

#### Query used to locate events:
```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where ProcessCommandLine has_any ("powershell.exe -ExecutionPolicy Bypass", "powershell.exe -NoProfile", "powershell.exe -WindowStyle Hidden")  
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine
```

---

### 3. Searched the DeviceProcessEvents Table for Persistence Mechanisms

Checked for scheduled tasks created to persist PowerShell execution. Found that at `2024-11-08T22:17:21.6357935Z`, a task named `SystemUpdate` was created to execute the PowerShell script at login.

#### Query used to locate events:
```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where ProcessCommandLine contains "schtasks /create"  
| where ProcessCommandLine contains "powershell.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine
```

---

### 4. Searched the DeviceNetworkEvents Table for Malicious Network Connections

Identified that at `2024-11-08T22:18:01.1246358Z`, PowerShell initiated a connection to a known malicious C2 server at IP `176.198.159.33`.

#### Query used to locate events:
```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessFileName == "powershell.exe"  
| where RemoteUrl contains "malicious-c2.com"  
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl
```

---

## Chronological Event Timeline

### 1. File Download - Malicious PowerShell Script
- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** User "employee" downloaded `malware.ps1`.
- **Action:** File download detected.
- **File Path:** `C:\Users\Public\malware.ps1`

### 2. Process Execution - Malicious PowerShell Execution
- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** User executed `malware.ps1` with bypass policies.
- **Action:** Process execution detected.
- **Command:** `powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File "C:\Users\Public\malware.ps1"`

### 3. Persistence Mechanism - Scheduled Task Creation
- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** Scheduled task `SystemUpdate` created to persist PowerShell execution.
- **Action:** Persistence method detected.
- **Command:** `schtasks /create /tn "SystemUpdate" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\malware.ps1" /sc onlogon /rl highest`

### 4. Network Connection - Malicious C2 Communication
- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** Connection to C2 server `176.198.159.33`.
- **Action:** Outbound network connection detected.
- **Process:** `powershell.exe`
- **File Path:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

---

## Summary

User "employee" on the device "threat-hunt-lab" downloaded and executed a malicious PowerShell script that established persistence using scheduled tasks. The script connected to an external Command and Control (C2) server, indicating potential malicious intent. The execution of PowerShell with bypass flags and the creation of unauthorized scheduled tasks are strong indicators of an attack.

---

## Response Taken
- Confirmed unauthorized PowerShell execution.
- Isolated the compromised device.
- Blocked outbound connections to known malicious C2 servers.
- Notified management and security operations for further investigation.

---

## Created By:
- **Author Name**: James Little
- **Author Contact**: [Your Contact Info]
- **Date**: February 12, 2025

## Validated By:
- **Reviewer Name**:
- **Reviewer Contact**:
- **Validation Date**:

---

## Revision History:
| **Version** | **Changes** | **Date** | **Modified By** |
|------------|------------|----------|----------------|
| 1.0 | Initial draft | `February 12, 2025` | `James Little` |

