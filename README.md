# Threat Hunt Report: Unauthorized VPN Usage

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- VPN Client Software

## [Scenario](https://github.com/jameslittle05/ThreatHunts/blob/main/Scenario.md)

Management suspects that some employees may be using unauthorized VPN clients to bypass network security controls. Recent network logs show unusual encrypted traffic patterns and connections to known VPN servers. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any unauthorized VPN usage and analyze related security incidents to mitigate potential risks. If any unauthorized VPN use is found, notify management.

### High-Level VPN-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any VPN client installation files.
- **Check `DeviceProcessEvents`** for any signs of VPN client execution.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections to known VPN servers or ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "vpn" in it and discovered what looks like the user "employee" downloaded a VPN client installer, did something that resulted in many VPN-related files being copied to the desktop, and the creation of a file called `vpn-config.txt` on the desktop at `2024-11-08T22:27:19.7259964Z`. These events began at `2024-11-08T22:14:48.6065231Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "labuser"  
| where InitiatingProcessAccountName == "employee"  
| where FileName contains "vpn"  
| where Timestamp >= datetime(2024-11-08T22:14:48.6065231Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "vpn-client-setup.exe". Based on the logs returned, at `2024-11-08T22:16:47.4484567Z`, an employee on the "labuser" device ran the file `vpn-client-setup.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents  
| where DeviceName == "labuser"  
| where ProcessCommandLine contains "vpn-client-setup.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

---

### 3. Searched the `DeviceProcessEvents` Table for VPN Client Execution

Searched for any indication that user "employee" actually opened the VPN client. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `vpnclient.exe` as well as related background processes spawned afterward.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "labuser"  
| where FileName has_any ("vpnclient.exe", "openvpn.exe", "nordvpn.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```

---

### 4. Searched the `DeviceNetworkEvents` Table for VPN Network Connections

Searched for any indication the VPN client was used to establish a connection using any of the known VPN ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "labuser" device successfully established a connection to the remote IP address `198.51.100.33` on port `1194`. The connection was initiated by the process `vpnclient.exe`, located in the folder `c:\users\employee\desktop\vpn\vpnclient.exe`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "labuser"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("vpnclient.exe", "openvpn.exe", "nordvpn.exe")  
| where RemotePort in ("1194", "443", "500", "4500")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```

---

## Summary

The user "employee" on the "labuser" device initiated and completed the installation of an unauthorized VPN client. They proceeded to launch the client, establish connections within the VPN network, and created various files related to VPN on their desktop, including a file named `vpn-config.txt`. This sequence of activities indicates that the user actively installed, configured, and used the VPN client, likely to bypass security controls and browse anonymously.

---

## Response Taken

Unauthorized VPN usage was confirmed on the endpoint `labuser` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---


