# Threat Event (Unauthorized VPN Usage)

**Unauthorized VPN Installation and Use**

## Steps the "Bad Actor" Took to Create Logs and IoCs:
1. Download a VPN client (e.g., NordVPN, ExpressVPN, ProtonVPN):
   - Example: https://protonvpn.com/download/
2. Install the VPN client silently:
   ```protonvpn-windows-setup.exe /silent```
3. Launch the VPN client from the installation directory.
4. Establish a VPN connection to an external server.
5. Browse various websites using the encrypted VPN tunnel.
6. Create a text file on the desktop named `vpn-usage-log.txt` containing connection details.
7. Delete the file to remove traces.

---

## Tables Used to Detect IoCs:

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting VPN client download, installation, and log file creation/deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of VPN clients and launching of VPN processes. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect VPN network activity, specifically VPN-related processes making connections over common VPN ports (1194, 443, 500, 4500, 51820). |

---

## Related Queries:

```kql
// Detect VPN client being downloaded
DeviceFileEvents
| where FileName startswith "protonvpn" or FileName startswith "nordvpn" or FileName startswith "expressvpn"

// Silent installation of VPN client
DeviceProcessEvents
| where ProcessCommandLine contains "protonvpn-windows-setup.exe /silent"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

// VPN client presence on disk
DeviceFileEvents
| where FileName has_any ("protonvpn.exe", "nordvpn.exe", "expressvpn.exe")
| project Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine

// VPN client or service was launched
DeviceProcessEvents
| where ProcessCommandLine has_any("protonvpn.exe", "nordvpn.exe", "expressvpn.exe")
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// VPN client making network connections
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("protonvpn.exe", "nordvpn.exe", "expressvpn.exe")
| where RemotePort in (1194, 443, 500, 4500, 51820)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// VPN usage log file created, modified, or deleted
DeviceFileEvents
| where FileName contains "vpn-usage-log.txt"
```

---

## Created By:
- **Author Name**: James Little
- **Author Contact**: 
- **Date**: February 12, 2025

## Validated By:
- **Reviewer Name**:
- **Reviewer Contact**:
- **Validation Date**:

---

## Additional Notes:
- Consider blocking VPN-related applications via endpoint protection policies.
- Monitor for unauthorized VPN usage as it may indicate data exfiltration or evasion tactics.

---

## Revision History:

| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `February 12, 2025` | `James Little`    |

