## Threat Hunt Report: Unauthorized TOR Usage

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Initial Tor Installer Interaction

At 2026-01-21 13:20:01, I began by reviewing DeviceFileEvents for any files containing the string “tor” associated with the user civil7948. This allowed me to establish a baseline for when Tor-related artifacts first appeared on the device.

The logs recorded the earliest Tor-related file activity at this time, indicating that the user had either downloaded or interacted with a Tor installer. I treated this as the initial access point in the investigation and used it to scope the rest of my timeline.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "win-11-vil-pro"  
| where InitiatingProcessAccountName == "civil7948"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2026-01-21T12:20:01.8371157Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

<img width="1861" height="766" alt="1 1" src="https://github.com/user-attachments/assets/a144bffd-60a8-4b3b-ba4e-ed5dadf4d818" />


### 2. Tor Installer Execution (Silent Install)

Next, I pivoted to DeviceProcessEvents to determine whether the installer was actually executed.

At 2026-01-21 13:25:12, I identified a process creation event for
tor-browser-windows-x86_64-portable-15.0.4.exe launched from the user’s Downloads directory.

The command-line parameters indicated silent installation behavior, which confirmed this wasn't just a passive download but an intentional execution step. At this stage, I marked the event as user-initiated software execution and continued tracking for follow-on activity.

**Query used to locate event:**

```kql
DeviceProcessEvents  
| where DeviceName == "win--11-vul-pro"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.4.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

<img width="1892" height="171" alt="2 2" src="https://github.com/user-attachments/assets/4a2d0571-3a3f-41f2-9f02-071cb42f75fe" />

---

### 3. Tor Browser Launched

To validate whether the installation led to active usage, I searched for Tor-related process creation.

At 2026-01-21 13:25:35, I observed tor.exe and firefox.exe (Tor Browser’s embedded browser) spawning from the Tor Browser directory on the user’s desktop.

This confirmed that the user successfully launched Tor Browser. The presence of multiple related processes, aligned with normal Tor runtime behavior, established a clear transition from installation to execution.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "win-11-vul-pro"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```

<img width="1887" height="956" alt="3 3" src="https://github.com/user-attachments/assets/7ce26522-d7b2-4af2-a3b3-60c8e7abfaa3" />

---

### 4. Tor Network Connectivity Established

After confirming execution, I shifted focus to DeviceNetworkEvents to determine whether the browser was actually used to communicate externally.

At 2026-01-21 13:39:06, I identified a successful outbound connection initiated by tor.exe to the remote IP 217.160.114.102 over port 9001, a port commonly associated with Tor relays.

This was a critical finding, as it confirmed active participation in the Tor network rather than just local application activity.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "win-11-vul-pro"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```

<img width="1872" height="443" alt="4 4" src="https://github.com/user-attachments/assets/9300d2ea-e66a-455b-8468-d108141df593" />

---

### 5. Additional Tor Traffic Over HTTPS

Between 13:39:12 and 13:48:44, I observed multiple additional outbound connections initiated by both tor.exe and firefox.exe over port 443.

Several of the destination domains appeared randomized and consistent with Tor browsing patterns. I interpreted this as evidence of active web browsing through the Tor network, rather than background service traffic alone.

---

### 6. Tor-Related Files and User Artifact Creation

To determine whether the user performed any actions tied to their browsing session, I returned to DeviceFileEvents.

At 2026-01-21 13:53:59, I identified the creation of a file named tor-shopping-list.txt on the user’s desktop. At the same time, multiple Tor-related files and shortcuts were copied or created in the same directory.

This suggested interactive user behavior, likely involving the saving or documentation of information while Tor Browser was in use.

---

### 7. Continued File Modifications

Finally, on 2026-01-21 13:54:27–13:54:28, I observed modification events for tor-shopping-list.txt.

The edits confirmed that the file was actively used after its creation, supporting my assessment that the user was engaged in a Tor-based browsing session and capturing information locally.

---

## Summary of Events

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `win-11-vul-pro` by the user `civil7948`. The device was isolated, and the user's direct manager was notified.

---
