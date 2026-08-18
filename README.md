# Suspicious PowerShell Detection & SOC Investigation

A hands-on SOC L1 lab using **Splunk Enterprise** and **Sysmon** to detect, investigate, and disposition suspicious PowerShell activity.

The lab covers PowerShell detection, process investigation, `ProcessGuid` correlation, network investigation, DNS analysis, MITRE ATT&CK mapping, and final alert disposition.

---

## Lab Objective

The goal of this lab was to investigate a PowerShell execution that used:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Host 'SOC Lab Investigation Test'"
```

I wanted to investigate the activity the same way a SOC L1 analyst would:

1. Detect the suspicious activity.
2. Identify the user and process.
3. Investigate the process details.
4. Correlate the process with other Sysmon events.
5. Check for network activity.
6. Investigate DNS activity.
7. Determine whether the activity was actually malicious.
8. Close or escalate the alert based on the evidence.

The PowerShell activity was an **authorized test performed inside my own lab environment**.

---

## Lab Environment

| Component | Details |
|---|---|
| SIEM | Splunk Enterprise |
| Endpoint | Windows |
| Endpoint Telemetry | Sysmon |
| Log Forwarder | Splunk Universal Forwarder |
| Splunk Index | `main` |
| Process Creation | Sysmon Event ID 1 |
| Network Connection | Sysmon Event ID 3 |
| DNS Query | Sysmon Event ID 22 |
| Splunk Receiving Port | TCP 9997 |

---

## Lab Architecture

```text
Windows Endpoint
       |
       v
     Sysmon
       |
       v
Splunk Universal Forwarder
       |
       | TCP 9997
       v
Splunk Enterprise
       |
       v
SOC Investigation
       |
       v
Detection -> Triage -> Correlation -> Disposition
```

---

# 1. Generate the Test Activity

I generated a controlled PowerShell event on the Windows endpoint:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Host 'SOC Lab Investigation Test'"
```

The command was intentionally designed to generate a suspicious-looking PowerShell process creation event.

The important indicator was:

```text
-ExecutionPolicy Bypass
```

This can be suspicious in a real environment because PowerShell is frequently abused for command and script execution.

However, I did **not** immediately classify the event as malicious.

The purpose of the investigation was to determine what actually happened.

---

# 2. Detect the PowerShell Activity

I used Sysmon Event ID 1 because it records process creation.

### SPL

```spl
index=main sourcetype=XmlWinEventLog EventCode=1 earliest=-24h
| where match(lower(CommandLine), "executionpolicy\s+bypass")
| eval Severity="Medium"
| eval Detection="Suspicious PowerShell - ExecutionPolicy Bypass"
| eval MITRE_Technique="T1059.001 - PowerShell"
| table _time Severity Detection MITRE_Technique host User Image ParentImage CommandLine ProcessId ProcessGuid
| sort -_time
```

### Detection Result

The query identified the PowerShell activity with the following details:

| Field | Value |
|---|---|
| Host | `Stark` |
| User | `Stark\PARADOX` |
| Process | `powershell.exe` |
| Process ID | `420` |
| Severity | Medium |
| Detection | Suspicious PowerShell - ExecutionPolicy Bypass |
| MITRE ATT&CK | T1059.001 |

The command line contained:

```text
-NoProfile -ExecutionPolicy Bypass
```

### Screenshot

![Suspicious PowerShell Detection](screenshots/01-suspicious-powershell-detection.png)

---

# 3. Investigate the Process

After detecting the PowerShell activity, I investigated the process details.

### SPL

```spl
index=main sourcetype=XmlWinEventLog EventCode=1 earliest=-24h
| search "SOC Lab Investigation Test"
| table _time host User Image ParentImage CommandLine ProcessId ProcessGuid ParentProcessGuid
| sort _time
```

The investigation returned the process information needed to continue the investigation.

### Information Reviewed

- Timestamp
- Host
- User
- Process image
- Parent process
- Command line
- Process ID
- ProcessGuid
- ParentProcessGuid

### Screenshot

![Process Investigation](screenshots/02-process-investigation.png)

---

# 4. PID Reuse Investigation

During the investigation, I found an important issue with using the Process ID alone.

The PowerShell process used:

```text
ProcessId = 420
```

However, PID `420` had also appeared in an earlier event associated with another process.

This is possible because Windows can reuse Process IDs after a process terminates.

Therefore, using:

```text
ProcessId=420
```

alone could incorrectly associate events from different processes.

This led me to use the Sysmon `ProcessGuid` for process-level correlation.

---

# 5. ProcessGuid Correlation

The PowerShell process had the following ProcessGuid:

```text
{f0be383d-f49a-6a83-710b-000000001a00}
```

Using `ProcessGuid` allowed me to investigate events belonging specifically to this PowerShell process instead of relying only on PID `420`.

This was important for the next stage of the investigation.

---

# 6. Network Investigation

I checked whether the specific PowerShell process established any network connection.

### SPL

```spl
index=main sourcetype=XmlWinEventLog EventCode=3 earliest=-24h
| search ProcessGuid="{f0be383d-f49a-6a83-710b-000000001a00}"
| table _time host User Image DestinationIp DestinationHostname DestinationPort ProcessId ProcessGuid
| sort _time
```

### Result

```text
0 events
```

No Sysmon Event ID 3 network connection was observed for the specific PowerShell ProcessGuid during the investigation period.

This meant there was **no observed network connection associated with this specific PowerShell process**.

### Screenshot

![Network Correlation](screenshots/03-network-correlation.png)

---

# 7. DNS Investigation

I also checked the DNS telemetry generated during the lab.

### SPL

```spl
index=main sourcetype=XmlWinEventLog EventCode=22 earliest=-24h
| search QueryName="example.com"
| table _time host User Image QueryName ProcessId ProcessGuid
| sort _time
```

A DNS query for:

```text
example.com
```

was present in the logs.

However, the DNS event had a **different ProcessGuid** from the suspicious PowerShell process.

Therefore, I did not associate the DNS event with the PowerShell detection.

This was an important correlation check because activity occurring on the same host does not automatically mean that the events came from the same process.

### Screenshot

![DNS Investigation](screenshots/04-dns-investigation.png)

---

# 8. Investigation Findings

| Investigation Check | Result |
|---|---|
| PowerShell execution detected | Yes |
| `ExecutionPolicy Bypass` detected | Yes |
| Process investigated | Yes |
| ProcessGuid identified | Yes |
| Network connection from specific PowerShell process | None observed |
| DNS activity observed | Yes |
| DNS linked to suspicious PowerShell ProcessGuid | No |
| Malicious payload observed | No |
| Evidence of exfiltration | None observed |
| Activity source | Authorized lab testing |
| Final disposition | Benign |

---

# 9. MITRE ATT&CK Mapping

## T1059.001 — Command and Scripting Interpreter: PowerShell

The detected behavior maps to:

**T1059.001 — PowerShell**

The mapping is based on the PowerShell process execution observed through Sysmon Event ID 1.

---

# 10. Final SOC Disposition

## Alert

**Suspicious PowerShell - ExecutionPolicy Bypass**

## Severity

**Medium**

## Investigation

The alert was generated because PowerShell was executed with `ExecutionPolicy Bypass`.

I investigated the PowerShell process and identified its `ProcessGuid`.

I then checked Sysmon Event ID 3 for network activity associated with that exact ProcessGuid.

No associated network connection was observed.

I also investigated the observed DNS activity, but its ProcessGuid did not match the PowerShell process.

The PowerShell activity was part of the authorized security test performed in the lab.

## Final Verdict

**Closed - Benign / Authorized Security Testing**

## Escalation

**Not required**

### Screenshot

![Final Disposition](screenshots/05-final-disposition.png)

---

# 11. Investigation Timeline

```text
PowerShell executed
        |
        v
ExecutionPolicy Bypass detected
        |
        v
Splunk detection triggered
        |
        v
Process details investigated
        |
        v
ProcessGuid identified
        |
        v
Network activity checked
        |
        v
No associated network connection
        |
        v
DNS activity investigated
        |
        v
Different ProcessGuid
        |
        v
Authorized lab activity confirmed
        |
        v
Alert closed as benign
```

---

# 12. What I Learned

### Process ID is not enough

Windows can reuse PIDs. During this investigation, PID `420` appeared with different processes at different times.

Using Sysmon `ProcessGuid` prevented incorrect correlation.

### Suspicious does not automatically mean malicious

`ExecutionPolicy Bypass` is a useful detection indicator, but it should trigger investigation rather than automatically result in escalation.

### Correlation needs evidence

The DNS event was observed on the same endpoint, but its ProcessGuid did not match the suspicious PowerShell process.

I therefore did not treat it as related activity.

### Detection is only the beginning

The important part of a SOC workflow is not just creating a detection.

The analyst needs to:

```text
Detect
   ↓
Investigate
   ↓
Correlate
   ↓
Validate
   ↓
Disposition
```

---

# 13. Skills Demonstrated

- Splunk Enterprise
- SPL
- Sysmon
- Windows Event Logs
- PowerShell Monitoring
- Process Investigation
- ProcessGuid Correlation
- Network Investigation
- DNS Investigation
- SOC L1 Alert Triage
- Incident Investigation
- MITRE ATT&CK
- False Positive Analysis
- Alert Disposition

---

# 14. Repository Structure

```text
Suspicious-PowerShell-Detection-SOC-Investigation/
│
├── README.md
│
└── screenshots/
    ├── 01-suspicious-powershell-detection.png
    ├── 02-process-investigation.png
    ├── 03-network-correlation.png
    ├── 04-dns-investigation.png
    └── 05-final-disposition.png
```

---

# Conclusion

This project gave me hands-on experience investigating suspicious PowerShell activity with Splunk and Sysmon.

The investigation started with a PowerShell `ExecutionPolicy Bypass` detection and continued through process analysis, PID reuse investigation, ProcessGuid correlation, network investigation, and DNS analysis.

The specific PowerShell process had no observed Sysmon network connection, and the DNS activity found during the investigation belonged to a different process.

The activity was confirmed as an authorized lab test.

**Final Result: Suspicious PowerShell detected → Investigated → No associated network connection observed → Authorized activity confirmed → Alert closed as benign.**
