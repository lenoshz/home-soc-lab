# Runbook: Registry Run Key Persistence

## Overview
This runbook covers detection and response to persistence established via Windows Registry
Run key modifications. Attackers use Run keys to ensure malicious code executes automatically
on user logon or system startup, maintaining access across reboots.

## Prerequisites
- Elasticsearch and Kibana running
- Detection rule `rule-006-persistence` enabled
- Sysmon Event ID 13 (registry value set) or Elastic Agent registry telemetry ingested
- Access to affected host via EDR or remote management
- Baseline of known-good Run key entries for comparison

## Detection
**Rule**: `rule-006-persistence` - Registry Run Key Persistence  
**Severity**: Medium  
**MITRE ATT&CK**: [T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)

This rule fires when a change event is detected on Windows Registry paths under
`SOFTWARE\Microsoft\Windows\CurrentVersion\Run*`, indicating a new autostart entry.

**KQL Query**:
```kql
event.category:registry AND registry.path:*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run* AND event.type:change
```

## Investigation Steps

1. **Identify the registry change**
   - Note `registry.path`, `registry.data.strings` (the value data), and `host.name`
   - Identify the process that made the change (`process.name`, `process.pid`)
   - Determine the registry hive: HKLM affects all users; HKCU affects the current user only

2. **Analyze the persistence payload**
   - Inspect the registry value data for the executable or script path
   - Hash the referenced file (SHA-256) and check against VirusTotal / internal AV
   - Determine if the file is in an unusual location (Temp, AppData, ProgramData)

3. **Check for related activity**
   - Correlate with rule-005 (Malware Execution) — was malware recently executed?
   - Search for the process that wrote the key in the process execution logs
   - Look for additional persistence (scheduled tasks, services, startup folder)

4. **Preserve evidence**
   - Export registry event logs and the process creation events from the affected host
   - Hash and archive the payload binary
   - Document all Run key values before making changes

## Containment

- [ ] Delete the malicious Run key entry via EDR or remote registry edit
- [ ] Kill any currently running instances of the persistence payload
- [ ] Isolate the host if active malware is confirmed
- [ ] Block the payload file hash at the EDR policy level
- [ ] Disable the user account if the HKCU key was set by a compromised user

## Eradication

- [ ] Run a full EDR scan to identify all related malware artifacts
- [ ] Check and clean all additional persistence locations (services, scheduled tasks, WMI)
- [ ] Remove the payload binary and any associated files
- [ ] Audit Run keys across the environment for similar entries (use Kibana alert)

## Recovery

- [ ] Confirm Run key is removed and system boots cleanly
- [ ] Restore any system files modified by the malware from backup
- [ ] Re-enable affected user accounts after password reset
- [ ] Monitor the host's registry for new autostart entries for 7 days

## Lessons Learned

Document findings after incident resolution:
- Root cause (how malware was initially delivered and executed)
- Whether application whitelisting or registry auditing would have prevented this
- Improvements to endpoint hardening (restrict HKLM Run key write access)
- Baseline maintenance for known-good autostart entries

## References
- [MITRE ATT&CK: T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)
- [Elastic Security: Persistence via Registry](https://www.elastic.co/guide/en/security/current/prebuilt-rules.html)
- [Microsoft: Registry Run Keys / Startup Folder](https://docs.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)
