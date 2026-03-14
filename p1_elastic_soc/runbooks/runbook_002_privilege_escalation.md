# Runbook: Privilege Escalation Detected

## Overview
This runbook addresses detected privilege escalation events where an adversary abuses
elevation control mechanisms (sudo, su, runas) to gain elevated system access. Successful
privilege escalation can lead to full host compromise and lateral movement.

## Prerequisites
- Elasticsearch and Kibana running
- Detection rule `rule-002-privilege-escalation` enabled
- Process execution logs (Sysmon, auditd, or Elastic Agent) ingested
- Sudo/PAM logs available for Linux hosts
- Windows Security logs for Windows hosts
- Access to host management (SSH, RDP, or EDR console)

## Detection
**Rule**: `rule-002-privilege-escalation` - Privilege Escalation Detected  
**Severity**: Critical  
**MITRE ATT&CK**: [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)

This rule fires when `sudo`, `su`, or `runas` executes successfully for a non-root user,
indicating a potential privilege escalation attempt or abuse of elevation controls.

**KQL Query**:
```kql
event.category:process AND process.name:(sudo OR su OR runas) AND event.outcome:success AND NOT user.name:root
```

## Investigation Steps

1. **Identify the escalating user**
   - Note `user.name`, `host.name`, and `process.command_line` from the alert
   - Determine if the user is authorized to escalate on that host
   - Review `/etc/sudoers` or Windows local admin group membership

2. **Assess the escalated command**
   - Examine `process.args` to understand what was run with elevated privileges
   - Flag commands that spawn shells, modify system files, or create new accounts
   - Check if the escalation is part of a known maintenance workflow

3. **Check for related activity**
   - Correlate with rule-001 (Brute Force) — was this account recently attacked?
   - Search for subsequent high-privilege process spawning from the same session
   - Look for new cron jobs, services, or registry keys created post-escalation

4. **Preserve evidence**
   - Capture process tree from EDR or `ps auxf` snapshot
   - Export auth/sudo logs for the affected host and timeframe
   - Record the full command line and parent process chain

## Containment

- [ ] Terminate the suspicious escalated session (kill PID or disconnect user session)
- [ ] Lock the affected user account in Active Directory / local passwd
- [ ] Revoke sudo privileges for the account pending investigation
- [ ] Isolate the host via Kibana Endpoint Management if active exploitation is confirmed
- [ ] Block lateral movement paths from the compromised host

## Eradication

- [ ] Audit sudoers file and remove unauthorized entries
- [ ] Review and remove any files/services created with elevated privileges
- [ ] Rotate credentials for the compromised account and any shared secrets on the host
- [ ] Patch the OS or application if a vulnerability was exploited for escalation

## Recovery

- [ ] Re-enable the user account after credential reset and access review
- [ ] Restore any modified system files from backup
- [ ] Re-enable the host after confirming clean state via EDR scan
- [ ] Monitor the account and host closely for 72 hours

## Lessons Learned

Document findings after incident resolution:
- Root cause (misconfigured sudoers, shared credentials, exploited vulnerability)
- Whether the escalation was authorized or malicious
- Improvements to least-privilege access controls
- Refinements to detection threshold or query

## References
- [MITRE ATT&CK: T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)
- [Elastic Security: Privilege Escalation](https://www.elastic.co/guide/en/security/current/prebuilt-rules.html)
- [CIS Benchmark: sudoers hardening](https://www.cisecurity.org/cis-benchmarks/)
