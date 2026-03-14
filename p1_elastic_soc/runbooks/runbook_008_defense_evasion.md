# Runbook: Security Tool Tampering

## Overview
This runbook covers detection of defense evasion through security tool tampering, where an
adversary attempts to disable or stop security tools (antivirus, EDR, Sysmon, Elastic Agent)
to operate without detection. This is a high-confidence indicator of an active attacker with
elevated privileges.

## Prerequisites
- Elasticsearch and Kibana running
- Detection rule `rule-008-defense-evasion` enabled
- Process execution logs (Sysmon or Elastic Agent) ingested
- EDR tamper protection enabled where possible
- Service management audit logs available
- Access to endpoint management console

## Detection
**Rule**: `rule-008-defense-evasion` - Security Tool Tampering  
**Severity**: High  
**MITRE ATT&CK**: [T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)

This rule fires when `sc stop`, `net stop`, or `taskkill` commands are executed targeting
known security tools (Windows Defender, antivirus, Sysmon, Elastic Agent).

**KQL Query**:
```kql
event.category:process AND event.type:start AND process.args:("sc stop" OR "net stop" OR "taskkill") AND process.args:(defender OR antivirus OR sysmon OR elastic)
```

## Investigation Steps

1. **Identify the tampering attempt**
   - Note `process.command_line`, `user.name`, `host.name`, and timestamp
   - Determine which security tool was targeted and whether the stop/kill succeeded
   - Check the current status of the targeted service on the affected host

2. **Assess attacker privilege level**
   - Stopping security services typically requires SYSTEM or local admin rights
   - Correlate with rule-002 (Privilege Escalation) to understand how access was gained
   - Review recent logon events for the executing user account

3. **Check for related activity**
   - Search for activity in the window after the tampering — what did the attacker do next?
   - Correlate with rule-005 (Malware Execution) and rule-006 (Persistence)
   - Look for new files dropped, accounts created, or lateral movement initiated

4. **Preserve evidence**
   - Export process execution events for the affected host around the tampering time
   - Capture Windows System Event Logs (Service Control Manager events 7035, 7036)
   - Note the full command line and any script wrappers used

## Containment

- [ ] Isolate the affected host via Kibana Endpoint Management
- [ ] Re-enable and restart the tampered security service remotely if possible
- [ ] Lock the user account that performed the tampering
- [ ] Enable EDR tamper protection policy to prevent future disabling
- [ ] Alert the security team of potential active attacker with elevated access

## Eradication

- [ ] Identify and remove the malware or tool that triggered the tampering
- [ ] Audit all security service configurations and restore to baseline
- [ ] Remove any scripts or scheduled tasks designed to disable security tools
- [ ] Patch the privilege escalation vector used to gain sufficient access

## Recovery

- [ ] Re-enable all security tools and verify telemetry flows to SIEM
- [ ] Conduct full EDR scan with updated signatures after services are restored
- [ ] Restore host from clean image if attacker had unmonitored dwell time
- [ ] Monitor all hosts for security service stop events for 72 hours

## Lessons Learned

Document findings after incident resolution:
- How the attacker gained privileges sufficient to stop security services
- Whether tamper protection was enabled on all endpoints
- Dwell time between initial access and detection
- Improvements: enable tamper protection, alert on service state changes

## References
- [MITRE ATT&CK: T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)
- [Elastic Security: Defense Evasion](https://www.elastic.co/guide/en/security/current/prebuilt-rules.html)
- [Elastic Agent Tamper Protection](https://www.elastic.co/guide/en/fleet/current/elastic-agent-policy.html)
