# Runbook: Lateral Movement via SMB/WMI

## Overview
This runbook covers lateral movement detection where an adversary uses SMB (port 445) or
WMI/RPC (port 135) to move between hosts within the network. Lateral movement typically
follows initial compromise and precedes objectives such as data theft or ransomware deployment.

## Prerequisites
- Elasticsearch and Kibana running
- Detection rule `rule-003-lateral-movement` enabled
- Network flow logs (Zeek, Packetbeat, or Elastic Agent network events) ingested
- Windows Event Logs (Event ID 4648, 4624 Type 3) available
- Network segmentation topology documented
- Access to firewall and EDR console

## Detection
**Rule**: `rule-003-lateral-movement` - Lateral Movement via SMB/WMI  
**Severity**: High  
**MITRE ATT&CK**: [T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)

This rule fires when outbound network connections to SMB (445) or WMI/RPC (135) ports are
observed from an internal source IP, excluding loopback traffic.

**KQL Query**:
```kql
event.category:network AND destination.port:(445 OR 135) AND event.action:connection_attempted AND source.ip:* AND NOT source.ip:127.0.0.1
```

## Investigation Steps

1. **Identify the source host**
   - Note `source.ip`, `host.name`, and `destination.ip` from the alert
   - Determine the asset role of both source and destination hosts (workstation, server, DC)
   - Verify whether SMB/WMI access between these hosts is expected and authorized

2. **Assess scope of movement**
   - Query for all destination IPs contacted by the source IP on ports 445/135 in the last hour
   - Build a movement graph: which hosts were accessed and in what sequence
   - Check for new network shares accessed (Windows Event ID 5140)

3. **Check for related activity**
   - Correlate with rule-001 (Brute Force) on the source host — was it recently compromised?
   - Look for process execution on destination hosts initiated remotely (PsExec, wmic.exe)
   - Review rule-005 (Malware Execution) alerts on destination hosts post-connection

4. **Preserve evidence**
   - Capture full network flow data for the movement path
   - Export Windows Security Event Logs (4624 Type 3, 4648) from all involved hosts
   - Document the timeline and host chain

## Containment

- [ ] Isolate the source host via Kibana Endpoint Management or network ACL
- [ ] Block SMB/WMI traffic from the source IP at the internal firewall segment
- [ ] Disable the compromised account used for lateral movement
- [ ] Quarantine destination hosts that received inbound connections if compromise is confirmed
- [ ] Force re-authentication on all hosts in the movement path

## Eradication

- [ ] Remove remote access tools or payloads dropped on destination hosts (PsExec, RATs)
- [ ] Delete any shares or scheduled tasks created during movement
- [ ] Rotate all credentials accessible from the compromised source host
- [ ] Patch SMB vulnerabilities (EternalBlue, PrintNightmare) if relevant

## Recovery

- [ ] Restore affected hosts from clean snapshots if malicious execution occurred
- [ ] Re-enable inter-host connectivity after network segmentation review
- [ ] Verify clean state of all hosts in the movement chain via EDR scan
- [ ] Monitor the network segment for 72 hours post-containment

## Lessons Learned

Document findings after incident resolution:
- Root cause (initial foothold method, missing network segmentation)
- Whether network microsegmentation would have prevented spread
- Detection gaps (was movement detected quickly enough?)
- Improvements to SMB/WMI access controls and monitoring

## References
- [MITRE ATT&CK: T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)
- [Elastic Security: Lateral Movement](https://www.elastic.co/guide/en/security/current/prebuilt-rules.html)
- [Microsoft: SMB Security Best Practices](https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3)
