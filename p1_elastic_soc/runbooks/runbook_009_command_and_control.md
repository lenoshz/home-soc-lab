# Runbook: C2 Beaconing Detected

## Overview
This runbook covers detection and response to Command and Control (C2) beaconing, where
malware on a compromised host makes periodic outbound connections to an attacker-controlled
server. C2 channels enable remote control, data exfiltration, and payload delivery.

## Prerequisites
- Elasticsearch and Kibana running
- Detection rule `rule-009-c2` enabled
- Network flow logs (Zeek conn logs, Packetbeat, or Elastic Agent) ingested
- Proxy/firewall egress logs available
- Threat intelligence integration (IP/domain reputation feeds)
- Access to firewall for egress blocking

## Detection
**Rule**: `rule-009-c2` - C2 Beaconing Detected  
**Severity**: High  
**MITRE ATT&CK**: [T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)

This rule fires when outbound network connections to public (non-RFC-1918) IP addresses are
observed, excluding loopback. Beaconing is characterized by regular intervals, consistent
byte counts, and connections to unusual external IPs.

**KQL Query**:
```kql
event.category:network AND event.type:connection AND destination.ip:* AND NOT destination.ip:(10.0.0.0/8 OR 192.168.0.0/16 OR 172.16.0.0/12 OR 127.0.0.1)
```

## Investigation Steps

1. **Identify the beaconing host and destination**
   - Note `source.ip`, `host.name`, `destination.ip`, `destination.port`, and connection frequency
   - Check `destination.ip` against threat intelligence (VirusTotal, Shodan, AbuseIPDB)
   - Determine what process is initiating the connections (correlate with process logs by PID)

2. **Analyze beaconing characteristics**
   - Plot connection intervals — C2 beacons often show regular intervals (e.g., every 60s)
   - Compare `network.bytes` per connection — consistent small sizes suggest keep-alive beacons
   - Identify the protocol (HTTP/S, DNS, ICMP) — check for domain fronting or unusual User-Agents

3. **Check for related activity**
   - Correlate with rule-005 (Malware Execution) — what process installed the implant?
   - Check rule-004 (Data Exfiltration) — is data being sent via the C2 channel?
   - Review rule-006 (Persistence) — how is the implant surviving reboots?

4. **Preserve evidence**
   - Export all network connections from the affected host for the past 24 hours
   - Capture PCAP if available for the C2 traffic
   - Hash and archive the implant binary
   - Document all C2 IPs, domains, and URIs observed

## Containment

- [ ] Block the C2 destination IP(s) at the perimeter firewall (egress rule)
- [ ] Block the C2 domain(s) at the DNS resolver
- [ ] Isolate the affected host via Kibana Endpoint Management
- [ ] Kill the beaconing process via EDR console
- [ ] Scan all other hosts for connections to the same C2 infrastructure

## Eradication

- [ ] Identify and remove the implant binary and all associated files
- [ ] Remove persistence mechanisms maintaining the implant (Run keys, services, cron)
- [ ] Block C2 IOCs (IPs, domains, file hashes) across all security controls
- [ ] Rotate credentials accessible from the compromised host

## Recovery

- [ ] Reimage the host if full compromise or extended dwell time is confirmed
- [ ] Restore user data from pre-infection backup
- [ ] Re-enroll in EDR and confirm no C2 traffic resumes
- [ ] Monitor egress traffic from all hosts for connections to related C2 infrastructure for 7 days

## Lessons Learned

Document findings after incident resolution:
- Initial infection vector and time-to-detection (dwell time)
- Whether egress filtering or proxy inspection would have blocked the C2 channel
- Effectiveness of threat intelligence integration
- Improvements: enforce egress proxy for all hosts, block direct internet access from endpoints

## References
- [MITRE ATT&CK: T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [Elastic Security: Command and Control](https://www.elastic.co/guide/en/security/current/prebuilt-rules.html)
- [SANS: Identifying C2 Beaconing](https://www.sans.org/reading-room/whitepapers/detection/)
