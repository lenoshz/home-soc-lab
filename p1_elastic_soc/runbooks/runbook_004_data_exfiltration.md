# Runbook: Data Exfiltration via DNS Tunneling

## Overview
This runbook covers detection and response to data exfiltration using DNS tunneling, where
an adversary encodes data in DNS queries to bypass data loss prevention controls. DNS
tunneling is a covert channel that can exfiltrate sensitive data slowly over time.

## Prerequisites
- Elasticsearch and Kibana running
- Detection rule `rule-004-data-exfiltration` enabled
- Zeek DNS logs (`zeek.dns` dataset) ingested
- DNS server query logs available
- DLP tools and data classification inventory available
- Access to DNS infrastructure and firewall

## Detection
**Rule**: `rule-004-data-exfiltration` - Data Exfiltration via DNS Tunneling  
**Severity**: High  
**MITRE ATT&CK**: [T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)

This rule fires when DNS queries are observed in the `zeek.dns` dataset with suspicious
characteristics. Indicators include TXT record queries to unusual domains, high query
frequency, or abnormally long subdomain labels.

**KQL Query**:
```kql
event.category:network AND network.protocol:dns AND dns.question.name:* AND event.dataset:zeek.dns
```

## Investigation Steps

1. **Identify the suspicious domain**
   - Note `dns.question.name` and `source.ip` from the alert
   - Check the domain against threat intelligence (VirusTotal, PassiveDNS)
   - Assess the query type — TXT and NULL records are common in DNS tunneling tools

2. **Assess query patterns**
   - Query for all DNS requests from `source.ip` in the past hour
   - Look for high query rate to a single domain (>50 queries/min is suspicious)
   - Check for abnormally long subdomain labels (>50 chars suggests encoded data)
   - Compare query entropy against baseline to detect encoded payloads

3. **Check for related activity**
   - Correlate source IP with rule-005 (Malware Execution) — was a tunneling tool run?
   - Identify what data the source host has access to (file shares, databases)
   - Review proxy/HTTP logs for complementary exfiltration channels

4. **Preserve evidence**
   - Export all DNS queries from the source host for the relevant timeframe
   - Capture PCAP if available (Zeek raw logs or network tap)
   - Identify and document all queried external domains and response data

## Containment

- [ ] Block the suspicious domain at the DNS resolver / RPZ (Response Policy Zone)
- [ ] Block outbound UDP/TCP 53 from the affected host to all except internal DNS servers
- [ ] Isolate the affected host via Kibana Endpoint Management
- [ ] Revoke the host's network access to sensitive data stores
- [ ] Alert data owners if classified data may have been exfiltrated

## Eradication

- [ ] Identify and remove the DNS tunneling tool from the host (iodine, dnscat2, etc.)
- [ ] Remove any C2 persistence mechanisms (cron jobs, startup entries)
- [ ] Rotate secrets accessible from the compromised host
- [ ] Audit DNS resolver logs to determine full scope of exfiltration

## Recovery

- [ ] Re-enable outbound DNS through the internal resolver only after validation
- [ ] Restore host from clean backup if malware was present
- [ ] Notify affected data owners and compliance team if sensitive data was confirmed leaked
- [ ] Monitor DNS traffic from the host for recurrence for 7 days

## Lessons Learned

Document findings after incident resolution:
- Root cause (malware infection vector, missing DNS security controls)
- Volume and sensitivity of exfiltrated data
- Whether DNS RPZ or anomaly detection would have caught this earlier
- Improvements to DNS monitoring and outbound DNS policy

## References
- [MITRE ATT&CK: T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [Elastic Security: DNS Tunneling Detection](https://www.elastic.co/guide/en/security/current/prebuilt-rules.html)
- [SANS: DNS Tunneling Detection](https://www.sans.org/reading-room/whitepapers/dns/)
