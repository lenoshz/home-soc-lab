# Runbook: Brute Force Login Attempt

## Overview
This runbook covers the response to a brute force authentication attack, where an adversary
attempts to gain access by systematically trying many passwords against one or more accounts.
Early detection and swift containment limit the risk of account compromise.

## Prerequisites
- Elasticsearch and Kibana running
- Detection rule `rule-001-brute-force` enabled
- Windows Security Event Logs (Event ID 4625/4624) or Linux auth logs ingested
- Access to Active Directory / IAM console
- Firewall or network ACL management access

## Detection
**Rule**: `rule-001-brute-force` - Brute Force Login Attempt  
**Severity**: High  
**MITRE ATT&CK**: [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)

This rule fires when multiple authentication failure events (Windows Event ID 4625) are
observed in a short window, indicating systematic password guessing.

**KQL Query**:
```kql
event.category:authentication AND event.outcome:failure AND winlog.event_id:4625
```

## Investigation Steps

1. **Identify the source**
   - Note the `source.ip` and `user.name` fields from the alert
   - Determine whether the source IP is internal, external, or a known VPN/proxy
   - Check threat intelligence feeds for the source IP reputation

2. **Assess scope**
   - Count total failures in the past 15 minutes: filter by `source.ip` and `event.outcome:failure`
   - Identify all target accounts (`user.name`) being attacked
   - Check if any account shows a subsequent `event.outcome:success` (Event ID 4624)

3. **Check for related activity**
   - Search for lateral movement from the same source IP post-success
   - Correlate with rule-003 (Lateral Movement) and rule-007 (Credential Access) alerts
   - Review VPN/proxy logs if source IP resolves to one

4. **Preserve evidence**
   - Export relevant log records from Kibana Discover to CSV/JSON
   - Note alert timestamps, source IP, targeted usernames, and affected hosts

## Containment

- [ ] Block the source IP at the perimeter firewall or WAF
- [ ] Lock affected user accounts via Active Directory or IAM console
- [ ] Enforce MFA on all accounts targeted in the attack
- [ ] If a successful login occurred, force password reset for the compromised account
- [ ] Isolate the targeted host if post-compromise activity is suspected

## Eradication

- [ ] Confirm no persistent access (scheduled tasks, new local accounts, registry run keys)
- [ ] Review and remove any attacker-created accounts or credentials
- [ ] Audit and tighten account lockout policy (e.g., lock after 5 failures)
- [ ] Validate that the blocked IP has not pivoted to alternate source IPs

## Recovery

- [ ] Unlock legitimate user accounts after IP block is in place
- [ ] Reset passwords for all targeted accounts as a precaution
- [ ] Re-enable services after verifying clean state
- [ ] Monitor the affected accounts and hosts for 48 hours post-incident

## Lessons Learned

Document findings after incident resolution:
- Root cause (exposed RDP/SSH, weak password policy, missing MFA)
- Detection gap assessment (was alert threshold appropriate?)
- Policy improvements (account lockout, MFA enforcement, geo-blocking)
- Update runbook with any new indicators or refinements

## References
- [MITRE ATT&CK: T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [Elastic Security: Brute Force Detection](https://www.elastic.co/guide/en/security/current/prebuilt-rules.html)
- [NIST SP 800-63B: Authentication Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
