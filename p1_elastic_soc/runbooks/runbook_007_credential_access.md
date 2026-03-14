# Runbook: LSASS Memory Dump Detected

## Overview
This runbook covers detection of LSASS (Local Security Authority Subsystem Service) memory
dumping, a critical credential harvesting technique. Attackers dump LSASS memory to extract
plaintext passwords, NTLM hashes, and Kerberos tickets for use in pass-the-hash or
pass-the-ticket attacks.

## Prerequisites
- Elasticsearch and Kibana running
- Detection rule `rule-007-credential-access` enabled
- Sysmon Event ID 10 (process access) telemetry ingested
- EDR with memory protection capability
- Active Directory domain admin access for credential rotation
- Incident response tooling (Volatility, EDR memory analysis)

## Detection
**Rule**: `rule-007-credential-access` - LSASS Memory Dump Detected  
**Severity**: Critical  
**MITRE ATT&CK**: [T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)

This rule fires when known credential dumping tools (procdump.exe, mimikatz.exe) or lsass.exe
itself accesses the lsass.exe process memory, indicating an active credential harvesting attempt.

**KQL Query**:
```kql
event.category:process AND process.name:(procdump.exe OR mimikatz.exe OR lsass.exe) AND event.action:access AND process.pid:* AND target.process.name:lsass.exe
```

## Investigation Steps

1. **Identify the attacking process**
   - Note `process.name`, `process.command_line`, `process.pid`, and `host.name`
   - Determine if the process is a known tool (procdump, mimikatz) or an unusual binary
   - Hash the attacking process executable and verify against threat intelligence

2. **Assess the access type**
   - Check `winlog.event_data.GrantedAccess` — LSASS dump requires `0x1010` or `0x1FFFFF`
   - Determine if the dump file was written to disk (look for `.dmp` or `.bin` file creation events)
   - Identify the user context running the attacker process — was it already elevated?

3. **Check for related activity**
   - Correlate with rule-002 (Privilege Escalation) — how did the attacker gain elevated access?
   - Look for subsequent authentication events from the host using newly harvested credentials
   - Check for Kerberoasting artifacts (rule-001 patterns against domain accounts)

4. **Preserve evidence**
   - Capture the memory dump file if present (for forensic analysis)
   - Export Sysmon Event ID 10 logs for the affected host
   - Document all process tree details and access timestamps

## Containment

- [ ] Isolate the affected host immediately via Kibana Endpoint Management
- [ ] Assume ALL credentials cached on that host are compromised
- [ ] Force password reset for all accounts that logged into the host (check Event ID 4624)
- [ ] Revoke all Kerberos tickets for affected users (`klist purge` / `Invoke-ADReplication`)
- [ ] Reset the KRBTGT account password (twice) if domain admin credentials are at risk

## Eradication

- [ ] Delete any LSASS dump files from disk
- [ ] Remove the credential dumping tool and associated artifacts
- [ ] Enable Credential Guard on the host to prevent future LSASS dumps
- [ ] Block known dumping tool hashes at EDR policy level
- [ ] Audit and remove any new accounts or scheduled tasks created post-dump

## Recovery

- [ ] Complete full credential rotation for all affected accounts
- [ ] Re-enable Credential Guard and Protected Users security group
- [ ] Restore the host from a clean image if full compromise is confirmed
- [ ] Monitor for pass-the-hash/ticket activity for 7 days across all rotated accounts

## Lessons Learned

Document findings after incident resolution:
- How the attacker obtained the privileges needed to access LSASS
- Whether Credential Guard was disabled or bypassed
- Number of accounts compromised and downstream impact
- Improvements: enable PPL (Protected Process Light) for LSASS, deploy Credential Guard

## References
- [MITRE ATT&CK: T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [Elastic Security: Credential Access](https://www.elastic.co/guide/en/security/current/prebuilt-rules.html)
- [Microsoft: Configuring Additional LSA Protection](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [Microsoft: Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard)
