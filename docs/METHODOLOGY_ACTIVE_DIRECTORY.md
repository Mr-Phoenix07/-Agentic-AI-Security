# Active Directory Security Assessment Methodology

> **Authorized use only.** Run only inside a directory you **own or are explicitly
> authorized to assess** (signed rules of engagement). Prefer a lab or an
> isolated, monitored assessment window, and coordinate with the blue team so
> detections can be validated. In AEGIS, hosts/scopes are enforced fail-closed and
> active checks run only through the controlled-validation path. This document is
> the human-readable companion to
> [`aegis/methodology/active_directory.py`](../aegis/methodology/active_directory.py)
> — run `aegis methodology active-directory` to query it.

This methodology uses the **assumed-breach** model common to modern internal
assessments and is aligned to **MITRE ATT&CK Enterprise**, Microsoft's *Securing
Active Directory* / tiered-administration guidance, CISA AD guidance, and the NIST
SP 800-53 access-control and audit families. It is deliberately **detection- and
hardening-forward**: each technique documents the assessment objective *and* the
Windows telemetry a defender should have plus the control that closes the gap. It
contains no attack tooling, commands, or payloads.

## Phases & techniques

### Phase 1 — Discovery & Enumeration
Build an accurate model of the domain: principals, groups, trusts, privileged relationships.

| ID | Technique | Objective | ATT&CK |
|----|-----------|-----------|--------|
| `AD-DISC-01` | Domain, user & group enumeration | Inventory objects, memberships, GPOs, trusts (authenticated LDAP as any user) | T1087, T1069, T1482 |
| `AD-DISC-02` | Attack-path / ACL relationship analysis | Find dangerous ACLs & delegation forming escalation edges to Domain Admin | T1069, T1078.002 |

- **Detection:** monitor bulk/anomalous LDAP queries (event 1644), baseline & alert
  on ACL changes to privileged objects (event 5136).
- **Hardening:** restrict who can read sensitive attributes, review privileged
  group membership regularly, deploy AD tiering, mark privileged accounts
  "sensitive, cannot be delegated," prefer scrutinised constrained delegation.

### Phase 2 — Credential Access Exposure
Determine whether credential material can be obtained from Kerberos, the directory, or endpoints.

| ID | Technique | Objective | ATT&CK |
|----|-----------|-----------|--------|
| `AD-CRED-01` | Kerberoasting exposure | Service accounts (SPNs) with weak passwords → offline recovery | T1558.003 |
| `AD-CRED-02` | AS-REP roasting exposure | Accounts with Kerberos pre-auth disabled | T1558.004 |
| `AD-CRED-03` | Endpoint credential-material exposure | Cached creds/tokens/secrets (LSASS, SYSVOL/GPP) | T1003, T1552 |

- **Detection:** abnormal Kerberos TGS volume, especially RC4 (event 4769);
  AS-REQ without pre-auth (event 4768, pre-auth type 0); LSASS access by non-system
  processes (Sysmon event 10).
- **Hardening:** group Managed Service Accounts (gMSA), enforce AES / disable RC4,
  require Kerberos pre-authentication, enable Credential Guard + RunAsPPL, deploy
  LAPS, remove secrets from SYSVOL and migrate off GPP passwords.

### Phase 3 — Lateral Movement
Evaluate whether obtained credentials/tickets enable movement between hosts.

| ID | Technique | Objective | ATT&CK |
|----|-----------|-----------|--------|
| `AD-LAT-01` | Credential-reuse & ticket-based movement | Pass-the-hash / pass-the-ticket / broad local-admin reuse | T1550.002, T1550.003, T1021 |

- **Detection:** lateral auth patterns (event 4624 type 3/10 from unusual sources),
  remote-service creation (event 7045), anomalous admin logons.
- **Hardening:** LAPS + deny lateral local-admin logons, host-firewall segmentation
  (block workstation-to-workstation SMB/RDP), Credential Guard, restrict NTLM.

### Phase 4 — Privilege Escalation & Domain Dominance
Identify conditions that grant domain-wide control.

| ID | Technique | Objective | ATT&CK |
|----|-----------|-----------|--------|
| `AD-ESC-01` | Directory-replication (DCSync) rights exposure | Non-DC principals holding replication rights | T1003.006 |
| `AD-ESC-02` | AD Certificate Services (AD CS) misconfiguration | Templates/CA settings enabling auth-capable cert issuance | T1649 |

- **Detection:** replication requests from non-DC sources (event 4662 with
  replication GUIDs); anomalous certificate issuance (events 4886/4887);
  certificate-based logons for sensitive accounts.
- **Hardening:** remove replication rights from non-DC principals; remove
  enrollee-supplied SAN, require manager approval, tighten template ACLs, disable
  dangerous CA flags, enable CA auditing.

### Phase 5 — Persistence & Defense Validation
Assess durable-access conditions and validate that detections/hardening work.

| ID | Technique | Objective | ATT&CK |
|----|-----------|-----------|--------|
| `AD-PERS-01` | Persistence-condition & Tier-0 integrity review | krbtgt hygiene, rogue trusts, GPO abuse, Tier-0 isolation | T1558.001, T1484.001, T1484.002 |

- **Detection:** GPO changes (event 5136 on GPC objects), TGT lifetime anomalies,
  golden/silver-ticket indicators.
- **Hardening:** rotate krbtgt twice on schedule and after compromise, enforce
  Tier-0 admin isolation and privileged access workstations (PAWs), restrict and
  monitor GPO edit rights and trusts.

## Why detection-forward?

AEGIS is a **defensive** platform. Documenting AD attack paths at the methodology
altitude — objective, signals, detection telemetry, and mitigation — is exactly how
MITRE ATT&CK and professional assessment standards present them, and it is the most
useful form for hardening. Turning an assessment finding into a concrete Windows
event to monitor and a control to apply is the deliverable that reduces risk.

## References

- MITRE ATT&CK Enterprise (Windows / Active Directory tactics & techniques)
- Microsoft — *Securing Active Directory* and the tiered administration model
- CISA — Active Directory security guidance
- NIST SP 800-53 — access-control (AC) and audit/accountability (AU) families
