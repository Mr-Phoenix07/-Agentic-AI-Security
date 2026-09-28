"""Active Directory security-assessment methodology.

A phased methodology for assessing on-premises Active Directory (and hybrid
Entra ID) environments on **authorized** engagements, aligned to **MITRE ATT&CK
Enterprise** and the assumed-breach model used by modern internal assessments.

Each technique is documented at the methodology altitude — objective, authorized
assessment approach, weakness signals, the concrete **detection** telemetry a
defender should have (Windows Security event IDs, Kerberos/LDAP signals), and the
**mitigation/hardening** control. It intentionally contains no attack tooling,
commands, or payloads: the value here is coverage + defense, and any active,
intrusive validation stays behind AEGIS's fail-closed authorization gate and
controlled-validation agent. This mirrors how the platform treats every live
target — declared inventory and controlled checks, never an autonomous exploit
engine.
"""

from __future__ import annotations

from ..core.types import FindingCategory as FC
from ..core.types import Severity as S
from .models import Methodology, Phase, Technique

_REFERENCES = {
    "mitre_attack": "MITRE ATT&CK Enterprise (Windows / Active Directory)",
    "ms_hardening": "Microsoft Securing Active Directory / Tiered Admin model",
    "cisa": "CISA AD Security guidance",
    "nist_800_53": "NIST SP 800-53 access-control & audit families",
}


ACTIVE_DIRECTORY = Methodology(
    id="active-directory",
    title="Active Directory Security Assessment",
    domain="active_directory",
    summary=(
        "An assumed-breach, ATT&CK-aligned methodology for assessing Active "
        "Directory: discovery and enumeration, credential-access exposure, "
        "lateral-movement paths, privilege-escalation and domain-dominance "
        "conditions, and persistence — each paired with the Windows detection "
        "telemetry and hardening control that closes it."
    ),
    authorization_note=(
        "Run only inside a directory you own or are explicitly authorized to "
        "assess (signed rules of engagement). Prefer a lab or an isolated, "
        "monitored assessment window; coordinate with the blue team so detections "
        "can be validated. In AEGIS, hosts/scopes are enforced fail-closed and "
        "active checks run only through the controlled-validation path."
    ),
    references=_REFERENCES,
    phases=[
        Phase(
            id="discovery",
            name="Discovery & Enumeration",
            goal="Build an accurate model of the domain: principals, groups, trusts, and privileged relationships.",
            techniques=[
                Technique(
                    id="AD-DISC-01",
                    name="Domain, user, and group enumeration",
                    objective="Inventory domain objects, group memberships, GPOs, and trusts to map the identity terrain (typically via authenticated LDAP as any domain user).",
                    approach="Query directory objects and build a relationship graph (users→groups→rights→hosts) to identify privileged principals and attack paths; read-only.",
                    signals=["Excessive/legacy privileged group membership", "Nested privileged groups", "Stale accounts with high rights"],
                    detection=["Monitor bulk/anomalous LDAP queries (event 1644 with diagnostics)", "Alert on directory enumeration from non-admin hosts"],
                    mitigations=["Restrict who can enumerate sensitive attributes", "Regularly review privileged group membership", "Deploy AD tiering to limit blast radius"],
                    frameworks={"mitre_attack": ["T1087 Account Discovery", "T1069 Permission Groups Discovery", "T1482 Domain Trust Discovery"]},
                    category=FC.DATA_EXPOSURE,
                    severity_hint=S.LOW,
                    tags=["enumeration", "ldap", "graph"],
                ),
                Technique(
                    id="AD-DISC-02",
                    name="Attack-path / ACL relationship analysis",
                    objective="Identify dangerous ACLs and delegation (GenericAll, WriteDACL, GenericWrite, constrained/unconstrained delegation) that form escalation edges to Domain Admin.",
                    approach="Analyze object ACLs and delegation settings to compute shortest privileged paths; purely analytical over collected relationship data.",
                    signals=["Unconstrained delegation on non-DC hosts", "Users with WriteDACL over privileged objects", "Shadow-admin paths via nested rights"],
                    detection=["Baseline and alert on ACL changes to privileged objects (event 5136)", "Flag new delegation configuration"],
                    mitigations=["Remove unnecessary ACEs; enforce least privilege on AD objects", "Mark privileged accounts 'sensitive, cannot be delegated'", "Prefer constrained delegation with protocol transition scrutiny"],
                    frameworks={"mitre_attack": ["T1069", "T1078.002 Domain Accounts"]},
                    category=FC.AUTHZ,
                    severity_hint=S.HIGH,
                    tags=["acl", "delegation", "bloodhound"],
                ),
            ],
        ),
        Phase(
            id="credential-access",
            name="Credential Access Exposure",
            goal="Determine whether credential material can be obtained from Kerberos, the directory, or endpoints.",
            techniques=[
                Technique(
                    id="AD-CRED-01",
                    name="Kerberoasting exposure (service-account SPNs)",
                    objective="Assess whether service accounts with SPNs use weak, crackable passwords, allowing offline recovery of service-ticket-encrypted credentials.",
                    approach="Inventory accounts with SPNs and evaluate password strength/rotation policy and encryption type; treat any offline validation as authorized and isolated.",
                    signals=["Service accounts with SPNs and weak/never-expiring passwords", "RC4 (etype 23) tickets permitted", "Service accounts in privileged groups"],
                    detection=["Alert on abnormal volume of Kerberos TGS requests (event 4769), especially RC4", "Baseline per-account service-ticket request rates"],
                    mitigations=["Use group Managed Service Accounts (gMSA) with long random passwords", "Enforce AES; disable RC4", "Keep service accounts out of privileged groups"],
                    frameworks={"mitre_attack": ["T1558.003 Kerberoasting"]},
                    category=FC.AUTHN,
                    severity_hint=S.HIGH,
                    tags=["kerberos", "spn", "service-account"],
                ),
                Technique(
                    id="AD-CRED-02",
                    name="AS-REP roasting exposure (pre-auth disabled)",
                    objective="Identify accounts with Kerberos pre-authentication disabled, whose AS-REP can be recovered offline.",
                    approach="Enumerate accounts with 'Do not require Kerberos preauthentication' set; report as configuration weakness.",
                    signals=["Accounts with DONT_REQ_PREAUTH set", "Such accounts also privileged or with weak passwords"],
                    detection=["Alert on AS-REQ without pre-auth (event 4768 with pre-auth type 0)", "Inventory pre-auth-disabled accounts continuously"],
                    mitigations=["Require Kerberos pre-authentication for all accounts", "Rotate/strengthen affected passwords"],
                    frameworks={"mitre_attack": ["T1558.004 AS-REP Roasting"]},
                    category=FC.AUTHN,
                    severity_hint=S.MEDIUM,
                    tags=["kerberos", "preauth"],
                ),
                Technique(
                    id="AD-CRED-03",
                    name="Endpoint credential-material exposure",
                    objective="Assess exposure of cached credentials, tokens, and secrets on endpoints (LSASS memory, credential caches, SYSVOL scripts/GPP).",
                    approach="Review protections (Credential Guard, LSASS protection, RunAsPPL) and scan SYSVOL/scripts for embedded secrets; read-only configuration review.",
                    signals=["Credential Guard disabled", "Cleartext secrets in SYSVOL/GPP/logon scripts", "Reused local-admin passwords across hosts"],
                    detection=["Alert on LSASS access by non-system processes (Sysmon event 10)", "Monitor SYSVOL for secrets"],
                    mitigations=["Enable Credential Guard + RunAsPPL", "Deploy LAPS for unique local-admin passwords", "Remove secrets from SYSVOL; migrate off GPP passwords"],
                    frameworks={"mitre_attack": ["T1003 OS Credential Dumping", "T1552 Unsecured Credentials"]},
                    category=FC.DATA_EXPOSURE,
                    severity_hint=S.HIGH,
                    tags=["lsass", "sysvol", "laps"],
                ),
            ],
        ),
        Phase(
            id="lateral",
            name="Lateral Movement",
            goal="Evaluate whether obtained credentials/tickets enable movement between hosts.",
            techniques=[
                Technique(
                    id="AD-LAT-01",
                    name="Credential-reuse & ticket-based movement",
                    objective="Determine whether hash/ticket reuse (pass-the-hash / pass-the-ticket) or over-broad local-admin rights allow lateral movement.",
                    approach="Map where each principal has local-admin rights and whether NTLM/Kerberos reuse is constrained; validate only against authorized hosts.",
                    signals=["Shared local-admin credentials across hosts", "Wide SMB/WinRM/RDP reachability between workstations", "NTLM permitted where Kerberos suffices"],
                    detection=["Alert on lateral auth patterns (event 4624 type 3/10 from unusual sources)", "Detect anomalous admin logons and remote-service creation (event 7045)"],
                    mitigations=["LAPS + deny lateral local-admin logons", "Host firewall segmentation (block workstation-to-workstation SMB/RDP)", "Windows Defender Credential Guard; restrict NTLM"],
                    frameworks={"mitre_attack": ["T1550.002 Pass the Hash", "T1550.003 Pass the Ticket", "T1021 Remote Services"]},
                    category=FC.AUTHZ,
                    severity_hint=S.HIGH,
                    tags=["lateral-movement", "pth", "ptt"],
                ),
            ],
        ),
        Phase(
            id="escalation",
            name="Privilege Escalation & Domain Dominance",
            goal="Identify conditions that grant domain-wide control.",
            techniques=[
                Technique(
                    id="AD-ESC-01",
                    name="Directory-replication (DCSync) rights exposure",
                    objective="Assess whether non-DC principals hold replication rights (Replicating Directory Changes / All) enabling secret extraction of any account.",
                    approach="Audit which principals hold DS-Replication-Get-Changes[-All] on the domain head; report over-grants as critical.",
                    signals=["Non-tier-0 principals with replication rights", "Service/user accounts granted domain replication"],
                    detection=["Alert on replication requests from non-DC sources (event 4662 with the replication GUIDs)", "Baseline expected replication partners"],
                    mitigations=["Remove replication rights from non-DC principals", "Restrict to domain controllers only; monitor tightly"],
                    frameworks={"mitre_attack": ["T1003.006 DCSync"]},
                    category=FC.AUTHZ,
                    severity_hint=S.CRITICAL,
                    tags=["dcsync", "replication", "tier0"],
                ),
                Technique(
                    id="AD-ESC-02",
                    name="AD Certificate Services (AD CS) misconfiguration",
                    objective="Identify vulnerable certificate templates / CA settings that permit authentication-capable certificate issuance for arbitrary principals.",
                    approach="Enumerate templates and CA flags for enrollee-supplied SAN, dangerous EKUs, and weak enrollment ACLs; analytical review of PKI configuration.",
                    signals=["Templates allowing requester-supplied SAN with client-auth EKU", "Low-privileged enrollment on privileged templates", "CA with EDITF_ATTRIBUTESUBJECTALTNAME2"],
                    detection=["Monitor certificate issuance (event 4886/4887) for anomalous SANs", "Alert on certificate-based logons for sensitive accounts"],
                    mitigations=["Remove enrollee-supplied SAN; require manager approval", "Tighten template enrollment ACLs", "Disable dangerous CA flags; enable CA auditing"],
                    frameworks={"mitre_attack": ["T1649 Steal or Forge Authentication Certificates"]},
                    category=FC.AUTHZ,
                    severity_hint=S.CRITICAL,
                    tags=["adcs", "pki", "esc"],
                ),
            ],
        ),
        Phase(
            id="persistence",
            name="Persistence & Defense Validation",
            goal="Assess durable-access conditions and validate that detections/hardening are effective.",
            techniques=[
                Technique(
                    id="AD-PERS-01",
                    name="Persistence-condition & Tier-0 integrity review",
                    objective="Identify conditions enabling durable domain access (e.g., forged-ticket exposure via krbtgt hygiene, rogue trusts, GPO abuse) and verify Tier-0 isolation.",
                    approach="Review krbtgt rotation cadence, trust configuration, GPO edit rights, and Tier-0 separation; recommend detections and drills rather than establishing persistence.",
                    signals=["krbtgt password never rotated", "Editable GPOs linked to Tier-0", "Unnecessary or unmonitored trusts"],
                    detection=["Monitor GPO changes (event 5136 on GPC objects)", "Alert on TGT lifetimes/anomalies; watch for golden/silver-ticket indicators"],
                    mitigations=["Rotate krbtgt twice on schedule and after compromise", "Enforce Tier-0 admin isolation and PAWs", "Restrict and monitor GPO edit rights and trusts"],
                    frameworks={"mitre_attack": ["T1558.001 Golden Ticket", "T1484.002 Domain Trust Modification", "T1484.001 Group Policy Modification"]},
                    category=FC.MONITORING,
                    severity_hint=S.HIGH,
                    tags=["persistence", "krbtgt", "tier0", "gpo"],
                ),
            ],
        ),
    ],
)
