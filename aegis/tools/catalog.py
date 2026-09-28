"""Built-in tool catalog.

Each entry is a :class:`~aegis.tools.spec.ToolSpec`. Two kinds exist:

* **Executable adapters** — ubiquitous, non-destructive *discovery / enumeration
  / scanning / static-analysis* tools. These ship a ``command_builder`` (safe,
  structured argv construction) and a ``parser`` (raw output → observations).
  Their invocation is still fully gated by the executor (scope, offline, risk,
  approval, audit).

* **Documentation-only contracts** — exploitation, credential, and DoS class
  tools. These carry metadata for *planning* (so the orchestrator can say "an
  IDOR here could be validated with X") but ship **no** ``command_builder``.
  AEGIS will refuse to auto-run them; a human must implement and authorize the
  adapter for a specific engagement. No offensive payloads live here.

Argv builders receive a validated :class:`ToolInvocation` and return a token
list. There is no shell; params are inert tokens.
"""

from __future__ import annotations

import json

from ..core.types import TargetKind
from .execution import ToolResult
from .spec import (
    ParsedObservation,
    RiskLevel,
    ToolCategory,
    ToolInvocation,
    ToolSpec,
)

_WEB = (TargetKind.WEB_APP, TargetKind.REST_API, TargetKind.GRAPHQL_API,
        TargetKind.AI_GATEWAY, TargetKind.HYBRID)
_NET = (TargetKind.WEB_APP, TargetKind.REST_API, TargetKind.HYBRID)


# --------------------------------------------------------------------------- #
# argv builders (structured -> tokens). All validate their inputs.
# --------------------------------------------------------------------------- #
def _require_str(inv: ToolInvocation, key: str, *, default: str | None = None) -> str:
    val = inv.opt(key, default)
    if val is None:
        raise ValueError(f"missing required param '{key}'")
    if not isinstance(val, str) or not val.strip():
        raise ValueError(f"param '{key}' must be a non-empty string")
    return val


def _build_subfinder(inv: ToolInvocation) -> list[str]:
    # passive subdomain enumeration for an authorized apex domain
    return ["subfinder", "-silent", "-d", inv.target]


def _build_nmap(inv: ToolInvocation) -> list[str]:
    # service/version detection; no aggressive NSE scripts by default.
    ports = str(inv.opt("ports", "top-1000"))
    argv = ["nmap", "-sV", "-Pn", "--open"]
    if ports == "top-1000":
        argv += ["--top-ports", "1000"]
    else:
        # accept only digits, commas, and dashes for a port spec
        if not all(c.isdigit() or c in ",-" for c in ports):
            raise ValueError("invalid port specification")
        argv += ["-p", ports]
    argv += ["-oX", "-", inv.target]   # XML to stdout
    return argv


def _build_httpx(inv: ToolInvocation) -> list[str]:
    return ["httpx", "-silent", "-json", "-title", "-tech-detect",
            "-status-code", "-u", inv.target]


def _build_whatweb(inv: ToolInvocation) -> list[str]:
    return ["whatweb", "--log-json=-", "--no-errors", inv.target]


def _build_nuclei(inv: ToolInvocation) -> list[str]:
    # signature scan with default templates; jsonl to stdout.
    argv = ["nuclei", "-silent", "-jsonl", "-u", inv.target]
    severity = inv.opt("severity")
    if severity:
        allowed = {"info", "low", "medium", "high", "critical"}
        sev = [s.strip() for s in str(severity).split(",")]
        if not set(sev) <= allowed:
            raise ValueError("invalid severity filter")
        argv += ["-severity", ",".join(sev)]
    # Targeted re-run for validation: restrict to a single template id. The id
    # is validated so it can only ever be a template selector, never a flag or
    # path traversal.
    template_id = inv.opt("template_id")
    if template_id:
        tid = str(template_id)
        if not all(c.isalnum() or c in "-_" for c in tid):
            raise ValueError("invalid nuclei template id")
        argv += ["-id", tid]
    return argv


def _build_ffuf(inv: ToolInvocation) -> list[str]:
    # content discovery; operator must supply their own wordlist path.
    wordlist = _require_str(inv, "wordlist")
    url = inv.target
    if "FUZZ" not in url:
        # place the FUZZ keyword on the path safely
        url = url.rstrip("/") + "/FUZZ"
    return ["ffuf", "-s", "-w", wordlist, "-u", url, "-of", "json", "-o", "-"]


def _build_gobuster(inv: ToolInvocation) -> list[str]:
    wordlist = _require_str(inv, "wordlist")
    return ["gobuster", "dir", "-q", "-u", inv.target, "-w", wordlist]


def _build_semgrep(inv: ToolInvocation) -> list[str]:
    # static analysis over a local, authorized source path (no network).
    path = _require_str(inv, "path")
    config = str(inv.opt("config", "auto"))
    return ["semgrep", "--quiet", "--json", "--config", config, path]


def _build_gitleaks(inv: ToolInvocation) -> list[str]:
    path = _require_str(inv, "path")
    return ["gitleaks", "detect", "--no-banner", "--report-format", "json",
            "--report-path", "-", "--source", path]


def _build_trivy(inv: ToolInvocation) -> list[str]:
    # container/image or filesystem posture scan.
    mode = str(inv.opt("mode", "image"))
    if mode not in {"image", "fs", "config"}:
        raise ValueError("trivy mode must be image|fs|config")
    return ["trivy", mode, "--quiet", "--format", "json", inv.target]


# --------------------------------------------------------------------------- #
# parsers (raw output -> observations). Defensive: never raise on junk.
# --------------------------------------------------------------------------- #
def _parse_jsonl(result: ToolResult, kind: str) -> list[ParsedObservation]:
    out: list[ParsedObservation] = []
    for i, line in enumerate(result.stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        out.append(ParsedObservation(kind=kind, value=_summ(obj), detail=obj,
                                     raw_ref=f"line:{i}"))
    return out


def _summ(obj: dict) -> str:
    for k in ("matched-at", "url", "input", "host", "matched"):
        v = obj.get(k) if isinstance(obj, dict) else None
        if isinstance(v, str):
            return v
    return json.dumps(obj)[:120]


def _parse_nuclei(result: ToolResult) -> list[ParsedObservation]:
    obs: list[ParsedObservation] = []
    for i, line in enumerate(result.stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        info = obj.get("info", {}) if isinstance(obj, dict) else {}
        obs.append(ParsedObservation(
            kind="template_match",
            value=str(obj.get("template-id") or info.get("name") or "match"),
            detail=obj,
            severity_hint=str(info.get("severity", "info")),
            raw_ref=f"line:{i}",
        ))
    return obs


def _parse_nmap(result: ToolResult) -> list[ParsedObservation]:
    # Parse the XML port table without a full XML dep: pull <port ...> lines.
    obs: list[ParsedObservation] = []
    for i, line in enumerate(result.stdout.splitlines()):
        s = line.strip()
        if s.startswith("<port ") and 'state="open"' in result.stdout[
            result.stdout.find(s):result.stdout.find(s) + 400
        ]:
            portid = _attr(s, "portid")
            proto = _attr(s, "protocol")
            if portid:
                obs.append(ParsedObservation(
                    kind="open_port", value=f"{portid}/{proto or 'tcp'}",
                    detail={"portid": portid, "protocol": proto},
                    raw_ref=f"line:{i}"))
    return obs


def _attr(s: str, name: str) -> str:
    marker = f'{name}="'
    j = s.find(marker)
    if j < 0:
        return ""
    j += len(marker)
    k = s.find('"', j)
    return s[j:k] if k > j else ""


def _parse_httpx(result: ToolResult) -> list[ParsedObservation]:
    return _parse_jsonl(result, kind="http_service")


def _parse_subfinder(result: ToolResult) -> list[ParsedObservation]:
    # one subdomain per line (text output).
    obs: list[ParsedObservation] = []
    seen: set[str] = set()
    for i, line in enumerate(result.stdout.splitlines()):
        host = line.strip().lower()
        # keep it to plausible hostnames; ignore banners/noise
        if not host or " " in host or "." not in host or host in seen:
            continue
        seen.add(host)
        obs.append(ParsedObservation(kind="subdomain", value=host,
                                     detail={"host": host}, raw_ref=f"line:{i}"))
    return obs


def _parse_ffuf(result: ToolResult) -> list[ParsedObservation]:
    # ffuf -of json emits a single JSON object with a "results" array.
    obs: list[ParsedObservation] = []
    try:
        doc = json.loads(result.stdout or "{}")
    except Exception:
        return obs
    for j, r in enumerate(doc.get("results", []) if isinstance(doc, dict) else []):
        if not isinstance(r, dict):
            continue
        url = r.get("url") or r.get("input", {}).get("FUZZ")
        if not url:
            continue
        obs.append(ParsedObservation(
            kind="path", value=str(url),
            detail={"url": url, "status": r.get("status"),
                    "length": r.get("length")},
            raw_ref=f"result:{j}"))
    return obs


def _parse_gobuster(result: ToolResult) -> list[ParsedObservation]:
    # lines like "/admin                (Status: 200) [Size: 1234]"
    obs: list[ParsedObservation] = []
    for i, line in enumerate(result.stdout.splitlines()):
        s = line.strip()
        if not s.startswith("/"):
            continue
        path = s.split()[0]
        status = ""
        if "Status:" in s:
            status = s.split("Status:", 1)[1].split(")")[0].strip()
        obs.append(ParsedObservation(kind="path", value=path,
                                     detail={"path": path, "status": status},
                                     raw_ref=f"line:{i}"))
    return obs


# --------------------------------------------------------------------------- #
# The catalog
# --------------------------------------------------------------------------- #
def default_catalog() -> list[ToolSpec]:
    """Return the built-in tool specs (fresh instances)."""
    return [
        # -- recon / passive ------------------------------------------------ #
        ToolSpec(
            name="subfinder", binary="subfinder", category=ToolCategory.RECON,
            purpose="Passive subdomain enumeration for an authorized apex domain.",
            risk_level=RiskLevel.PASSIVE, supported_targets=_WEB,
            applies_when=("domain",), evidence_format="text",
            input_schema={"target": "apex domain (authorized)"},
            command_builder=_build_subfinder, parser=_parse_subfinder,
            references=("https://github.com/projectdiscovery/subfinder",),
        ),
        # -- network -------------------------------------------------------- #
        ToolSpec(
            name="nmap", binary="nmap", category=ToolCategory.NETWORK,
            purpose="Service/version detection on authorized hosts (no aggressive NSE).",
            risk_level=RiskLevel.ACTIVE, supported_targets=_NET,
            applies_when=("host", "ip", "network"), evidence_format="xml",
            input_schema={"target": "host/ip", "ports": "top-1000 | comma/range spec"},
            command_builder=_build_nmap, parser=_parse_nmap,
            references=("https://nmap.org/book/man.html",),
        ),
        # -- fingerprint ---------------------------------------------------- #
        ToolSpec(
            name="httpx", binary="httpx", category=ToolCategory.FINGERPRINT,
            purpose="HTTP probing: status, title, technology detection.",
            risk_level=RiskLevel.SAFE, supported_targets=_WEB,
            applies_when=("http", "https", "web"), evidence_format="jsonl",
            input_schema={"target": "URL or host"},
            command_builder=_build_httpx, parser=_parse_httpx,
            references=("https://github.com/projectdiscovery/httpx",),
        ),
        ToolSpec(
            name="whatweb", binary="whatweb", category=ToolCategory.FINGERPRINT,
            purpose="Web technology fingerprinting.",
            risk_level=RiskLevel.SAFE, supported_targets=_WEB,
            applies_when=("http", "https", "web"), evidence_format="json",
            input_schema={"target": "URL"},
            command_builder=_build_whatweb,
            references=("https://github.com/urbanadventurer/WhatWeb",),
        ),
        # -- web scan ------------------------------------------------------- #
        ToolSpec(
            name="nuclei", binary="nuclei", category=ToolCategory.WEB_SCAN,
            purpose="Template-based misconfiguration/exposure signature scanning.",
            risk_level=RiskLevel.ACTIVE, supported_targets=_WEB,
            applies_when=("http", "https", "web", "api"), evidence_format="jsonl",
            input_schema={"target": "URL", "severity": "optional severity filter"},
            command_builder=_build_nuclei, parser=_parse_nuclei,
            references=("https://github.com/projectdiscovery/nuclei",),
        ),
        # -- web enumeration ------------------------------------------------ #
        ToolSpec(
            name="ffuf", binary="ffuf", category=ToolCategory.WEB_ENUM,
            purpose="Content/endpoint discovery via wordlist fuzzing (operator wordlist).",
            risk_level=RiskLevel.ACTIVE, supported_targets=_WEB,
            applies_when=("http", "https", "web"), evidence_format="json",
            input_schema={"target": "base URL", "wordlist": "path to operator wordlist"},
            command_builder=_build_ffuf, parser=_parse_ffuf,
            references=("https://github.com/ffuf/ffuf",),
        ),
        ToolSpec(
            name="gobuster", binary="gobuster", category=ToolCategory.WEB_ENUM,
            purpose="Directory/content discovery (operator wordlist).",
            risk_level=RiskLevel.ACTIVE, supported_targets=_WEB,
            applies_when=("http", "https", "web"), evidence_format="text",
            input_schema={"target": "base URL", "wordlist": "path to operator wordlist"},
            command_builder=_build_gobuster, parser=_parse_gobuster,
            references=("https://github.com/OJ/gobuster",),
        ),
        # -- static analysis (local, no network) ---------------------------- #
        ToolSpec(
            name="semgrep", binary="semgrep", category=ToolCategory.STATIC_ANALYSIS,
            purpose="Static source analysis over an authorized local code path.",
            risk_level=RiskLevel.SAFE, supported_targets=(TargetKind.WEB_APP,),
            applies_when=("source", "code"), requires_network=False,
            evidence_format="json",
            input_schema={"path": "local source path", "config": "ruleset (default auto)"},
            command_builder=_build_semgrep,
            references=("https://semgrep.dev/docs/",),
        ),
        ToolSpec(
            name="gitleaks", binary="gitleaks", category=ToolCategory.STATIC_ANALYSIS,
            purpose="Detect secrets committed in an authorized local repository.",
            risk_level=RiskLevel.SAFE, supported_targets=(TargetKind.WEB_APP,),
            applies_when=("source", "code", "repo"), requires_network=False,
            evidence_format="json",
            input_schema={"path": "local repo path"},
            command_builder=_build_gitleaks,
            references=("https://github.com/gitleaks/gitleaks",),
        ),
        # -- container / infra ---------------------------------------------- #
        ToolSpec(
            name="trivy", binary="trivy", category=ToolCategory.CONTAINER,
            purpose="Image/filesystem/IaC vulnerability & misconfiguration posture.",
            risk_level=RiskLevel.SAFE, supported_targets=(TargetKind.WEB_APP,),
            applies_when=("container", "image", "iac"), requires_network=False,
            evidence_format="json",
            input_schema={"target": "image ref or path", "mode": "image|fs|config"},
            command_builder=_build_trivy,
            references=("https://aquasecurity.github.io/trivy/",),
        ),

        # ================================================================== #
        # Documentation-only contracts (no command_builder => never auto-run)
        # ================================================================== #
        ToolSpec(
            name="sqlmap", binary="sqlmap", category=ToolCategory.EXPLOITATION,
            purpose="Injection confirmation/validation. Documentation-only: requires "
                    "a human-implemented, engagement-authorized adapter.",
            risk_level=RiskLevel.DANGEROUS, supported_targets=_WEB,
            applies_when=("sql", "injection-candidate"),
            command_builder=None,
            notes="Gated. Enable exploitation=true and implement a scoped adapter "
                  "with human approval before any validation is attempted.",
            references=("https://github.com/sqlmapproject/sqlmap",),
        ),
        ToolSpec(
            name="metasploit", binary="msfconsole", category=ToolCategory.EXPLOITATION,
            purpose="Exploit validation framework. Documentation-only contract.",
            risk_level=RiskLevel.DANGEROUS, supported_targets=_NET,
            command_builder=None,
            notes="Gated. Exploit validation must be human-driven under written "
                  "authorization; no auto adapter is shipped.",
            references=("https://docs.metasploit.com/",),
        ),
        ToolSpec(
            name="hydra", binary="hydra", category=ToolCategory.CREDENTIAL,
            purpose="Authentication strength testing. Documentation-only contract.",
            risk_level=RiskLevel.DANGEROUS, supported_targets=_WEB,
            command_builder=None,
            notes="Gated. credential_testing=true plus a human-implemented, "
                  "scoped adapter and explicit approval are required.",
            references=("https://github.com/vanhauser-thc/thc-hydra",),
        ),
    ]
