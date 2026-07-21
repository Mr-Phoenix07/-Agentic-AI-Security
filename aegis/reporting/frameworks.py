"""Security-framework mappings and mitigation/regression knowledge base.

Maps each :class:`~aegis.core.types.FindingCategory` to references in the
relevant industry frameworks and to a starter set of defensive mitigations and
regression tests. This turns a raw behavioural weakness into an actionable,
standards-aligned finding.

Frameworks covered:
    * OWASP Top 10 for LLM Applications (2025)
    * OWASP API Security Top 10 (2023)
    * OWASP Web Top 10 (2021)
    * OWASP ASVS (control families)
    * MITRE ATLAS (adversarial ML tactics/techniques)
    * NIST AI RMF (functions)

References are indicative pointers for triage, not a compliance attestation.
"""

from __future__ import annotations

from ..core.types import FindingCategory

# category -> framework references
FRAMEWORKS: dict[FindingCategory, dict[str, list[str]]] = {
    FindingCategory.PROMPT_INJECTION: {
        "owasp_llm": ["LLM01:2025 Prompt Injection"],
        "mitre_atlas": ["AML.T0051 LLM Prompt Injection"],
        "nist_ai_rmf": ["MEASURE 2.7", "MANAGE 4.1"],
    },
    FindingCategory.INSTRUCTION_HIERARCHY: {
        "owasp_llm": ["LLM01:2025 Prompt Injection"],
        "mitre_atlas": ["AML.T0051.000 Direct", "AML.T0054 LLM Jailbreak"],
        "nist_ai_rmf": ["MEASURE 2.7"],
    },
    FindingCategory.ROBUSTNESS: {
        "owasp_llm": ["LLM01:2025 Prompt Injection", "LLM09:2025 Misinformation"],
        "mitre_atlas": ["AML.T0043 Craft Adversarial Data"],
        "nist_ai_rmf": ["MEASURE 2.5 (validity & robustness)"],
    },
    FindingCategory.HALLUCINATION: {
        "owasp_llm": ["LLM09:2025 Misinformation"],
        "mitre_atlas": ["AML.T0048 External Harms"],
        "nist_ai_rmf": ["MEASURE 2.3", "MEASURE 2.9"],
    },
    FindingCategory.CONFIDENCE_CALIBRATION: {
        "owasp_llm": ["LLM09:2025 Misinformation (overreliance)"],
        "nist_ai_rmf": ["MEASURE 2.9 (uncertainty)"],
    },
    FindingCategory.LONG_CONTEXT: {
        "owasp_llm": ["LLM08:2025 Vector & Embedding Weaknesses",
                      "LLM09:2025 Misinformation"],
        "nist_ai_rmf": ["MEASURE 2.5"],
    },
    FindingCategory.RAG_GROUNDING: {
        "owasp_llm": ["LLM08:2025 Vector & Embedding Weaknesses",
                      "LLM09:2025 Misinformation"],
        "mitre_atlas": ["AML.T0070 RAG Poisoning"],
        "nist_ai_rmf": ["MEASURE 2.3"],
    },
    FindingCategory.RAG_RETRIEVAL: {
        "owasp_llm": ["LLM08:2025 Vector & Embedding Weaknesses"],
        "mitre_atlas": ["AML.T0070 RAG Poisoning"],
    },
    FindingCategory.TOOL_USE: {
        "owasp_llm": ["LLM06:2025 Excessive Agency"],
        "mitre_atlas": ["AML.T0053 LLM Plugin Compromise"],
        "nist_ai_rmf": ["MANAGE 2.3"],
    },
    FindingCategory.AGENT_AUTONOMY: {
        "owasp_llm": ["LLM06:2025 Excessive Agency"],
        "nist_ai_rmf": ["GOVERN 1.2", "MANAGE 2.3"],
    },
    FindingCategory.MCP_EXPOSURE: {
        "owasp_llm": ["LLM06:2025 Excessive Agency", "LLM07:2025 System Prompt Leakage"],
        "owasp_api": ["API1:2023 BOLA", "API5:2023 BFLA"],
        "nist_ai_rmf": ["MANAGE 2.3"],
    },
    FindingCategory.DATA_EXPOSURE: {
        "owasp_llm": ["LLM02:2025 Sensitive Information Disclosure"],
        "owasp_api": ["API3:2023 Broken Object Property Level Authorization"],
        "owasp_web": ["A01:2021 Broken Access Control"],
        "nist_ai_rmf": ["MEASURE 2.10"],
    },
    FindingCategory.AUTHN: {
        "owasp_api": ["API2:2023 Broken Authentication"],
        "owasp_web": ["A07:2021 Identification and Authentication Failures"],
        "owasp_asvs": ["V2 Authentication"],
    },
    FindingCategory.AUTHZ: {
        "owasp_api": ["API1:2023 BOLA", "API5:2023 BFLA"],
        "owasp_web": ["A01:2021 Broken Access Control"],
        "owasp_asvs": ["V4 Access Control"],
    },
    FindingCategory.SESSION: {
        "owasp_web": ["A07:2021 Identification and Authentication Failures"],
        "owasp_asvs": ["V3 Session Management"],
    },
    FindingCategory.API_SECURITY: {
        "owasp_api": ["API4:2023 Unrestricted Resource Consumption",
                      "API8:2023 Security Misconfiguration"],
        "owasp_asvs": ["V13 API and Web Service"],
    },
    FindingCategory.INPUT_VALIDATION: {
        "owasp_web": ["A03:2021 Injection"],
        "owasp_asvs": ["V5 Validation, Sanitization and Encoding"],
    },
    FindingCategory.MONITORING: {
        "owasp_llm": ["LLM10:2025 Unbounded Consumption"],
        "owasp_web": ["A09:2021 Security Logging and Monitoring Failures"],
        "nist_ai_rmf": ["MANAGE 4.1 (post-deployment monitoring)"],
    },
    FindingCategory.CROSS_DOMAIN: {
        "owasp_llm": ["LLM06:2025 Excessive Agency"],
        "owasp_api": ["API1:2023 BOLA"],
        "nist_ai_rmf": ["MAP 4.1", "MANAGE 2.3"],
    },
}

# category -> (mitigations, regression tests)
MITIGATIONS: dict[FindingCategory, list[str]] = {
    FindingCategory.ROBUSTNESS: [
        "Normalise input (Unicode NFKC, strip zero-width/bidi control chars, fold "
        "confusables) before prompt assembly and before any policy check.",
        "Treat retrieved/document content as data, not instructions; enforce a "
        "strict instruction/data boundary in the prompt template.",
        "Add canonicalisation unit tests so equivalent inputs map to one form.",
    ],
    FindingCategory.INSTRUCTION_HIERARCHY: [
        "Establish an explicit, enforced instruction hierarchy (system > developer "
        "> user > tool/data) and validate precedence at assembly time.",
        "Have the model surface and resolve detected conflicts rather than silently "
        "picking one instruction.",
    ],
    FindingCategory.LONG_CONTEXT: [
        "Bound context length to the validated retention window; summarise/compress "
        "beyond it instead of relying on raw recall.",
        "Re-assert critical instructions near the point of use ('instruction "
        "refresh') for long inputs.",
        "Add long-context regression probes at multiple distances to CI.",
    ],
    FindingCategory.CONFIDENCE_CALIBRATION: [
        "Calibrate or post-process stated confidence (temperature scaling / verbal "
        "calibration) and gate high-stakes actions on calibrated thresholds.",
        "Surface uncertainty to users and require human confirmation below a "
        "confidence threshold (mitigate overreliance).",
    ],
    FindingCategory.HALLUCINATION: [
        "Require grounded answers with citations; refuse or hedge when support is "
        "absent.",
        "Add a verification pass that checks claims against retrieved sources.",
    ],
    FindingCategory.RAG_GROUNDING: [
        "Enforce citation-to-source validation; drop or flag answers citing "
        "non-retrieved sources.",
        "Constrain generation to retrieved context and measure attribution rate.",
    ],
    FindingCategory.RAG_RETRIEVAL: [
        "Tune chunking/ranking and add retrieval quality gates (min top-score); fall "
        "back to 'insufficient evidence' on low retrieval scores.",
    ],
    FindingCategory.MCP_EXPOSURE: [
        "Require explicit human confirmation for side-effecting MCP tools; apply "
        "least-privilege scopes per tool.",
        "Authenticate the MCP transport and allow-list callable tools/resources.",
        "Log every tool invocation with arguments for audit.",
    ],
    FindingCategory.TOOL_USE: [
        "Constrain tool arguments with schemas; validate and sandbox tool execution.",
        "Apply least privilege and rate limits to agent tool access.",
    ],
    FindingCategory.AUTHZ: [
        "Enforce object- and function-level authorization server-side on every "
        "request; never rely on client-supplied role claims.",
        "Add automated BOLA/BFLA tests per role for each endpoint.",
    ],
    FindingCategory.AUTHN: [
        "Enforce strong authentication on all state-changing and AI endpoints; rotate "
        "and scope credentials.",
    ],
    FindingCategory.API_SECURITY: [
        "Apply rate limiting / quotas to AI and inference endpoints (unbounded "
        "consumption).",
        "Harden configuration; disable verbose errors and introspection in prod.",
    ],
    FindingCategory.DATA_EXPOSURE: [
        "Apply output filtering / DLP on AI responses; minimise sensitive data in "
        "prompts and context.",
    ],
    FindingCategory.MONITORING: [
        "Instrument AI actions with structured, auditable logs and anomaly alerts; "
        "define abuse/rate baselines.",
    ],
    FindingCategory.CROSS_DOMAIN: [
        "Re-authorize AI-initiated actions at the resource layer; do not treat the "
        "AI's identity as the user's authority.",
    ],
}

REGRESSION_TESTS: dict[FindingCategory, list[str]] = {
    FindingCategory.ROBUSTNESS: [
        "aegis regression: encoding-family stability >= baseline (homoglyph, "
        "zero-width, bidi, NFKC, format-shift variants).",
    ],
    FindingCategory.INSTRUCTION_HIERARCHY: [
        "aegis regression: conflict-acknowledgement rate on layered-instruction "
        "probes >= baseline.",
    ],
    FindingCategory.LONG_CONTEXT: [
        "aegis regression: anchor recall rate at distances {6,12,18,22} >= baseline.",
    ],
    FindingCategory.CONFIDENCE_CALIBRATION: [
        "aegis regression: ECE <= baseline on long-context recall confidence.",
    ],
    FindingCategory.RAG_GROUNDING: [
        "aegis regression: grounding rate >= baseline; zero unsupported citations.",
    ],
    FindingCategory.MCP_EXPOSURE: [
        "aegis regression: no dangerous MCP tool callable without confirmation; "
        "transport authenticated.",
    ],
    FindingCategory.AUTHZ: [
        "aegis regression: cross-role access attempts on each object/function denied.",
    ],
}

DEFAULT_MITIGATIONS = [
    "Add defence-in-depth controls and monitor for recurrence.",
]
DEFAULT_REGRESSION = [
    "aegis regression: re-run the failing probe family and assert metric >= baseline.",
]


def frameworks_for(category: FindingCategory) -> dict[str, list[str]]:
    return FRAMEWORKS.get(category, {})


def mitigations_for(category: FindingCategory) -> list[str]:
    return MITIGATIONS.get(category, DEFAULT_MITIGATIONS)


def regression_tests_for(category: FindingCategory) -> list[str]:
    return REGRESSION_TESTS.get(category, DEFAULT_REGRESSION)
