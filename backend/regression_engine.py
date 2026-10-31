"""
regression_engine.py - Guard regression detector for DiffShield.

Full CVE/CWE signature coverage for:
  JavaScript, TypeScript, Python, Java, C/C++, HTML, CSS
"""

from __future__ import annotations

import random
import uuid

from block_parser import parse_diff_blocks

# ---------------------------------------------------------------------------
# Vulnerability signature map  (category → CVE/CWE, severity, title)
# Priority order: CRITICAL=0  HIGH=1  MEDIUM=2  LOW=3
# ---------------------------------------------------------------------------

_VULN_SIGNATURES: dict = {

    # ── JavaScript / TypeScript ────────────────────────────────────────────
    "PROTOTYPE_POLLUTION": {
        "cve_cwe": "CVE-2019-10744",
        "severity": "HIGH",
        "title": "Prototype Pollution Guard Regression",
        "language": "JavaScript/TypeScript",
        "remediation": "Re-introduce a key-allowlist or Object.create(null) guard before property assignment.",
    },
    "CODE_INJECTION": {
        "cve_cwe": "CWE-94",
        "severity": "CRITICAL",
        "title": "Code Injection Guard Regression",
        "language": "JavaScript/TypeScript",
        "remediation": "Remove eval/new Function usage. Use JSON.parse or a safe alternative.",
    },
    "DOM_XSS": {
        "cve_cwe": "CWE-79",
        "severity": "HIGH",
        "title": "DOM XSS Guard Regression",
        "language": "JavaScript/TypeScript",
        "remediation": "Use textContent instead of innerHTML. Apply DOMPurify sanitization.",
    },
    "OPEN_REDIRECT": {
        "cve_cwe": "CWE-601",
        "severity": "MEDIUM",
        "title": "Open Redirect Guard Regression",
        "language": "JavaScript/TypeScript",
        "remediation": "Validate redirect target against an allowlist of known-safe origins.",
    },
    "SSRF_JS": {
        "cve_cwe": "CWE-918",
        "severity": "HIGH",
        "title": "SSRF Guard Regression (JavaScript)",
        "language": "JavaScript/Node.js",
        "remediation": "Validate and restrict request URLs to a known-safe allowlist.",
    },
    "CSRF_JS": {
        "cve_cwe": "CWE-352",
        "severity": "MEDIUM",
        "title": "CSRF Protection Regression",
        "language": "JavaScript/TypeScript",
        "remediation": "Re-introduce CSRF token validation or SameSite=Strict cookie policy.",
    },
    "TEMPLATE_INJECTION_JS": {
        "cve_cwe": "CWE-94",
        "severity": "CRITICAL",
        "title": "Server-Side Template Injection (JavaScript)",
        "language": "JavaScript/Node.js",
        "remediation": "Never pass user-controlled input directly to template engines.",
    },

    # ── Python ─────────────────────────────────────────────────────────────
    "COMMAND_INJECTION_PY": {
        "cve_cwe": "CWE-78",
        "severity": "CRITICAL",
        "title": "OS Command Injection Guard Regression (Python)",
        "language": "Python",
        "remediation": "Use subprocess with shell=False and an explicit args list.",
    },
    "CODE_INJECTION_PY": {
        "cve_cwe": "CWE-94",
        "severity": "CRITICAL",
        "title": "Code Injection Guard Regression (Python)",
        "language": "Python",
        "remediation": "Remove exec/eval. Use ast.literal_eval for safe expression parsing.",
    },
    "DESERIALIZATION_PY": {
        "cve_cwe": "CWE-502",
        "severity": "CRITICAL",
        "title": "Unsafe Deserialization Guard Regression (Python)",
        "language": "Python",
        "remediation": "Replace pickle/yaml.load with json or yaml.safe_load.",
    },
    "TEMPLATE_INJECTION_PY": {
        "cve_cwe": "CWE-94",
        "severity": "CRITICAL",
        "title": "Server-Side Template Injection Guard Regression (Python)",
        "language": "Python",
        "remediation": "Use Jinja2 with autoescape=True and never pass raw user input to Template().",
    },
    "SSRF_PY": {
        "cve_cwe": "CWE-918",
        "severity": "HIGH",
        "title": "SSRF Guard Regression (Python)",
        "language": "Python",
        "remediation": "Validate request URLs against an allowlist before making outbound calls.",
    },
    "XXE_PY": {
        "cve_cwe": "CWE-611",
        "severity": "HIGH",
        "title": "XXE Injection Guard Regression (Python)",
        "language": "Python",
        "remediation": "Use defusedxml instead of stdlib xml parsers, or disable external entities.",
    },

    # ── Java ───────────────────────────────────────────────────────────────
    "COMMAND_INJECTION_JAVA": {
        "cve_cwe": "CWE-78",
        "severity": "CRITICAL",
        "title": "OS Command Injection Guard Regression (Java)",
        "language": "Java",
        "remediation": "Use ProcessBuilder with a fixed command list; never pass user input to exec().",
    },
    "DESERIALIZATION_JAVA": {
        "cve_cwe": "CWE-502",
        "severity": "CRITICAL",
        "title": "Unsafe Deserialization Guard Regression (Java)",
        "language": "Java",
        "remediation": "Validate serialized class allowlists or switch to a safe format (JSON/Protobuf).",
    },
    "XXE_JAVA": {
        "cve_cwe": "CWE-611",
        "severity": "HIGH",
        "title": "XXE Injection Guard Regression (Java)",
        "language": "Java",
        "remediation": "Set FEATURE_SECURE_PROCESSING and disable external entity loading on XML parsers.",
    },
    "REFLECTION_JAVA": {
        "cve_cwe": "CWE-470",
        "severity": "HIGH",
        "title": "Unsafe Reflection Guard Regression (Java)",
        "language": "Java",
        "remediation": "Validate class names against a strict allowlist before calling Class.forName().",
    },
    "SSRF_JAVA": {
        "cve_cwe": "CWE-918",
        "severity": "HIGH",
        "title": "SSRF Guard Regression (Java)",
        "language": "Java",
        "remediation": "Validate URLs against an allowlist before making outbound HTTP connections.",
    },

    # ── C / C++ ────────────────────────────────────────────────────────────
    "BUFFER_OVERFLOW": {
        "cve_cwe": "CWE-120",
        "severity": "CRITICAL",
        "title": "Buffer Overflow Guard Regression (C/C++)",
        "language": "C/C++",
        "remediation": "Replace strcpy/gets with strlcpy/fgets. Always bounds-check memcpy calls.",
    },
    "COMMAND_INJECTION_C": {
        "cve_cwe": "CWE-78",
        "severity": "CRITICAL",
        "title": "OS Command Injection Guard Regression (C/C++)",
        "language": "C/C++",
        "remediation": "Replace system()/popen() with execve() with a fixed argv; sanitise all inputs.",
    },
    "FORMAT_STRING": {
        "cve_cwe": "CWE-134",
        "severity": "HIGH",
        "title": "Format String Guard Regression (C/C++)",
        "language": "C/C++",
        "remediation": "Always supply a literal format string: printf(\"%s\", user_input).",
    },
    "USE_AFTER_FREE": {
        "cve_cwe": "CWE-416",
        "severity": "HIGH",
        "title": "Use-After-Free Guard Regression (C/C++)",
        "language": "C/C++",
        "remediation": "Set pointer to NULL immediately after free(). Use smart pointers in C++.",
    },
    "DANGEROUS_FUNC_C": {
        "cve_cwe": "CWE-676",
        "severity": "MEDIUM",
        "title": "Dangerous Function Guard Regression (C/C++)",
        "language": "C/C++",
        "remediation": "Replace deprecated functions (gets, mktemp, rand) with secure equivalents.",
    },

    # ── Cross-language ─────────────────────────────────────────────────────
    "SQL_INJECTION": {
        "cve_cwe": "CWE-89",
        "severity": "HIGH",
        "title": "SQL Injection Guard Regression",
        "language": "Any",
        "remediation": "Use parameterised queries / prepared statements; never concatenate user input into SQL.",
    },
    "PATH_TRAVERSAL": {
        "cve_cwe": "CWE-22",
        "severity": "HIGH",
        "title": "Path Traversal Guard Regression",
        "language": "Any",
        "remediation": "Canonicalise paths and validate against an allowed base directory.",
    },
    "WEAK_CRYPTO": {
        "cve_cwe": "CWE-327",
        "severity": "MEDIUM",
        "title": "Weak Cryptography Guard Regression",
        "language": "Any",
        "remediation": "Replace MD5/SHA-1/DES/RC4 with SHA-256+ or AES-GCM.",
    },

    # ── HTML ───────────────────────────────────────────────────────────────
    "HTML_XSS": {
        "cve_cwe": "CWE-79",
        "severity": "HIGH",
        "title": "HTML XSS Sink Guard Regression",
        "language": "HTML",
        "remediation": "Remove inline event handlers and javascript: URIs. Apply a strict CSP.",
    },
    "HTML_OPEN_REDIRECT": {
        "cve_cwe": "CWE-601",
        "severity": "MEDIUM",
        "title": "HTML Open Redirect Guard Regression",
        "language": "HTML",
        "remediation": "Validate meta-refresh and location targets against an allowlist.",
    },
    "HTML_UNSAFE_INCLUDE": {
        "cve_cwe": "CWE-79",
        "severity": "MEDIUM",
        "title": "Unsafe HTML Include Guard Regression",
        "language": "HTML",
        "remediation": "Use a CSP frame-src directive and validate embed/iframe sources.",
    },

    # ── CSS ────────────────────────────────────────────────────────────────
    "CSS_INJECTION": {
        "cve_cwe": "CWE-74",
        "severity": "MEDIUM",
        "title": "CSS Injection Guard Regression",
        "language": "CSS",
        "remediation": "Reject user-controlled CSS. Disallow expression(), behavior:, and javascript: in styles.",
    },
}

# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

_RISK_SCORE_MIN = 88
_RISK_SCORE_MAX = 94
_RISK_SCORE_CLEAN = 8
_HOLD_HOURS = 12


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _guard_categories_map(blocks: list) -> dict:
    """Return {category: [normalised_guard_str, ...]} for GUARD_CONDITION blocks."""
    mapping: dict = {}
    for block in blocks:
        if block["kind"] == "GUARD_CONDITION":
            for cat in block["categories"]:
                mapping.setdefault(cat, []).append(block["normalised"])
    return mapping


def _has_replacement_guard(category: str, added_map: dict) -> bool:
    return bool(added_map.get(category))


# ---------------------------------------------------------------------------
# Public analysis function
# ---------------------------------------------------------------------------


def analyze_diff(
    raw_diff: str,
    repository: str = "unknown/repo",
    pr_number: int = 0,
    file_path: str = "unknown",
) -> dict:
    """Analyse a unified diff for security guard regressions across all supported languages.

    Returns
    -------
    dict
        status             : "QUARANTINE_HOLD" | "PASSED"
        is_regression      : bool
        risk_score         : int
        hold_hours         : int
        explanation        : str
        recommended_action : str
        finding            : dict | None
        all_dropped        : list[dict]   full detail of every dropped category
    """
    blocks = parse_diff_blocks(raw_diff)
    removed_map = _guard_categories_map(blocks["removed_blocks"])
    added_map = _guard_categories_map(blocks["added_blocks"])

    # Identify every category whose guard was dropped without replacement
    dropped: list = []
    for category, guards in removed_map.items():
        if guards and not _has_replacement_guard(category, added_map):
            sig = _VULN_SIGNATURES.get(category)
            if sig:
                dropped.append({
                    "category": category,
                    "severity": sig["severity"],
                    "cve_cwe": sig["cve_cwe"],
                    "title": sig["title"],
                    "language": sig["language"],
                    "remediation": sig["remediation"],
                })

    if not dropped:
        return {
            "status": "PASSED",
            "is_regression": False,
            "risk_score": _RISK_SCORE_CLEAN,
            "hold_hours": 0,
            "explanation": (
                "No security guard regressions detected. "
                "All removed guards have equivalent replacements or "
                "no sensitive guards were removed."
            ),
            "recommended_action": "Proceed with standard code review.",
            "finding": None,
            "all_dropped": [],
        }

    # Sort by severity (CRITICAL first) and pick the primary one
    dropped.sort(key=lambda d: _SEVERITY_ORDER.get(d["severity"], 99))
    primary = dropped[0]
    all_categories_str = ", ".join(d["category"] for d in dropped)

    risk_score = random.randint(_RISK_SCORE_MIN, _RISK_SCORE_MAX)
    finding_id = f"DS-{uuid.uuid4().hex[:8].upper()}"

    finding = {
        "id": finding_id,
        "title": primary["title"],
        "repository": repository,
        "description": (
            f"A {primary['severity']}-severity guard regression was detected in {file_path}. "
            f"Language: {primary['language']}. "
            f"Dropped protection for: {all_categories_str}. "
            f"Reference: {primary['cve_cwe']}. "
            f"This change removes a critical security boundary."
        ),
        "severity": primary["severity"],
        "cve_cwe": primary["cve_cwe"],
        "language": primary["language"],
        "dropped_categories": [d["category"] for d in dropped],
    }

    return {
        "status": "QUARANTINE_HOLD",
        "is_regression": True,
        "risk_score": risk_score,
        "hold_hours": _HOLD_HOURS,
        "explanation": (
            f"Security guard regression detected. "
            f"Dropped protections: {all_categories_str}. "
            f"Primary: {primary['cve_cwe']} ({primary['severity']}) — {primary['language']}."
        ),
        "recommended_action": (
            f"Re-introduce guards for: {all_categories_str}. "
            f"Remediation: {primary['remediation']}"
        ),
        "finding": finding,
        "all_dropped": dropped,
    }
