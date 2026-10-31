"""
test_diffshield.py - Full multi-language verification tests for DiffShield.

Each diff uses REALISTIC guard patterns where the removed guard line itself
references the dangerous sink/keyword it protects, which is how real security
checks appear in code (inline guard or combined condition).
"""

from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import block_parser
import regression_engine
import snapshot_vault

PASS_T = "\033[92mPASS\033[0m"
FAIL_T = "\033[91mFAIL\033[0m"
_results: list = []

def check(name: str, condition: bool, detail: str = "") -> None:
    status = PASS_T if condition else FAIL_T
    print(f"  [{status}] {name}" + (f"\n         {detail}" if detail else ""))
    _results.append(condition)

def section(title: str) -> None:
    print(f"\n{'='*56}")
    print(f"  {title}")
    print(f"{'='*56}")

def qh(r: dict) -> bool:
    return r["status"] == "QUARANTINE_HOLD"

# ─────────────────────────────────────────────────────────────
# JavaScript
# ─────────────────────────────────────────────────────────────
section("JavaScript — Prototype Pollution (CVE-2019-10744)")
r = regression_engine.analyze_diff(
    "--- a/merge.js\n+++ b/merge.js\n@@ @@\n-  if (key === '__proto__') continue;\n   obj[key] = src[key];",
    repository="test/js", pr_number=1, file_path="merge.js")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CVE-2019-10744", r["finding"]["cve_cwe"] == "CVE-2019-10744", str(r["finding"]["cve_cwe"]))
check("risk >= 88", r["risk_score"] >= 88, str(r["risk_score"]))

section("JavaScript — DOM XSS (CWE-79)")
r = regression_engine.analyze_diff(
    "--- a/ui.js\n+++ b/ui.js\n@@ @@\n-  if (!/<script/.test(s)) el.innerHTML = clean(s);\n   el.innerHTML = s;",
    repository="test/js", pr_number=2, file_path="ui.js")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-79", r["finding"]["cve_cwe"] == "CWE-79", str(r["finding"]["cve_cwe"]))

section("JavaScript — Code Injection / eval (CWE-94)")
r = regression_engine.analyze_diff(
    "--- a/run.js\n+++ b/run.js\n@@ @@\n-  if (isTrusted) return eval(code);\n   eval(code);",
    repository="test/js", pr_number=3, file_path="run.js")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-94", r["finding"]["cve_cwe"] == "CWE-94", str(r["finding"]["cve_cwe"]))

section("JavaScript — Open Redirect (CWE-601)")
r = regression_engine.analyze_diff(
    "--- a/auth.js\n+++ b/auth.js\n@@ @@\n-  if (isTrustedOrigin(url)) window.location.replace(url);\n   window.location.replace(url);",
    repository="test/js", pr_number=4, file_path="auth.js")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-601", r["finding"]["cve_cwe"] == "CWE-601", str(r["finding"]["cve_cwe"]))

section("JavaScript — SSRF (CWE-918)")
r = regression_engine.analyze_diff(
    "--- a/proxy.js\n+++ b/proxy.js\n@@ @@\n-  if (isAllowed(url)) return fetch(url);\n   return fetch(url);",
    repository="test/js", pr_number=5, file_path="proxy.js")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-918", r["finding"]["cve_cwe"] == "CWE-918", str(r["finding"]["cve_cwe"]))

section("JavaScript — Template Injection (CWE-94)")
r = regression_engine.analyze_diff(
    "--- a/tmpl.js\n+++ b/tmpl.js\n@@ @@\n-  if (isSafeTemplate(src)) return _.template(src);\n   return _.template(src);",
    repository="test/js", pr_number=6, file_path="tmpl.js")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-94 (template)", "94" in r["finding"]["cve_cwe"], str(r["finding"]["cve_cwe"]))

# ─────────────────────────────────────────────────────────────
# Python
# ─────────────────────────────────────────────────────────────
section("Python — Command Injection (CWE-78)")
r = regression_engine.analyze_diff(
    "--- a/runner.py\n+++ b/runner.py\n@@ @@\n-    if safe_cmd: os.system(cmd)\n     os.system(cmd)",
    repository="test/py", pr_number=7, file_path="runner.py")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-78", r["finding"]["cve_cwe"] == "CWE-78", str(r["finding"]["cve_cwe"]))
check("Language: Python", r["finding"]["language"] == "Python", r["finding"]["language"])

section("Python — Code Injection / exec (CWE-94)")
r = regression_engine.analyze_diff(
    "--- a/dyn.py\n+++ b/dyn.py\n@@ @@\n-    if is_safe(code): exec(code)\n     exec(code)",
    repository="test/py", pr_number=8, file_path="dyn.py")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-94 (py)", "94" in r["finding"]["cve_cwe"])

section("Python — Unsafe Deserialization pickle (CWE-502)")
r = regression_engine.analyze_diff(
    "--- a/loader.py\n+++ b/loader.py\n@@ @@\n-    if trusted: return pickle.loads(data)\n     return pickle.loads(data)",
    repository="test/py", pr_number=9, file_path="loader.py")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-502", r["finding"]["cve_cwe"] == "CWE-502", str(r["finding"]["cve_cwe"]))

section("Python — Template Injection Jinja2 (CWE-94)")
r = regression_engine.analyze_diff(
    "--- a/view.py\n+++ b/view.py\n@@ @@\n-    if safe_tmpl: return render_template_string(tmpl)\n     return render_template_string(tmpl)",
    repository="test/py", pr_number=10, file_path="view.py")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-94 (tmpl)", "94" in r["finding"]["cve_cwe"])

section("Python — SSRF requests (CWE-918)")
r = regression_engine.analyze_diff(
    "--- a/client.py\n+++ b/client.py\n@@ @@\n-    if is_internal(url): return requests.get(url)\n     return requests.get(url)",
    repository="test/py", pr_number=11, file_path="client.py")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-918 (py)", r["finding"]["cve_cwe"] == "CWE-918", str(r["finding"]["cve_cwe"]))

section("Python — XXE (CWE-611)")
r = regression_engine.analyze_diff(
    "--- a/xml_p.py\n+++ b/xml_p.py\n@@ @@\n-    if safe_xml: xml.etree.ElementTree.parse(f)\n     xml.etree.ElementTree.parse(f)",
    repository="test/py", pr_number=12, file_path="xml_p.py")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-611 (py)", r["finding"]["cve_cwe"] == "CWE-611", str(r["finding"]["cve_cwe"]))

# ─────────────────────────────────────────────────────────────
# Java
# ─────────────────────────────────────────────────────────────
section("Java — OS Command Injection (CWE-78)")
r = regression_engine.analyze_diff(
    "--- a/Exec.java\n+++ b/Exec.java\n@@ @@\n-        if (safe) Runtime.getRuntime().exec(cmd);\n         Runtime.getRuntime().exec(cmd);",
    repository="test/java", pr_number=13, file_path="Exec.java")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-78 (java)", r["finding"]["cve_cwe"] == "CWE-78", str(r["finding"]["cve_cwe"]))
check("Language: Java", r["finding"]["language"] == "Java", r["finding"]["language"])

section("Java — Unsafe Deserialization (CWE-502)")
r = regression_engine.analyze_diff(
    "--- a/Deser.java\n+++ b/Deser.java\n@@ @@\n-        if (valid) return ois.readObject();\n         return ois.readObject();",
    repository="test/java", pr_number=14, file_path="Deser.java")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-502 (java)", r["finding"]["cve_cwe"] == "CWE-502", str(r["finding"]["cve_cwe"]))

section("Java — XXE (CWE-611)")
r = regression_engine.analyze_diff(
    "--- a/P.java\n+++ b/P.java\n@@ @@\n-        if (secure) DocumentBuilderFactory.newInstance();\n         DocumentBuilderFactory.newInstance();",
    repository="test/java", pr_number=15, file_path="P.java")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-611 (java)", r["finding"]["cve_cwe"] == "CWE-611", str(r["finding"]["cve_cwe"]))

section("Java — Unsafe Reflection (CWE-470)")
r = regression_engine.analyze_diff(
    "--- a/Ref.java\n+++ b/Ref.java\n@@ @@\n-        if (allowedClass) Class.forName(name);\n         Class.forName(name);",
    repository="test/java", pr_number=16, file_path="Ref.java")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-470", r["finding"]["cve_cwe"] == "CWE-470", str(r["finding"]["cve_cwe"]))

section("Java — SSRF (CWE-918)")
r = regression_engine.analyze_diff(
    "--- a/Http.java\n+++ b/Http.java\n@@ @@\n-        if (trusted) new URL(endpoint);\n         new URL(endpoint);",
    repository="test/java", pr_number=17, file_path="Http.java")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-918 (java)", r["finding"]["cve_cwe"] == "CWE-918", str(r["finding"]["cve_cwe"]))

# ─────────────────────────────────────────────────────────────
# C / C++
# ─────────────────────────────────────────────────────────────
section("C/C++ — Buffer Overflow strcpy (CWE-120)")
r = regression_engine.analyze_diff(
    "--- a/copy.c\n+++ b/copy.c\n@@ @@\n-    if (len < sizeof(dst)) strcpy(dst, src);\n     strcpy(dst, src);",
    repository="test/c", pr_number=18, file_path="copy.c")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-120", r["finding"]["cve_cwe"] == "CWE-120", str(r["finding"]["cve_cwe"]))
check("Language: C/C++", r["finding"]["language"] == "C/C++", r["finding"]["language"])

section("C/C++ — Command Injection system() (CWE-78)")
r = regression_engine.analyze_diff(
    "--- a/sh.c\n+++ b/sh.c\n@@ @@\n-    if (validated) system(cmd);\n     system(cmd);",
    repository="test/c", pr_number=19, file_path="sh.c")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-78 (c)", r["finding"]["cve_cwe"] == "CWE-78", str(r["finding"]["cve_cwe"]))

section("C/C++ — Format String printf (CWE-134)")
r = regression_engine.analyze_diff(
    "--- a/log.c\n+++ b/log.c\n@@ @@\n-    if (safe_fmt) printf(msg);\n     printf(msg);",
    repository="test/c", pr_number=20, file_path="log.c")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-134", r["finding"]["cve_cwe"] == "CWE-134", str(r["finding"]["cve_cwe"]))

section("C/C++ — Dangerous gets() (CWE-676)")
r = regression_engine.analyze_diff(
    "--- a/in.c\n+++ b/in.c\n@@ @@\n-    if (buf_ok) gets(buf);\n     gets(buf);",
    repository="test/c", pr_number=21, file_path="in.c")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-676 or CWE-120", r["finding"]["cve_cwe"] in ("CWE-676","CWE-120"), str(r["finding"]["cve_cwe"]))

# ─────────────────────────────────────────────────────────────
# HTML
# ─────────────────────────────────────────────────────────────
section("HTML — Inline XSS onclick (CWE-79)")
r = regression_engine.analyze_diff(
    "--- a/page.html\n+++ b/page.html\n@@ @@\n-    <!-- if safe --> <div onclick=\"safe()\">x</div>\n     <div onclick=\"javascript:alert(1)\">x</div>",
    repository="test/html", pr_number=22, file_path="page.html")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-79 (html)", r["finding"]["cve_cwe"] == "CWE-79", str(r["finding"]["cve_cwe"]))
check("Language: HTML", r["finding"]["language"] == "HTML", r["finding"]["language"])

# ─────────────────────────────────────────────────────────────
# CSS
# ─────────────────────────────────────────────────────────────
section("CSS — CSS Injection expression() (CWE-74)")
r = regression_engine.analyze_diff(
    "--- a/style.css\n+++ b/style.css\n@@ @@\n-    /* if no expression() */ background: safe;\n     background: expression(alert(1));",
    repository="test/css", pr_number=23, file_path="style.css")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-74", r["finding"]["cve_cwe"] == "CWE-74", str(r["finding"]["cve_cwe"]))
check("Language: CSS", r["finding"]["language"] == "CSS", r["finding"]["language"])

# ─────────────────────────────────────────────────────────────
# Cross-language
# ─────────────────────────────────────────────────────────────
section("Cross-language — SQL Injection (CWE-89)")
r = regression_engine.analyze_diff(
    "--- a/db.py\n+++ b/db.py\n@@ @@\n-    if safe_query: cursor.execute(q)\n     cursor.execute(q)",
    repository="test/db", pr_number=24, file_path="db.py")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-89", r["finding"]["cve_cwe"] == "CWE-89", str(r["finding"]["cve_cwe"]))

section("Cross-language — Path Traversal (CWE-22)")
r = regression_engine.analyze_diff(
    "--- a/files.py\n+++ b/files.py\n@@ @@\n-    if '../' not in path: open(path)\n     open(path)",
    repository="test/files", pr_number=25, file_path="files.py")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-22", r["finding"]["cve_cwe"] == "CWE-22", str(r["finding"]["cve_cwe"]))

section("Cross-language — Weak Crypto MD5 (CWE-327)")
r = regression_engine.analyze_diff(
    "--- a/auth.py\n+++ b/auth.py\n@@ @@\n-    if strong_algo: return hashlib.md5(pw)\n     return hashlib.md5(pw)",
    repository="test/auth", pr_number=26, file_path="auth.py")
check("QUARANTINE_HOLD", qh(r), r["status"])
check("CWE-327", r["finding"]["cve_cwe"] == "CWE-327", str(r["finding"]["cve_cwe"]))

# ─────────────────────────────────────────────────────────────
# Clean diff
# ─────────────────────────────────────────────────────────────
section("Clean diff — PASSED, risk=8")
r = regression_engine.analyze_diff(
    "--- a/README.md\n+++ b/README.md\n@@ @@\n-# Old Title\n+# New Title",
    repository="test/docs", pr_number=27, file_path="README.md")
check("PASSED", r["status"] == "PASSED", r["status"])
check("risk_score == 8", r["risk_score"] == 8, str(r["risk_score"]))
check("finding is None", r["finding"] is None)

# ─────────────────────────────────────────────────────────────
# Vault
# ─────────────────────────────────────────────────────────────
section("Snapshot Vault")
sid = snapshot_vault.archive_snapshot(
    "test/c", 18, "copy.c", "int copy(){}", 
    "--- a/copy.c\n+++ b/copy.c\n@@ @@\n-    if (len<sizeof(dst)) strcpy(dst,src);\n     strcpy(dst,src);"
)
check("archived (id > 0)", isinstance(sid, int) and sid > 0, str(sid))
rb = snapshot_vault.retrieve_rollback("test/c", 18)
check("rollback.found", rb["found"] is True)
check("reverse_patch present", bool(rb.get("reverse_patch")))
check("DB file exists", (Path(__file__).parent / "diffshield_vault.db").exists())

# ─────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────
print(f"\n{'='*56}")
passed = sum(_results)
total = len(_results)
if passed == total:
    print(f"  \033[92mOK: ALL {total} CHECKS PASSED\033[0m")
else:
    print(f"  FAIL: {total - passed} of {total} CHECKS FAILED")
print(f"{'='*56}\n")
sys.exit(0 if passed == total else 1)
