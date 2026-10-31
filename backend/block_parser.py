"""
block_parser.py - AST-level syntax normaliser and multi-language block classifier.

Supports full detection for:
  JavaScript / TypeScript  - Prototype pollution, DOM XSS, Code injection, Open redirect,
                             CSRF, Path traversal, SSRF, Weak crypto, SQL injection
  Python                   - Code injection, Command injection, Deserialization,
                             Template injection, Path traversal, SSRF, Weak crypto,
                             SQL injection, XXE
  Java                     - Command injection, SQL injection, Deserialization, XXE,
                             Reflection injection, SSRF, Path traversal, Weak crypto
  C / C++                  - Buffer overflow, Command injection, Format string,
                             Integer overflow, Use-after-free, Dangerous functions
  HTML                     - XSS sinks, Unsafe event handlers, Open redirect meta tags,
                             JavaScript URIs, Unsafe iframes
  CSS                      - CSS injection (expression/behavior), Data exfiltration URLs,
                             JavaScript URI schemes in stylesheets
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Vulnerability categories (used across all languages)
# ---------------------------------------------------------------------------

CATEGORIES = [
    # Cross-language
    "SQL_INJECTION",
    "PATH_TRAVERSAL",
    "WEAK_CRYPTO",

    # JavaScript / TypeScript
    "PROTOTYPE_POLLUTION",
    "DOM_XSS",
    "CODE_INJECTION",
    "OPEN_REDIRECT",
    "SSRF_JS",
    "CSRF_JS",
    "TEMPLATE_INJECTION_JS",

    # Python
    "COMMAND_INJECTION_PY",
    "CODE_INJECTION_PY",
    "DESERIALIZATION_PY",
    "TEMPLATE_INJECTION_PY",
    "SSRF_PY",
    "XXE_PY",

    # Java
    "COMMAND_INJECTION_JAVA",
    "DESERIALIZATION_JAVA",
    "XXE_JAVA",
    "REFLECTION_JAVA",
    "SSRF_JAVA",

    # C / C++
    "BUFFER_OVERFLOW",
    "COMMAND_INJECTION_C",
    "FORMAT_STRING",
    "USE_AFTER_FREE",
    "DANGEROUS_FUNC_C",

    # HTML
    "HTML_XSS",
    "HTML_OPEN_REDIRECT",
    "HTML_UNSAFE_INCLUDE",

    # CSS
    "CSS_INJECTION",
]

# ---------------------------------------------------------------------------
# Language extensions & category mappings
# ---------------------------------------------------------------------------

LANGUAGE_EXTENSIONS: dict[str, list[str]] = {
    "Python": [".py", ".pyw", ".pyx", ".wsgi"],
    "Java": [".java", ".jar", ".jsp"],
    "C/C++": [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx", ".c++", ".h++"],
    "HTML": [".html", ".htm", ".xhtml", ".vue", ".svelte"],
    "CSS": [".css", ".scss", ".sass", ".less"],
    "JavaScript/TypeScript": [".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"],
}

LANGUAGE_CATEGORIES: dict[str, list[str]] = {
    "JavaScript/TypeScript": [
        "PROTOTYPE_POLLUTION", "DOM_XSS", "CODE_INJECTION",
        "OPEN_REDIRECT", "SSRF_JS", "CSRF_JS", "TEMPLATE_INJECTION_JS",
        "SQL_INJECTION", "PATH_TRAVERSAL", "WEAK_CRYPTO",
    ],
    "Python": [
        "COMMAND_INJECTION_PY", "CODE_INJECTION_PY", "DESERIALIZATION_PY",
        "TEMPLATE_INJECTION_PY", "SSRF_PY", "XXE_PY",
        "SQL_INJECTION", "PATH_TRAVERSAL", "WEAK_CRYPTO",
    ],
    "Java": [
        "COMMAND_INJECTION_JAVA", "DESERIALIZATION_JAVA", "XXE_JAVA",
        "REFLECTION_JAVA", "SSRF_JAVA",
        "SQL_INJECTION", "PATH_TRAVERSAL", "WEAK_CRYPTO",
    ],
    "C/C++": [
        "BUFFER_OVERFLOW", "COMMAND_INJECTION_C", "FORMAT_STRING",
        "USE_AFTER_FREE", "DANGEROUS_FUNC_C",
        "SQL_INJECTION", "PATH_TRAVERSAL", "WEAK_CRYPTO",
    ],
    "HTML": [
        "HTML_XSS", "HTML_OPEN_REDIRECT", "HTML_UNSAFE_INCLUDE",
        "DOM_XSS", "SQL_INJECTION", "PATH_TRAVERSAL", "WEAK_CRYPTO",
    ],
    "CSS": [
        "CSS_INJECTION", "SQL_INJECTION", "PATH_TRAVERSAL", "WEAK_CRYPTO",
    ],
}


def detect_language(file_path: str) -> str:
    """Detect the canonical language name from a file path extension."""
    if not file_path:
        return "Unknown"
    lower = file_path.lower()
    for lang, exts in LANGUAGE_EXTENSIONS.items():
        if any(lower.endswith(ext) for ext in exts):
            return lang
    return "Unknown"


# ---------------------------------------------------------------------------
# Sensitive patterns per category
# ---------------------------------------------------------------------------

_SENSITIVE_PATTERNS: dict[str, list[str]] = {

    # ── JavaScript / TypeScript ────────────────────────────────────────────
    "PROTOTYPE_POLLUTION": [
        "__proto__", "constructor[", "prototype[",
        ".constructor.", "Object.setPrototypeOf(",
        "Object.assign({}",
    ],
    "DOM_XSS": [
        "innerHTML", "outerHTML", "document.write(",
        "document.writeln(", "insertAdjacentHTML(",
        ".srcdoc =", ".src =", "location.href =",
        "document.cookie", "window.location =",
    ],
    "CODE_INJECTION": [
        "eval(", "new Function(", "setTimeout(",
        "setInterval(", "Function.prototype.call",
        "Function.prototype.apply", "vm.runInNewContext(",
        "vm.runInThisContext(",
    ],
    "OPEN_REDIRECT": [
        "window.location.replace(", "window.location.assign(",
        "location.replace(", "location.assign(",
        "res.redirect(", "response.redirect(",
    ],
    "SSRF_JS": [
        "fetch(", "axios.get(", "axios.post(",
        "http.get(", "https.get(", "request(",
        "got(", "node-fetch",
    ],
    "CSRF_JS": [
        "csrf", "xsrf", "csrftoken", "x-csrf-token",
        "SameSite=None", "sameSite: \"none\"",
    ],
    "TEMPLATE_INJECTION_JS": [
        "_.template(", "Handlebars.compile(",
        "nunjucks.renderString(", "pug.render(",
        "ejs.render(", "mustache.render(",
    ],

    # ── Python ─────────────────────────────────────────────────────────────
    "COMMAND_INJECTION_PY": [
        "os.system(", "subprocess.call(", "subprocess.run(",
        "subprocess.Popen(", "os.popen(", "commands.getoutput(",
        "pty.spawn(", "popen2.", "shell=True",
    ],
    "CODE_INJECTION_PY": [
        "eval(", "compile(", "__import__(",
        "execfile(", "globals()[", "locals()[",
        " exec(", "\nexec(", "\texec(",
    ],
    "DESERIALIZATION_PY": [
        "pickle.loads(", "pickle.load(", "yaml.load(",
        "marshal.loads(", "jsonpickle.decode(",
        "shelve.open(", "dill.loads(",
    ],
    "TEMPLATE_INJECTION_PY": [
        "render_template_string(", "Environment(",
        "Template(", "from_string(", "Markup(",
    ],
    "SSRF_PY": [
        "requests.get(", "requests.post(", "urllib.request.urlopen(",
        "urllib2.urlopen(", "httplib.HTTPConnection(",
        "http.client.HTTPConnection(", "aiohttp.ClientSession(",
    ],
    "XXE_PY": [
        "xml.etree.ElementTree.parse(", "lxml.etree.parse(",
        "minidom.parseString(", "SAXParser(",
        "defusedxml", "etree.XMLParser(",
    ],

    # ── Java ───────────────────────────────────────────────────────────────
    "COMMAND_INJECTION_JAVA": [
        "Runtime.getRuntime().exec(", "new ProcessBuilder(",
        "ProcessBuilder(", ".exec(", "Runtime.exec(",
    ],
    "DESERIALIZATION_JAVA": [
        "ObjectInputStream(", ".readObject(", ".readUnshared(",
        "XStream.fromXML(", "SerializationUtils.deserialize(",
        "Yaml.load(", "new ObjectMapper(",
    ],
    "XXE_JAVA": [
        "DocumentBuilderFactory.newInstance(", "SAXParserFactory.newInstance(",
        "XMLReader", "XMLInputFactory", "TransformerFactory",
        "setFeature(\"http://xml.org/sax/features/external-general-entities\", true)",
        "SchemaFactory",
    ],
    "REFLECTION_JAVA": [
        "Class.forName(", ".getDeclaredMethod(", ".getMethod(",
        ".invoke(", ".newInstance(", "MethodHandles.lookup(",
    ],
    "SSRF_JAVA": [
        "new URL(", "HttpURLConnection", "URLConnection",
        "OkHttpClient", "CloseableHttpClient", "RestTemplate(",
        "WebClient.create(",
    ],

    # ── C / C++ ────────────────────────────────────────────────────────────
    "BUFFER_OVERFLOW": [
        "strcpy(", "strcat(", "sprintf(", "gets(",
        "scanf(\"%s", "memcpy(", "memmove(",
        "stpcpy(", "wcscpy(", "wcscat(",
    ],
    "COMMAND_INJECTION_C": [
        "system(", "popen(", "execve(", "execl(",
        "execlp(", "execvp(", "execle(", "execvpe(",
        "ShellExecute(", "CreateProcess(",
    ],
    "FORMAT_STRING": [
        "printf(", "fprintf(", "sprintf(", "snprintf(",
        "vprintf(", "vsprintf(", "syslog(", "err(",
    ],
    "USE_AFTER_FREE": [
        "free(", "delete ", "delete[] ",
    ],
    "DANGEROUS_FUNC_C": [
        "gets(", "mktemp(", "tmpnam(", "rand(",
        "srand(", "alloca(",
    ],

    # ── SQL (all languages) ────────────────────────────────────────────────
    "SQL_INJECTION": [
        "SELECT ", "INSERT INTO", "UPDATE ", "DELETE FROM",
        "WHERE ", "DROP TABLE", "UNION SELECT", "cursor.execute(",
        "executeQuery(", "executeUpdate(", "createStatement(",
        "raw(", "RawSQL(", "sqlite3.connect(",
        "mysql.connector.connect(",
    ],

    # ── Path traversal (all languages) ────────────────────────────────────
    "PATH_TRAVERSAL": [
        "../", "..\\", "%2e%2e%2f", "%2e%2e/",
        "os.path.join(", "open(request", "open(user",
        "new File(", "Paths.get(", "FileInputStream(",
        "fopen(", "ifstream(", "readFile(",
    ],

    # ── Weak crypto (all languages) ────────────────────────────────────────
    "WEAK_CRYPTO": [
        "md5(", "MD5(", "MessageDigest.getInstance(\"MD5\")",
        "sha1(", "SHA1(", "MessageDigest.getInstance(\"SHA-1\")",
        "DES", "RC4", "ECB", "createCipheriv(\"des",
        "createCipheriv(\"rc4", "hashlib.md5(",
        "hashlib.sha1(", "CryptoJS.MD5(",
    ],

    # ── HTML ───────────────────────────────────────────────────────────────
    "HTML_XSS": [
        "javascript:", "<script", "onerror=", "onload=",
        "onclick=", "onmouseover=", "onfocus=", "onblur=",
        "onkeypress=", "onkeydown=", "onchange=", "onsubmit=",
        "data:text/html", "vbscript:",
    ],
    "HTML_OPEN_REDIRECT": [
        "http-equiv=\"refresh\"", "http-equiv='refresh'",
        "window.location", "document.location",
    ],
    "HTML_UNSAFE_INCLUDE": [
        "<iframe src=", "<frame src=", "<embed src=",
        "<object data=", "src=\"data:", "src='data:",
    ],

    # ── CSS ────────────────────────────────────────────────────────────────
    "CSS_INJECTION": [
        "expression(", "behavior:", "url(javascript:",
        "url(vbscript:", "-moz-binding:", "src:url(",
        "content:url(", "@import url(\"http",
        "background:url(\"http",
    ],
}

# ---------------------------------------------------------------------------
# Loop / guard / mutation patterns
# ---------------------------------------------------------------------------

_LOOP_KEYWORDS: list = [
    "for ", "while ", ".forEach", ".map(",
    "foreach(", "for(", "while(",
]

_GUARD_KEYWORDS: list = [
    r"\bif\b", r"\bif\(", r"\belif\b",
    r"\bcontinue\b", r"\breturn\b", r"\bbreak\b",
    r"\bthrow\b", r"\bassert\b",
    r"\btry\b", r"\bcatch\b",
    r"#ifndef\b", r"#ifdef\b", r"#if\b",   # C/C++ preprocessor guards
    r"\bguard\b",                         # Swift / future-proofing
]

_MUTATION_PATTERNS: list = [
    r"\[.+?\]\s*=",        # bracket assignment
    r"\.\w+\s*=\s*",       # dot assignment
    r"\.set\(",            # Map.set / setter
    r"\.assign\(",         # Object.assign
    r"\.put\(",            # Java Map.put
    r"\.append\(",         # list append
    r"\.push\(",           # array push
    r"=\s*malloc\(",       # C heap alloc
    r"=\s*calloc\(",
    r"=\s*realloc\(",
]


# ---------------------------------------------------------------------------
# Core API
# ---------------------------------------------------------------------------


def normalize_line(line: str) -> str:
    """Canonicalise a source line for deterministic pattern matching.

    Steps:
    1. Strip leading/trailing whitespace; collapse internal runs to one space.
    2. Unify string delimiters: single-quotes and backticks → double-quotes.
    3. Unify JS equality operators: === → ==, !== → !=.
    """
    normalised = " ".join(line.strip().split())
    normalised = normalised.replace("'", '"').replace("`", '"')
    normalised = normalised.replace("===", "==").replace("!==", "!=")
    return normalised


def _detect_categories(normalised: str, language: str = None) -> list[str]:
    """Return all sensitive categories whose keywords appear in *normalised*.

    If language is given and recognized, only check patterns relevant to that language
    (and cross-language categories) to prevent false-positive collisions.
    """
    matched: list[str] = []
    lower = normalised.lower()

    allowed = set(LANGUAGE_CATEGORIES.get(language, CATEGORIES))

    for category, keywords in _SENSITIVE_PATTERNS.items():
        if category not in allowed:
            continue
        for kw in keywords:
            if kw in normalised or kw.lower() in lower:
                matched.append(category)
                break
    return matched


def classify_block(line: str, language: str = None) -> dict:
    """Classify a single diff code line.

    Returns
    -------
    dict
        kind        : LOOP_ENTRY | GUARD_CONDITION | MUTATION_SINK | STATEMENT
        raw         : original line text
        normalised  : canonicalised form
        categories  : sensitive categories (populated if line matches sensitive sink/guard)
        sinks       : all sensitive categories detected on this line
    """
    normalised = normalize_line(line)
    sinks = _detect_categories(normalised, language=language)

    result: dict = {
        "kind": "STATEMENT",
        "raw": line,
        "normalised": normalised,
        "categories": sinks,
        "sinks": sinks,
    }

    # ── LOOP_ENTRY ─────────────────────────────────────────────────────────
    for kw in _LOOP_KEYWORDS:
        if kw in normalised:
            result["kind"] = "LOOP_ENTRY"
            return result

    # ── GUARD_CONDITION ────────────────────────────────────────────────────
    is_guard = any(re.search(pat, normalised) for pat in _GUARD_KEYWORDS)
    if is_guard:
        result["kind"] = "GUARD_CONDITION"
        return result

    # ── MUTATION_SINK ──────────────────────────────────────────────────────
    for pat in _MUTATION_PATTERNS:
        if re.search(pat, normalised):
            result["kind"] = "MUTATION_SINK"
            return result

    return result


def parse_diff_blocks(raw_diff: str, fallback_file_path: str = "unknown") -> dict:
    """Parse a unified diff into classified file objects, hunks, and aggregated block lists.

    Handles single-file and multi-file unified diffs (git diffs), mapping each file
    to its language and preserving hunk-level context for multi-line guard detection.

    Returns
    -------
    dict
        removed_blocks : list[dict] (aggregated for backwards compatibility)
        added_blocks   : list[dict] (aggregated for backwards compatibility)
        files          : list[dict] (per-file structured diffs with hunks and detected language)
    """
    files: list[dict] = []
    current_file: dict | None = None
    current_hunk: dict | None = None

    def start_new_file(path: str):
        nonlocal current_file, current_hunk
        if current_hunk and current_file:
            current_file["hunks"].append(current_hunk)
            current_hunk = None
        if current_file:
            files.append(current_file)
        clean_path = path.strip()
        if clean_path.startswith("a/") or clean_path.startswith("b/"):
            clean_path = clean_path[2:]
        lang = detect_language(clean_path)
        current_file = {
            "file_path": clean_path,
            "language": lang,
            "hunks": [],
            "removed_blocks": [],
            "added_blocks": [],
        }

    def start_new_hunk(header: str):
        nonlocal current_file, current_hunk
        if not current_file:
            start_new_file(fallback_file_path)
        if current_hunk and current_file:
            current_file["hunks"].append(current_hunk)
        current_hunk = {
            "header": header,
            "removed_blocks": [],
            "added_blocks": [],
            "context_blocks": [],
            "hunk_sinks": set(),
        }

    all_removed: list[dict] = []
    all_added: list[dict] = []

    for raw_line in raw_diff.splitlines():
        # Git diff file headers
        if raw_line.startswith("diff --git"):
            parts = raw_line.split()
            if len(parts) >= 4 and parts[3].startswith("b/"):
                start_new_file(parts[3][2:])
            else:
                start_new_file(fallback_file_path)
            continue

        if raw_line.startswith("+++ "):
            path = raw_line[4:].strip()
            if path != "/dev/null":
                if path.startswith("b/"):
                    path = path[2:]
                if current_file and current_file["file_path"] in ("unknown", fallback_file_path):
                    current_file["file_path"] = path
                    current_file["language"] = detect_language(path)
                elif not current_file:
                    start_new_file(path)
            continue

        if raw_line.startswith("--- "):
            if not current_file:
                path = raw_line[4:].strip()
                if path.startswith("a/"):
                    path = path[2:]
                start_new_file(path)
            continue

        if raw_line.startswith("@@"):
            start_new_hunk(raw_line)
            continue

        # Skip other metadata
        if any(raw_line.startswith(p) for p in ("index ", "Binary", "new file", "deleted file")):
            continue

        lang = current_file["language"] if current_file else detect_language(fallback_file_path)

        # Removed line
        if raw_line.startswith("-"):
            if not current_hunk:
                start_new_hunk("@@")
            classified = classify_block(raw_line[1:], language=lang)
            all_removed.append(classified)
            if current_hunk:
                current_hunk["removed_blocks"].append(classified)
                for s in classified["sinks"]:
                    current_hunk["hunk_sinks"].add(s)
            if current_file:
                current_file["removed_blocks"].append(classified)

        # Added line
        elif raw_line.startswith("+"):
            if not current_hunk:
                start_new_hunk("@@")
            classified = classify_block(raw_line[1:], language=lang)
            all_added.append(classified)
            if current_hunk:
                current_hunk["added_blocks"].append(classified)
                for s in classified["sinks"]:
                    current_hunk["hunk_sinks"].add(s)
            if current_file:
                current_file["added_blocks"].append(classified)

        # Context line
        else:
            content = raw_line[1:] if raw_line.startswith(" ") else raw_line
            if content.strip():
                if not current_hunk:
                    start_new_hunk("@@")
                classified = classify_block(content, language=lang)
                if current_hunk:
                    current_hunk["context_blocks"].append(classified)
                    for s in classified["sinks"]:
                        current_hunk["hunk_sinks"].add(s)

    if current_hunk and current_file:
        current_file["hunks"].append(current_hunk)
    if current_file:
        files.append(current_file)

    if not files:
        files.append({
            "file_path": fallback_file_path,
            "language": detect_language(fallback_file_path),
            "hunks": [],
            "removed_blocks": all_removed,
            "added_blocks": all_added,
        })

    return {
        "removed_blocks": all_removed,
        "added_blocks": all_added,
        "files": files,
    }
