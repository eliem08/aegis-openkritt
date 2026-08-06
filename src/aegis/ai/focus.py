"""Per-language focus: the guards a framework already enforces, and the CWEs to hunt.

Two original heuristics that make each generation pass sharper for a cheap model:

* FRAMEWORK GUARDS — many false-negatives on mature code are the model not knowing the
  framework already enforces a check (Django's ORM parameterizes, Rails strong-params,
  Spring Security annotations). Telling the model which guards exist for the detected
  stack stops it flagging non-bugs AND tells it exactly what to check is *missing*.
* ANCHOR CWES — "find any bug" is weak; narrowing to the top weakness classes for the
  language/stack (PHP → access-control, SQLi, SSRF) focuses a small model on where the
  real bugs in that ecosystem live.

Deterministic, keyed off file extensions and cheap content signals. Original guidance.
"""

from __future__ import annotations

import re
from pathlib import Path

# ext -> (language label, framework-guard primer, anchor CWE classes)
_LANG = {
    ".php": ("PHP",
             "PHP web apps commonly use PDO/mysqli prepared statements (parameterized), a "
             "framework CSRF token, and per-controller capability/permission checks. Flag "
             "only where these guards are ABSENT on the path — e.g. string-interpolated "
             "SQL, an action with no permission check its siblings have.",
             ["access control / IDOR", "SQL injection", "SSRF", "auth bypass"]),
    ".py": ("Python",
            "Django/Flask: the ORM parameterizes queries and Django enforces CSRF and "
            "permission classes; Flask leaves authz to the developer. Flag raw SQL "
            "(cursor.execute with f-strings/%), views missing a permission/login guard "
            "their siblings have, and SSRF via requests/urllib on user URLs.",
            ["access control / IDOR", "SSRF", "deserialization", "SQL injection"]),
    ".rb": ("Ruby",
            "Rails: strong-params gate mass-assignment, ActiveRecord parameterizes, and "
            "before_action enforces auth. Flag find(params[:id]) without an ownership "
            "scope, actions missing a before_action their siblings have, and raw SQL.",
            ["access control / IDOR", "mass assignment", "SQL injection"]),
    ".js": ("JavaScript/Node",
            "Express/Nest: auth is middleware and ORMs parameterize. Flag a route missing "
            "the auth middleware its siblings mount, an object fetched by req id with no "
            "owner/tenant filter, unsanitized input to a query/exec/innerHTML, and SSRF.",
            ["access control / IDOR", "SSRF", "prototype pollution", "injection"]),
    ".ts": ("TypeScript/Node",
            "Nest/Express: guards/decorators enforce authz; ORMs parameterize. Flag a "
            "handler missing the @UseGuards/auth its siblings have, an unscoped id lookup, "
            "prototype pollution, and SSRF via fetch/axios on user-controlled URLs.",
            ["access control / IDOR", "SSRF", "prototype pollution", "injection"]),
    ".go": ("Go",
            "Go services: database/sql parameterizes with placeholders; authz is explicit. "
            "Flag fmt.Sprintf into a query, a handler missing the auth middleware its "
            "siblings have, SSRF via http.Get on user URLs, and path traversal on file ops.",
            ["access control", "SSRF", "SQL injection", "path traversal"]),
    ".java": ("Java",
              "Spring: @PreAuthorize/Security config enforce authz; JPA/PreparedStatement "
              "parameterize. Flag string-concatenated JDBC, an endpoint missing the "
              "@PreAuthorize its siblings have, SSRF, XXE, and insecure deserialization.",
              ["access control", "deserialization", "SSRF", "SQL injection"]),
    ".rs": ("Rust",
            "Rust: memory-safe by default; focus on logic. Flag `unsafe` blocks with "
            "attacker-influenced length/index math, auth/ownership gaps in handlers, and "
            "SSRF on user URLs.",
            ["access control", "unsafe memory math", "SSRF"]),
    ".sol": ("Solidity",
             "Contracts: onlyOwner/role modifiers and checks-effects-interactions guard "
             "against unauthorized calls and reentrancy. Flag a state-changing function "
             "missing the access modifier its siblings have, external calls before state "
             "updates (reentrancy), unchecked arithmetic on value, and signature/replay "
             "gaps.",
             ["access control", "reentrancy", "arithmetic/accounting", "signature/replay"]),
}


def language_of(path: str) -> str:
    lang, _, _ = _LANG.get(Path(path).suffix.lower(), ("", "", []))
    return lang


def focus_text(path: str) -> str:
    """The framework-guard primer + anchor CWEs for a file's language, as a prompt block."""
    lang, guards, cwes = _LANG.get(Path(path).suffix.lower(), ("", "", []))
    if not lang:
        return ""
    return ("\n## Stack focus (" + lang + ")\n"
            "Framework guards that usually already exist here: " + guards + "\n"
            "Anchor the hunt on this stack's highest-yield classes: " + "; ".join(cwes) + ".")


# Cheap content signals -> a more specific framework note, layered on top of the language.
_FRAMEWORK_SIGNS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"from django|django\.", re.I),
     "Django detected: CSRF + permission_classes are enforced by default; the real bugs "
     "are missing object-level ownership checks and raw() queries."),
    (re.compile(r"@RestController|@PreAuthorize|springframework", re.I),
     "Spring detected: check for endpoints lacking the @PreAuthorize their siblings carry."),
    (re.compile(r"express\(\)|require\('express'|from 'express'", re.I),
     "Express detected: auth is middleware — look for a route that omits the auth "
     "middleware mounted on its sibling routes."),
    (re.compile(r"openzeppelin|Ownable|AccessControl", re.I),
     "OpenZeppelin detected: functions should carry onlyOwner/onlyRole — flag any "
     "state-changer that lacks the modifier its siblings use."),
    (re.compile(r"\$_FILES|move_uploaded_file|multipart/form-data|MultipartFile|"
                r"multer|formidable|busboy", re.I),
     "FILE UPLOAD handler detected: this is a CWE-434 surface. Check the validation is not "
     "bypassable — a client-controlled MIME/Content-Type ($_FILES['type']) or extension is "
     "NOT trustworthy; getimagesize() alone is defeated by a polyglot. A real bug is: no "
     "server-side extension allow-list, the file stored under its original name, and/or the "
     "upload dir web-served (so rev.php / double-extension / %00 / .htaccess -> code exec). "
     "Trace: is the destination extension fixed to a validated safe set, or attacker-derived?"),
)


def framework_note(content: str) -> str:
    for pattern, note in _FRAMEWORK_SIGNS:
        if pattern.search(content):
            return "\n" + note
    return ""
