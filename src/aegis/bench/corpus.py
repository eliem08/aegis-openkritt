"""Aegis-Bench corpus — a deterministic, in-repo regression benchmark.

Each :class:`Case` is a labeled *pair*: a VULNERABLE snippet the detectors should flag, and a
CLEAN snippet (negative control) they should NOT. The benchmark writes each snippet to a temp
file, runs the real installed scanners over it (via the tool bridge), and scores detection —
so precision/recall are *measured*, never asserted. Cases target Aegis's own bundled Semgrep
rules (JWT / upload / PHP / Ruby / web-taint) so the benchmark validates the detectors we ship.

`match` is a lowercase substring checked against a finding's CWE + message; a vulnerable case
counts as detected only when a finding in its file matches, which keeps the metric honest
(any-finding would over-count). Snippets are intentionally minimal and self-contained.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Case:
    id: str
    cwe: str
    filename: str          # extension drives language selection
    vulnerable: str        # should be flagged
    clean: str             # negative control — should NOT be flagged
    match: str             # lowercase substring expected in the finding's cwe/message


CASES: tuple[Case, ...] = (
    Case("php-sqli-wpdb", "CWE-89", "sqli.php",
         "<?php $wpdb->query(\"SELECT * FROM u WHERE id=\" . $_GET['id']);",
         "<?php $wpdb->query($wpdb->prepare(\"SELECT * FROM u WHERE id=%d\", $_GET['id']));",
         "cwe-89"),
    Case("php-xss-echo", "CWE-79", "xss.php",
         "<?php echo $_GET['name'];",
         "<?php echo esc_html($_GET['name']);",
         "cwe-79"),
    Case("php-lfi-include", "CWE-98", "lfi.php",
         "<?php include $_GET['page'];",
         "<?php include __DIR__ . '/templates/home.php';",
         "cwe-98"),
    Case("php-cmdi-system", "CWE-78", "cmd.php",
         "<?php system($_GET['cmd']);",
         "<?php system('ls -la /var/www');",
         "cwe-78"),
    Case("php-unserialize", "CWE-502", "deser.php",
         "<?php $o = unserialize($_POST['data']);",
         "<?php $o = json_decode($_POST['data'], true);",
         "cwe-502"),
    Case("php-upload-original-name", "CWE-434", "upload.php",
         "<?php move_uploaded_file($_FILES['f']['tmp_name'], $dir . $_FILES['f']['name']);",
         "<?php move_uploaded_file($_FILES['f']['tmp_name'], $dir . '/' . $safe_id . '.png');",
         "cwe-434"),
    Case("php-hardcoded-jwt-secret", "CWE-798", "secret.php",
         "<?php $jwt_secret = \"s3cr3tK3yV4lue9x21Z\";",
         "<?php $jwt_secret = getenv('JWT_SECRET');",
         "cwe-798"),
    Case("py-jwt-verify-false", "CWE-347", "auth.py",
         "import jwt\nd = jwt.decode(token, verify=False)\n",
         "import jwt\nd = jwt.decode(token, key, algorithms=['RS256'])\n",
         "cwe-347"),
    Case("py-jwt-alg-none", "CWE-347", "alg.py",
         "import jwt\nd = jwt.decode(token, key, algorithms=['none'])\n",
         "import jwt\nd = jwt.decode(token, key, algorithms=['RS256'])\n",
         "cwe-347"),
    Case("js-jwt-verify-none", "CWE-347", "verify.js",
         "const jwt = require('jsonwebtoken');\njwt.verify(token, key, {algorithms: ['none']});\n",
         "const jwt = require('jsonwebtoken');\njwt.verify(token, key, {algorithms: ['RS256']});\n",
         "cwe-347"),
)


def languages() -> set[str]:
    return {c.filename.rsplit(".", 1)[-1] for c in CASES}
