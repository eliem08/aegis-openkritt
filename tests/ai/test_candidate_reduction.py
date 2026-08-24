"""Deterministic candidate-reduction funnel: noise is suppressed with reasons, real classes
survive, cross-engine corroboration boosts, and families cluster. No scanners required."""

from __future__ import annotations

from aegis.ai.candidate_reduction import path_class, reduce_candidates


def row(tool, rule, path, *, line=10, sev="medium", conf=0.6, cwe=None, summary=""):
    """Build a canonical Aegis scanner row (matches tool_registry._row output)."""
    return {
        "json_answer": {"vulnerability_type": cwe or rule, "file_path": path, "line": line,
                        "summary": summary, "explanation": ""},
        "severity": sev, "source": f"aegis:tool:{tool}", "validation_status": "unverified",
        "confidence": conf, "scanner_metadata": {"rule_id": rule, "cwe": cwe},
    }


def test_path_class():
    assert path_class("src/app/db.py") == "source"
    assert path_class("tests/test_db.py") == "test"
    assert path_class("src/aegis/bench/corpus.py") == "bench"
    assert path_class("examples/demo.php") == "example"
    assert path_class("node_modules/x/index.js") == "vendor"
    assert path_class("static/app.min.js") == "generated"
    assert path_class("docs/guide.md") == "docs"
    assert path_class("deploy/docker-compose.yml") == "deploy"
    assert path_class("config/settings.yaml") == "config"
    # regression (self-hunt 2026-08-24): Dolibarr dev/tools/*.php taint findings from
    # whole-repo scanners must land in a non-product class so the funnel suppresses them.
    assert path_class("dev/tools/github_pr_reviewers_webhook.php") == "build"
    assert path_class("dev/setup_helper.php") == "build"


def test_hygiene_rules_are_suppressed_with_reasons():
    rows = [row("bandit", r, "src/app/x.py") for r in ("B101", "B110", "B112", "B404", "B603")]
    red = reduce_candidates(rows)
    assert red.survivors == []
    assert len(red.suppressed) == 5
    assert all(c.reason.startswith("low-value-rule") for c in red.suppressed)


def test_dependency_advisories_are_suppressed_so_real_findings_surface():
    """Known CVE/GHSA advisories in third-party deps otherwise top the survivor list (osv+trivy+
    grype corroborate) and bury the target's own bugs. They must drop to `suppressed`."""
    rows = [
        row("osv-scanner", "GHSA-pjjw-qhg8-p2p9", "requirements.txt", cwe="GHSA-pjjw-qhg8-p2p9"),
        row("grype", "CVE-2024-30251", "requirements.txt", cwe="CVE-2024-30251"),
        row("trivy", "GHSA-2fqr-mr3j-6wp8", "yarn.lock", cwe="GHSA-2fqr-mr3j-6wp8"),
        # the target's OWN code bug must still survive
        row("semgrep", "aegis-ruby-unsafe-render-inline", "app/controllers/x.rb",
            cwe="CWE-1336", conf=0.9),
    ]
    red = reduce_candidates(rows)
    dep = [c for c in red.suppressed if c.reason.startswith("dependency-advisory")]
    assert len(dep) == 3
    assert red.funnel.get("drop_dependency_advisory") == 3
    assert [c.cwe for c in red.survivors] == ["CWE-1336"]      # real finding surfaces alone


def test_real_cwe_ids_are_not_mistaken_for_advisories():
    """A CWE id (the target's own bug class) must never be filtered as a dependency advisory."""
    red = reduce_candidates([
        row("semgrep", "aegis-php-sqli", "src/app.php", cwe="CWE-89", conf=0.9),
    ])
    assert [c.cwe for c in red.survivors] == ["CWE-89"]
    assert red.funnel.get("drop_dependency_advisory", 0) == 0


def test_checkov_docker_prefix_family_collapses():
    # on a Dockerfile these are suppressed by the non-product (deploy) path; on a non-deploy
    # path the CKV_DOCKER_* rule prefix still suppresses them.
    red = reduce_candidates([row("checkov", "CKV_DOCKER_2", "Dockerfile"),
                             row("checkov", "CKV_DOCKER_7", "Dockerfile")])
    assert red.survivors == []
    rule_hit = reduce_candidates([row("checkov", "CKV_DOCKER_2", "src/app/thing.py")])
    assert rule_hit.survivors == []
    assert "low-value-rule:CKV_DOCKER_*" in rule_hit.suppressed[0].reason


def test_placeholder_and_bench_secrets_suppressed_but_real_source_secret_survives():
    rows = [
        row("detect-secrets", "Secret", ".env.example", cwe="CWE-798"),
        row("detect-secrets", "Secret", "src/aegis/bench/corpus.py", cwe="CWE-798"),
        row("detect-secrets", "Secret", "deploy/docker-compose.yml", cwe="CWE-798"),
        row("detect-secrets", "Secret", "src/app/settings.py", cwe="CWE-798",
            sev="high", conf=0.9, summary="AWS key literal"),
    ]
    red = reduce_candidates(rows)
    kept = [c.path for c in red.survivors]
    assert kept == ["src/app/settings.py"]
    assert len(red.suppressed) == 3


def test_real_injection_in_nonproduct_path_is_suppressed():
    # a real-looking SQLi, but it lives in the test tree -> not the product's attack surface
    red = reduce_candidates([row("semgrep", "sqli", "tests/test_x.py", cwe="CWE-89", sev="high")])
    assert red.survivors == []
    assert red.suppressed[0].reason == "non-product-path:test"


def test_real_candidates_survive():
    rows = [
        row("semgrep", "sqli", "src/app/db.py", cwe="CWE-89", sev="high", conf=0.9),
        row("semgrep", "deser", "src/app/handler.py", cwe="CWE-502", sev="critical", conf=0.8),
    ]
    red = reduce_candidates(rows)
    assert {c.cwe for c in red.survivors} == {"CWE-89", "CWE-502"}
    # critical outranks high
    assert red.survivors[0].cwe == "CWE-502"


def test_cross_engine_corroboration_boosts_score():
    solo = reduce_candidates([row("semgrep", "sqli", "src/a.py", cwe="CWE-89", line=10)])
    duo = reduce_candidates([
        row("semgrep", "sqli", "src/a.py", cwe="CWE-89", line=10),
        row("bandit", "B608", "src/a.py", cwe="CWE-89", line=11),   # same 5-line bucket
    ])
    assert duo.survivors[0].corroborators == 2
    assert solo.survivors[0].corroborators == 1
    assert duo.survivors[0].score > solo.survivors[0].score


def test_broadened_nonproduct_paths():
    # patterns the fleet sweep surfaced as noise
    assert path_class("Example_Submissions/x/certora_build.py") == "example"
    assert path_class("blend/backstop/certora_build.py") == "build"
    assert path_class("protocol-deploy/deploy/__init__.py") in ("build", "deploy")
    assert path_class("scripts/deploy.py") == "build"
    assert path_class("x/discord-export/foo_Files/lottie.min-99657.js") == "generated"
    assert path_class("lib/forge-std/Test.sol") == "vendor"


def test_brakeman_is_weak_single_engine_but_corroborated_survives():
    # brakeman-only SQLi on mature Rails is high-FP -> suppressed alone
    solo = reduce_candidates([row("brakeman", "SQL Injection", "app/models/user.rb",
                                  cwe="CWE-89", sev="high", conf=0.6)])
    assert solo.survivors == []
    assert "brakeman" in solo.suppressed[0].reason
    # brakeman + semgrep agreeing at the same locus -> survives (real corroboration)
    duo = reduce_candidates([
        row("brakeman", "SQL Injection", "app/models/user.rb", line=10, cwe="CWE-89", conf=0.6),
        row("semgrep", "tainted-sql", "app/models/user.rb", line=11, cwe="CWE-89", conf=0.7)])
    assert len(duo.survivors) == 2


def test_njsscan_and_shell_subprocess_are_weak_single_engine():
    # njsscan node_insecure_random_generator on Math.random in real source -> suppressed
    r1 = reduce_candidates([row("njsscan", "node_insecure_random_generator", "src/web/captcha.js",
                                sev="medium", conf=0.0)])
    assert r1.survivors == []
    assert "njsscan" in r1.suppressed[0].reason
    # bandit B602 (subprocess shell=True) alone in real source -> suppressed (needs corroboration)
    r2 = reduce_candidates([row("bandit", "B602", "src/app/run.py", sev="high", conf=0.0)])
    assert r2.survivors == []
    assert "B602" in r2.suppressed[0].reason
    # B602 in a build/deploy script -> suppressed as non-product path
    r3 = reduce_candidates([row("bandit", "B602", "certora/certora_build.py", sev="high")])
    assert r3.survivors == []
    assert r3.suppressed[0].reason.startswith("non-product-path")


def test_weak_single_engine_needs_corroboration():
    # bandit B608 (string SQL) alone with modest confidence -> suppressed, needs corroboration
    solo = reduce_candidates([row("bandit", "B608", "src/a.py", cwe="CWE-89", conf=0.6)])
    assert solo.survivors == []
    assert solo.suppressed[0].reason.startswith("weak-single-engine:B608")
    # same B608 corroborated by a taint engine at the same locus -> survives
    duo = reduce_candidates([
        row("bandit", "B608", "src/a.py", line=10, cwe="CWE-89", conf=0.6),
        row("semgrep", "tainted-sql", "src/a.py", line=11, cwe="CWE-89", conf=0.7),
    ])
    assert len(duo.survivors) == 2
    # a highly confident single engine still survives alone
    strong = reduce_candidates([row("bandit", "B608", "src/a.py", cwe="CWE-89", conf=0.9)])
    assert len(strong.survivors) == 1


def test_unverified_detect_secrets_in_source_needs_corroboration():
    weak = reduce_candidates([row("detect-secrets", "Secret", "src/app/x.py",
                                  cwe="CWE-798", conf=0.68)])
    assert weak.survivors == []
    assert "detect-secrets-unverified" in weak.suppressed[0].reason
    # corroborated by gitleaks (rule engine) at the same locus -> survives
    duo = reduce_candidates([
        row("detect-secrets", "Secret", "src/app/x.py", line=10, cwe="CWE-798", conf=0.68),
        row("gitleaks", "aws-key", "src/app/x.py", line=10, cwe="CWE-798", conf=0.85),
    ])
    assert len(duo.survivors) == 2


def test_exact_duplicates_collapse():
    r = row("bandit", "B608", "src/a.py", line=10)
    red = reduce_candidates([r, dict(r)])
    assert red.funnel["deduped"] == 1


def test_funnel_reduces_noise_to_a_handful():
    # 20 noise rows + 2 real -> survivors should be exactly the 2 real
    noise = ([row("bandit", "B110", f"src/mod{i}.py", line=i) for i in range(8)]
             + [row("bandit", "B603", f"src/run{i}.py", line=i) for i in range(6)]
             + [row("detect-secrets", "Secret", ".env.example", line=i, cwe="CWE-798")
                for i in range(4)]
             + [row("checkov", "CKV_DOCKER_2", "Dockerfile", line=i) for i in range(2)])
    real = [row("semgrep", "sqli", "src/app/db.py", cwe="CWE-89", sev="high", conf=0.9),
            row("semgrep", "cmdi", "src/app/exec.py", cwe="CWE-78", sev="high", conf=0.85)]
    red = reduce_candidates(noise + real)
    assert red.funnel["raw"] == 22
    assert red.funnel["survivors"] == 2
    assert len(red.families) == 2
    assert {c.cwe for c in red.survivors} == {"CWE-89", "CWE-78"}
