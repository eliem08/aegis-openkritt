"""Registry of external security skills Aegis can orchestrate, and an arm's-length invoker.

These are AI-agent *skills* (Claude Code / Cursor / Copilot) published by security teams.
Aegis does not vendor their source: MIT skills may be installed and reused with
attribution, and skills with no license (all-rights-reserved by default) are only ever
*invoked* where the operator has installed them — never copied. This module is original
metadata (names, sources, observed licenses, lane mapping) plus an invoker that drives
an installed skill through a caller-supplied runner, exactly like the open-kritt bridge.

The point: Aegis knows what each skill is for, maps it to the right lane, and can drive
the installed ones as part of a hunt — powerful, and clean on licensing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class License(str, Enum):
    MIT = "MIT"                 # may install + reuse with attribution
    UNKNOWN = "unknown"         # no license file observed => all rights reserved: INVOKE ONLY
    OTHER = "other"

    @property
    def may_vendor(self) -> bool:
        return self is License.MIT


class Lane(str, Enum):
    CONTRACT = "contract"       # Solidity / smart-contract audit
    FUZZING = "fuzzing"         # fuzz-suite generation
    CODE = "code"               # general source security review
    STATIC = "static"           # static-analysis / rule authoring
    SUPPLY_CHAIN = "supply_chain"
    THREAT_MODEL = "threat_model"
    VALIDATION = "validation"   # adversarial / vulnerability validation


@dataclass(frozen=True)
class Skill:
    name: str
    source: str                 # owner/repo[/path]
    license: License
    lanes: tuple[Lane, ...]
    description: str
    invoke_hint: str = ""       # how the operator installs/runs it in their agent

    @property
    def invoke_only(self) -> bool:
        """No-license skills must be invoked where installed, never copied into Aegis."""
        return not self.license.may_vendor


# Curated from the repos the operator provided (2026-08). Descriptions/mapping are
# original; this is metadata, not the skills' content.
SKILLS: tuple[Skill, ...] = (
    # --- Pashov Audit Group (MIT) — the smart-contract prize ---
    Skill("solidity-auditor", "pashov/skills/solidity-auditor", License.MIT,
          (Lane.CONTRACT, Lane.VALIDATION),
          "Multi-agent Solidity security audit (attacker-framing, many parallel agents).",
          "Install pashov/skills; run solidity-auditor on the contract source."),
    Skill("x-ray", "pashov/skills/x-ray", License.MIT, (Lane.CONTRACT, Lane.THREAT_MODEL),
          "Pre-audit scan: threat model, invariants, entry points, git analysis.",
          "Install pashov/skills; run x-ray on the codebase."),
    Skill("fizz", "pashov/skills/fizz", License.MIT, (Lane.CONTRACT, Lane.FUZZING),
          "Generate a full Echidna/Medusa fuzz suite for a Foundry/Hardhat project.",
          "Install pashov/skills; run fizz on the codebase, then run echidna/medusa."),
    # --- Cloudflare (MIT) — the parallel-agent pipeline ---
    Skill("security-audit-skill", "cloudflare/security-audit-skill", License.MIT,
          (Lane.CODE, Lane.VALIDATION),
          "Six-phase parallel-agent audit: recon, hunt, validate, report, structured "
          "output, independent verification.",
          "Install cloudflare/security-audit-skill; run it on the target repo."),
    # --- github/awesome-copilot (MIT) ---
    Skill("security-review", "github/awesome-copilot/skills/security-review", License.MIT,
          (Lane.CODE,), "General security code-review skill.",
          "Copilot skill; invoke security-review on the diff/repo."),
    # --- Trail of Bits (license not observed -> invoke only) ---
    Skill("static-analysis", "trailofbits/skills/plugins/static-analysis", License.UNKNOWN,
          (Lane.STATIC, Lane.CODE), "Apply static-analysis techniques to the codebase."),
    Skill("constant-time-analysis", "trailofbits/skills/plugins/constant-time-analysis",
          License.UNKNOWN, (Lane.CODE,), "Find timing side-channels in crypto code."),
    Skill("variant-analysis", "trailofbits/skills/plugins/variant-analysis", License.UNKNOWN,
          (Lane.STATIC, Lane.CODE), "Find variants of a known bug across the codebase."),
    Skill("semgrep-rule-creator", "trailofbits/skills/plugins/semgrep-rule-creator",
          License.UNKNOWN, (Lane.STATIC,), "Author Semgrep static-analysis rules."),
    Skill("property-based-testing", "trailofbits/skills/plugins/property-based-testing",
          License.UNKNOWN, (Lane.FUZZING,), "Implement property-based tests."),
    Skill("building-secure-contracts", "trailofbits/skills/plugins/building-secure-contracts",
          License.UNKNOWN, (Lane.CONTRACT,), "Guidance for secure smart-contract development."),
    Skill("differential-review", "trailofbits/skills/plugins/differential-review",
          License.UNKNOWN, (Lane.CODE,), "Security review of a diff / code change."),
    Skill("insecure-defaults", "trailofbits/skills/plugins/insecure-defaults", License.UNKNOWN,
          (Lane.CODE,), "Identify insecure default configurations."),
    Skill("supply-chain-risk-auditor", "trailofbits/skills/plugins/supply-chain-risk-auditor",
          License.UNKNOWN, (Lane.SUPPLY_CHAIN,), "Assess software supply-chain risk."),
    Skill("zeroize-audit", "trailofbits/skills/plugins/zeroize-audit", License.UNKNOWN,
          (Lane.CODE,), "Audit proper zeroization of secrets in memory."),
    Skill("rust-review", "trailofbits/skills/plugins/rust-review", License.UNKNOWN,
          (Lane.CODE,), "Security-focused Rust code review."),
    Skill("c-review", "trailofbits/skills/plugins/c-review", License.UNKNOWN,
          (Lane.CODE,), "Security-focused C code review."),
    Skill("mutation-testing", "trailofbits/skills/plugins/mutation-testing", License.UNKNOWN,
          (Lane.FUZZING,), "Assess test resilience via mutation testing."),
    # --- Factory-AI (no license -> invoke only) ---
    Skill("security-review", "Factory-AI/skills/skills/security-review", License.UNKNOWN,
          (Lane.CODE,), "Security assessment of code."),
    Skill("threat-model-generation", "Factory-AI/skills/skills/threat-model-generation",
          License.UNKNOWN, (Lane.THREAT_MODEL,), "Generate a threat model for a system."),
    Skill("vulnerability-validation", "Factory-AI/skills/skills/vulnerability-validation",
          License.UNKNOWN, (Lane.VALIDATION,), "Validate/confirm identified vulnerabilities."),
    Skill("commit-security-scan", "Factory-AI/skills/skills/commit-security-scan",
          License.UNKNOWN, (Lane.CODE,), "Scan a commit for security issues."),
    # --- Sentry (no license -> invoke only) ---
    Skill("find-bugs", "getsentry/skills/skills/find-bugs", License.UNKNOWN, (Lane.CODE,),
          "Bug detection across the codebase."),
    Skill("django-access-review", "getsentry/skills/skills/django-access-review",
          License.UNKNOWN, (Lane.CODE,), "Django access-control / authorization review."),
    Skill("gha-security-review", "getsentry/skills/skills/gha-security-review", License.UNKNOWN,
          (Lane.CODE, Lane.SUPPLY_CHAIN), "GitHub Actions workflow security review."),
    Skill("sentry-security-review", "getsentry/skills/skills/security-review", License.UNKNOWN,
          (Lane.CODE,), "General security code review."),
)


def all_skills() -> tuple[Skill, ...]:
    return SKILLS


def for_lane(lane: Lane) -> list[Skill]:
    return [s for s in SKILLS if lane in s.lanes]


def vendorable() -> list[Skill]:
    """Skills Aegis may install/reuse (MIT, with attribution)."""
    return [s for s in SKILLS if s.license.may_vendor]


def invoke_only() -> list[Skill]:
    """Skills Aegis may only invoke where installed (no license => all rights reserved)."""
    return [s for s in SKILLS if s.invoke_only]


def recommend(target_kind: str) -> list[Skill]:
    """Skills to run for a target: contract targets get the Solidity/fuzz set, else the
    general code-review set. MIT-first so vendorable options surface before invoke-only."""
    lanes = ((Lane.CONTRACT, Lane.FUZZING, Lane.VALIDATION) if target_kind == "contract"
             else (Lane.CODE, Lane.STATIC, Lane.VALIDATION))
    picked = [s for s in SKILLS if any(l in s.lanes for l in lanes)]
    picked.sort(key=lambda s: (not s.license.may_vendor, s.name))
    return picked


@dataclass
class SkillRun:
    skill: str
    ok: bool
    output: str = ""
    error: str = ""


class SkillInvoker:
    """Drive installed skills through a caller-supplied runner — never copies a skill.

    ``runner(skill, target) -> (ok, output)`` is the operator's own bridge to their
    agent (e.g. the `claude` CLI with the skill installed). Aegis picks which skills to
    run and collects results; it does not embed the skills."""

    def __init__(self, runner, *, events: list | None = None) -> None:
        self._runner = runner
        self.events = events if events is not None else []

    def run(self, skills: list[Skill], target: str) -> list[SkillRun]:
        results: list[SkillRun] = []
        for skill in skills:
            try:
                ok, output = self._runner(skill, target)
                results.append(SkillRun(skill=skill.name, ok=bool(ok), output=str(output)[:8000]))
            except Exception as exc:
                results.append(SkillRun(skill=skill.name, ok=False,
                                        error=f"{type(exc).__name__}: {exc}"[:200]))
            self.events.append(results[-1])
        return results


def make_shell_runner(cmd_template: str, *, timeout: int = 1800, run=None):
    """A runner that invokes an INSTALLED skill via the operator's own command.

    ``cmd_template`` is the operator's command with ``{source}`` (the skill's owner/repo/
    path) and ``{target}`` placeholders — e.g. their `claude` CLI wired to run an
    installed skill. Aegis substitutes and runs it; it never embeds the skill's content.
    ``run`` is injectable for tests (defaults to subprocess). Returns (ok, output)."""
    import shlex

    def _default_run(argv, timeout):
        import subprocess
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode == 0, (p.stdout or "") + (("\n" + p.stderr) if p.stderr else "")

    runner_impl = run or _default_run

    def runner(skill, target):
        cmd = cmd_template.format(source=skill.source, target=target, name=skill.name)
        return runner_impl(shlex.split(cmd), timeout)

    return runner
