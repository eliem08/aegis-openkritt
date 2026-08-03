"""HackerOne program → open·kritt scan → review console (code-repo programs).

The connective flow for programs whose scope is **source code**: read a program's
authorized scope from HackerOne (read-only), pick the in-scope repositories, launch
an open·kritt scan on each, and merge the findings into Aegis's review console.

Boundaries kept, on purpose:

* **Authorization is honored.** A repo is only scanned if it is in a *submittable*
  scope of a program whose policy permits automated + AI tooling
  (``ProgramRules.automation_allowed`` / ``ai_allowed``). If the program forbids
  either, nothing is launched and the reason is reported.
* **Human-supervised.** This launches scans on authorized targets and surfaces
  their findings as unverified candidates. It does not exploit, and it never
  auto-submits anything back to HackerOne.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from aegis.ingest.hackerone import map_program
from aegis.report import build_console

from .openkritt import ingest_openkritt_findings

_REPO_RE = re.compile(r"(?:github\.com|gitlab\.com|bitbucket\.org)[/:]([^/\s]+/[^/\s#?]+)", re.I)
_BARE_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


@dataclass(frozen=True)
class RepoTarget:
    repo_full: str            # "org/repo" — what open·kritt's repo_full expects
    identifier: str           # the original scope identifier
    asset_type: str = ""


@dataclass
class ScanTemplate:
    """The non-target scan settings open·kritt requires; discover or pass explicitly."""
    workflow_id: str
    post_script_id: str
    severity_ranker: str                       # the ranker's markdown content
    model: str                                 # a model id from the connected account
    harness: str = "claude-code"               # matches a connected Claude login
    model_provider: str = "claude"
    repo_scope: str = "full repository"
    launch_policy: str = "queue"               # don't preempt a running scan
    agent_skill_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScanLaunch:
    repo: RepoTarget
    scan_id: str | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.scan_id is not None


@dataclass
class RepoScope:
    repos: list[RepoTarget] = field(default_factory=list)
    gated: bool = False
    reason: str = ""


@dataclass
class PipelineResult:
    handle: str
    program_name: str = ""
    repos: list[RepoTarget] = field(default_factory=list)
    launches: list[ScanLaunch] = field(default_factory=list)
    gated: bool = False
    reason: str = ""

    @property
    def scan_ids(self) -> list[str]:
        return [l.scan_id for l in self.launches if l.scan_id]


# --- scope -> repos ---------------------------------------------------------

def repos_in_scope(rules) -> RepoScope:
    """In-scope repositories, gated by the program's automation/AI policy."""
    if not rules.automation_allowed:
        return RepoScope(gated=True, reason="program policy prohibits automated tooling")
    if not rules.ai_allowed:
        return RepoScope(gated=True, reason="program policy prohibits AI tooling")

    repos: list[RepoTarget] = []
    seen: set[str] = set()
    for asset in rules.source_code_assets():
        repo_full = _to_repo_full(asset.identifier)
        if repo_full and repo_full.lower() not in seen:
            seen.add(repo_full.lower())
            repos.append(RepoTarget(repo_full=repo_full, identifier=asset.identifier,
                                    asset_type=asset.asset_type.value))
    if not repos:
        return RepoScope(reason="no in-scope source-code repositories found")
    return RepoScope(repos=repos)


def _to_repo_full(identifier: str) -> str | None:
    s = (identifier or "").strip()
    m = _REPO_RE.search(s)
    if m:
        return m.group(1).removesuffix(".git")
    if _BARE_RE.match(s):                        # already "org/repo"
        return s.removesuffix(".git")
    return None


# --- discover the scan template from a live backend -------------------------

def discover_scan_template(client, *, model: str, harness: str = "claude-code",
                           model_provider: str = "claude", **overrides) -> ScanTemplate:
    """Fill workflow / post-script / severity-ranker from the backend's configured
    resources (open·kritt ships defaults). Raises if a required resource is absent."""
    workflows = client.list_workflows()
    post_scripts = client.list_post_scripts()
    rankers = client.list_severity_rankers()
    if not workflows:
        raise PipelineError("open·kritt has no workflow configured")
    if not post_scripts:
        raise PipelineError("open·kritt has no post-script configured")
    if not rankers:
        raise PipelineError("open·kritt has no severity ranker configured")
    return ScanTemplate(
        workflow_id=str(_first_id(workflows)),
        post_script_id=str(_first_id(post_scripts)),
        severity_ranker=str(rankers[0].get("content") or rankers[0].get("markdown") or ""),
        model=model, harness=harness, model_provider=model_provider, **overrides)


# --- launch scans -----------------------------------------------------------

def build_scan_payload(repo: RepoTarget, t: ScanTemplate) -> dict:
    return {
        "workflowId": t.workflow_id,
        "postScriptId": t.post_script_id,
        "repo_kind": "remote",
        "repo_full": repo.repo_full,
        "repo_scope": t.repo_scope,
        "model": t.model,
        "harness": t.harness,
        "model_provider": t.model_provider,
        "severity_ranker": t.severity_ranker,
        "launchPolicy": t.launch_policy,
        "agentSkillIds": list(t.agent_skill_ids),
    }


def launch_repo_scans(client, repos, template: ScanTemplate) -> list[ScanLaunch]:
    launches: list[ScanLaunch] = []
    for repo in repos:
        try:
            resp = client.create_scan(build_scan_payload(repo, template))
            scan_id = str(resp.get("id") or resp.get("scanId") or "")
            launches.append(ScanLaunch(repo, scan_id=scan_id or None,
                                       error=None if scan_id else "no scan id in response"))
        except Exception as exc:                 # network / validation error -> report, keep going
            launches.append(ScanLaunch(repo, error=str(exc)))
    return launches


# --- collect findings into one console --------------------------------------

def console_for_scans(client, scan_ids, *, calibration=None, **ingest_kwargs) -> dict:
    """Merge findings from several open·kritt scans into one review-console model."""
    candidates = []
    for scan_id in scan_ids:
        candidates.extend(client.import_candidates(scan_id, **ingest_kwargs))
    model = build_console(candidates, calibration=calibration)
    model["scan_ids"] = [str(s) for s in scan_ids]
    return model


# --- orchestration ----------------------------------------------------------

def run_repo_pipeline(h1_client, ok_client, handle: str, *, model: str,
                      template: ScanTemplate | None = None, launch: bool = True,
                      max_repos: int | None = None) -> PipelineResult:
    """Discover a program's repos and (optionally) launch an open·kritt scan on each.

    ``launch=False`` plans only — it returns the in-scope repos without touching
    open·kritt (used by the hunter's dry-run). ``max_repos`` caps how many repos are
    launched.
    """
    program = h1_client.get_program(handle)
    scopes = h1_client.get_structured_scopes(handle)
    rules = map_program(program, scopes)

    scope = repos_in_scope(rules)
    repos = scope.repos[:max_repos] if max_repos else scope.repos
    result = PipelineResult(handle=rules.handle or handle, program_name=rules.name,
                            repos=repos, gated=scope.gated, reason=scope.reason)
    if scope.gated or not repos or not launch:
        return result

    template = template or discover_scan_template(ok_client, model=model)
    result.launches = launch_repo_scans(ok_client, repos, template)
    return result


class PipelineError(RuntimeError):
    """A prerequisite for launching scans is missing (e.g. no workflow configured)."""


def _first_id(items):
    return items[0].get("id") if isinstance(items[0], dict) else items[0]
