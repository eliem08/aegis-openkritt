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
    max_severity: str = ""    # payout ceiling for this asset (critical/high/…)
    eligible_for_bounty: bool = False


@dataclass
class ScanTemplate:
    """The non-target scan settings open·kritt requires; discover or pass explicitly."""
    workflow_id: str
    post_script_id: str
    severity_ranker: str                       # the ranker's markdown content
    model: str                                 # primary model id from the connected account
    harness: str = "claude-code"               # matches a connected Claude login
    model_provider: str = "claude"
    repo_scope: str = "full repository"
    launch_policy: str = "queue"               # don't preempt a running scan
    agent_skill_ids: tuple[str, ...] = ()
    fallback_models: tuple[str, ...] = ()      # tried in order if the primary is unavailable
    required_extra_keys: tuple[str, ...] = ()  # extra.* keys the workflow/post-script need
    extra: dict = field(default_factory=dict)  # static extra values (merged per launch)

    @property
    def models(self) -> list[str]:
        """Primary then fallbacks, de-duplicated, empties dropped."""
        seen: set[str] = set()
        out: list[str] = []
        for m in (self.model, *self.fallback_models):
            if m and m not in seen:
                seen.add(m)
                out.append(m)
        return out


@dataclass(frozen=True)
class ScanLaunch:
    repo: RepoTarget
    scan_id: str | None = None
    error: str | None = None
    model: str | None = None                   # which model actually launched it

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

def repos_in_scope(rules, *, bounty_only: bool = False) -> RepoScope:
    """In-scope repositories, gated by the program's automation/AI policy.

    ``bounty_only`` keeps only bounty-eligible repos (so the hunter spends effort
    where it can actually pay out).
    """
    if not rules.automation_allowed:
        return RepoScope(gated=True, reason="program policy prohibits automated tooling")
    if not rules.ai_allowed:
        return RepoScope(gated=True, reason="program policy prohibits AI tooling")

    repos: list[RepoTarget] = []
    seen: set[str] = set()
    for asset in rules.source_code_assets():
        if bounty_only and not asset.eligible_for_bounty:
            continue
        repo_full = _to_repo_full(asset.identifier)
        if repo_full and repo_full.lower() not in seen:
            seen.add(repo_full.lower())
            repos.append(RepoTarget(
                repo_full=repo_full, identifier=asset.identifier,
                asset_type=asset.asset_type.value,
                max_severity=str(asset.max_severity or ""),
                eligible_for_bounty=bool(asset.eligible_for_bounty)))
    if not repos:
        reason = ("no bounty-eligible source-code repositories found" if bounty_only
                  else "no in-scope source-code repositories found")
        return RepoScope(reason=reason)
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

_EXTRA_REF = re.compile(r"extra\.([a-zA-Z0-9_]+)")


def discover_scan_template(client, *, model: str, harness: str = "claude-code",
                           model_provider: str = "claude", fallbacks=None,
                           workflow_id=None, post_script_id=None,
                           **overrides) -> ScanTemplate:
    """Fill workflow / post-script / severity-ranker from the backend's configured
    resources. Prefers the default of each; ``workflow_id`` / ``post_script_id``
    override the choice. Also discovers the ``extra.*`` keys the chosen workflow and
    post-script require, so a launch validates.

    ``fallbacks`` are model ids tried in order if the primary is unavailable; when
    ``None`` they are auto-derived from the account's model catalog.
    """
    workflows = client.list_workflows()
    post_scripts = client.list_post_scripts()
    rankers = client.list_severity_rankers()
    if not workflows:
        raise PipelineError("open·kritt has no workflow configured")
    if not post_scripts:
        raise PipelineError("open·kritt has no post-script configured")
    if not rankers:
        raise PipelineError("open·kritt has no severity ranker configured")

    workflow = _pick(workflows, workflow_id)
    post_script = _pick(post_scripts, post_script_id)
    ranker = _pick(rankers, None)
    if fallbacks is None:
        try:
            fallbacks = tuple(m for m in client.list_models(model_provider) if m != model)
        except Exception:
            fallbacks = ()
    required = _required_extra_keys(client, workflow.get("id"), post_script)
    return ScanTemplate(
        workflow_id=str(workflow.get("id")),
        post_script_id=str(post_script.get("id")),
        severity_ranker=str(ranker.get("content") or ranker.get("markdown") or ""),
        model=model, harness=harness, model_provider=model_provider,
        fallback_models=tuple(fallbacks), required_extra_keys=required, **overrides)


def _pick(items: list, chosen_id) -> dict:
    """The chosen item by id, else the one flagged default, else the first."""
    if chosen_id is not None:
        for it in items:
            if str(it.get("id")) == str(chosen_id):
                return it
    for it in items:
        if it.get("isDefault"):
            return it
    return items[0]


def _required_extra_keys(client, workflow_id, post_script) -> tuple[str, ...]:
    """The extra.* keys referenced by the workflow's steps and the post-script."""
    keys: set[str] = set()
    try:
        wf = client.get_workflow(workflow_id)
        for step in (wf.get("steps") or []):
            keys.update(_EXTRA_REF.findall(str(step.get("content") or "")))
    except Exception:
        pass
    keys.update(_EXTRA_REF.findall(str((post_script or {}).get("content") or "")))
    return tuple(sorted(keys))


# --- launch scans -----------------------------------------------------------

def build_scan_payload(repo: RepoTarget, t: ScanTemplate, *, model: str | None = None,
                       extra: dict | None = None) -> dict:
    return {
        "workflowId": t.workflow_id,
        "postScriptId": t.post_script_id,
        "repo_kind": "remote",
        "repo_full": repo.repo_full,
        "repo_scope": t.repo_scope,
        "model": model or t.model,
        "harness": t.harness,
        "model_provider": t.model_provider,
        "severity_ranker": t.severity_ranker,
        "launchPolicy": t.launch_policy,
        "agentSkillIds": list(t.agent_skill_ids),
        "extra": {**t.extra, **(extra or {})},
    }


def resolve_extra(keys, *, handle: str = "", repo: RepoTarget | None = None) -> dict:
    """Best-effort values for a workflow's required ``extra.*`` keys.

    Known keys map to real context (the program's HackerOne URL, the repo);
    anything else gets the program URL so the launch still validates.
    """
    url = f"https://hackerone.com/{handle}" if handle else ""
    repo_full = repo.repo_full if repo else ""
    known = {
        "bug_bounty_url": url, "program_url": url, "program": handle, "handle": handle,
        "target": repo_full, "repo": repo_full, "repo_full": repo_full, "scope": repo_full,
    }
    return {k: (known.get(k) or url or repo_full) for k in keys}


def launch_repo_scans(client, repos, template: ScanTemplate, *, handle: str = "") -> list[ScanLaunch]:
    """Launch one scan per repo, filling required extra keys and falling back through
    ``template.models`` in order when the primary is rejected or unavailable."""
    models = template.models or [template.model]
    launches: list[ScanLaunch] = []
    for repo in repos:
        extra = resolve_extra(template.required_extra_keys, handle=handle, repo=repo)
        scan_id = used = None
        last_error = "no models configured"
        for model in models:
            try:
                resp = client.create_scan(build_scan_payload(repo, template, model=model, extra=extra))
                sid = str(resp.get("id") or resp.get("scanId") or "")
                if sid:
                    scan_id, used = sid, model
                    break
                last_error = f"{model}: no scan id in response"
            except Exception as exc:             # capacity / validation / network -> try next
                last_error = f"{model}: {_err(exc)}"
        launches.append(ScanLaunch(repo, scan_id=scan_id, model=used,
                                   error=None if scan_id else last_error))
    return launches


def _err(exc: Exception) -> str:
    """A useful message even for httpx errors (surface the response body)."""
    resp = getattr(exc, "response", None)
    if resp is not None:
        try:
            return f"HTTP {resp.status_code}: {resp.text[:300]}"
        except Exception:
            return f"HTTP {resp.status_code}"
    return str(exc)


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
                      max_repos: int | None = None, fallbacks=None,
                      bounty_only: bool = False, workflow_id=None,
                      post_script_id=None) -> PipelineResult:
    """Discover a program's repos and (optionally) launch an open·kritt scan on each.

    ``launch=False`` plans only — it returns the in-scope repos without touching
    open·kritt (used by the hunter's dry-run). ``max_repos`` caps how many repos are
    launched. ``bounty_only`` restricts to bounty-eligible repos.
    """
    program = h1_client.get_program(handle)
    scopes = h1_client.get_structured_scopes(handle)
    rules = map_program(program, scopes)

    scope = repos_in_scope(rules, bounty_only=bounty_only)
    repos = scope.repos[:max_repos] if max_repos else scope.repos
    result = PipelineResult(handle=rules.handle or handle, program_name=rules.name,
                            repos=repos, gated=scope.gated, reason=scope.reason)
    if scope.gated or not repos or not launch:
        return result

    template = template or discover_scan_template(
        ok_client, model=model, fallbacks=fallbacks,
        workflow_id=workflow_id, post_script_id=post_script_id)
    result.launches = launch_repo_scans(ok_client, repos, template, handle=rules.handle or handle)
    return result


class PipelineError(RuntimeError):
    """A prerequisite for launching scans is missing (e.g. no workflow configured)."""


def _first_id(items):
    return items[0].get("id") if isinstance(items[0], dict) else items[0]
