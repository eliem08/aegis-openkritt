"""Hosted product API — the SaaS surface for the seven product surfaces.

Each product runs as an async job (they can take minutes): POST returns a job id, GET polls it.
All routes require at least an **agent** token and run within that principal's tenant. The engine
binding is resolved from ``app.state.product_ports`` (tests inject fakes) or the real engine.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from aegis.products import (
    bounty_triage,
    pr_gatekeeper,
    proof_of_fix,
    proof_of_vuln,
    repo_autopilot,
    slop_filter,
    standing_redteam,
)
from aegis.products.jobs import ProductJobStore
from aegis.products.ports import Ports, default_ports

from ..config import ApiPrincipal
from ..security import require_agent

router = APIRouter(prefix="/products", tags=["products"])


def _ports(request: Request) -> Ports:
    return getattr(request.app.state, "product_ports", None) or default_ports()


def _jobs(request: Request) -> ProductJobStore:
    js = getattr(request.app.state, "product_jobs", None)
    if js is None:
        js = ProductJobStore()
        request.app.state.product_jobs = js
    return js


def _submit(request: Request, principal: ApiPrincipal, product: str, fn) -> dict:
    return _jobs(request).submit(product, fn, tenant=principal.name).public()


# --- request bodies ------------------------------------------------------------------------

class ProofVulnIn(BaseModel):
    finding: Any
    repo_dir: str
    reproduce: bool = True
    repository: str = ""


class ProofFixIn(BaseModel):
    finding: Any
    vuln_dir: str
    fixed_dir: str
    repository: str = ""


class SlopFilterIn(BaseModel):
    findings: Any
    repo_dir: str
    reproduce: bool = False
    repository: str = ""


class TriageIn(BaseModel):
    reports: Any
    repo_dir: str | None = None
    validate_reports: bool = True
    repository: str = ""


class AutopilotIn(BaseModel):
    repo: str
    repo_dir: str | None = None
    files: int = 12
    samples: int = 2
    reproduce: bool = True
    reproduced_only: bool = False


class PrGateIn(BaseModel):
    repo: str
    changed: list[str] = []
    repo_dir: str | None = None
    files: int = 40
    samples: int = 2
    fail_on: list[str] = ["confirmed", "reproduced"]


class RedteamIn(BaseModel):
    repo: str
    repo_dir: str | None = None
    previous_ids: list[str] | None = None
    files: int = 12
    samples: int = 2
    reproduce: bool = True


# --- B: proof / validation -----------------------------------------------------------------

@router.post("/proof-vuln", status_code=status.HTTP_202_ACCEPTED)
def proof_vuln(body: ProofVulnIn, request: Request,
               principal: ApiPrincipal = Depends(require_agent)) -> dict:
    ports = _ports(request)
    return _submit(request, principal, "proof-vuln",
                   lambda: proof_of_vuln.run(body.finding, body.repo_dir, ports=ports,
                                             reproduce=body.reproduce,
                                             repository=body.repository).to_dict())


@router.post("/proof-fix", status_code=status.HTTP_202_ACCEPTED)
def proof_fix(body: ProofFixIn, request: Request,
              principal: ApiPrincipal = Depends(require_agent)) -> dict:
    ports = _ports(request)
    return _submit(request, principal, "proof-fix",
                   lambda: proof_of_fix.run(body.finding, body.vuln_dir, body.fixed_dir,
                                            ports=ports, repository=body.repository).to_dict())


@router.post("/slop-filter", status_code=status.HTTP_202_ACCEPTED)
def slop_filter_ep(body: SlopFilterIn, request: Request,
                   principal: ApiPrincipal = Depends(require_agent)) -> dict:
    ports = _ports(request)
    return _submit(request, principal, "slop-filter",
                   lambda: slop_filter.run(body.findings, body.repo_dir, ports=ports,
                                           reproduce=body.reproduce,
                                           repository=body.repository).to_dict())


@router.post("/triage", status_code=status.HTTP_202_ACCEPTED)
def triage(body: TriageIn, request: Request,
           principal: ApiPrincipal = Depends(require_agent)) -> dict:
    ports = _ports(request)
    return _submit(request, principal, "bounty-triage",
                   lambda: bounty_triage.run(body.reports, repo_dir=body.repo_dir, ports=ports,
                                             validate=body.validate_reports,
                                             repository=body.repository).to_dict())


# --- A: finders ----------------------------------------------------------------------------

@router.post("/autopilot", status_code=status.HTTP_202_ACCEPTED)
def autopilot(body: AutopilotIn, request: Request,
              principal: ApiPrincipal = Depends(require_agent)) -> dict:
    ports = _ports(request)
    return _submit(request, principal, "repo-autopilot",
                   lambda: repo_autopilot.run(body.repo, repo_dir=body.repo_dir, ports=ports,
                                              files=body.files, samples=body.samples,
                                              reproduce=body.reproduce,
                                              reproduced_only=body.reproduced_only).to_dict())


@router.post("/pr-gate", status_code=status.HTTP_202_ACCEPTED)
def pr_gate(body: PrGateIn, request: Request,
            principal: ApiPrincipal = Depends(require_agent)) -> dict:
    ports = _ports(request)
    return _submit(request, principal, "pr-gatekeeper",
                   lambda: pr_gatekeeper.run(body.repo, body.changed, repo_dir=body.repo_dir,
                                             ports=ports, files=body.files, samples=body.samples,
                                             fail_on=tuple(body.fail_on)).to_dict())


@router.post("/redteam", status_code=status.HTTP_202_ACCEPTED)
def redteam(body: RedteamIn, request: Request,
            principal: ApiPrincipal = Depends(require_agent)) -> dict:
    ports = _ports(request)
    return _submit(request, principal, "standing-redteam",
                   lambda: standing_redteam.run(body.repo, repo_dir=body.repo_dir, ports=ports,
                                                previous_ids=body.previous_ids, files=body.files,
                                                samples=body.samples,
                                                reproduce=body.reproduce).to_dict())


# --- jobs ----------------------------------------------------------------------------------

@router.get("/jobs")
def list_jobs(request: Request, principal: ApiPrincipal = Depends(require_agent)) -> dict:
    jobs = _jobs(request).list(tenant=principal.name)
    return {"jobs": [j.public() for j in jobs]}


@router.get("/jobs/{job_id}")
def job_status(job_id: str, request: Request,
               principal: ApiPrincipal = Depends(require_agent)) -> dict:
    job = _jobs(request).get(job_id)
    if job is None or job.tenant != principal.name:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="job not found")
    return job.public()
