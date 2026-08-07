"""Generate severity-inclusive hunt candidates from repository/runtime signals.

The generator is intentionally conservative: it proposes research hypotheses and
safe/local validation work. It does not perform live exploitation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from .state_store import JarvisStateStore
from .weakness_catalog import (
    UNIVERSAL_FAMILIES,
    HuntCandidate,
    SeverityTier,
    WeaknessFamily,
)


@dataclass(frozen=True)
class SurfaceSignal:
    surface: str
    confidence: float
    changed: bool = False
    evidence: tuple[str, ...] = ()


_MARKERS: Mapping[str, tuple[str, ...]] = {
    "graphql": ("graphql", "apollo", "graphene", "strawberry", "ariadne"),
    "websocket": ("websocket", "socket.io", "sockjs", "ws/", "channels"),
    "payments": ("stripe", "payment", "billing", "checkout", "invoice", "coupon"),
    "jobs": ("celery", "rq", "bullmq", "sidekiq", "worker", "queue", "cron"),
    "archives": ("zipfile", "tarfile", "archive", "unpack", "extract"),
    "imports": ("import", "upload", "csv", "multipart", "attachment"),
    "webhooks": ("webhook", "callback_url", "callback-url"),
    "mobile": ("android", "ios", "mobile"),
    "ci": (".github/workflows", ".gitlab-ci", "jenkinsfile", "circleci"),
    "iac": ("terraform", ".tf", "cloudformation", "pulumi", "kubernetes", "helm"),
    "cloud-config": ("aws", "gcp", "azure", "s3", "iam", "bucket"),
    "browser": ("playwright", "selenium", "puppeteer", "browser"),
    "spa": ("react", "vue", "angular", "svelte", "next.js", "nuxt"),
    "api": ("openapi", "swagger", "fastapi", "express", "api/", "router"),
    "web": ("flask", "django", "rails", "spring", "laravel", "http"),
    "dependencies": ("requirements.txt", "package-lock", "pnpm-lock", "yarn.lock", "cargo.lock", "go.sum"),
    "containers": ("dockerfile", "docker-compose", "compose.yml", "compose.yaml"),
}


_DEFAULT_PAYOUTS = {
    SeverityTier.INFO: 100.0,
    SeverityTier.LOW: 350.0,
    SeverityTier.MEDIUM: 1500.0,
    SeverityTier.HIGH: 5000.0,
    SeverityTier.CRITICAL: 10000.0,
}


def infer_surfaces(paths: Iterable[str], text_hints: Iterable[str] = ()) -> tuple[SurfaceSignal, ...]:
    corpus = "\n".join([*(str(path).lower() for path in paths), *(str(hint).lower() for hint in text_hints)])
    signals: list[SurfaceSignal] = []
    for surface, markers in _MARKERS.items():
        hits = tuple(marker for marker in markers if marker in corpus)
        if not hits:
            continue
        confidence = min(1.0, 0.55 + 0.12 * len(hits))
        signals.append(SurfaceSignal(surface=surface, confidence=confidence, evidence=hits))
    return tuple(sorted(signals, key=lambda signal: (-signal.confidence, signal.surface)))


def _family_for_surface(surface: str) -> tuple[WeaknessFamily, ...]:
    return tuple(family for family in UNIVERSAL_FAMILIES if surface in family.surfaces)


def generate_hunt_candidates(
    *,
    program_id: str,
    signals: Iterable[SurfaceSignal],
    state_store: JarvisStateStore | None = None,
    coverage_attempts: Mapping[tuple[str, str], int] | None = None,
    payout_overrides: Mapping[str, float] | None = None,
) -> tuple[HuntCandidate, ...]:
    coverage_attempts = coverage_attempts or {}
    payout_overrides = payout_overrides or {}
    candidates: list[HuntCandidate] = []

    for signal in signals:
        for family in _family_for_surface(signal.surface):
            prior = state_store.learned_prior(program_id, family.family_id) if state_store else None
            samples = prior.samples if prior else 0
            p_accepted = prior.acceptance_probability if prior else 0.55
            p_unique = prior.uniqueness_probability if prior else 0.60
            learned_payout = prior.mean_payout_usd if prior else 0.0
            baseline = payout_overrides.get(
                family.family_id,
                learned_payout or _DEFAULT_PAYOUTS[family.baseline_severity],
            )
            attempts = max(0, int(coverage_attempts.get((signal.surface, family.family_id), 0)))
            coverage_gap = 1.0 / (1.0 + attempts)
            novelty = min(1.0, 0.45 + 0.35 * coverage_gap + (0.20 if signal.changed else 0.0))
            chainability = min(1.0, 0.15 + 0.12 * len(family.chain_tags))
            validation_cost = max(0.25, (prior.mean_cost_usd if prior and samples else 1.0))
            # Surface confidence is used as a weak validity prior; runtime/source evidence must
            # still advance through the normal evidence lifecycle.
            p_valid = min(0.9, 0.35 + 0.45 * signal.confidence)
            p_reproducible = 0.72 if family.default_validation_mode.startswith("local") else 0.62
            candidates.append(
                HuntCandidate(
                    family=family,
                    surface=signal.surface,
                    severity=family.baseline_severity,
                    expected_payout_usd=max(0.0, baseline),
                    p_valid=p_valid,
                    p_accepted=p_accepted,
                    p_unique=p_unique,
                    p_reproducible=p_reproducible,
                    validation_cost_usd=validation_cost,
                    novelty_score=novelty,
                    chainability=chainability,
                    coverage_gap=coverage_gap,
                )
            )

    return tuple(candidates)
