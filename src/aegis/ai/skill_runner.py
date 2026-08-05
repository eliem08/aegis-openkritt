"""Aegis-native, prompt-only runner for installed arm's-length skills.

The safe invoker behind ``AEGIS_SKILL_CMD``. Given an installed skill (its
owner/repo/subpath) and a target source tree, it READS the skill's instruction file
(SKILL.md / README / *.md) and runs those instructions as a DeepSeek prompt over the
target source, emitting findings JSON on stdout for SkillBridge to fold in.

SAFETY: this NEVER executes a skill's own scripts or installers — only its natural-
language instructions are read and handed to the LLM. That keeps third-party skills
from running arbitrary downloaded code on the host; they become guided prompts, and
every result is still unverified until Aegis's validator and a human gate it.

    python -m aegis.ai.skill_runner --skill pashov/skills/solidity-auditor --target <dir>
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

_SKILLS_DIR = Path(os.environ.get("AEGIS_SKILLS_DIR", str(Path.home() / ".aegis" / "skills")))
_INSTR_NAMES = ("SKILL.md", "skill.md", "README.md", "readme.md", "index.md")
_SRC_EXT = {".py", ".js", ".ts", ".go", ".rb", ".php", ".java", ".rs", ".sol", ".cs", ".c", ".cpp"}


def _find_instructions(skill_source: str) -> tuple[str, str]:
    """Resolve an installed skill's instruction text. Returns (title, text) or ('','')."""
    parts = skill_source.split("/")
    if len(parts) < 2:
        return "", ""
    repo_dir = _SKILLS_DIR / f"{parts[0]}__{parts[1]}"
    sub = repo_dir.joinpath(*parts[2:]) if len(parts) > 2 else repo_dir
    # prefer the exact subpath; else search the repo for a same-named skill dir
    candidates = [sub] if sub.is_dir() else []
    if len(parts) > 2 and not sub.is_dir():
        candidates += list(repo_dir.rglob(parts[-1])) if repo_dir.is_dir() else []
    candidates.append(repo_dir)
    for base in candidates:
        if not base.is_dir():
            continue
        for name in _INSTR_NAMES:
            f = base / name
            if f.is_file():
                return skill_source, f.read_text(encoding="utf-8", errors="replace")[:8000]
        mds = sorted(base.glob("*.md"))
        if mds:
            return skill_source, mds[0].read_text(encoding="utf-8", errors="replace")[:8000]
    return "", ""


def _resolve_target_dir(target: str) -> Path | None:
    p = Path(target)
    if p.is_dir():
        return p
    guess = Path("reports/clones") / target.replace("/", "__")   # owner/repo -> clone cache
    return guess if guess.is_dir() else None


def _sample_source(root: Path, *, max_files: int = 6, max_bytes: int = 2400) -> str:
    chunks, n = [], 0
    for f in sorted(root.rglob("*")):
        if n >= max_files or not f.is_file() or f.suffix.lower() not in _SRC_EXT:
            continue
        try:
            body = f.read_text(encoding="utf-8", errors="replace")[:max_bytes]
        except Exception:
            continue
        rel = f.relative_to(root)
        chunks.append(f"### FILE: {rel}\n{body}")
        n += 1
    return "\n\n".join(chunks)


def run_skill(skill_source: str, target: str) -> list[dict]:
    title, instructions = _find_instructions(skill_source)
    if not instructions:
        return []
    tdir = _resolve_target_dir(target)
    if tdir is None:
        return []
    source = _sample_source(tdir)
    if not source.strip():
        return []
    from .client import DeepSeekClient
    from .config import DeepSeekConfig

    env = dict(os.environ)
    env.update(DEEPSEEK_THINKING="disabled", DEEPSEEK_TEMPERATURE="0.1", DEEPSEEK_MAX_TOKENS="4096")
    system = (
        "You are running an installed third-party security-review SKILL as guidance. "
        "Apply the skill's instructions to the supplied source. Report ONLY concrete, "
        "code-anchored security findings you can point to a file+line for. Invent nothing. "
        "Return ONLY a JSON array: "
        '[{"title":"","file":"","line":0,"severity":"critical|high|medium|low",'
        '"summary":"","confidence":0.0}] — an empty array [] if there is nothing real.')
    user = (f"# SKILL INSTRUCTIONS ({title})\n{instructions}\n\n"
            f"# TARGET SOURCE (sampled)\n{source}\n\n"
            "Apply the skill and return the JSON array only.")
    try:
        with DeepSeekClient(DeepSeekConfig.from_env(env)) as client:
            data = client.complete_json([
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ])
    except Exception:
        return []
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        for k in ("findings", "vulnerabilities", "results", "issues"):
            if isinstance(data.get(k), list):
                return [d for d in data[k] if isinstance(d, dict)]
    return []


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aegis.ai.skill_runner")
    ap.add_argument("--skill", required=True, help="installed skill source (owner/repo/subpath)")
    ap.add_argument("--target", required=True, help="target source dir, or owner/repo (clone cache)")
    args = ap.parse_args(argv)
    findings = run_skill(args.skill, args.target)
    print(json.dumps(findings))     # SkillBridge parses this stdout
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
