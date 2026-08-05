"""Install the arm's-length skill catalog: clone each source repo, execute NOTHING.

Aegis never vendors a skill's source and never runs a skill's installer/scripts (that
would be executing untrusted downloaded code). This just shallow-clones the distinct
source repos into AEGIS_SKILLS_DIR so the Aegis-native runner can READ a skill's
instructions and invoke it as a prompt via DeepSeek. Unknown-licensed repos are
invoke-only (cloned to run locally, never copied into Aegis).

Run NMitchem/SkillScan against a skill before enabling it — these are third-party.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from aegis.ai.skill_registry import SKILLS

SKILLS_DIR = Path(os.environ.get("AEGIS_SKILLS_DIR", str(Path.home() / ".aegis" / "skills")))


def distinct_repos() -> dict[str, str]:
    """catalog entry -> top-level 'owner/repo' to clone (dedup monorepo subpaths)."""
    repos: dict[str, str] = {}
    for s in SKILLS:
        src = getattr(s, "repo", "") or getattr(s, "source", "") or ""
        parts = src.split("/")
        if len(parts) >= 2:
            repos[f"{parts[0]}/{parts[1]}"] = "/".join(parts[:2])
    return repos


def main() -> int:
    SKILLS_DIR.mkdir(parents=True, exist_ok=True)
    repos = sorted(set(distinct_repos().values()))
    print(f"installing {len(repos)} distinct skill repos -> {SKILLS_DIR}\n"
          f"(clone only; NEVER running their scripts)\n", flush=True)
    ok, failed = 0, []
    for repo in repos:
        dest = SKILLS_DIR / repo.replace("/", "__")
        if (dest / ".git").is_dir():
            print(f"  reuse   {repo}"); ok += 1; continue
        r = subprocess.run(
            ["git", "clone", "--depth", "1", f"https://github.com/{repo}.git", str(dest)],
            capture_output=True, text=True)
        if r.returncode == 0:
            print(f"  cloned  {repo}"); ok += 1
        else:
            print(f"  FAILED  {repo} — {r.stderr.strip().splitlines()[-1][:80] if r.stderr.strip() else '?'}")
            failed.append(repo)
    print(f"\ninstalled {ok}/{len(repos)} repos ({len(SKILLS)} skills). failed: {failed or 'none'}")
    print("\nNext: scan before enabling —")
    print(f"  ls {SKILLS_DIR}")
    print("  # then set AEGIS_SKILL_CMD to the Aegis-native runner (prompt-only, no script exec):")
    print("  #   AEGIS_SKILL_CMD='python -m aegis.ai.skill_runner --skill {source} --target {target}'")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
