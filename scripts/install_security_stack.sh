#!/usr/bin/env bash
# Install the security-scanner stack Aegis invokes arm's-length.
#
# Aegis does NOT vendor any tool or skill — it invokes the ones you install here and
# reads their findings. Python scanners go into the active venv; the Go binaries and the
# agent skills are installed to where you invoke them.
set -u

echo "== Python scanners (into the active interpreter) =="
python -m pip install --quiet semgrep bandit njsscan slither-analyzer detect-secrets \
  && echo "  installed: semgrep, bandit, njsscan, slither, detect-secrets"

echo
echo "== Go binaries (install separately, then ensure on PATH) =="
echo "  gitleaks : https://github.com/gitleaks/gitleaks/releases   (MIT)"
echo "  trivy    : https://github.com/aquasecurity/trivy/releases  (Apache-2.0)"
echo "  # e.g. (macOS/Linux):  brew install gitleaks trivy"

echo
echo "== Agent skills (clone where your agent CLI can invoke them) =="
echo "  SCAN A SKILL BEFORE YOU USE IT — these execute code. Run NMitchem/SkillScan first."
SKILLS_DIR="${AEGIS_SKILLS_DIR:-$HOME/.aegis/skills}"
mkdir -p "$SKILLS_DIR"
for repo in \
  pashov/skills \
  cloudflare/security-audit-skill \
  NMitchem/SkillScan \
  dstiliadis/security-review-skill \
  ; do  # MIT-licensed set (vendorable with attribution); clone others only if you accept their terms
  name="$(basename "$repo")"
  if [ -d "$SKILLS_DIR/$name/.git" ]; then
    echo "  reuse  $repo"
  else
    git clone --depth 1 "https://github.com/$repo.git" "$SKILLS_DIR/$name" >/dev/null 2>&1 \
      && echo "  cloned $repo -> $SKILLS_DIR/$name" \
      || echo "  FAILED $repo (skip)"
  fi
done

echo
echo "== Wire skill invocation (arm's-length) =="
echo "  export AEGIS_SKILL_CMD='<your-agent-cli> --skill {source} --target {target}'"
echo "  Then hunt_repo / hunt_contract will invoke installed skills and fold results in."
echo
echo "Done. Verify: python -c \"from aegis.ai.tool_bridge import available_tools; print([t.name for t in available_tools()])\""
