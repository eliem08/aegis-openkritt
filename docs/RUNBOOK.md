# Runbook — Aegis + open·kritt, running together

Two services, wired at arm's length. **Aegis** (this repo) is the deterministic
control plane + review console. **open·kritt** is a separate AGPL-3.0 AI research
platform that runs on Docker and brings its own model access. Aegis pulls its
findings over HTTP; no open·kritt source lives in this repo (see
`docs/OPENKRITT_INTEGRATION.md`).

## Model access — two independent consumers

| Consumer | Model | Where the credential lives |
|---|---|---|
| **open·kritt** agents | Your **Claude Code login** (or Codex/OpenAI/Anthropic/OpenRouter) | Connected by `./kritt setup`; reads `~/.claude/.credentials.json`. **No API key pasted.** |
| **Aegis** planner (`aegis.ai`, optional) | DeepSeek | `DEEPSEEK_API_KEY` in this repo's `.env`. Blank ⇒ deterministic fallback. |

These do not share a key. Your Claude login powers open·kritt; DeepSeek (if you
want the Aegis planner) is separate and optional.

## What's already configured

- **open·kritt** installed at `../open-kritt` (a sibling of this repo, outside its
  git tree) with a `.env` copied from `.env.example`, provider keys left blank so
  it uses your Claude login. Backend port **3002**, frontend **5173**.
- **This repo's `.env`** has `AEGIS_OPENKRITT_URL=http://127.0.0.1:3002` (and a
  blank `AEGIS_OPENKRITT_API_KEY`), so the review console talks to open·kritt once
  it's up. Verified: `ControlPlaneConfig.build_openkritt_client()` resolves.

## Bring it up

**1 — open·kritt (Docker + your Claude login).** Requires Docker Desktop and
Node 20+. From `../open-kritt` (use Git Bash or WSL on Windows):

```bash
./kritt setup     # connects your Claude Code login; leave API-key fields blank
```

`setup` guides you through the available logins and brings up the stack
(`docker compose up -d` if you prefer to do it yourself). The UI is at
`http://127.0.0.1:5173`, the API at `http://127.0.0.1:3002`. Run a scan on a repo
and note its **scan id**.

> Heads-up: driving an automated multi-agent scanner off a Claude *subscription*
> login is much heavier than interactive use — confirm it fits your plan's terms.

**2 — Aegis control plane + review console.** From this repo:

```bash
python -m aegis.api     # loads .env automatically; serves on 127.0.0.1:8000
```

Open `http://127.0.0.1:8000/ui`. Enter the open·kritt scan id and **Load from
backend** — its findings arrive as Aegis candidates, merged and de-duplicated with
any native detector output. No backend yet? Use **Upload export** with an
open·kritt findings JSON instead.

To exercise the console without auth friction during local dev:

```bash
AEGIS_AUTH_DISABLED=1 python -m aegis.api
```

## Optional — turn on the Aegis DeepSeek planner

Paste a DeepSeek key into this repo's `.env` (`DEEPSEEK_API_KEY=`) yourself; it is
git-ignored. Without it, Aegis plans deterministically — nothing breaks. Note the
Aegis planner is DeepSeek/OpenAI-compatible; it does **not** use the Claude login
(that's open·kritt's).

## Windows / Docker Desktop notes (applied to the local `../open-kritt/.env`)

Two host-specific fixes were needed to bring the stack up on this machine; both are
in `../open-kritt/.env` (git-ignored, out of tree):

- **DB host port.** Host `:5432` was already occupied, so `POSTGRES_PORT=5442`
  (the internal `db:5432` is unchanged, so nothing else needed touching).
- **Engine host path.** The engine spawns sibling scan containers and needs a real
  Docker-host path, so `ENGINE_DOCKER_DATA_DIR_HOST` must be an **absolute** path.
  Compose defaults it to `${PWD}/.data/engine`; run `docker compose` **from the
  open-kritt directory in Git Bash** so `${PWD}` is `/c/Users/.../open-kritt`, or set
  it explicitly (done here:
  `ENGINE_DOCKER_DATA_DIR_HOST=/c/Users/21263/Downloads/open-kritt/.data/engine`).
  If it's blank/relative the engine exits with code 2
  (`ENGINE_DOCKER_DATA_DIR_HOST must be an absolute host path`).

Status after these fixes: all five services (`db`, `backend`, `engine`,
`executor-view`, `frontend`) come up, and Aegis's `/ui/review` reports
`backend_connected: true`. Scans still require the Claude login (step 1 above).

## Boundaries kept

- open·kritt stays a separate process under its own AGPL obligations; Aegis only
  consumes its HTTP finding contract.
- Imported findings are **candidates**, not verdicts — they still pass Aegis's
  verification gate, and exploit payloads (`malicious_input_example`) never reach
  the console. Submission stays human-approved.
