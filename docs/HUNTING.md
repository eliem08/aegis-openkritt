# Automatic hunting

`python -m aegis.hunt` runs the whole pipeline on a loop:

```
authorized HackerOne programs
        │  (gate: automation + AI permitted, in-scope SOURCE code repos)
        ▼
launch open·kritt scans on each repo
        ▼
collect findings → review console (ranked by everything learned so far)
        ▼
sync HackerOne report outcomes back into calibration + planner memory
        ▼
     sleep, repeat
```

## What it will and won't do

**Will:** discover authorized programs, launch scans on their in-scope code repos,
pull findings into the console, and fold report outcomes back into the learning loop.

**Won't — and can't, by construction:**
- **Exploit.** It runs scanners; it never runs exploits.
- **Submit.** It never submits to HackerOne. A human reviews the console and submits.
  (The only HackerOne writes anywhere in the platform are none — every HackerOne call
  is a read.)
- **Touch out-of-scope or automation-forbidden targets.** A program is skipped unless
  its policy permits automated **and** AI tooling and it has in-scope source-code
  repos. Skips are reported with a reason.
- **Surprise-launch.** It is **dry-run by default** — it plans what it *would* scan
  and launches nothing until you set `AEGIS_HUNT_ARM=1`.

## Run it

Dry-run first (plans only, launches nothing) — from the project dir:

```bash
AEGIS_HUNT_CYCLES=1 ./.venv/Scripts/python -m aegis.hunt
```

You'll see, per cycle, how many programs were considered, which were gated out, how
many repos are in scope, and (armed) how many scans launched. When you're happy with
the plan, arm it:

```bash
AEGIS_HUNT_ARM=1 AEGIS_HUNT_MODEL=<claude-model-id> ./.venv/Scripts/python -m aegis.hunt
```

Scope it to specific programs and pace it:

```bash
AEGIS_HUNT_ARM=1 AEGIS_HUNT_MODEL=<model> \
AEGIS_HUNT_HANDLES=some-program,another \
AEGIS_HUNT_INTERVAL=1800 AEGIS_HUNT_MAX_PROGRAMS=2 AEGIS_HUNT_MAX_REPOS=2 \
  ./.venv/Scripts/python -m aegis.hunt
```

Prerequisites: `AEGIS_OPENKRITT_URL` (running open·kritt) and
`HACKERONE_API_USERNAME` / `HACKERONE_API_TOKEN` in `.env`. Set `AEGIS_LEARN_DB` to
persist what it learns across runs.

## Or trigger one cycle from the console

`POST /ui/hunt` runs a single cycle and returns the summary:

```bash
curl -s -X POST http://127.0.0.1:8000/ui/hunt -H "Content-Type: application/json" -d '{}'
```

Dry-run unless you pass `{"arm": true, "model": "<model>"}`. Optional
`handles`, `max_programs`, `max_repos`.

## Watch it work

While it hunts, open the console at `http://127.0.0.1:8000/ui` — findings accumulate,
ranked by the learned priors, and reorder as you record verdicts and as HackerOne
resolutions sync in. The hunter fills the queue; you decide what's real and what ships.

## A word on running it unattended

Armed, this launches real scans against real programs and consumes your model
budget (e.g. a Claude subscription — heavier than interactive use). Start with a
dry-run, arm with small caps and a specific handle list, and keep the human-review /
human-submit boundary: that's the line that keeps automated hunting authorized.
