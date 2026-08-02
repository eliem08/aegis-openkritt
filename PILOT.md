# Running a supervised pilot

The bridge from "well-built" to "earns money." This is a **human-supervised**
run on **one** program. The golden rules never bend:

- **You** confirm scope and rules by reading the program's actual policy — the
  heuristic parser is an aid, not authority.
- **Nothing active runs** without a signed authorization covering the exact
  target, and the scope proxy physically blocks everything else.
- **Submission is manual.** The tool prepares reports; you review and submit.
- Only **your own** test accounts and seeded data are touched — never a real
  user's.

## 0. Prerequisites

- An authorized program that **explicitly permits automated testing** (many
  don't — check).
- **Two researcher-owned test accounts** on that program, and for BOLA: note
  one account's object id in an id-bearing endpoint plus a **canary** (a value
  only that account should see).
- Read the program's policy for: automation clause, AI-disclosure requirement,
  rate cap, out-of-scope assets, prohibited techniques, safe-harbor terms.

## 1. Ingest and sanity-check the program

```bash
HACKERONE_API_USERNAME=you HACKERONE_API_TOKEN=… python examples/hackerone_ingest.py <handle>
```

Confirm the printed `automation_ok`, `ai_ok`, rate cap, in-scope targets, and
**conflicts**. If automation is prohibited, **stop** — this agent must not run
there.

## 2. Configure the control plane (durable + encrypted)

Generate keys and set them in `.env` (git-ignored):

```bash
# Ed25519 signing keypair (keep the PRIVATE key in a secrets manager):
python -c "from aegis.policy import Ed25519Signer as S; s=S.generate('kid-1'); print('public', s.public_key_hex()); print('private', s.private_key_hex())"
# Encryption-at-rest key:
python -c "from aegis.api.crypto import generate_key; print(generate_key())"
```

Set in `.env`: `AEGIS_ED25519_PUBLIC_KEYS`, `AEGIS_API_KEYS`,
`AEGIS_DB_URL` (or `AEGIS_DB_PATH`), `AEGIS_ENCRYPTION_KEY`. Then:

```bash
docker compose up -d postgres        # or use AEGIS_DB_PATH=aegis.db
python -m aegis.api                  # control plane on :8000
```

## 3. Pre-flight (validate the safety plumbing — no network)

```bash
python examples/pilot_preflight.py <handle>      # or no arg for the sample
```

This confirms: the scope allowlist is right, the gate **allows** an in-scope
passive action and **denies** out-of-scope and prohibited actions, and surfaces
any automation/AI conflicts. Do not proceed until it's all green.

## 4. Register + sign the authorization (operator)

The operator reviews the draft authorization (targets, permitted actions,
rate), signs it (Ed25519 private key), and `POST /engagements`. This is the
human gate that turns discovered scope into permission.

## 5. Dry-run recon (passive), then detectors (gated)

- Recon (`ReconWorker`) maps the surface through the scope proxy — passive.
- Seed your BOLA/BFLA config (owned account ids + canaries), then run the
  `DetectorWorker`. Every request is gated and scope-enforced; a fired kill
  switch or a sensitive-data hit stops the run.

## 6. Review, prepare, submit (manually)

For each **verified** finding, `prepare_submission` produces a redacted,
quality-gated, HackerOne-ready report and a duplicate check. **You** read it,
confirm it's real and in scope, and submit through the platform yourself.

## 7. Track outcomes

Record accepted / duplicate / informative / rejected. Feed disclosed reports
back into the knowledge corpus (`python -m aegis.knowledge corpus.jsonl`) so
priors improve. Watch **bounty per research hour**; stop programs that stay
negative.

## Stop conditions (any of these → halt)

- Kill switch fired (operator, health check, or latency/error spike).
- Real sensitive data encountered (PII/secrets/cross-tenant) — path stops,
  redacts, escalates.
- Target instability or rate-limit responses.
- Any ambiguity about scope, authorization, or rules — escalate to a human.

## Legal

Stay within written authorization and the program's safe-harbor terms. Honor
disclosure timelines/embargoes. Never train on private program data without
authorization. When unsure, stop and ask.
