# Unchecked RNG return on the EdDSA/Schnorr signing nonce → predictable/uninitialized nonce → private-key recovery on RNG failure

> **DRAFT for human review — not submitted.** This report was produced by the Aegis
> + open·kritt pipeline (Systems/Crypto workflow, `claude-sonnet-5`) and then
> **manually verified against the public source**. Before submitting, confirm the
> program's scope and severity bar (see *Severity & submission notes*). Do not submit
> without your own judgement — an unreachable-RNG-failure issue is scored differently
> by different programs.

## Summary

`ED25519_sign_with_scalar()` generates the per-signature EdDSA/Schnorr nonce with a
**bare, unchecked** call to OpenSSL's `RAND_bytes()`. If `RAND_bytes()` fails, its
return value is ignored, the `nonce` buffer is left as **uninitialized stack
memory**, and that value is used directly as the signing nonce. Because this scheme
uses a **random** nonce (not RFC 8032's deterministic one), a predictable or repeated
nonce leaks the private signing scalar via standard nonce-reuse algebra. The
function is on the production MPC signing path used when the key is a raw scalar
(the threshold / MPC-reconstructed case), and it bypasses the codebase's own
RNG-checking wrapper (`gen_random`, which asserts on failure).

## Target

- **Project:** `coinbase/cb-mpc` (Coinbase MPC Library)
- **Commit:** `6538e40caff9bbb1f5d90f0d3cdbbc3867b266c2` (2026-08-01)
- **File / line:** `src/cbmpc/crypto/ec25519_core.cpp:1120`
- **Weakness:** CWE-252 (unchecked return value), CWE-330/CWE-338 (use of
  insufficiently random values), CWE-457 (use of uninitialized variable — on the
  failure path)

## Affected code (verified from source)

The signing routine (`src/cbmpc/crypto/ec25519_core.cpp`):

```cpp
extern "C" int ED25519_sign_with_scalar(uint8_t* out_sig, const uint8_t* message, size_t message_len,
                                        const uint8_t public_key[32], const uint8_t scalar_bin[32]) {
  uint8_t nonce[64];
  RAND_bytes(nonce, 64);            // <-- return value ignored; nonce stays uninitialized on failure
  ...
  sign_with_nonce(out_sig, message, message_len, public_key, az, nonce);
  ...
  return 1;                         // <-- always returns success, even if a check were added
}
```

`nonce` is the real secret nonce `r` — `sign_with_nonce()` computes the standard
Schnorr/EdDSA signature:

```cpp
bn_t nonce_bn = from_le_mod_q(mem_t(nonce, 64));   // r = nonce mod q
curve_t::mul_to_generator(nonce_bn, R);            // R = r·G
bn_t hram_bn = hash_hram(signature, message, public_key);   // h = H(R, A, M)
bn_t s = q.mul(hram_bn, az_bn);                    // h·a
s = q.add(s, nonce_bn);                            // s = r + h·a  (mod q)
```

**Production reachability** (`src/cbmpc/crypto/base_eddsa.cpp:227`):

```cpp
buf_t ecurve_ed_t::sign(const ecc_prv_key_t& K, mem_t hash) const {
  ...
  if (K.ed_bin.empty()) {
    buf_t scalar = K.value().to_bin(ed25519::prv_bin_size());
    ED25519_sign_with_scalar(sig.data(), hash.data, hash.size, pub_bin.data(), scalar.data());  // return ignored here too
  } else {
    ED25519_sign(...);
  }
```

**Contrast — the codebase's own safe pattern** (`src/cbmpc/crypto/base.cpp:82`):

```cpp
void gen_random(byte_ptr output, int size) {
  int res = RAND_bytes(output, size);
  cb_assert(res > 0);               // the library DOES check elsewhere; this path bypasses it
}
```

## Impact

If `RAND_bytes()` fails, `nonce` is uninitialized stack memory — not random, and
plausibly **constant across calls** in the same execution context (same stack frame
layout) or otherwise predictable. For a random-nonce Schnorr/EdDSA scheme:

- **Nonce reuse:** two signatures `(R, s1)`, `(R, s2)` over messages `m1 ≠ m2` with
  the same `r` give `r = (s1 − s2)·(h1 − h2)⁻¹ mod q`, then `a = (s1 − r)·h1⁻¹ mod q`
  — **full private-key recovery**.
- **Nonce prediction:** if `r` is guessable, `a = (s − r)·h⁻¹ mod q` directly.

In an MPC / threshold-custody context this is the signing key material, so the
consequence is compromise of the signing key for that party.

## Preconditions / trigger conditions

Exploitation requires `RAND_bytes()` to **fail** (return ≤ 0). This is **not
remotely attacker-triggerable** in a normally-seeded environment, but is realistic
operationally:

- entropy starvation early in boot / in minimal containers;
- a sandbox/seccomp policy blocking `getrandom(2)` (common in hardened MPC-node
  deployments);
- a FIPS provider self-test failure or misconfiguration;
- OpenSSL RNG fault conditions.

A passive observer who then collects ≥ 2 signatures produced under the fault
recovers the key. No crafted network payload is needed.

## Severity & submission notes

**Assessed severity: Medium.** Impact is **critical** (private-key recovery) but the
likelihood is **low** (needs an RNG failure that is generally not attacker-induced
remotely). Programs vary: crypto-signing hygiene defects in key code are sometimes
accepted as Low/Medium, sometimes marked Informative when the failure path is deemed
unreachable. **Confirm cb-mpc is in Coinbase's HackerOne scope and that they accept
this class before submitting.** The strongest framing for triage is *"the signer
fails open on RNG failure, using an uninitialized nonce, in violation of the
library's own `gen_random` fail-closed pattern."*

## Remediation

Fail closed on RNG failure and propagate the error (the function already returns
`int` but always returns `1`):

```cpp
if (RAND_bytes(nonce, 64) != 1) {
  OPENSSL_cleanse(nonce, sizeof(nonce));
  return 0;                          // do not sign with a non-random nonce
}
```

Better still: use the existing checked wrapper (`crypto::gen_random`) for
consistency, and/or adopt a **deterministic (RFC 8032) or hedged** nonce so signing
never depends solely on live RNG success. Have callers (`ecurve_ed_t::sign`) check
and propagate the return value.

## Provenance & honesty

- **Found by:** Aegis + open·kritt, "Systems, Memory Safety & Crypto" workflow, model
  `claude-sonnet-5`. Other passes (Injection/SSRF, Secrets, and an earlier Opus
  Systems pass) returned no additional findings on this repo.
- **Verified:** the code, the caller, the signing math, and the `gen_random` contrast
  were all confirmed against the pinned public commit above — this is not a
  model-only claim.
- **Not demonstrated live:** exploitation depends on inducing an RNG failure, which
  was not performed; the key-recovery step is shown analytically. Treat this as a
  code-audit finding, not a working exploit.
