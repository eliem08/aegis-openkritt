# owncloud/core — findings from three independent passes (DRAFT, for review)

> Not submitted anywhere. Every item below was checked against the real pinned
> source (commit `995d39ddd9c1`, branch `master`) before being written down —
> confidence levels reflect that check, not the model's self-reported confidence.

Three passes converged on this target: Aegis's native DeepSeek pipeline (targeted
auth/session/token files), open·kritt's Injection workflow on Sonnet (whole-repo),
and manual verification of both against the live GitHub source.

## 1. Public-link password bypass on federated (remote) shares — HIGH, verified real

**File:** `apps/dav/lib/Connector/PublicAuth.php:114-115`
**CWE-287** (improper authentication)
**Source:** Aegis-native DeepSeek pipeline, confirmed by Aegis's citation validator, then manually re-verified.

```php
if ($share->getPassword() !== null) {                    // share IS password-protected
    if ($share->getShareType() === \OCP\Share::SHARE_TYPE_LINK) {
        // ... password IS checked here (checkPassword) ...
    } elseif ($share->getShareType() === \OCP\Share::SHARE_TYPE_REMOTE) {
        return true;                                       // <-- password NEVER checked
    } else {
        return false;
    }
} else {
    return true;
}
```

**The bug:** this whole branch only runs when `$share->getPassword() !== null` — the
share *is* password-protected. For `SHARE_TYPE_LINK` the password is correctly
verified. For `SHARE_TYPE_REMOTE` (a federated share) it unconditionally
`return true`s — **the password is never checked at all.** Anyone who knows or
guesses a federated share's token can access it via WebDAV with no password,
even though the owner set one.

**Why I'm confident:** read directly off the pinned source; the logic is
unambiguous — no complex data flow to misjudge, just a branch that returns `true`
before the password check that exists two lines above it for the sibling case.

**Open question for you to close before submitting:** whether federated
(`SHARE_TYPE_REMOTE`) shares are documented as supporting a password at all in
current ownCloud — if the UI never lets you set one, the impact narrows (but the
code path is still wrong and worth reporting either way).

## 2. Authenticated SSRF via federated-share remote-URL testing — MEDIUM, real but overclaimed

**Files:** `apps/files_sharing/lib/External/Manager.php:551`,
`apps/federatedfilesharing/lib/DiscoveryManager.php:179`
**CWE-918** (SSRF)
**Source:** open·kritt, Injection & SSRF workflow, `claude-sonnet-5`.

```php
protected function testUrl(IClientService $clientService, string $remote, ...): bool {
    $client = $clientService->newClient();
    $response = json_decode($client->get($remote, [...])->getBody());   // outbound GET to $remote
```

This is real: the server makes an outbound HTTP request to a URL supplied when
adding a federated share, with no visible allowlist/private-IP block — classic
SSRF (can be used to probe internal services, cloud metadata endpoints, etc.).

**Correction to the original finding:** open·kritt reported the entry point as
*"unauthenticated."* I checked the controller
(`ExternalSharesController`) and its actions are annotated `@NoAdminRequired`
only — **no `@PublicPage`**, which in ownCloud's routing means login is still
required. So this is an **authenticated** SSRF (any logged-in user, not just
admins), not an unauthenticated one. Still a real, often-paid bug class — just
correct the precondition before submitting.

## 3. Session-deletion cookie missing Secure/HttpOnly — LOW, real but minor

**File:** `lib/private/Session/CryptoWrapper.php:139-150` (`deleteCookie()`)
**CWE-614**
**Source:** Aegis-native DeepSeek pipeline, confirmed by the citation validator.

```php
public function deleteCookie(): void {
    $options = [..., 'secure' => false, 'httponly' => false, 'samesite' => 'None'];
    $this->sendCookieToBrowser('', $options);
}
```

Real code, but I checked `prepareOptions()` (used by `sendCookie`/`refreshCookie`,
the paths that actually carry the secret passphrase) and it correctly sets
`'secure' => ($this->request->getServerProtocol() === 'https')`. Only the
*deletion* path (empty value, clearing the cookie) skips that. Sending an empty,
already-expired cookie without Secure/HttpOnly has minimal real impact — flag it
as a hygiene nit, not a submittable vulnerability on its own.

## 4. Ed25519 main-subgroup check is inverted — HIGH, verified against upstream libsodium

**File:** `paragonie/sodium_compat/src/Core/Ed25519.php:125-130`
**Also affects:** `src/File.php` (the real, security-critical call site)
**CWE-697** (incorrect comparison) leading to **CWE-347** (improper verification of
cryptographic signature)
**Source:** open·kritt, Systems/Crypto workflow (DeepSeek v4 Flash via OpenRouter),
escalated from "unresolved" to confirmed after checking upstream libsodium's actual
C reference implementation byte-for-byte.

**Upstream libsodium** (`ed25519_ref10.c`, `ge25519_is_on_main_subgroup`):
```c
ge25519_mul_l(&pl, p);
fe25519_sub(t, pl.Y, pl.Z);
return fe25519_iszero(pl.X) & fe25519_iszero(t);      // TRUE iff L*p is the identity
```

**sodium_compat** (`Ed25519.php:125-130`):
```php
$p1 = self::ge_mul_l($A);
$t = self::fe_sub($p1->Y, $p1->Z);
return self::fe_isnonzero($p1->X) && self::fe_isnonzero($t);   // TRUE iff L*p is NOT the identity
```

These are not merely "off by a negation" — they disagree exactly on the two
determinate cases: a genuine main-subgroup point (which becomes the identity when
multiplied by the group order `L`) is wrongly reported `false`, and a
mixed-order/torsion point (which generically does *not* become the identity) is
wrongly reported `true`.

**The real consequence — this function is actually used for a security check.**
`src/File.php`'s file-signature verification does:
```php
if (ParagonIE_Sodium_Core_Ed25519::small_order($publicKey)) {
    throw new SodiumException('Public key has small order');
}
if (!ParagonIE_Sodium_Core_Ed25519::is_on_main_subgroup($A)) {
    throw new SodiumException('Public key is not on main subgroup');
}
```
`small_order()` only catches *pure* small-order points (order 1/2/4/8).
`is_on_main_subgroup()` exists to catch the case `small_order()` misses: a **mixed**
public key with both a large-order and a small-order (torsion) component. Because
the check is inverted, such a key generically produces `is_on_main_subgroup() ==
true`, so `!true == false` — **the guard never throws, and the malicious key is
accepted.** This defeats the cofactor/torsion defense in Ed25519 file-signature
verification, the classic precondition for small-subgroup confinement and
signature-malleability attacks.

I did not build or run a live exploit (no PoC nonce/point was constructed); the
inversion and the security-relevant call site are both verified directly from
source, byte-for-byte against the canonical reference implementation.

## Not investigated further (low value)

- `federatedfilesharing/lib/TokenHandler.php:31` — short federated-share token
  length reducing entropy. Plausible but low severity; not chased.
- The three `owncloud`/`hyperledger`/`kubernetes-csi-api`/`circle-cctp` scans in
  this batch that returned 0 findings — consistent with well-audited code, no
  contradiction found.

## Bottom line, and where each of these actually goes

**HackerOne facts I pulled live (not assumed):** both programs show
`submission_state: "paused"` on HackerOne right now.

- **ownCloud's HackerOne program is explicitly discontinued.** Its policy text
  says so directly: *"ownCloud Security Bug Bounty Program on Hackerone is
  discontinued. Please head over to https://security.owncloud.com for our VDP."*
  **Do not submit findings #1–#3 through HackerOne.** Take #1 (the federated-share
  password bypass — the real, high-confidence one) and, if you choose, #2 (the
  corrected authenticated-SSRF) to `security.owncloud.com` instead. I have not
  visited that page or assumed its process; check its current scope/process
  yourself before sending anything. Skip #3 (cookie hygiene) — not worth the
  channel.
- **Paragonie is paused on HackerOne too, but their policy explicitly welcomes
  email regardless:** *"security@paragonie.com will get your reports to the right
  person"* — GPG key included in their policy — *"or open a new issue on GitHub if
  you want to disclose publicly."* They're an explicit **full-disclosure shop**:
  *"Any reports (valid or invalid) will be disclosed fully as soon as possible."*
  That cuts both ways — it's a low-friction path to report #4 (now a confirmed,
  high-severity finding), but also means don't send anything you're not confident
  in, because it becomes public regardless of outcome.
  Their reward table: **"Critical (RCE, Catastrophic Cryptography Failure):
  $200+"** — an inverted subgroup check that defeats torsion-attack protection in
  signature verification is a reasonable fit for that tier, though the payout is
  modest either way (this is a $200-class program, not a $15k one).

**Net: one strong finding per target** — #1 for ownCloud (via their own VDP site,
not HackerOne), #4 for paragonie (via email, since HackerOne is paused there too).
I have not sent anything anywhere; both are still yours to review and send.
