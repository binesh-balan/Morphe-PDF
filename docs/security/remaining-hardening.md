# Remaining hardening

What is still outstanding after the P0 and P1/P2 remediation work, why, and what closing
each one requires. Everything here is deliberate — nothing was silently skipped.

## Requires a build or a running instance

These cannot be done or verified in a static environment.

### resolutionStrategy.force does not work in this build

**Important build defect, verified empirically.** Every `resolutionStrategy.force` inside
`subprojects { configurations.configureEach { … } }` in `build.gradle` is **inert** — the
declared version is never applied. Several of those lines carry CVE-mitigation comments
(`commons-lang3` CVE-2025-48924, `commons-io` CVE-2024-47554, `gson` CVE-2022-25647,
`rhino` CVE-2025-66453). None of them is mitigating anything.

Proven by adding a force for `httpcore5` to 5.4.3 there and regenerating the lock state:
it stayed on 5.3.6. Re-expressed as `resolutionStrategy.eachDependency` — which runs *at
resolution time* rather than configuration time — it applied immediately.

The Morphe-PDF security floors at the bottom of `build.gradle` use `eachDependency` for
this reason. **The pre-existing `force` block has been left alone** rather than converted:
after the Spring Boot 4.0.8 bump every version it targets already resolves clean, so
converting it would change resolved versions for no security gain and some risk. Convert
it when one of those pins actually matters again — and verify against the lockfile, never
by reading the build file.

### Generate Gradle lock state

**Done.** Lock state committed for the root project and all three modules.

Locking runs in `LockMode.LENIENT`, not the default STRICT, because the build has three
flavours that resolve different dependency sets — `core`
(`DISABLE_ADDITIONAL_FEATURES=true`), `proprietary`, and `saas`. Lock state is
per-configuration, not per-flavour, so STRICT fails the `core` flavour with *"Did not
resolve &lt;x&gt; which is part of the dependency lock state"* for every security/SAML/JPA
module the wider flavours pull in.

LENIENT still pins every version the lock records, which is what makes the tree
reproducible and scannable. The trade-off: a **new** dependency absent from the lock state
no longer fails the build. Regenerate and review the lockfile diff whenever dependencies
change.

```bash
./gradlew resolveAndLockAll --write-locks
git add '**/gradle.lockfile' && git commit -m "build: commit Gradle dependency lock state"
```

Re-run and commit whenever a dependency changes. The `sbom` job in `security-scan.yml`
warns if the SBOM comes back with fewer than 50 Maven components.

### Validate the Content-Security-Policy

`SecurityHeadersFilter` ships a strict default policy that has never been exercised against
a browser. Run with `morphe.security.csp.report-only=true`, load every tool page, confirm
the console reports no violations, then set it back to `false`. Swagger UI is the most
likely thing to trip it, since `script-src` carries no `'unsafe-inline'`.

### Runtime network and process observation

Phases 18–19 of the assessment were never run. The air-gap conclusion rests on static
analysis: every runtime outbound call is behind a flag that is off by default, and the
container entrypoint contains no network calls. Confirm it empirically — run the built
image on an isolated network with egress denied, exercise the tools, and capture traffic.

### Pin the Calibre download

`docker/base/Dockerfile` verifies Ghostscript (sha512), QPDF (sha256) and ImageMagick
(sha256), but Calibre is still fetched unverified — its published checksum could not be
retrieved when the pins were added. Calibre ships per-architecture, so this needs two
values. To close it:

```bash
curl -fsSLO https://download.calibre-ebook.com/9.4.0/calibre-9.4.0-x86_64.txz
sha256sum calibre-9.4.0-x86_64.txz     # repeat for the arm64 asset
```

Then add `CALIBRE_SHA256_X86_64` / `CALIBRE_SHA256_ARM64` build args and a `sha256sum -c`
step, matching the pattern already used for the other three. Prefer verifying Calibre's
GPG signature if you can establish the signing key out of band.

Worth checking first whether you need Calibre at all — the entrypoint currently logs
`"issue with calibre in current version, feature currently disabled"`, so the advanced
HTML/ebook path it supports may be dead weight. Dropping it removes a large parser from
the attack surface entirely.

## Cannot be fixed upstream yet

### `extract-zip` 2.0.1 — GHSA-jmr9-qjv8-65gv (High)

Symlink path traversal. **2.0.1 is the latest published version — no fix exists.** Reached
only through `@puppeteer/browsers`, a development dependency; Trivy's production scan does
not report it. It never ships. Re-check when upstream publishes a fix.

### `fast-uri` 3.1.4 — GHSA-7p8r-x3mc-p8w7 (High)

Host confusion via backslash authority. Fixed in 4.x, but it is pulled in as `^3.0.1` by
`table` → `ajv` (ESLint tooling). Forcing 4.x through an `overrides` entry crosses a major
version with API changes, to patch a dev-only lint dependency. Not worth the breakage.
Re-check when `ajv` widens its range.

Both are dev-only. The two advisories that reached production (`nanoid` CVE-2026-67213 and
`react-router` GHSA-qwww-vcr4-c8h2) are fixed.

## Deliberate design decisions

### P0 #3 — session JWT still in `localStorage` (cookie mode built, not enabled)

Still the largest open item, and **not closed** despite the migration being merged. The
backend issues and accepts the HttpOnly cookie, but the frontend flip is still gated behind
`VITE_AUTH_COOKIE_MODE=true`.

The 30 authenticated UI test failures that gated it are **fixed**: the session bootstrap
(`SpringAuthClient.getSession()`) returned early whenever no token was readable, so in cookie
mode it never asked `/api/v1/auth/me` and the app rendered logged-out. It now verifies against
the server when the `stirling_session` marker is present, and three more specs that seeded a
token without that marker were corrected. The stubbed suite passes identically in both modes
(276 passed / 25 skipped).

What still blocks the flip is everything the stubbed suite cannot reach: the Entra ID and SAML
round trips, real logout cookie expiry, and desktop/API-key auth.

Two process failures let an unvalidated auth change reach `main`, both worth avoiding again:

- `build.yml` only triggers on `pull_request: branches: ["main"]`. A PR stacked on another
  branch never runs it, and **retargeting a PR does not re-trigger workflows** — close and
  reopen, or push a commit.
- `frontend-validation` and `playwright-e2e` are path-filtered, so backend/workflow/lockfile
  PRs skip them entirely. A frontend change merged this way can sit unverified indefinitely.

To close it: work the test plan in
[`P0-3-jwt-cookie-migration.md`](./P0-3-jwt-cookie-migration.md) against a real deployment —
Entra ID and SAML round trips especially — then flip the flag's default. Verify the suite
against a production build, never the dev server; the reason is documented there.

### Cross-Origin-Opener-Policy is not set

`same-origin` severs `window.opener` and breaks OAuth/SSO popup flows. Set it at the
reverse proxy only after confirming your identity provider uses full-page redirects rather
than a popup.

### Committed test certificates and H2 fixtures are kept

The assessment suggested deleting them. That was over-reach — they are throwaway fixtures
under `src/test/resources` that real tests depend on, they are referenced only from `.spec`
and `.test` files, and removing them breaks the suite for no security gain.

### GitHub Actions are currently disabled on the fork

Disabled to stop the inherited `push-docker.yml` publishing a container image to ghcr.io on
push to `main`. That workflow and 16 other publish/deploy/sync workflows have since been
removed, so Actions can be re-enabled:

```bash
gh api -X PUT repos/binesh-balan/Morphe-PDF/actions/permissions -F enabled=true
```

## Not yet started

- **Entra ID wiring.** OIDC and SAML2 are both supported by the application; nothing is
  configured. Enforce MFA at the IdP — Morphe-PDF has none of its own.
- **Parser sandboxing.** Ghostscript, LibreOffice, ImageMagick and Calibre are the largest
  inherent attack surface, and it is inherent rather than a code defect. Run them in a
  network-less sidecar with a tailored seccomp profile.
- **Image signing and admission control.** Sign built images (cosign) and require valid
  signatures at deploy time.
- **Branch protection** on `main`, requiring the `security-scan` and `all-checks-passed`
  gates.
- **Make the secret-scan gate blocking.** `security-scan.yml` runs gitleaks with
  `--exit-code 0`, so it reports without failing. A full-history scan surfaces ~84 findings,
  all of the false-positive classes verified during the assessment (interactive
  "enter the password:" prompts, PostHog's public `phc_` key, test fixtures) — failing every
  run would train people to ignore the job. Generate a baseline of the accepted findings,
  commit it, then add `--baseline-path` with `--exit-code 1` so only *new* secrets fail.
- **Dependency graph and Dependabot: enabled.** Both were turned on via
  `PATCH /repos/{owner}/{repo}` with `security_and_analysis[dependabot_security_updates]`,
  which implicitly enables the dependency graph it requires — contrary to an earlier
  note here that it was UI-only for forks. `dependency-review` is now blocking.
- **OSV gate in `security-scan.yml` is still advisory.** Java is at 0 advisories; the
  only findings left are the two accepted dev-only npm ones. Uncomment the
  `raise SystemExit` there once those are formally accepted or fixed upstream.