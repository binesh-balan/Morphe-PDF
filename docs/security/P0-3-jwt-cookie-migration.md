# P0 #3 — Session JWT moved out of `localStorage` into an HttpOnly cookie

**Status: implemented, DISABLED BY DEFAULT, stubbed suite green, IdP round trips unverified.**

> Cookie mode is opt-in behind `VITE_AUTH_COOKIE_MODE=true`. It shipped on by default and
> that was a mistake: `build.yml` only triggers on PRs targeting `main`, this migration
> targeted another branch, and #6/#9 touched no frontend paths — so the frontend suite never
> ran against it. When it finally did (via a Dependabot PR touching the frontend lockfile) it
> failed **30 authenticated UI tests**, starting with the settings/config button never
> rendering.
>
> **Those failures are now fixed** — see "Why the suite failed" below. The stubbed suite
> passes identically in both modes (276 passed / 25 skipped, chromium, `vite preview` over a
> production build). The flag stays **off** because the stubbed suite cannot exercise the
> parts most likely to break: the Entra ID and SAML round trips, real logout cookie expiry,
> and the desktop/API-key paths.
>
> **The token therefore still lives in `localStorage` — P0 #3 is not closed.** The backend
> half is additive and always active: it sets the HttpOnly cookie *and* returns the body
> token, and accepts either on the way back. So the server is ready; only the frontend flip
> is gated.

## Why the suite failed

Two defects, one real and one in the tests.

**1. The session bootstrap never asked the server.** `SpringAuthClient.getSession()` opened
with `const token = getToken(); if (!token) return { session: null }`. In cookie mode
`getToken()` is null *by design*, so every bootstrap reported "no session" without making a
request. `UseSession` → `session` → `user` is what gates the settings/config button, which is
why the symptom read as a missing button and 30 specs timed out waiting for it. Every other
entry point — `AuthCallback`, `getCurrentUser`, session monitoring — routes through the same
call, so the one guard disabled all of them.

It now falls through to `/api/v1/auth/me` when the `stirling_session` marker is present,
sending no `Authorization` header and letting the browser's HttpOnly cookie authenticate the
request. No marker still means no request and no session.

Cookie mode cannot read token expiry, so `expires_at` is 0 and the *proactive* refresh in
`startSessionMonitoring()` never fires. The reactive path still covers it: a 401 triggers
`refreshSession()` through the response interceptor. Give `/auth/me` an expiry field if
proactive refresh becomes necessary.

**2. Three more specs seeded a token without the marker.** The original pass fixed
`stub-test-base.ts` plus `audit-log-ui`, `license-states`, `first-login-modal` and
`api-keys-ui`, but `teams-ui`, `login-agreement-modal` and `premium-feature-gates` build
their own setup instead of using the fixture, so they were missed. All three now seed
`stirling_session` alongside `stirling_jwt`.

`live/authentication-login.spec.ts` had the mirror-image bug: it cleared the cookie and the
token to simulate an expired session but left the marker, so the client believed it still had
a session and went through a refresh attempt instead of the intended clean logged-out state.
It now removes the marker too. **Unverified** — the live suite needs a backend.

**Original status note:** The code is written and parses; none of it has been
exercised against a browser, an identity provider, or the test suite. Treat this document as
the test plan, not as a record of something already proven.

## What changed

The backend now issues the session JWT as an `HttpOnly; Secure; SameSite=Lax` cookie and
accepts it on the way back in. Web builds no longer keep the token in `localStorage`. The
desktop client and programmatic API callers keep using bearer tokens.

`SameSite` is `Lax`, not `Strict`, deliberately: `Strict` omits the cookie on the cross-site
navigation back from an identity provider, so the first request after an Entra ID or SAML
redirect arrives unauthenticated and loops the login. `Lax` still withholds the cookie from
cross-site POST and XHR, which is the property that matters.

### Backend

| File | Change |
|---|---|
| `common/constants/JwtConstants.java` | `JWT_COOKIE_NAME` |
| `security/service/JwtServiceInterface.java` | Declares `addTokenToResponse` / `clearTokenCookie` |
| `security/service/JwtService.java` | Reads the cookie first, then falls back to the `Authorization` header; builds the cookie via `ResponseCookie`; `Secure` overridable through `morphe.security.jwt.cookie.secure` |
| `security/controller/api/AuthController.java` | Cookie set on login and refresh, expired on logout |
| `security/CustomAuthenticationSuccessHandler.java` | Form login previously minted a JWT and discarded it; it is now delivered as a cookie |
| `security/oauth2/CustomOAuth2AuthenticationSuccessHandler.java` | Cookie set before the redirect |
| `security/saml2/CustomSaml2AuthenticationSuccessHandler.java` | Cookie set before the redirect |
| `security/configuration/SecurityConfiguration.java` | CSRF configuration added behind a flag (see below) |

The change is **additive**: `access_token` still appears in the login and refresh response
bodies, and the OAuth/SAML redirect still carries the token in its URL fragment. Nothing that
worked before stops working, which is what makes it safe to deploy ahead of the frontend
flip. Fragments are not sent to servers and do not appear in proxy logs, though they do enter
browser history — remove the fragment once you have confirmed no client depends on it.

### Frontend

New `core/services/authTransport.ts` is the single place that knows how the session is
carried. `isCookieMode()` is true for web builds and false for desktop (detected via
`__TAURI_INTERNALS__`); override with `VITE_AUTH_COOKIE_MODE=false` to fall back to the old
behaviour.

In cookie mode `getToken()` returns `null`, so no `Authorization` header is attached and the
browser's cookie carries the session. Every client already sets `withCredentials`.

Because an HttpOnly cookie is invisible to script, "is the user logged in?" can no longer be
answered by looking for the token. A non-sensitive `stirling_session` marker replaces it —
it carries no credential and is a UI hint only. The server remains the authority.

Rewired: `httpClient.ts`, `apiClientSetup.ts`, `useRequestHeaders.ts`, `springAuthClient.ts`
(13 sites), `AuthCallback.tsx`, `ErrorBoundary.tsx`, `LoginAgreementModal.tsx`,
`useOnboardingOrchestrator.ts`, `httpErrorHandler.ts`. Desktop modules are untouched.

Two behavioural traps handled while rewiring:

- The 401 auto-refresh path was gated on a readable token, so in cookie mode it would never
  have fired. It now gates on `hasSession()`.
- The refresh handler treated a missing body token as an error. In cookie mode the refreshed
  cookie is already on the response, so an absent body token is no longer fatal.

### CSRF — added but **off by default**

`morphe.security.csrf.enabled` (default `false`). Cookie-borne credentials are sent
automatically by the browser, which reintroduces CSRF exposure that bearer tokens did not
have. `SameSite=Lax` already blocks the cross-site POST and XHR vector; token-based CSRF is
defence in depth on top of that.

It ships disabled because enabling it is not a safe unattended change:

- the SAML assertion-consumer endpoint receives a legitimate **cross-site POST** from the
  identity provider and must stay exempt (`/login/saml2/sso/**` and `/saml2/**` are already
  in the ignore list);
- any client authenticating with `X-API-KEY` cannot present a CSRF token.

The frontend side already works — `apiClientSetup.ts` reads the `XSRF-TOKEN` cookie and sends
`X-XSRF-TOKEN`, and that header is already in the CORS allow-list. Turn the flag on, then run
the SAML and API-key checks below.

## Test plan

Nothing below is verifiable by inspection. Run all of it.

1. **Form login.** Confirm `Set-Cookie` carries `HttpOnly; Secure; SameSite=Lax`, and that
   `localStorage.getItem("stirling_jwt")` is `null` in a web build.
2. **Authenticated calls.** Confirm requests succeed with **no** `Authorization` header.
3. **Refresh.** Let the token expire; confirm auto-refresh fires and the cookie is reissued.
4. **Logout.** Confirm the cookie is expired server-side, then replay the old cookie and
   expect `401`. Clearing client state alone is not sufficient.
5. **Entra ID (OIDC) round trip.** This is where the `SameSite` trap surfaces. Confirm login
   completes and lands authenticated.
6. **SAML round trip.** Same, and confirm the IdP's cross-site POST to the ACS endpoint is
   not rejected.
7. **Desktop app** against a remote server — bearer auth must be unchanged.
8. **API key and MCP chains** — must be unaffected.
9. **With `morphe.security.csrf.enabled=true`:** a cross-site POST without `X-XSRF-TOKEN` is
   rejected; the app's own requests still succeed; SAML login still completes; API-key callers
   still work.
10. **Existing suites — fixed and verified.** Every seeding site now also sets the
    `stirling_session` marker that `hasSession()` reads: `core/tests/helpers/stub-test-base.ts`
    plus `audit-log-ui`, `license-states`, `first-login-modal`, `api-keys-ui`, `teams-ui`,
    `login-agreement-modal` and `premium-feature-gates`. `stirling_jwt` is retained for
    desktop/bearer mode.

    Verify with a production build, not the dev server — `vite`'s on-demand transforms blow
    the 30s navigation timeout on the heavy tool pages and manufacture ~20 failures that have
    nothing to do with auth (38 minutes and 29 failures, against 4 minutes and 0 failures for
    the same commit built and previewed):

    ```bash
    cd frontend
    VITE_BUILD_FOR_PREVIEW=1 VITE_AUTH_COOKIE_MODE=true npx vite build editor
    cd editor && CI=1 npx playwright test --project=stubbed --workers=4
    ```

## Rollback

Set `VITE_AUTH_COOKIE_MODE=false` and rebuild the frontend. The backend change is additive
and needs no rollback — it keeps returning `access_token` in the body and accepting bearer
headers.

## Definition of done

- No web-build code path reads or writes `stirling_jwt` in `localStorage` — **done in code**,
  confirm at runtime.
- Stubbed Playwright suite passes with the flag on — **done**, at parity with bearer mode.
- OIDC and SAML logins complete — **unverified**.
- Desktop and API-key authentication unchanged — **unverified**.
- CSRF enabled for cookie-authenticated routes — **not done**; flag exists, still off.
- Token removed from the OAuth/SAML redirect fragment — **not done**; deliberate, pending
  confirmation that no client depends on it.
