# FastAPI Passkey Starter Kit

Starter architecture for a FastAPI user system with passkeys as the only authentication method.

## Current Prototype Scope

- Backend API scaffold implemented with FastAPI + SQLAlchemy (SQLite by default).
- Full role + signup-token domain model implemented.
- WebAuthn is implemented with `duo-labs/py_webauthn` for registration/authentication options and verification.
- Optional fallback mode exists for non-WebAuthn testing only: `APP_INSECURE_DEV_WEBAUTHN=true`.

## Core Principles

- Authentication is passkey-only (WebAuthn) for all accounts.
- No email and no password.
- Signup tokens are authorization for account creation, not login credentials.
- Roles are `user`, `admin`, and `superadmin`.
- Public `user` signup mode is runtime-configurable by `superadmin`.

## Local Development

1. Install dependencies:
   - `uv sync --dev`
2. Create bootstrap superadmin token:
   - `uv run python scripts/create_bootstrap_token.py --expires-in-minutes 120`
3. Run API:
   - `uv run uvicorn app.main:app --reload`
4. Open pages:
   - `http://localhost:8000/signup`
   - `http://localhost:8000/admin_signup`
   - `http://localhost:8000/login`
   - `http://localhost:8000/passkeys`
   - `http://localhost:8000/admin`
   - `http://localhost:8000/me`

### HTTPS and localhost

- Real WebAuthn requires a secure context.
- `http://localhost` is accepted by modern browsers for local dev.
- For non-localhost environments, use HTTPS and ensure RP/origin match.

## Role and Signup Model

### Bootstrap first superadmin

- The system is bootstrapped with a one-time `superadmin` signup token generated from CLI.
- The first superadmin signs up from the web frontend using:
  - `username`
  - one-time signup token
  - passkey registration

### Ongoing privileged signup

- Superadmins can generate one-time signup tokens for:
  - `admin`
  - `superadmin`
- Each token:
  - is single-use
  - has an expiration time
  - is stored as a hash in DB (never plaintext at rest)

### Normal user signup

- Signup mode is controlled by a superadmin setting:
  - `open`: public signup is allowed (`username + passkey`).
  - `invite_only`: signup requires one-time token (`username + token + passkey`).
- This setting only affects normal `user` accounts.
- `admin` and `superadmin` signups remain token-required regardless of mode.

### Signup mode governance

- Only `superadmin` can change `public_user_signup_mode`.
- Changes take effect immediately for new signup attempts.
- Every mode change should be written to an audit log:
  - actor user id
  - previous mode
  - new mode
  - timestamp

## Signup and Login Flows

### Signup flow

1. User submits `username` (and token when required by role/mode).
2. Server validates token if present (exists, unused, unexpired, role scope).
3. Server starts WebAuthn registration challenge.
4. Client creates passkey.
5. Server verifies attestation and, in one transaction:
   - creates user with role
   - stores first passkey credential
   - marks token as used (if token-based signup)
6. Server creates session and redirects to authenticated page.

### Login flow

1. User starts passkey login.
2. Server issues WebAuthn assertion challenge.
3. Client signs challenge with passkey.
4. Server verifies assertion and creates session.

## Passkey Management

Authenticated users can:

- list registered passkeys
- rename passkey labels (device nicknames)
- add additional passkeys
- remove passkeys, except the last remaining credential

If a user loses all passkeys, the account is unrecoverable by design.

## Security Notes

- Protect signup token secrets in transit and UI handling.
- Hash token values before storing them.
- Use short expiry windows for privileged signup tokens.
- Enforce atomic signup transaction to avoid partial state.
- Apply DB constraints and transaction locking to prevent race conditions.
- Keep `APP_INSECURE_DEV_WEBAUTHN=false` in production.

## API Endpoints (Prototype)

- Auth:
  - `GET /api/auth/public-signup-mode`
  - `POST /api/auth/signup/begin`
  - `POST /api/auth/signup/complete`
  - `POST /api/auth/login/begin`
  - `POST /api/auth/login/complete`
  - `POST /api/auth/logout`
  - `GET /api/auth/me`
- Passkeys:
  - `GET /api/passkeys`
  - `POST /api/passkeys/begin-add`
  - `POST /api/passkeys/complete-add`
  - `PATCH /api/passkeys/{passkey_id}`
  - `DELETE /api/passkeys/{passkey_id}`
- Admin:
  - `GET /api/admin/settings/public-signup-mode`
  - `PUT /api/admin/settings/public-signup-mode`
  - `POST /api/admin/signup-tokens`
  - `GET /api/admin/signup-tokens`

## Prototype Web Routes

- `GET /signup`: user signup form (username + optional token + browser passkey prompt).
- `GET /admin_signup`: privileged signup form (username + required token + browser passkey prompt).
- `GET /login`: single login page for all roles.
- `GET /passkeys`: passkey management page (list, add, rename, delete).
- `GET /admin`: admin console UI for signup mode and invite token management.
- `GET /me`: signed-in session and passkey viewer.
