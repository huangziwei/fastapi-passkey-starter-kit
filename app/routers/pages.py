from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import get_db
from app.models import Role
from app.services.session_service import get_user_by_session_token

router = APIRouter(include_in_schema=False)


SIGNUP_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>__TITLE__</title>
  <style>
    :root {
      --bg: #f7fafc;
      --panel: #ffffff;
      --text: #1a202c;
      --muted: #4a5568;
      --accent: #0b7285;
      --danger: #c92a2a;
      --border: #d9e2ec;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Avenir Next", "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at 10% 10%, #d6f5ff 0, transparent 35%),
        radial-gradient(circle at 90% 90%, #ffe8cc 0, transparent 30%),
        var(--bg);
      display: grid;
      place-items: center;
      padding: 24px;
    }
    .card {
      width: min(560px, 100%);
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 24px;
      box-shadow: 0 12px 30px rgba(23, 43, 77, 0.08);
    }
    h1 { margin: 0 0 8px; font-size: 1.6rem; }
    p { margin: 0 0 16px; color: var(--muted); }
    label { display: block; font-size: 0.92rem; margin: 12px 0 6px; }
    input {
      width: 100%;
      padding: 10px 12px;
      border: 1px solid var(--border);
      border-radius: 10px;
      font-size: 1rem;
    }
    button {
      margin-top: 16px;
      width: 100%;
      border: 0;
      border-radius: 10px;
      padding: 11px 12px;
      background: var(--accent);
      color: white;
      font-size: 1rem;
      cursor: pointer;
    }
    .status { margin-top: 14px; min-height: 20px; font-size: 0.95rem; }
    .err { color: var(--danger); }
    .ok { color: #2b8a3e; }
    .row {
      display: flex;
      gap: 10px;
      margin-top: 14px;
      flex-wrap: wrap;
    }
    .row a { color: var(--accent); text-decoration: none; }
  </style>
</head>
<body>
  <main class="card">
    <h1>__HEADING__</h1>
    <p>__TOKEN_NOTE__</p>
    <form id="signup-form">
      <label for="username">Username</label>
      <input id="username" name="username" autocomplete="username" required minlength="3" maxlength="32" />

      <div id="token-wrap">
        <label for="token">Signup token</label>
        <input id="token" name="token" __TOKEN_REQUIRED_ATTR__ />
      </div>

      <button id="submit-btn" type="submit">Create account</button>
    </form>
    <div id="status" class="status"></div>
    <div class="row">
      <a href="/signup">User signup</a>
      <a href="/admin_signup">Admin signup</a>
      <a href="/login">Login</a>
      <a href="/passkeys">Passkeys</a>
      <a href="/admin">Admin</a>
      <a href="/me">Session view</a>
    </div>
  </main>

  <script>
    const TOKEN_REQUIRED = __TOKEN_REQUIRED_JS__;
    const MODE_AWARE = __MODE_AWARE_JS__;

    function setStatus(message, ok) {
      const status = document.getElementById("status");
      status.className = ok ? "status ok" : "status err";
      status.textContent = message;
    }

    function base64urlToUint8Array(base64url) {
      const pad = "=".repeat((4 - (base64url.length % 4)) % 4);
      const base64 = (base64url + pad).replace(/-/g, "+").replace(/_/g, "/");
      const raw = atob(base64);
      const bytes = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i++) {
        bytes[i] = raw.charCodeAt(i);
      }
      return bytes;
    }

    function uint8ArrayToBase64url(bytes) {
      let binary = "";
      for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }

    function serializeRegistrationCredential(credential) {
      return {
        id: credential.id,
        rawId: uint8ArrayToBase64url(new Uint8Array(credential.rawId)),
        type: credential.type,
        response: {
          attestationObject: uint8ArrayToBase64url(new Uint8Array(credential.response.attestationObject)),
          clientDataJSON: uint8ArrayToBase64url(new Uint8Array(credential.response.clientDataJSON)),
          transports: credential.response.getTransports ? credential.response.getTransports() : [],
        },
        clientExtensionResults: credential.getClientExtensionResults
          ? credential.getClientExtensionResults()
          : {},
      };
    }

    async function postJson(url, payload) {
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(payload),
      });

      let data = {};
      try {
        data = await response.json();
      } catch (_err) {
        // no-op
      }

      if (!response.ok) {
        throw new Error(data.detail || "Request failed");
      }

      return data;
    }

    async function initSignupMode() {
      const tokenWrap = document.getElementById("token-wrap");
      const tokenInput = document.getElementById("token");

      if (TOKEN_REQUIRED) {
        tokenWrap.style.display = "block";
        tokenInput.required = true;
        return;
      }

      if (!MODE_AWARE) {
        tokenWrap.style.display = "none";
        tokenInput.required = false;
        return;
      }

      try {
        const modeResp = await fetch("/api/auth/public-signup-mode", { credentials: "include" });
        const modeJson = await modeResp.json();
        if (modeResp.ok && modeJson.mode === "invite_only") {
          tokenWrap.style.display = "block";
          tokenInput.required = true;
          tokenInput.placeholder = "Invite token required";
        } else {
          tokenWrap.style.display = "none";
          tokenInput.required = false;
        }
      } catch (_err) {
        tokenWrap.style.display = "none";
        tokenInput.required = false;
      }
    }

    document.getElementById("signup-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      setStatus("", false);

      const submitButton = document.getElementById("submit-btn");
      submitButton.disabled = true;

      const username = document.getElementById("username").value.trim();
      const token = document.getElementById("token").value.trim();

      if (TOKEN_REQUIRED && !token) {
        setStatus("Signup token is required.", false);
        submitButton.disabled = false;
        return;
      }

      if (!window.PublicKeyCredential || !navigator.credentials) {
        setStatus("Passkeys are not supported in this browser.", false);
        submitButton.disabled = false;
        return;
      }

      try {
        const beginPayload = { username };
        if (token) beginPayload.token = token;

        const begin = await postJson("/api/auth/signup/begin", beginPayload);

        const publicKeyOptions = begin.public_key;
        publicKeyOptions.challenge = base64urlToUint8Array(publicKeyOptions.challenge);
        publicKeyOptions.user.id = base64urlToUint8Array(publicKeyOptions.user.id);
        publicKeyOptions.excludeCredentials = (publicKeyOptions.excludeCredentials || []).map((item) => ({
          ...item,
          id: base64urlToUint8Array(item.id),
        }));

        const credential = await navigator.credentials.create({ publicKey: publicKeyOptions });
        if (!credential || !credential.rawId) {
          throw new Error("Failed to create passkey credential");
        }

        await postJson("/api/auth/signup/complete", {
          challenge_id: begin.challenge_id,
          credential: serializeRegistrationCredential(credential),
        });

        setStatus("Signup successful. Redirecting...", true);
        window.setTimeout(() => { window.location.href = "/me"; }, 500);
      } catch (error) {
        setStatus(error.message || String(error), false);
      } finally {
        submitButton.disabled = false;
      }
    });

    initSignupMode();
  </script>
</body>
</html>
"""


LOGIN_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>__TITLE__</title>
  <style>
    :root {
      --bg: #f7fafc;
      --panel: #ffffff;
      --text: #1a202c;
      --muted: #4a5568;
      --accent: #0b7285;
      --danger: #c92a2a;
      --border: #d9e2ec;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Avenir Next", "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at 10% 10%, #d6f5ff 0, transparent 35%),
        radial-gradient(circle at 90% 90%, #ffe8cc 0, transparent 30%),
        var(--bg);
      display: grid;
      place-items: center;
      padding: 24px;
    }
    .card {
      width: min(560px, 100%);
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 24px;
      box-shadow: 0 12px 30px rgba(23, 43, 77, 0.08);
    }
    h1 { margin: 0 0 8px; font-size: 1.6rem; }
    p { margin: 0 0 16px; color: var(--muted); }
    label { display: block; font-size: 0.92rem; margin: 12px 0 6px; }
    input {
      width: 100%;
      padding: 10px 12px;
      border: 1px solid var(--border);
      border-radius: 10px;
      font-size: 1rem;
    }
    button {
      margin-top: 16px;
      width: 100%;
      border: 0;
      border-radius: 10px;
      padding: 11px 12px;
      background: var(--accent);
      color: white;
      font-size: 1rem;
      cursor: pointer;
    }
    .status { margin-top: 14px; min-height: 20px; font-size: 0.95rem; }
    .err { color: var(--danger); }
    .ok { color: #2b8a3e; }
    .row {
      display: flex;
      gap: 10px;
      margin-top: 14px;
      flex-wrap: wrap;
    }
    .row a { color: var(--accent); text-decoration: none; }
  </style>
</head>
<body>
  <main class="card">
    <h1>__HEADING__</h1>
    <p>__NOTE__</p>
    <form id="login-form">
      <label for="username">Username</label>
      <input id="username" name="username" autocomplete="username" required minlength="3" maxlength="32" />

      <button id="submit-btn" type="submit">Login with passkey</button>
    </form>
    <div id="status" class="status"></div>
    <div class="row">
      <a href="/signup">User signup</a>
      <a href="/admin_signup">Admin signup</a>
      <a href="/login">Login</a>
      <a href="/passkeys">Passkeys</a>
      <a href="/admin">Admin</a>
      <a href="/me">Session view</a>
    </div>
  </main>

  <script>
    function setStatus(message, ok) {
      const status = document.getElementById("status");
      status.className = ok ? "status ok" : "status err";
      status.textContent = message;
    }

    function base64urlToUint8Array(base64url) {
      const pad = "=".repeat((4 - (base64url.length % 4)) % 4);
      const base64 = (base64url + pad).replace(/-/g, "+").replace(/_/g, "/");
      const raw = atob(base64);
      const bytes = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i++) {
        bytes[i] = raw.charCodeAt(i);
      }
      return bytes;
    }

    function uint8ArrayToBase64url(bytes) {
      let binary = "";
      for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }

    function serializeAuthenticationCredential(credential) {
      const response = credential.response;
      return {
        id: credential.id,
        rawId: uint8ArrayToBase64url(new Uint8Array(credential.rawId)),
        type: credential.type,
        response: {
          authenticatorData: uint8ArrayToBase64url(new Uint8Array(response.authenticatorData)),
          clientDataJSON: uint8ArrayToBase64url(new Uint8Array(response.clientDataJSON)),
          signature: uint8ArrayToBase64url(new Uint8Array(response.signature)),
          userHandle: response.userHandle
            ? uint8ArrayToBase64url(new Uint8Array(response.userHandle))
            : null,
        },
        clientExtensionResults: credential.getClientExtensionResults
          ? credential.getClientExtensionResults()
          : {},
      };
    }

    async function postJson(url, payload) {
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(payload),
      });

      let data = {};
      try {
        data = await response.json();
      } catch (_err) {
        // no-op
      }

      if (!response.ok) {
        throw new Error(data.detail || "Request failed");
      }

      return data;
    }

    document.getElementById("login-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      setStatus("", false);

      const submitButton = document.getElementById("submit-btn");
      submitButton.disabled = true;

      const username = document.getElementById("username").value.trim();

      if (!window.PublicKeyCredential || !navigator.credentials) {
        setStatus("Passkeys are not supported in this browser.", false);
        submitButton.disabled = false;
        return;
      }

      try {
        const begin = await postJson("/api/auth/login/begin", { username });
        const publicKeyOptions = begin.public_key;
        publicKeyOptions.challenge = base64urlToUint8Array(publicKeyOptions.challenge);
        publicKeyOptions.allowCredentials = (publicKeyOptions.allowCredentials || []).map((item) => ({
          ...item,
          id: base64urlToUint8Array(item.id),
        }));

        const assertion = await navigator.credentials.get({ publicKey: publicKeyOptions });
        if (!assertion || !assertion.rawId) {
          throw new Error("Failed to verify passkey");
        }

        await postJson("/api/auth/login/complete", {
          challenge_id: begin.challenge_id,
          credential: serializeAuthenticationCredential(assertion),
        });

        setStatus("Login successful. Redirecting...", true);
        window.setTimeout(() => { window.location.href = "/me"; }, 400);
      } catch (error) {
        setStatus(error.message || String(error), false);
      } finally {
        submitButton.disabled = false;
      }
    });
  </script>
</body>
</html>
"""


PASSKEYS_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Passkey Management</title>
  <style>
    :root {
      --bg: #f7fafc;
      --panel: #ffffff;
      --text: #1a202c;
      --muted: #4a5568;
      --accent: #0b7285;
      --danger: #c92a2a;
      --border: #d9e2ec;
      --ok: #2b8a3e;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Avenir Next", "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at 10% 10%, #d6f5ff 0, transparent 35%),
        radial-gradient(circle at 90% 90%, #ffe8cc 0, transparent 30%),
        var(--bg);
      padding: 24px;
    }
    .container {
      max-width: 860px;
      margin: 0 auto;
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 20px;
      box-shadow: 0 12px 30px rgba(23, 43, 77, 0.08);
    }
    h1 { margin: 0 0 8px; font-size: 1.6rem; }
    p { margin: 0 0 14px; color: var(--muted); }
    .row {
      display: flex;
      gap: 10px;
      margin-top: 14px;
      flex-wrap: wrap;
    }
    .row a { color: var(--accent); text-decoration: none; }
    .status { margin-top: 12px; min-height: 20px; font-size: 0.95rem; }
    .err { color: var(--danger); }
    .ok { color: var(--ok); }
    .add {
      margin-top: 14px;
      padding: 14px;
      border: 1px solid var(--border);
      border-radius: 10px;
      background: #fbfdff;
    }
    label {
      display: block;
      margin: 10px 0 6px;
      font-size: 0.9rem;
    }
    input {
      width: 100%;
      padding: 10px 12px;
      border: 1px solid var(--border);
      border-radius: 10px;
      font-size: 1rem;
    }
    button {
      border: 0;
      border-radius: 8px;
      padding: 9px 12px;
      background: var(--accent);
      color: #fff;
      cursor: pointer;
    }
    .danger {
      background: var(--danger);
    }
    .list {
      margin-top: 16px;
      display: grid;
      gap: 10px;
    }
    .item {
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px;
      background: #fff;
    }
    .meta {
      font-size: 0.86rem;
      color: var(--muted);
      margin-bottom: 8px;
      word-break: break-all;
    }
    .actions {
      margin-top: 10px;
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }
  </style>
</head>
<body>
  <main class="container">
    <h1>Passkey management</h1>
    <p id="user-line">Loading user...</p>
    <div class="row">
      <a href="/signup">User signup</a>
      <a href="/admin_signup">Admin signup</a>
      <a href="/login">Login</a>
      <a href="/passkeys">Passkeys</a>
      <a href="/admin">Admin</a>
      <a href="/me">Session view</a>
    </div>

    <section class="add">
      <label for="new-label">New passkey label</label>
      <input id="new-label" value="Additional passkey" maxlength="120" />
      <div class="actions">
        <button id="add-btn">Add passkey</button>
        <button id="refresh-btn" type="button">Refresh</button>
        <button id="logout-btn" class="danger" type="button">Logout</button>
      </div>
      <div id="status" class="status"></div>
    </section>

    <section class="list" id="passkey-list"></section>
  </main>

  <script>
    function setStatus(message, ok) {
      const status = document.getElementById("status");
      status.className = ok ? "status ok" : "status err";
      status.textContent = message;
    }

    function base64urlToUint8Array(base64url) {
      const pad = "=".repeat((4 - (base64url.length % 4)) % 4);
      const base64 = (base64url + pad).replace(/-/g, "+").replace(/_/g, "/");
      const raw = atob(base64);
      const bytes = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i++) {
        bytes[i] = raw.charCodeAt(i);
      }
      return bytes;
    }

    function uint8ArrayToBase64url(bytes) {
      let binary = "";
      for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/g, "");
    }

    function serializeRegistrationCredential(credential) {
      return {
        id: credential.id,
        rawId: uint8ArrayToBase64url(new Uint8Array(credential.rawId)),
        type: credential.type,
        response: {
          attestationObject: uint8ArrayToBase64url(new Uint8Array(credential.response.attestationObject)),
          clientDataJSON: uint8ArrayToBase64url(new Uint8Array(credential.response.clientDataJSON)),
          transports: credential.response.getTransports ? credential.response.getTransports() : [],
        },
        clientExtensionResults: credential.getClientExtensionResults
          ? credential.getClientExtensionResults()
          : {},
      };
    }

    async function requestJson(url, options = {}) {
      const response = await fetch(url, { credentials: "include", ...options });
      let data = {};
      try {
        data = await response.json();
      } catch (_err) {
        // no-op
      }
      if (!response.ok) {
        throw new Error(data.detail || "Request failed");
      }
      return data;
    }

    async function fetchUserAndPasskeys() {
      const [user, passkeys] = await Promise.all([
        requestJson("/api/auth/me"),
        requestJson("/api/passkeys"),
      ]);
      return { user, passkeys };
    }

    function renderPasskeys(passkeys) {
      const container = document.getElementById("passkey-list");
      container.innerHTML = "";

      if (!passkeys.length) {
        const empty = document.createElement("p");
        empty.textContent = "No passkeys found.";
        container.appendChild(empty);
        return;
      }

      for (const passkey of passkeys) {
        const item = document.createElement("article");
        item.className = "item";

        const meta = document.createElement("div");
        meta.className = "meta";
        meta.textContent = `Credential: ${passkey.credential_id}`;
        item.appendChild(meta);

        const label = document.createElement("label");
        label.textContent = "Label";
        item.appendChild(label);

        const input = document.createElement("input");
        input.value = passkey.label;
        input.maxLength = 120;
        item.appendChild(input);

        const actions = document.createElement("div");
        actions.className = "actions";

        const renameButton = document.createElement("button");
        renameButton.textContent = "Save label";
        renameButton.addEventListener("click", async () => {
          try {
            const nextLabel = input.value.trim();
            if (!nextLabel) {
              throw new Error("Label cannot be empty");
            }
            await requestJson(`/api/passkeys/${passkey.id}`, {
              method: "PATCH",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ label: nextLabel }),
            });
            setStatus("Passkey label updated.", true);
            await refresh();
          } catch (error) {
            setStatus(error.message || String(error), false);
          }
        });
        actions.appendChild(renameButton);

        const deleteButton = document.createElement("button");
        deleteButton.className = "danger";
        deleteButton.textContent = "Delete passkey";
        deleteButton.addEventListener("click", async () => {
          try {
            await requestJson(`/api/passkeys/${passkey.id}`, { method: "DELETE" });
            setStatus("Passkey deleted.", true);
            await refresh();
          } catch (error) {
            setStatus(error.message || String(error), false);
          }
        });
        actions.appendChild(deleteButton);

        item.appendChild(actions);
        container.appendChild(item);
      }
    }

    async function refresh() {
      try {
        const { user, passkeys } = await fetchUserAndPasskeys();
        document.getElementById("user-line").textContent = `Signed in as ${user.username} (${user.role})`;
        renderPasskeys(passkeys);
      } catch (error) {
        setStatus(error.message || String(error), false);
      }
    }

    document.getElementById("refresh-btn").addEventListener("click", refresh);

    document.getElementById("logout-btn").addEventListener("click", async () => {
      await requestJson("/api/auth/logout", { method: "POST" });
      window.location.href = "/login";
    });

    document.getElementById("add-btn").addEventListener("click", async () => {
      setStatus("", false);
      if (!window.PublicKeyCredential || !navigator.credentials) {
        setStatus("Passkeys are not supported in this browser.", false);
        return;
      }

      const addButton = document.getElementById("add-btn");
      addButton.disabled = true;

      try {
        const begin = await requestJson("/api/passkeys/begin-add", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
        });

        const publicKeyOptions = begin.public_key;
        publicKeyOptions.challenge = base64urlToUint8Array(publicKeyOptions.challenge);
        publicKeyOptions.user.id = base64urlToUint8Array(publicKeyOptions.user.id);
        publicKeyOptions.excludeCredentials = (publicKeyOptions.excludeCredentials || []).map((item) => ({
          ...item,
          id: base64urlToUint8Array(item.id),
        }));

        const credential = await navigator.credentials.create({ publicKey: publicKeyOptions });
        if (!credential || !credential.rawId) {
          throw new Error("Failed to create passkey credential");
        }

        const label = (document.getElementById("new-label").value || "").trim() || "Additional passkey";

        await requestJson("/api/passkeys/complete-add", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            challenge_id: begin.challenge_id,
            credential: serializeRegistrationCredential(credential),
            label,
          }),
        });

        setStatus("Passkey added.", true);
        await refresh();
      } catch (error) {
        setStatus(error.message || String(error), false);
      } finally {
        addButton.disabled = false;
      }
    });

    refresh();
  </script>
</body>
</html>
"""


ADMIN_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Admin Console</title>
  <style>
    :root {
      --bg: #f7fafc;
      --panel: #ffffff;
      --text: #1a202c;
      --muted: #4a5568;
      --accent: #0b7285;
      --danger: #c92a2a;
      --border: #d9e2ec;
      --ok: #2b8a3e;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Avenir Next", "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at 10% 10%, #d6f5ff 0, transparent 35%),
        radial-gradient(circle at 90% 90%, #ffe8cc 0, transparent 30%),
        var(--bg);
      padding: 24px;
    }
    .container {
      max-width: 980px;
      margin: 0 auto;
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 20px;
      box-shadow: 0 12px 30px rgba(23, 43, 77, 0.08);
    }
    h1 { margin: 0 0 8px; font-size: 1.7rem; }
    h2 { margin: 18px 0 10px; font-size: 1.2rem; }
    p { margin: 0 0 12px; color: var(--muted); }
    .row {
      display: flex;
      gap: 10px;
      margin-top: 12px;
      flex-wrap: wrap;
    }
    .row a { color: var(--accent); text-decoration: none; }
    .card {
      margin-top: 14px;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px;
      background: #fbfdff;
    }
    label {
      display: block;
      margin: 10px 0 6px;
      font-size: 0.9rem;
    }
    input, select {
      width: 100%;
      padding: 10px 12px;
      border: 1px solid var(--border);
      border-radius: 10px;
      font-size: 1rem;
    }
    button {
      border: 0;
      border-radius: 8px;
      padding: 9px 12px;
      background: var(--accent);
      color: #fff;
      cursor: pointer;
      margin-top: 10px;
    }
    .status { margin-top: 10px; min-height: 20px; font-size: 0.95rem; }
    .err { color: var(--danger); }
    .ok { color: var(--ok); }
    .muted { color: var(--muted); }
    .token-output {
      margin-top: 8px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      background: #f1f5f9;
      border-radius: 8px;
      padding: 10px;
      word-break: break-all;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 8px;
      font-size: 0.92rem;
    }
    th, td {
      border-bottom: 1px solid var(--border);
      text-align: left;
      padding: 8px 6px;
      vertical-align: top;
      word-break: break-word;
    }
  </style>
</head>
<body>
  <main class="container">
    <h1>Admin console</h1>
    <p id="whoami">Loading user...</p>
    <div class="row">
      <a href="/signup">User signup</a>
      <a href="/admin_signup">Admin signup</a>
      <a href="/login">Login</a>
      <a href="/passkeys">Passkeys</a>
      <a href="/admin">Admin</a>
      <a href="/me">Session view</a>
    </div>

    <section class="card">
      <h2>Public user signup mode</h2>
      <p class="muted">Controls whether normal users can sign up without invite tokens.</p>
      <label for="mode-select">Mode</label>
      <select id="mode-select">
        <option value="open">open</option>
        <option value="invite_only">invite_only</option>
      </select>
      <button id="save-mode-btn">Save mode</button>
      <div id="mode-status" class="status"></div>
    </section>

    <section class="card">
      <h2>Create signup token</h2>
      <p class="muted">Only superadmins can issue one-time invite tokens.</p>
      <label for="token-role">Role to grant</label>
      <select id="token-role">
        <option value="user">user</option>
        <option value="admin">admin</option>
        <option value="superadmin">superadmin</option>
      </select>
      <label for="token-expiry">Expires in minutes</label>
      <input id="token-expiry" type="number" min="1" max="43200" value="60" />
      <button id="create-token-btn">Create token</button>
      <div id="token-status" class="status"></div>
      <div id="token-output" class="token-output" style="display:none;"></div>
    </section>

    <section class="card">
      <h2>Recent signup tokens</h2>
      <button id="refresh-tokens-btn">Refresh list</button>
      <div id="list-status" class="status"></div>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Hint</th>
            <th>Role</th>
            <th>Expires</th>
            <th>Used</th>
          </tr>
        </thead>
        <tbody id="token-tbody"></tbody>
      </table>
    </section>
  </main>

  <script>
    function setStatus(id, message, ok) {
      const el = document.getElementById(id);
      el.className = ok ? "status ok" : "status err";
      el.textContent = message;
    }

    async function requestJson(url, options = {}) {
      const response = await fetch(url, { credentials: "include", ...options });
      let data = {};
      try {
        data = await response.json();
      } catch (_err) {
        // no-op
      }
      if (!response.ok) {
        throw new Error(data.detail || "Request failed");
      }
      return data;
    }

    function renderTokenRows(items) {
      const tbody = document.getElementById("token-tbody");
      tbody.innerHTML = "";
      for (const item of items) {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${item.id}</td>
          <td>${item.token_hint}</td>
          <td>${item.role_to_grant}</td>
          <td>${item.expires_at}</td>
          <td>${item.used_at || "-"}</td>
        `;
        tbody.appendChild(tr);
      }
      if (!items.length) {
        const tr = document.createElement("tr");
        tr.innerHTML = '<td colspan="5" class="muted">No tokens found.</td>';
        tbody.appendChild(tr);
      }
    }

    async function loadMode() {
      try {
        const modeResp = await requestJson("/api/admin/settings/public-signup-mode");
        document.getElementById("mode-select").value = modeResp.mode;
        setStatus("mode-status", `Current mode: ${modeResp.mode}`, true);
      } catch (error) {
        setStatus("mode-status", error.message || String(error), false);
      }
    }

    async function loadTokens() {
      try {
        const list = await requestJson("/api/admin/signup-tokens");
        renderTokenRows(list.items || []);
        setStatus("list-status", "Token list refreshed.", true);
      } catch (error) {
        renderTokenRows([]);
        setStatus("list-status", error.message || String(error), false);
      }
    }

    async function init() {
      try {
        const me = await requestJson("/api/auth/me");
        document.getElementById("whoami").textContent = `Signed in as ${me.username} (${me.role})`;
        const isSuperadmin = me.role === "superadmin";

        if (!isSuperadmin) {
          document.getElementById("save-mode-btn").disabled = true;
          document.getElementById("create-token-btn").disabled = true;
          setStatus("mode-status", "Only superadmins can update mode.", false);
          setStatus("token-status", "Only superadmins can create signup tokens.", false);
        }
      } catch (error) {
        document.getElementById("whoami").textContent = error.message || String(error);
      }

      await loadMode();
      await loadTokens();
    }

    document.getElementById("save-mode-btn").addEventListener("click", async () => {
      try {
        const mode = document.getElementById("mode-select").value;
        await requestJson("/api/admin/settings/public-signup-mode", {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ mode }),
        });
        setStatus("mode-status", `Saved mode: ${mode}`, true);
      } catch (error) {
        setStatus("mode-status", error.message || String(error), false);
      }
    });

    document.getElementById("create-token-btn").addEventListener("click", async () => {
      const output = document.getElementById("token-output");
      output.style.display = "none";
      output.textContent = "";
      try {
        const role = document.getElementById("token-role").value;
        const expires = Number(document.getElementById("token-expiry").value || 60);
        const created = await requestJson("/api/admin/signup-tokens", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ role, expires_in_minutes: expires }),
        });
        setStatus("token-status", "Token created. Copy it now; it is shown once.", true);
        output.style.display = "block";
        output.textContent = `${created.token}`;
        await loadTokens();
      } catch (error) {
        setStatus("token-status", error.message || String(error), false);
      }
    });

    document.getElementById("refresh-tokens-btn").addEventListener("click", loadTokens);

    init();
  </script>
</body>
</html>
"""


def _render_signup_page(
    *,
    title: str,
    heading: str,
    token_required: bool,
    token_note: str,
    mode_aware: bool,
) -> str:
    return (
        SIGNUP_TEMPLATE.replace("__TITLE__", title)
        .replace("__HEADING__", heading)
        .replace("__TOKEN_NOTE__", token_note)
        .replace("__TOKEN_REQUIRED_ATTR__", "required" if token_required else "")
        .replace("__TOKEN_REQUIRED_JS__", "true" if token_required else "false")
        .replace("__MODE_AWARE_JS__", "true" if mode_aware else "false")
    )


def _render_login_page(*, title: str, heading: str, note: str) -> str:
    return (
        LOGIN_TEMPLATE.replace("__TITLE__", title)
        .replace("__HEADING__", heading)
        .replace("__NOTE__", note)
    )


def _render_me_page() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Session</title>
  <style>
    body {
      margin: 0;
      font-family: "Avenir Next", "Segoe UI", sans-serif;
      background: #f8fafc;
      color: #1f2937;
      padding: 24px;
    }
    .container {
      max-width: 760px;
      margin: 0 auto;
      background: #fff;
      border: 1px solid #dbe3eb;
      border-radius: 12px;
      padding: 20px;
    }
    pre {
      background: #f1f5f9;
      border-radius: 10px;
      padding: 12px;
      overflow: auto;
    }
    .row {
      display: flex;
      gap: 8px;
      margin-top: 10px;
      flex-wrap: wrap;
    }
    button {
      border: 0;
      border-radius: 8px;
      padding: 10px 14px;
      background: #0b7285;
      color: #fff;
      cursor: pointer;
    }
    a { color: #0b7285; text-decoration: none; }
  </style>
</head>
<body>
  <main class="container">
    <h1>Current session</h1>
    <p>
      <a href="/signup">User signup</a> |
      <a href="/admin_signup">Admin signup</a> |
      <a href="/login">Login</a> |
      <a href="/passkeys">Passkeys</a> |
      <a href="/admin">Admin</a>
    </p>
    <h3>User</h3>
    <pre id="user-json">Loading...</pre>
    <h3>Passkeys</h3>
    <pre id="passkeys-json">Loading...</pre>
    <div class="row">
      <button id="logout-btn">Logout</button>
      <button id="refresh-btn">Refresh</button>
    </div>
  </main>
  <script>
    async function fetchJson(url) {
      const r = await fetch(url, { credentials: "include" });
      if (!r.ok) {
        const body = await r.json().catch(() => ({}));
        throw new Error(body.detail || "Request failed");
      }
      return r.json();
    }

    async function refresh() {
      try {
        const user = await fetchJson("/api/auth/me");
        const passkeys = await fetchJson("/api/passkeys");
        document.getElementById("user-json").textContent = JSON.stringify(user, null, 2);
        document.getElementById("passkeys-json").textContent = JSON.stringify(passkeys, null, 2);
      } catch (error) {
        document.getElementById("user-json").textContent = error.message;
        document.getElementById("passkeys-json").textContent = "[]";
      }
    }

    document.getElementById("refresh-btn").addEventListener("click", refresh);
    document.getElementById("logout-btn").addEventListener("click", async () => {
      await fetch("/api/auth/logout", { method: "POST", credentials: "include" });
      window.location.href = "/login";
    });

    refresh();
  </script>
</body>
</html>
"""


@router.get("/")
def index() -> RedirectResponse:
    return RedirectResponse(url="/signup", status_code=307)


@router.get("/signup", response_class=HTMLResponse)
def signup_page() -> HTMLResponse:
    return HTMLResponse(
        _render_signup_page(
            title="User Signup",
            heading="User signup",
            token_required=False,
            token_note="Enter username. Add a token only when signup mode is invite-only.",
            mode_aware=True,
        )
    )


@router.get("/admin_signup", response_class=HTMLResponse)
def admin_signup_page() -> HTMLResponse:
    return HTMLResponse(
        _render_signup_page(
            title="Admin Signup",
            heading="Admin or Superadmin signup",
            token_required=True,
            token_note="Admin signup always requires a privileged one-time token.",
            mode_aware=False,
        )
    )


@router.get("/login", response_class=HTMLResponse)
def login_page() -> HTMLResponse:
    return HTMLResponse(
        _render_login_page(
            title="Login",
            heading="Login",
            note="All roles use the same passkey login flow.",
        )
    )


@router.get("/passkeys", response_class=HTMLResponse)
def passkeys_page() -> HTMLResponse:
    return HTMLResponse(PASSKEYS_TEMPLATE)


@router.get("/admin", response_class=HTMLResponse)
def admin_page(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> HTMLResponse:
    session_token = request.cookies.get(settings.session_cookie_name)
    if not session_token:
        return RedirectResponse(url="/login", status_code=303)

    user = get_user_by_session_token(db, session_token=session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    if user.role not in {Role.ADMIN, Role.SUPERADMIN}:
        return RedirectResponse(url="/me", status_code=303)

    return HTMLResponse(ADMIN_TEMPLATE)


@router.get("/me", response_class=HTMLResponse)
def me_page() -> HTMLResponse:
    return HTMLResponse(_render_me_page())
