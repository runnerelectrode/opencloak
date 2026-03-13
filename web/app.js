(function () {
  "use strict";

  const $ = (sel) => document.querySelector(sel);
  const signInSection = $("#sign-in");
  const identitySection = $("#identity");
  const exchangeSection = $("#exchange");

  async function init() {
    try {
      const session = await fetchJSON("/auth/session");
      if (session.authenticated) {
        showIdentity(session);
        showExchange(session);
      } else {
        await showSignIn();
      }
    } catch {
      await showSignIn();
    }
  }

  async function showSignIn() {
    signInSection.classList.add("active");
    identitySection.classList.remove("active");
    exchangeSection.classList.remove("active");

    const container = $("#issuer-buttons");
    try {
      const issuers = await fetchJSON("/auth/issuers");
      if (issuers.length === 0) {
        container.innerHTML =
          '<p class="no-issuers">No identity providers configured.<br>Run <code>opencloak add-issuer</code> with <code>--client-id</code> to enable sign-in.</p>';
        return;
      }
      container.innerHTML = "";
      for (const issuer of issuers) {
        const a = document.createElement("a");
        a.href = "/auth/" + encodeURIComponent(issuer.id);
        a.className = "signin-btn";
        a.textContent = "Sign in with " + issuer.id;
        container.appendChild(a);
      }
    } catch {
      container.innerHTML = '<p class="no-issuers">Failed to load identity providers.</p>';
    }
  }

  function showIdentity(session) {
    signInSection.classList.remove("active");
    identitySection.classList.add("active");

    const claims = session.claims || {};
    const name = claims.name || claims.email || claims.sub || "Unknown";
    const detail = claims.email && claims.name ? claims.email : session.issuer_id || "";

    $("#user-name").textContent = name;
    $("#user-detail").textContent = detail;

    const decoded = decodeJwt(session.id_token);
    $("#claims-json").textContent = JSON.stringify(decoded, null, 2);
    $("#raw-token").textContent = session.id_token;

    $("#logout-btn").onclick = handleLogout;
  }

  function showExchange(session) {
    exchangeSection.classList.add("active");

    const curlCmd =
      "curl -X POST http://localhost:3422/token \\\n" +
      "  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \\\n" +
      "  -d actor_token=<your-id-token> \\\n" +
      "  -d actor_token_type=urn:ietf:params:oauth:token-type:id_token \\\n" +
      "  -d resource=https://discord.com/api \\\n" +
      "  -d scope=identify";
    $("#curl-cmd").textContent = curlCmd;

    const btn = $("#exchange-btn");
    const resultDiv = $("#exchange-result");
    btn.onclick = async function () {
      btn.disabled = true;
      btn.textContent = "Exchanging...";
      resultDiv.innerHTML = "";
      try {
        const body = new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
          actor_token: session.id_token,
          actor_token_type: "urn:ietf:params:oauth:token-type:id_token",
          resource: "https://discord.com/api",
          scope: "identify",
        });
        const res = await fetch("/token", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: body,
        });
        const data = await res.json();
        const statusClass = res.ok ? "status-ok" : "status-err";
        resultDiv.innerHTML =
          '<p class="label ' + statusClass + '">Response (' + res.status + "):</p>" +
          "<pre>" + escapeHtml(JSON.stringify(data, null, 2)) + "</pre>";
      } catch (err) {
        resultDiv.innerHTML =
          '<p class="label status-err">Error: ' + escapeHtml(err.message) + "</p>";
      } finally {
        btn.disabled = false;
        btn.textContent = "Try Token Exchange";
      }
    };
  }

  function decodeJwt(token) {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) return { error: "not a JWT" };
      const payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
      return JSON.parse(atob(payload));
    } catch {
      return { error: "failed to decode" };
    }
  }

  async function handleLogout() {
    try {
      await fetch("/auth/logout", { method: "POST" });
    } catch {
      // ignore
    }
    window.location.hash = "";
    window.location.reload();
  }

  async function fetchJSON(url) {
    const res = await fetch(url);
    if (!res.ok) throw new Error("HTTP " + res.status);
    return res.json();
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  document.addEventListener("DOMContentLoaded", init);
})();
