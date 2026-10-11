"use strict";

(() => {
  const identity = document.getElementById("account-identity");
  const email = document.getElementById("account-email");
  const username = document.getElementById("account-username");
  const usernameLabel = document.getElementById("account-username-label");
  const status = document.getElementById("account-status");
  const reload = document.getElementById("account-reload");

  async function loadIdentity() {
    if (reload.disabled) return;
    reload.disabled = true;
    identity.hidden = true;
    email.textContent = "";
    username.textContent = "";
    username.hidden = true;
    usernameLabel.hidden = true;
    status.textContent = "Loading session identity…";

    try {
      const response = await fetch("/oauth2/userinfo", {
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        headers: { Accept: "application/json" },
      });

      if (response.status === 401 || response.status === 403) {
        status.textContent = "Your session is unavailable or has expired. Return to Auth-O-Tron sign in to continue.";
        return;
      }
      if (!response.ok) throw new Error("Identity unavailable");

      const user = await response.json();
      // Valid: {"email":"demo@example.org"}; invalid: {"email":42}.
      if (!user || typeof user.email !== "string" || !user.email.trim()) {
        throw new Error("Identity unavailable");
      }

      email.textContent = user.email;
      if (typeof user.preferredUsername === "string" && user.preferredUsername.trim()) {
        username.textContent = user.preferredUsername;
        username.hidden = false;
        usernameLabel.hidden = false;
      }
      identity.hidden = false;
      status.textContent = "Session identity loaded. Wait more than 60 seconds, then reload to exercise backend refresh. Identity alone does not confirm token rotation.";
    } catch {
      status.textContent = "Could not load session identity. Retry, or return to Auth-O-Tron sign in if your session has expired.";
    } finally {
      reload.disabled = false;
    }
  }

  reload.addEventListener("click", loadIdentity);
  loadIdentity();
})();
