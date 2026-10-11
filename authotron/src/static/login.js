"use strict";

(() => {
  const dialog = document.getElementById("login-dialog");
  if (!dialog || typeof dialog.showModal !== "function" ||
      typeof window.fetch !== "function" || typeof window.AbortController !== "function") return;
  dialog.hidden = false;

  const content = document.getElementById("login-dialog-content");
  const status = document.getElementById("login-dialog-status");
  const close = dialog.querySelector(".login-dialog-close");
  const endpoints = new Map([
    ["basic", "/login/basic"],
    ["api-key", "/login/ecmwf-api-key"],
  ]);
  const failure = "Sign-in could not be completed. Please try again.";
  let endpoint = null;
  let opener = null;
  let version = 0;
  let inFlight = false;
  let posting = false;
  let controller = null;

  function clearCredentials() {
    content.querySelectorAll("input").forEach((input) => { input.value = ""; });
  }

  function busy(value, post = false) {
    inFlight = value;
    posting = value && post;
    dialog.setAttribute("aria-busy", String(value));
    close.disabled = posting;
    content.querySelectorAll("button, input").forEach((node) => { node.disabled = value; });
    const submit = content.querySelector('button[type="submit"]');
    if (submit) submit.textContent = posting ? "Signing in…" : "Sign in";
  }

  function heading(text) {
    const title = document.createElement("h2");
    title.id = "login-dialog-title";
    title.textContent = text;
    return title;
  }

  function retry() {
    clearCredentials();
    content.replaceChildren(heading("Sign in"));
    status.textContent = failure;
    const button = document.createElement("button");
    button.type = "button";
    button.className = "login-action";
    button.textContent = "Try again";
    button.addEventListener("click", () => {
      if (!inFlight && dialog.open) load();
    });
    content.append(button);
    button.focus();
  }

  // Accept /login/basic, never /login/basic?return_to=... or another origin.
  function fixedUrl(value, path) {
    const url = new URL(value, window.location.origin);
    return url.origin === window.location.origin && url.pathname === path &&
      url.search === "" && url.hash === "" && url.username === "" && url.password === "";
  }

  async function renderForm(response, selected, ticket) {
    if (!response.headers.get("content-type")?.startsWith("text/html")) return false;
    const text = await response.text();
    if (ticket !== version || !dialog.open) return false;
    const page = new DOMParser().parseFromString(text, "text/html");
    const card = page.querySelector(".login-card");
    const source = card?.querySelector("form.key-form");
    const title = card?.querySelector("h2#login-card-title");
    if (!source || !title || source.getAttribute("method")?.toLowerCase() !== "post" ||
        !fixedUrl(source.getAttribute("action"), selected)) return false;
    const names = selected === "/login/basic" ? ["csrf", "username", "password"] : ["csrf", "api_key"];
    const transaction = source.querySelector('input[name="oauth_transaction"]');
    if (transaction) {
      if (transaction.type !== "hidden" || !/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(transaction.value)) return false;
      names.push("oauth_transaction");
    }
    const inputs = [...source.querySelectorAll("input")];
    if (inputs.length !== names.length || names.some((name) =>
      inputs.filter((input) => input.name === name).length !== 1)) return false;
    const csrf = inputs.find((input) => input.name === "csrf");
    if (csrf.type !== "hidden" || !csrf.value) return false;

    // Rebuild only known form controls and text; server HTML cannot introduce
    // resource loads, event handlers, additional fields, or request destinations.
    const form = document.createElement("form");
    form.className = "key-form";
    form.method = "post";
    form.action = selected;
    for (const name of names) {
      const original = inputs.find((input) => input.name === name);
      const input = document.createElement("input");
      input.name = name;
      input.type = ["csrf", "oauth_transaction"].includes(name) ? "hidden" : name === "username" ? "text" : "password";
      if (input.type === "hidden") {
        input.value = original.value;
      } else {
        input.id = `login-dialog-${name}`;
        input.className = "login-input";
        input.required = true;
        input.maxLength = name === "username" ? 256 : name === "password" ? 1024 : 512;
        input.autocomplete = name === "username" ? "username" : name === "password" ? "current-password" : "off";
        const label = document.createElement("label");
        label.htmlFor = input.id;
        label.textContent = [...source.querySelectorAll("label")]
          .find((node) => node.htmlFor === original.id)?.textContent ||
          (name === "username" ? "Username" : name === "password" ? "Password" : "ECMWF API key");
        form.append(label);
      }
      form.append(input);
    }
    const submit = document.createElement("button");
    submit.type = "submit";
    submit.className = "login-action";
    submit.textContent = "Sign in";
    form.append(submit);
    form.addEventListener("submit", submitForm);
    content.replaceChildren(heading(title.textContent));
    for (const message of card.querySelectorAll("p.login-card-message, p.login-card-detail")) {
      const paragraph = document.createElement("p");
      paragraph.className = message.className;
      paragraph.textContent = message.textContent;
      if (message.getAttribute("role") === "alert") paragraph.setAttribute("role", "alert");
      content.append(paragraph);
    }
    content.append(form);
    status.textContent = "";
    return true;
  }

  async function load() {
    const ticket = ++version;
    const selected = endpoint;
    controller = new AbortController();
    content.replaceChildren(heading("Sign in"));
    status.textContent = "Loading sign-in…";
    busy(true);
    let rendered = false;
    try {
      const response = await fetch(selected, {
        credentials: "same-origin", cache: "no-store", signal: controller.signal,
        headers: { Accept: "text/html" },
      });
      if (response.ok && !response.redirected) rendered = await renderForm(response, selected, ticket);
    } catch (_) {
      // Network diagnostics never include credentials or response bodies.
    } finally {
      controller = null;
      busy(false);
      if (ticket === version && dialog.open) {
        if (!rendered) retry();
        else content.querySelector('input:not([type="hidden"])')?.focus();
      }
    }
  }

  async function submitForm(event) {
    event.preventDefault();
    if (inFlight || !dialog.open) return;
    const form = event.currentTarget;
    if (!form.reportValidity()) return;
    const selected = endpoint;
    const ticket = ++version;
    let body = new URLSearchParams();
    for (const input of form.querySelectorAll("input")) body.append(input.name, input.value);
    busy(true, true);
    status.textContent = "Verifying your identity…";
    let rendered = false;
    let succeeded = false;
    try {
      // URLSearchParams preserves spaces and Unicode and emits URL-encoded POST,
      // never multipart. A POST stays active even if the user wants to close.
      const pending = fetch(selected, {
        method: "POST", credentials: "same-origin", cache: "no-store",
        headers: { Accept: "text/html", "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
        body,
      });
      body = null;
      clearCredentials();
      const response = await pending;
      const destination = form.querySelector('input[name="oauth_transaction"]') ? "/oauth/continue" : "/login/account";
      if (response.ok && response.redirected && fixedUrl(response.url, destination)) {
        succeeded = true;
        window.location.assign(destination);
        return;
      }
      if (!response.redirected && [400, 401, 403, 413].includes(response.status)) {
        rendered = await renderForm(response, selected, ticket);
      }
    } catch (_) {
      // Present one generic failure; retry obtains one fresh flow-bound form.
    } finally {
      body = null;
      form.querySelectorAll("input").forEach((input) => { input.value = ""; });
      busy(false);
      if (!succeeded && ticket === version && dialog.open) {
        if (!rendered) retry();
        else content.querySelector('input:not([type="hidden"])')?.focus();
      }
    }
  }

  document.querySelectorAll("a[data-login-dialog]").forEach((link) => {
    const selected = endpoints.get(link.dataset.loginDialog);
    if (!selected || !fixedUrl(link.href, selected)) return;
    link.addEventListener("click", (event) => {
      if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      event.preventDefault();
      if (inFlight || dialog.open) return;
      endpoint = selected;
      opener = link;
      dialog.showModal();
      close.focus();
      load();
    });
  });

  close.addEventListener("click", () => { if (!posting) dialog.close(); });
  dialog.addEventListener("cancel", (event) => { if (posting) event.preventDefault(); });
  dialog.addEventListener("close", () => {
    ++version;
    clearCredentials();
    content.replaceChildren(heading("Sign in"));
    status.textContent = "";
    endpoint = null;
    opener?.focus();
    opener = null;
    // Let a pending GET settle before another flow can replace its shared cookie.
  });
  window.addEventListener("pagehide", () => {
    if (!posting) controller?.abort();
    clearCredentials();
  });
})();
