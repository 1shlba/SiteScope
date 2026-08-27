/* SiteScope shared front-end helpers: DOM, API access, formatting, toasts. */

const SS = (() => {
  "use strict";

  /* ---------------------------------------------------------------- DOM */

  const $  = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  function el(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === "class") node.className = value;
      else if (key === "text") node.textContent = value;
      else if (key.startsWith("on") && typeof value === "function") {
        node.addEventListener(key.slice(2).toLowerCase(), value);
      } else node.setAttribute(key, value);
    }
    for (const child of [].concat(children)) {
      if (child === null || child === undefined) continue;
      node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    }
    return node;
  }

  function clear(node) {
    while (node && node.firstChild) node.removeChild(node.firstChild);
    return node;
  }

  /* ---------------------------------------------------------------- API */

  async function api(path, options = {}) {
    const config = { headers: { "Content-Type": "application/json" }, ...options };
    if (config.body && typeof config.body !== "string") {
      config.body = JSON.stringify(config.body);
    }

    let response;
    try {
      response = await fetch(path, config);
    } catch (err) {
      throw new Error("Could not reach the SiteScope service. Is the application still running?");
    }

    const isJson = (response.headers.get("content-type") || "").includes("application/json");
    const payload = isJson ? await response.json() : null;

    if (!response.ok) {
      throw new Error((payload && payload.error) || `Request failed (${response.status})`);
    }
    return payload;
  }

  /* ------------------------------------------------------------ Toasts */

  function toast(message, kind = "") {
    let host = $(".toast-host");
    if (!host) {
      host = el("div", { class: "toast-host" });
      document.body.appendChild(host);
    }
    const node = el("div", { class: `toast ${kind}`, text: message });
    host.appendChild(node);
    setTimeout(() => {
      node.style.transition = "opacity .3s, transform .3s";
      node.style.opacity = "0";
      node.style.transform = "translateY(6px)";
      setTimeout(() => node.remove(), 320);
    }, kind === "error" ? 6000 : 3600);
  }

  /* -------------------------------------------------------- Formatting */

  const numberFormat = new Intl.NumberFormat("en-AU");
  const formatNumber = (value) => numberFormat.format(value || 0);

  function pluralise(count, singular, plural) {
    return `${count} ${count === 1 ? singular : (plural || singular + "s")}`;
  }

  function escapeHtml(text) {
    return String(text ?? "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  const SEVERITY = {
    critical: { label: "Critical", colour: "#ef4444", range: "CVSS 9.0-10.0" },
    high:     { label: "High",     colour: "#f97316", range: "CVSS 7.0-8.9" },
    medium:   { label: "Medium",   colour: "#eab308", range: "CVSS 4.0-6.9" },
    low:      { label: "Low",      colour: "#3b82f6", range: "CVSS 0.1-3.9" },
    info:     { label: "Information", colour: "#8b93a7", range: "Advisory" },
  };

  /* ---------------------------------------------------------- Polling */

  function poll(fn, intervalMs) {
    let stopped = false;
    let timer = null;

    async function tick() {
      if (stopped) return;
      try {
        const keepGoing = await fn();
        if (keepGoing === false) { stopped = true; return; }
      } catch (err) {
        console.error("Poll failed:", err);
      }
      if (!stopped) timer = setTimeout(tick, intervalMs);
    }

    tick();
    return () => { stopped = true; if (timer) clearTimeout(timer); };
  }

  /* --------------------------------------------------------- Empty state */

  function emptyState(title, message, actionLabel, onAction) {
    const node = el("div", { class: "empty" }, [
      icon("search", 34),
      el("h3", { text: title }),
      el("p", { text: message }),
    ]);
    if (actionLabel && onAction) {
      node.appendChild(el("button", {
        class: "btn btn-primary", text: actionLabel, onClick: onAction,
      }));
    }
    return node;
  }

  const ICONS = {
    search: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
    shield: '<path d="M12 3l8 3.4v5.1c0 4.6-3.2 8.6-8 9.5-4.8-.9-8-4.9-8-9.5V6.4z"/>',
    file:   '<path d="M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8z"/><path d="M14 3v5h5"/>',
    alert:  '<path d="M10.3 4.3L2.5 18a2 2 0 001.7 3h15.6a2 2 0 001.7-3L13.7 4.3a2 2 0 00-3.4 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
  };

  function icon(name, size = 16) {
    const wrapper = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    wrapper.setAttribute("viewBox", "0 0 24 24");
    wrapper.setAttribute("width", size);
    wrapper.setAttribute("height", size);
    wrapper.setAttribute("fill", "none");
    wrapper.setAttribute("stroke", "currentColor");
    wrapper.setAttribute("stroke-width", "1.6");
    wrapper.setAttribute("stroke-linecap", "round");
    wrapper.setAttribute("stroke-linejoin", "round");
    wrapper.innerHTML = ICONS[name] || ICONS.search;
    return wrapper;
  }

  return { $, $$, el, clear, api, toast, formatNumber, pluralise, escapeHtml,
           SEVERITY, poll, emptyState, icon };
})();
