// Theme: auto / light / dark.
//
// Loaded synchronously in <head> (external file with SRI, CSP forbids inline
// scripts) so data-theme is set before the first paint. The choice is not a
// secret and never leaves the browser: it lives only in localStorage.
//
// Two kinds of controls:
//   #theme                  — header button, cycles auto -> light -> dark
//   [data-theme-choice=x]   — segmented control in settings
//
// DOM rule: only setAttribute / removeAttribute / toggleAttribute. No innerHTML.
"use strict";

(() => {
  const KEY = "trebuchet.theme";
  const ORDER = ["auto", "light", "dark"];
  const BG = { light: "#f3f4f6", dark: "#0d0f12" };
  const NAMES = { auto: "авто", light: "светлая", dark: "тёмная" };
  const root = document.documentElement;

  function load() {
    try {
      const v = localStorage.getItem(KEY);
      return ORDER.includes(v) ? v : "auto";
    } catch {
      return "auto";
    }
  }

  function save(t) {
    try {
      localStorage.setItem(KEY, t);
    } catch {
      /* private mode: the choice just isn't remembered */
    }
  }

  function apply(t) {
    if (t === "auto") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", t);

    for (const m of document.querySelectorAll('meta[name="theme-color"]')) {
      const isDark = (m.getAttribute("media") || "").includes("dark");
      m.setAttribute("content", t === "auto" ? (isDark ? BG.dark : BG.light) : BG[t]);
    }

    for (const btn of document.querySelectorAll("[data-theme-toggle]")) {
      btn.setAttribute("data-value", t);
      btn.setAttribute("aria-label", "Тема: " + NAMES[t] + ". Переключить");
      // SVG elements have no .hidden property: toggle the attribute itself.
      for (const icon of btn.querySelectorAll("[data-icon]")) {
        icon.toggleAttribute("hidden", icon.getAttribute("data-icon") !== t);
      }
    }
    for (const b of document.querySelectorAll("[data-theme-choice]")) {
      b.setAttribute("aria-pressed", String(b.getAttribute("data-theme-choice") === t));
    }
  }

  function set(t) {
    apply(t);
    save(t);
  }

  apply(load());

  function wire() {
    apply(load());
    for (const btn of document.querySelectorAll("[data-theme-toggle]")) {
      btn.addEventListener("click", () => {
        const cur = btn.getAttribute("data-value");
        set(ORDER[(ORDER.indexOf(cur) + 1) % ORDER.length]);
      });
    }
    for (const b of document.querySelectorAll("[data-theme-choice]")) {
      b.addEventListener("click", () => {
        const t = b.getAttribute("data-theme-choice");
        if (ORDER.includes(t)) set(t);
      });
    }
    // Another tab changed the theme.
    window.addEventListener("storage", (e) => {
      if (e.key === KEY) apply(load());
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", wire);
  else wire();
})();
