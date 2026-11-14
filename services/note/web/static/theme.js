// Theme switch: auto -> light -> dark.
//
// Loaded synchronously in <head> (external file with SRI, CSP forbids inline
// scripts) so data-theme is set before the first paint and the page never
// flashes the wrong theme. The choice is not a secret and never leaves the
// browser: it lives only in localStorage of this origin.
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

    // Two <meta name="theme-color"> tags, one per prefers-color-scheme.
    // A manual choice overrides both; "auto" restores each to its own theme.
    for (const m of document.querySelectorAll('meta[name="theme-color"]')) {
      const isDark = (m.getAttribute("media") || "").includes("dark");
      m.setAttribute("content", t === "auto" ? (isDark ? BG.dark : BG.light) : BG[t]);
    }

    const btn = document.getElementById("theme");
    if (!btn) return;
    btn.setAttribute("data-value", t);
    btn.setAttribute("aria-label", "Тема: " + NAMES[t] + ". Переключить");
    for (const icon of btn.querySelectorAll("[data-icon]")) {
      // SVG elements have no .hidden property: toggle the attribute itself.
      icon.toggleAttribute("hidden", icon.getAttribute("data-icon") !== t);
    }
  }

  apply(load());

  function wire() {
    const btn = document.getElementById("theme");
    if (!btn) return;
    apply(load());
    btn.addEventListener("click", () => {
      const cur = btn.getAttribute("data-value");
      const next = ORDER[(ORDER.indexOf(cur) + 1) % ORDER.length];
      apply(next);
      save(next);
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", wire);
  else wire();
})();
