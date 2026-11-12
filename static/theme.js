"use strict";
(() => {
  const key = "team-vault.theme";
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  let preference = "system";
  try { const stored = localStorage.getItem(key); if (["light", "dark", "system"].includes(stored)) preference = stored; } catch { /* Theme works even when storage is unavailable. */ }
  const apply = () => {
    const dark = preference === "system" ? media.matches : preference === "dark";
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    document.querySelectorAll("[data-theme-toggle]").forEach(button => {
      const label = dark ? "Включить светлую тему" : "Включить тёмную тему";
      button.setAttribute("aria-label", label);
      button.title = label;
    });
  };
  apply();
  media.addEventListener("change", apply);
  document.addEventListener("DOMContentLoaded", () => {
    apply();
    document.querySelectorAll("[data-theme-toggle]").forEach(control => {
      control.addEventListener("click", () => {
        preference = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
        try { localStorage.setItem(key, preference); } catch { /* No secret data is stored here. */ }
        apply();
      });
    });
  });
  window.addEventListener("storage", event => {
    if (event.key === key || event.key === null) { preference = ["light", "dark", "system"].includes(event.newValue) ? event.newValue : "system"; apply(); }
  });
})();
