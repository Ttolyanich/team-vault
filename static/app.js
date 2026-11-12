"use strict";
const toastTimers = new WeakMap();
const toastHost = () => {
  const root = document.getElementById("notifications");
  if (!root) return null;
  const host = Array.from(document.querySelectorAll("dialog[open]")).at(-1) || document.body;
  if (root.parentElement !== host) host.append(root);
  if (root.showPopover) {
    root.setAttribute("popover", "manual");
    if (!root.matches(":popover-open") && root.children.length) root.showPopover();
  }
  return root;
};
const dismissToast = toast => {
  clearTimeout(toastTimers.get(toast));
  toast.remove();
  const root = document.getElementById("notifications");
  if (!root?.children.length && root?.hidePopover && root.matches(":popover-open")) root.hidePopover();
};
const startToast = toast => {
  clearTimeout(toastTimers.get(toast));
  if (toast.dataset.toastError === "true" || toast.matches(":hover") || toast.contains(document.activeElement)) return;
  toastTimers.set(toast, setTimeout(() => dismissToast(toast), 4500));
};
const prepareToast = toast => {
  toast.querySelector("[data-toast-close]")?.addEventListener("click", () => dismissToast(toast));
  toast.addEventListener("pointerenter", () => clearTimeout(toastTimers.get(toast)));
  toast.addEventListener("pointerleave", () => startToast(toast));
  toast.addEventListener("focusin", () => clearTimeout(toastTimers.get(toast)));
  toast.addEventListener("focusout", () => setTimeout(() => startToast(toast), 0));
  startToast(toast);
};
const notify = (text, error = false) => {
  const root = document.getElementById("notifications");
  if (!root) return;
  const repeated = Array.from(root.children).find(toast => toast.dataset.toastError === String(error) && toast.querySelector(".toast-text")?.textContent === text);
  if (repeated) { startToast(repeated); toastHost(); return; }
  const toast = document.createElement("div"); toast.className = `toast${error ? " toast-error" : ""}`; toast.dataset.toastError = String(error);
  const icon = document.createElement("span"); icon.className = "toast-icon"; icon.setAttribute("aria-hidden", "true"); icon.textContent = error ? "!" : "✓";
  const message = document.createElement("span"); message.className = "toast-text"; message.setAttribute("role", error ? "alert" : "status"); message.textContent = text;
  const close = document.createElement("button"); close.type = "button"; close.className = "toast-close"; close.dataset.toastClose = ""; close.setAttribute("aria-label", "Закрыть уведомление");
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg"); svg.setAttribute("viewBox", "0 0 24 24"); svg.setAttribute("aria-hidden", "true"); svg.setAttribute("fill", "none"); svg.setAttribute("stroke", "currentColor"); svg.setAttribute("stroke-width", "1.8"); svg.setAttribute("stroke-linecap", "round");
  const path = document.createElementNS(svg.namespaceURI, "path"); path.setAttribute("d", "m6 6 12 12M18 6 6 18"); svg.append(path); close.append(svg);
  toast.append(icon, message, close); root.append(toast); prepareToast(toast); toastHost();
};
async function post(url, values) {
  const csrf = document.querySelector('[name="csrfmiddlewaretoken"]')?.value;
  const response = await fetch(url, { method: "POST", credentials: "same-origin", headers: { "X-CSRFToken": csrf }, body: new URLSearchParams(values) });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || "Не удалось выполнить действие. Проверьте доступ или повторите позже.");
  return body;
}
async function copy(value) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(value);
    } else {
      const textarea = document.createElement("textarea");
      textarea.value = value;
      textarea.style.position = "fixed";
      textarea.style.left = "-999999px";
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      textarea.remove();
    }
    notify("Скопировано в буфер обмена.");
  } catch (err) {
    notify("Не удалось скопировать в буфер обмена.", true);
  }
}
document.querySelectorAll("form[data-confirm]").forEach(form => form.addEventListener("submit", event => { if (!window.confirm(form.dataset.confirm)) event.preventDefault(); }));
document.querySelectorAll("[data-reveal]").forEach(button => button.addEventListener("click", async () => {
  if (button.dataset.output && button.getAttribute("aria-pressed") === "true") {
    document.getElementById(button.dataset.output).value = "••••••••••••";
    button.textContent = "Показать"; button.setAttribute("aria-pressed", "false"); return;
  }
  button.disabled = true;
  try {
    const result = await post(button.dataset.url, { field: button.dataset.reveal });
    if (button.dataset.output) {
      document.getElementById(button.dataset.output).value = result.value;
      button.textContent = "Скрыть"; button.setAttribute("aria-pressed", "true");
    }
    if (button.dataset.copy) await copy(result.value);
  } catch (error) { notify(error.message, true); }
  finally { button.disabled = false; }
}));
let totpTimer, activeCode = "";
const clearTotp = () => { clearInterval(totpTimer); activeCode = ""; const box = document.getElementById("totp-result"); if (box) { box.hidden = true; document.getElementById("totp-code").textContent = ""; } };
document.getElementById("totp-request")?.addEventListener("click", async event => {
  const button = event.currentTarget;
  button.disabled = true;
  clearTotp();
  try {
    const result = await post(button.dataset.url, { request_id: crypto.randomUUID() });
    const deadline = performance.now() + (result.expires_at - result.server_time) * 1000;
    activeCode = result.code;
    document.getElementById("totp-code").textContent = result.code;
    document.getElementById("totp-result").hidden = false;
    const tick = () => { const left = Math.ceil((deadline - performance.now()) / 1000); if (left <= 0) { clearTotp(); notify("Код истёк. Запросите следующий, когда он понадобится."); } else document.getElementById("totp-time").textContent = `Действует ещё ${left} сек.${left <= 5 ? " — лучше дождаться следующего кода" : ""}`; };
    tick(); totpTimer = setInterval(tick, 250);
  } catch (error) { notify(error.message, true); }
  finally { button.disabled = false; }
});
document.getElementById("totp-copy")?.addEventListener("click", async () => { try { if (activeCode) await copy(activeCode); } catch { notify("Не удалось скопировать код. Выделите его вручную.", true); } });
document.querySelectorAll("[data-recovery]").forEach(button => button.addEventListener("click", async () => {
  if (button.dataset.recovery === "reveal" && button.getAttribute("aria-pressed") === "true") {
    button.closest(".recovery-row").querySelector("output").textContent = "";
    button.textContent = "Показать"; button.setAttribute("aria-pressed", "false"); return;
  }
  if (button.dataset.recovery === "used" && !window.confirm("Отметить этот резервный код использованным?")) return;
  button.disabled = true;
  try { const result = await post(button.dataset.url, { action: button.dataset.recovery }); if (result.used) window.location.reload(); else { button.closest(".recovery-row").querySelector("output").textContent = result.value; button.textContent = "Скрыть"; button.setAttribute("aria-pressed", "true"); } }
  catch (error) { notify(error.message, true); }
  finally { button.disabled = false; }
}));
window.addEventListener("pagehide", () => { clearTotp(); document.querySelectorAll("[data-secret-value]").forEach(field => { field.value = "••••••••••••"; }); document.querySelectorAll("[data-reveal][data-output], [data-recovery=reveal]").forEach(button => { button.textContent = "Показать"; button.setAttribute("aria-pressed", "false"); }); document.querySelectorAll(".recovery-row output").forEach(field => { field.textContent = ""; }); });
document.querySelectorAll("[data-copy-value]").forEach(button => button.addEventListener("click", async () => {
  try { await copy(button.dataset.copyValue); } catch { notify("Не удалось скопировать адрес. Выделите его вручную.", true); }
}));
document.getElementById("microsoft-check")?.addEventListener("click", async event => {
  const button = event.currentTarget;
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  try { const body = await post(button.dataset.url, {}); notify(body.message); }
  catch (error) { notify(error.message, true); }
  finally { button.disabled = false; button.removeAttribute("aria-busy"); }
});

document.querySelectorAll("[data-integration-check]").forEach(form => form.addEventListener("submit", async event => {
  event.preventDefault();
  const button = form.querySelector("button");
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  try { const body = await post(form.action, {}); notify(body.message); }
  catch (error) { notify(error.message, true); }
  finally { button.disabled = false; button.removeAttribute("aria-busy"); }
}));

document.getElementById("id_transport")?.addEventListener("change", event => {
  const port = document.getElementById("id_port");
  if (["389", "636"].includes(port.value)) port.value = event.target.value === "ldaps" ? "636" : "389";
});

document.querySelectorAll("[data-team-drawer]").forEach(dialog => {
  dialog.tabIndex = -1;
  dialog.showModal();
  dialog.focus({preventScroll:true});
  dialog.addEventListener("cancel", event => { event.preventDefault(); window.location.assign(dialog.dataset.closeUrl); });
  dialog.addEventListener("click", event => {
    if (event.target !== dialog) return;
    const bounds = dialog.getBoundingClientRect();
    if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) window.location.assign(dialog.dataset.closeUrl);
  });
});

const accessMode = document.getElementById("id_access_mode");
if (accessMode) {
  const updatePolicyFields = () => ["id_department_role", "id_department_totp"].forEach(id => {
    const field = document.getElementById(id)?.closest(".form-field");
    if (field) field.hidden = accessMode.value !== "department";
  });
  accessMode.addEventListener("change", updatePolicyFields);
  updatePolicyFields();
}

document.querySelectorAll('[data-help-button]').forEach(button => {
  const panel = document.getElementById(button.getAttribute('popovertarget'));
  if (!panel) return;
  const position = () => {
    const bounds = button.getBoundingClientRect();
    const width = Math.min(360, innerWidth - 32);
    panel.style.inset = 'auto'; panel.style.margin = '0';
    panel.style.left = `${Math.max(16, Math.min(bounds.left, innerWidth - width - 16))}px`;
    panel.style.top = `${Math.max(16, Math.min(bounds.bottom + 8, innerHeight - panel.getBoundingClientRect().height - 16))}px`;
  };
  panel.addEventListener('toggle', () => { if (panel.matches(':popover-open')) position(); });
  window.addEventListener('resize', () => { if (panel.matches(':popover-open')) position(); });
  document.addEventListener('scroll', () => { if (panel.matches(':popover-open')) position(); }, true);
});

(() => {
  const trigger = document.querySelector('[data-nav-toggle]');
  const sidebar = document.getElementById('main-sidebar');
  const main = document.getElementById('app-main');
  const backdrop = document.querySelector('.nav-backdrop');
  if (!trigger || !sidebar || !main || !backdrop) return;
  const mobile = matchMedia('(max-width:750px)');
  let opened = false;
  const update = (next, restoreFocus = false) => {
    opened = mobile.matches && next;
    document.body.classList.toggle('nav-open', opened);
    trigger.setAttribute('aria-expanded', String(opened));
    backdrop.hidden = !opened;
    sidebar.inert = mobile.matches && !opened;
    main.inert = opened;
    if (opened) {
      sidebar.setAttribute('role', 'dialog'); sidebar.setAttribute('aria-modal', 'true');
      sidebar.setAttribute('aria-label', 'Главное меню');
      sidebar.querySelector('.menu-close').focus({preventScroll:true});
    } else {
      sidebar.removeAttribute('role'); sidebar.removeAttribute('aria-modal'); sidebar.removeAttribute('aria-label');
      if (restoreFocus && mobile.matches) trigger.focus({preventScroll:true});
    }
  };
  trigger.addEventListener('click', () => update(!opened, opened));
  document.querySelectorAll('[data-nav-close]').forEach(button => button.addEventListener('click', () => update(false, true)));
  sidebar.querySelectorAll('a').forEach(link => link.addEventListener('click', () => { if (opened) update(false, true); }));
  document.addEventListener('keydown', event => {
    if (!opened) return;
    if (event.key === 'Escape') { event.preventDefault(); update(false, true); }
    if (event.key === 'Tab') {
      const focusable = Array.from(sidebar.querySelectorAll('a,button,summary')).filter(element => element.getClientRects().length && !element.disabled);
      const first = focusable[0], last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    }
  });
  mobile.addEventListener('change', () => {
    const focusWasInside = sidebar.contains(document.activeElement);
    update(false, focusWasInside);
  });
  update(false);
})();

document.querySelectorAll("[data-toast]").forEach(prepareToast);
if (document.getElementById("notifications")?.children.length) toastHost();
