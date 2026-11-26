// TeamVault Chrome Extension - Popup Logic

const DEFAULT_SERVER_URL = "https://teamvault-demo.itsg.kz";

const COPY_ICON_SVG = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/></svg>`;

let state = {
  serverUrl: DEFAULT_SERVER_URL,
  token: null,
  activeTab: null,
  currentDomain: "",
  user: null,
};

// UI Elements
const els = {
  statusMessage: document.getElementById("status-message"),
  viewSettings: document.getElementById("view-settings"),
  viewAuth: document.getElementById("view-auth"),
  viewMain: document.getElementById("view-main"),
  serverUrlInput: document.getElementById("server-url"),
  btnSettingsToggle: document.getElementById("btn-settings-toggle"),
  btnSettingsClose: document.getElementById("btn-settings-close"),
  btnSaveSettings: document.getElementById("btn-save-settings"),
  btnOpenLogin: document.getElementById("btn-open-login"),
  btnRefreshAuth: document.getElementById("btn-refresh-auth"),
  currentDomain: document.getElementById("current-domain"),
  searchInput: document.getElementById("search-input"),
  loadingSpinner: document.getElementById("loading-spinner"),
  emptyState: document.getElementById("empty-state"),
  emptyText: document.getElementById("empty-text"),
  credentialsList: document.getElementById("credentials-list"),
  appFooter: document.getElementById("app-footer"),
  userAvatar: document.getElementById("user-avatar"),
  userName: document.getElementById("user-name"),
  linkOpenVault: document.getElementById("link-open-vault"),
  btnLogout: document.getElementById("btn-logout"),
};

function showMessage(text, type = "success") {
  els.statusMessage.textContent = text;
  els.statusMessage.className = `status-message ${type}`;
  setTimeout(() => {
    els.statusMessage.className = "status-message hidden";
  }, 3500);
}

function showView(name) {
  els.viewSettings.classList.add("hidden");
  if (els.viewAuth) els.viewAuth.classList.add("hidden");
  els.viewMain.classList.add("hidden");

  if (name === "settings") {
    els.viewSettings.classList.remove("hidden");
    els.serverUrlInput.value = state.serverUrl;
  } else if (name === "auth") {
    if (els.viewAuth) els.viewAuth.classList.remove("hidden");
    els.appFooter.classList.add("hidden");
  } else if (name === "main") {
    els.viewMain.classList.remove("hidden");
    els.appFooter.classList.remove("hidden");
  }
}

async function apiCall(endpoint, method = "GET", body = null) {
  const url = `${state.serverUrl.replace(/\/+$/, "")}${endpoint}`;
  const headers = {
    "X-TeamVault-Extension": "1",
    "Accept": "application/json",
  };

  if (state.token) {
    headers["Authorization"] = `Bearer ${state.token}`;
    headers["X-Session-Key"] = state.token;
  }

  const opts = {
    method,
    headers,
    credentials: "include",
  };

  if (body) {
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }

  try {
    const res = await fetch(url, opts);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    return data;
  } catch (err) {
    console.error("API error:", err);
    throw err;
  }
}

function extractDomain(urlStr) {
  if (!urlStr) return "";
  try {
    const u = new URL(urlStr);
    if (u.protocol !== "http:" && u.protocol !== "https:") return "";
    return u.hostname.toLowerCase();
  } catch {
    return "";
  }
}

async function copyToClipboard(text, successMsg = "Скопировано в буфер обмена!") {
  try {
    await navigator.clipboard.writeText(text);
    showMessage(successMsg, "success");
  } catch {
    showMessage("Не удалось скопировать", "error");
  }
}

function renderCredentials(items) {
  els.credentialsList.innerHTML = "";

  if (!items || items.length === 0) {
    els.emptyState.classList.remove("hidden");
    if (els.searchInput.value.trim()) {
      els.emptyText.textContent = "По вашему запросу ничего не найдено.";
    } else {
      els.emptyText.textContent = `Для ${state.currentDomain || "этого сайта"} нет сохранённых записей.`;
    }
    return;
  }

  els.emptyState.classList.add("hidden");

  items.forEach((item) => {
    const card = document.createElement("div");
    card.className = "cred-card";

    // Card Header
    const header = document.createElement("div");
    header.className = "cred-header";
    header.innerHTML = `
      <div class="cred-title">${escapeHtml(item.title)}</div>
      <span class="cred-vault-badge">${escapeHtml(item.vault)}</span>
    `;
    card.appendChild(header);

    // Login Row
    if (item.login) {
      const loginRow = document.createElement("div");
      loginRow.className = "cred-login-row";
      loginRow.innerHTML = `
        <span class="cred-login-text" title="${escapeHtml(item.login)}">${escapeHtml(item.login)}</span>
        <button class="btn-copy-login" title="Скопировать логин">${COPY_ICON_SVG}</button>
      `;
      loginRow.querySelector(".btn-copy-login").addEventListener("click", () => {
        copyToClipboard(item.login, "Логин скопирован");
      });
      card.appendChild(loginRow);
    }

    // Actions Row
    const actions = document.createElement("div");
    actions.className = "cred-actions";

    // Fill button
    const btnFill = document.createElement("button");
    btnFill.className = "btn btn-primary";
    btnFill.innerHTML = "⚡ Заполнить";
    btnFill.title = "Автоматически подставить логин и пароль на открытой странице";
    btnFill.addEventListener("click", () => fillIntoActiveTab(item.id, btnFill));
    actions.appendChild(btnFill);

    // Copy Password button
    const btnCopyPwd = document.createElement("button");
    btnCopyPwd.className = "btn btn-secondary";
    btnCopyPwd.innerHTML = "🔑 Пароль";
    btnCopyPwd.title = "Запросить и скопировать пароль";
    btnCopyPwd.addEventListener("click", () => copyPassword(item.id, btnCopyPwd));
    actions.appendChild(btnCopyPwd);

    // TOTP button
    if (item.has_totp) {
      const btnTotp = document.createElement("button");
      btnTotp.className = "btn btn-totp";
      btnTotp.innerHTML = "⏱ Код TOTP";
      btnTotp.title = "Получить одноразовый код подтверждения";
      btnTotp.addEventListener("click", () => fetchAndShowTotp(item.id, card, btnTotp));
      actions.appendChild(btnTotp);
    }

    card.appendChild(actions);
    els.credentialsList.appendChild(card);
  });
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/[&<>"']/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[m]));
}

async function fillIntoActiveTab(itemId, btn) {
  const originalText = btn ? btn.innerHTML : "";
  try {
    if (btn) btn.innerHTML = "⏳ Запрос...";
    const creds = await apiCall(`/api/extension/fill/${itemId}/`, "POST");

    if (!state.activeTab || !state.activeTab.id) {
      showMessage("Нет активной вкладки для заполнения", "error");
      if (btn) btn.innerHTML = originalText;
      return;
    }

    chrome.tabs.sendMessage(
      state.activeTab.id,
      {
        action: "FILL_CREDENTIALS",
        login: creds.login,
        password: creds.password,
      },
      (response) => {
        if (btn) btn.innerHTML = originalText;
        if (chrome.runtime.lastError) {
          showMessage("Откройте страницу входа для автоподстановки", "error");
        } else if (response && response.success) {
          showMessage("Данные успешно подставлены!", "success");
          setTimeout(() => window.close(), 600);
        } else {
          showMessage("Поля на странице не найдены", "error");
        }
      }
    );
  } catch (err) {
    if (btn) btn.innerHTML = originalText;
    showMessage(err.message || "Ошибка получения пароля", "error");
  }
}

async function copyPassword(itemId, btn) {
  const originalText = btn ? btn.innerHTML : "";
  try {
    if (btn) btn.innerHTML = "⏳...";
    const creds = await apiCall(`/api/extension/fill/${itemId}/`, "POST");
    await copyToClipboard(creds.password, "Пароль скопирован в буфер!");
    if (btn) {
      btn.innerHTML = "✓ Скопирован";
      setTimeout(() => { btn.innerHTML = originalText; }, 1800);
    }
  } catch (err) {
    if (btn) btn.innerHTML = originalText;
    showMessage(err.message || "Ошибка получения пароля", "error");
  }
}

async function fetchAndShowTotp(itemId, cardEl, btn) {
  try {
    const existingTotp = cardEl.querySelector(".totp-box");
    if (existingTotp) {
      existingTotp.remove();
      return;
    }

    showMessage("Генерация кода...", "success");
    const res = await apiCall(`/api/extension/totp/${itemId}/`, "POST");

    const totpBox = document.createElement("div");
    totpBox.className = "totp-box";
    totpBox.innerHTML = `
      <span class="totp-digits">${res.code}</span>
      <span class="totp-timer">⏳ ${res.seconds_left} сек</span>
      <button class="btn btn-secondary btn-copy-totp" style="min-height:36px; padding:6px 12px; font-size:13px;">Скопировать</button>
    `;

    totpBox.querySelector(".btn-copy-totp").addEventListener("click", () => {
      copyToClipboard(res.code, "Код TOTP скопирован!");
    });

    // Also send to tab to fill if OTP input exists
    if (state.activeTab && state.activeTab.id) {
      chrome.tabs.sendMessage(state.activeTab.id, { action: "FILL_TOTP", code: res.code }, () => {
        if (chrome.runtime.lastError) {}
      });
    }

    await copyToClipboard(res.code, `Код TOTP (${res.code}) скопирован!`);
    cardEl.appendChild(totpBox);
  } catch (err) {
    showMessage(err.message || "Ошибка генерации TOTP", "error");
  }
}

async function loadCredentials(query = "") {
  els.loadingSpinner.classList.remove("hidden");
  els.emptyState.classList.add("hidden");

  try {
    const params = new URLSearchParams();
    if (state.currentDomain) params.set("domain", state.currentDomain);
    if (query) params.set("q", query);

    const data = await apiCall(`/api/extension/find/?${params.toString()}`);
    els.loadingSpinner.classList.add("hidden");
    renderCredentials(data.items || []);
  } catch (err) {
    els.loadingSpinner.classList.add("hidden");
    showMessage(err.message || "Ошибка загрузки записей", "error");
  }
}

async function checkAuthAndInit() {
  els.loadingSpinner.classList.remove("hidden");

  try {
    const status = await apiCall("/api/extension/status/");
    els.loadingSpinner.classList.add("hidden");

    if (status.authenticated) {
      state.user = status;
      let displayName = status.name || status.username || "User";
      if (displayName.startsWith("ad_") && status.email) {
        displayName = status.email.split("@")[0];
      }
      els.userName.textContent = displayName;

      // Initials for avatar
      let initial = "U";
      if (displayName && displayName.trim()) {
        const parts = displayName.trim().split(/\s+/).filter(p => !/^[A-Za-z0-9_-]{1,6}\d+$/.test(p));
        const useParts = parts.length > 0 ? parts : displayName.trim().split(/\s+/);
        if (useParts.length >= 2) {
          initial = (useParts[0][0] + useParts[1][0]).toUpperCase();
        } else {
          initial = useParts[0][0].toUpperCase();
        }
      } else if (status.username) {
        initial = status.username.replace(/^ad_/i, "").charAt(0).toUpperCase() || "U";
      }
      if (els.userAvatar) els.userAvatar.textContent = initial;

      els.linkOpenVault.href = state.serverUrl;
      showView("main");
      await loadCredentials();
    } else {
      showView("auth");
    }
  } catch (err) {
    els.loadingSpinner.classList.add("hidden");
    showView("auth");
  }
}

// Event Listeners
els.btnSettingsToggle.addEventListener("click", () => {
  showView("settings");
});

els.btnSettingsClose.addEventListener("click", () => {
  checkAuthAndInit();
});

els.btnSaveSettings.addEventListener("click", async () => {
  let url = els.serverUrlInput.value.trim();
  if (!url) url = DEFAULT_SERVER_URL;
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
  }
  state.serverUrl = url;
  await chrome.storage.local.set({ serverUrl: url });
  showMessage("Адрес сервера сохранён", "success");
  checkAuthAndInit();
});

if (els.btnOpenLogin) {
  els.btnOpenLogin.addEventListener("click", () => {
    chrome.tabs.create({ url: state.serverUrl + "/login/" });
  });
}

if (els.btnRefreshAuth) {
  els.btnRefreshAuth.addEventListener("click", () => {
    checkAuthAndInit();
  });
}

els.btnLogout.addEventListener("click", async () => {
  try {
    await apiCall("/api/extension/logout/", "POST");
  } catch {}
  state.token = null;
  state.user = null;
  await chrome.storage.local.remove(["token"]);
  showMessage("Вы вышли из системы", "success");
  showView("auth");
});

let searchDebounceTimer = null;
els.searchInput.addEventListener("input", (e) => {
  clearTimeout(searchDebounceTimer);
  searchDebounceTimer = setTimeout(() => {
    loadCredentials(e.target.value.trim());
  }, 250);
});

// App Startup
async function init() {
  const stored = await chrome.storage.local.get(["serverUrl", "token"]);
  if (stored.serverUrl) state.serverUrl = stored.serverUrl;
  if (stored.token) state.token = stored.token;

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    state.activeTab = tab;
    state.currentDomain = extractDomain(tab?.url);
    els.currentDomain.textContent = state.currentDomain || "Новая вкладка";
  } catch (err) {
    console.error("Tab query failed:", err);
  }

  await checkAuthAndInit();
}

document.addEventListener("DOMContentLoaded", init);
