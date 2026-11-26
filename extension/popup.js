// TeamVault Chrome Extension - Popup Logic

const DEFAULT_SERVER_URL = "https://teamvault-demo.itsg.kz";

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
  viewLogin: document.getElementById("view-login"),
  viewMain: document.getElementById("view-main"),
  serverUrlInput: document.getElementById("server-url"),
  btnSettingsToggle: document.getElementById("btn-settings-toggle"),
  btnSettingsClose: document.getElementById("btn-settings-close"),
  btnSaveSettings: document.getElementById("btn-save-settings"),
  formLogin: document.getElementById("form-login"),
  loginUsername: document.getElementById("login-username"),
  loginPassword: document.getElementById("login-password"),
  currentDomain: document.getElementById("current-domain"),
  searchInput: document.getElementById("search-input"),
  loadingSpinner: document.getElementById("loading-spinner"),
  emptyState: document.getElementById("empty-state"),
  emptyText: document.getElementById("empty-text"),
  credentialsList: document.getElementById("credentials-list"),
  appFooter: document.getElementById("app-footer"),
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
  els.viewLogin.classList.add("hidden");
  els.viewMain.classList.add("hidden");

  if (name === "settings") {
    els.viewSettings.classList.remove("hidden");
    els.serverUrlInput.value = state.serverUrl;
  } else if (name === "login") {
    els.viewLogin.classList.remove("hidden");
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

async function copyToClipboard(text, successMsg = "Скопировано в буфер!") {
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
        <button class="icon-btn btn-copy-login" title="Скопировать логин">📋</button>
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
    btnFill.addEventListener("click", () => fillIntoActiveTab(item.id));
    actions.appendChild(btnFill);

    // Copy Password button
    const btnCopyPwd = document.createElement("button");
    btnCopyPwd.className = "btn btn-secondary";
    btnCopyPwd.innerHTML = "🔑 Пароль";
    btnCopyPwd.title = "Запросить и скопировать пароль";
    btnCopyPwd.addEventListener("click", () => copyPassword(item.id));
    actions.appendChild(btnCopyPwd);

    // TOTP button
    if (item.has_totp) {
      const btnTotp = document.createElement("button");
      btnTotp.className = "btn btn-secondary";
      btnTotp.innerHTML = "⏱ TOTP";
      btnTotp.title = "Получить одноразовый код подтверждения";
      btnTotp.addEventListener("click", () => fetchAndShowTotp(item.id, card));
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

async function fillIntoActiveTab(itemId) {
  try {
    showMessage("Запрос пароля...", "success");
    const creds = await apiCall(`/api/extension/fill/${itemId}/`, "POST");

    if (!state.activeTab || !state.activeTab.id) {
      showMessage("Нет активной вкладки для заполнения", "error");
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
        if (chrome.runtime.lastError) {
          showMessage("Откройте страницу входа для автоподстановки", "error");
        } else if (response && response.success) {
          showMessage("Данные подставлены!", "success");
          window.close();
        } else {
          showMessage("Поля на странице не найдены", "error");
        }
      }
    );
  } catch (err) {
    showMessage(err.message || "Ошибка получения пароля", "error");
  }
}

async function copyPassword(itemId) {
  try {
    showMessage("Запрос пароля...", "success");
    const creds = await apiCall(`/api/extension/fill/${itemId}/`, "POST");
    await copyToClipboard(creds.password, "Пароль скопирован в буфер!");
  } catch (err) {
    showMessage(err.message || "Ошибка получения пароля", "error");
  }
}

async function fetchAndShowTotp(itemId, cardEl) {
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
      <button class="btn btn-secondary btn-copy-totp" style="padding:3px 6px;">📋 Скопировать</button>
    `;

    totpBox.querySelector(".btn-copy-totp").addEventListener("click", () => {
      copyToClipboard(res.code, "Код TOTP скопирован!");
    });

    // Also send to tab to fill if OTP input exists
    if (state.activeTab && state.activeTab.id) {
      chrome.tabs.sendMessage(state.activeTab.id, { action: "FILL_TOTP", code: res.code }, () => {
        // ignore errors if not on totp page
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
      els.userName.textContent = status.name || status.username;
      els.linkOpenVault.href = state.serverUrl;
      showView("main");
      await loadCredentials();
    } else {
      showView("login");
    }
  } catch (err) {
    els.loadingSpinner.classList.add("hidden");
    showView("login");
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

els.formLogin.addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = els.loginUsername.value.trim();
  const password = els.loginPassword.value;

  els.loadingSpinner.classList.remove("hidden");

  try {
    const res = await apiCall("/api/extension/login/", "POST", { username, password });
    els.loadingSpinner.classList.add("hidden");

    state.token = res.token;
    await chrome.storage.local.set({ token: res.token });

    showMessage("Вход выполнен успешно!", "success");
    checkAuthAndInit();
  } catch (err) {
    els.loadingSpinner.classList.add("hidden");
    showMessage(err.message || "Неверный логин или пароль", "error");
  }
});

els.btnLogout.addEventListener("click", async () => {
  try {
    await apiCall("/api/extension/logout/", "POST");
  } catch {}
  state.token = null;
  state.user = null;
  await chrome.storage.local.remove(["token"]);
  showMessage("Вы вышли из системы", "success");
  showView("login");
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
  // 1. Load saved config
  const stored = await chrome.storage.local.get(["serverUrl", "token"]);
  if (stored.serverUrl) state.serverUrl = stored.serverUrl;
  if (stored.token) state.token = stored.token;

  // 2. Query active tab
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    state.activeTab = tab;
    state.currentDomain = extractDomain(tab?.url);
    els.currentDomain.textContent = state.currentDomain || "Новая вкладка";
  } catch (err) {
    console.error("Tab query failed:", err);
  }

  // 3. Check auth
  await checkAuthAndInit();
}

document.addEventListener("DOMContentLoaded", init);
