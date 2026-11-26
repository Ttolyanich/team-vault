// TeamVault Chrome Extension - Content Script

function setInputValue(el, value) {
  if (!el) return;
  el.focus();
  const proto = Object.getPrototypeOf(el);
  const descriptor = Object.getOwnPropertyDescriptor(proto, 'value') || Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
  if (descriptor && descriptor.set) {
    descriptor.set.call(el, value);
  } else {
    el.value = value;
  }
  el.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
  el.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
}

function isVisible(el) {
  if (!el) return false;
  const style = window.getComputedStyle(el);
  return style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0' && el.offsetWidth > 0 && el.offsetHeight > 0;
}

function findPasswordInput() {
  const inputs = Array.from(document.querySelectorAll('input[type="password"]'));
  return inputs.find(isVisible) || inputs[0];
}

function findLoginInput(passwordInput) {
  // If inside a form, search within the form first
  const form = passwordInput ? passwordInput.closest('form') : document;
  const selector = 'input[type="text"], input[type="email"], input[type="tel"], input:not([type])';
  const candidates = Array.from((form || document).querySelectorAll(selector)).filter(isVisible);

  if (passwordInput) {
    // Check elements preceding password input in DOM order
    const formInputs = Array.from((form || document).querySelectorAll('input')).filter(isVisible);
    const pwdIndex = formInputs.indexOf(passwordInput);
    if (pwdIndex > 0) {
      for (let i = pwdIndex - 1; i >= 0; i--) {
        const inp = formInputs[i];
        if (inp.type !== 'hidden' && inp.type !== 'submit' && inp.type !== 'button' && inp.type !== 'checkbox' && inp.type !== 'radio') {
          return inp;
        }
      }
    }
  }

  // Look for semantic names
  const regex = /(user|login|email|auth|account|name)/i;
  for (const inp of candidates) {
    if (regex.test(inp.name || '') || regex.test(inp.id || '') || regex.test(inp.getAttribute('autocomplete') || '')) {
      return inp;
    }
  }

  return candidates[0] || null;
}

function findTotpInput() {
  const selector = 'input[type="text"], input[type="number"], input[type="tel"], input:not([type])';
  const candidates = Array.from(document.querySelectorAll(selector)).filter(isVisible);
  const regex = /(otp|totp|code|2fa|token|two-factor|verification|mfa|пароль|код)/i;

  for (const inp of candidates) {
    const ac = inp.getAttribute('autocomplete') || '';
    if (ac === 'one-time-code' || regex.test(inp.name || '') || regex.test(inp.id || '') || regex.test(inp.placeholder || '')) {
      return inp;
    }
  }
  return candidates[0] || null;
}

function showBanner(text, type = 'success') {
  const existing = document.getElementById('teamvault-toast-banner');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.id = 'teamvault-toast-banner';
  toast.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    z-index: 2147483647;
    background: #0f172a;
    color: ${type === 'success' ? '#2ebd85' : '#f59e0b'};
    border: 1px solid ${type === 'success' ? '#2ebd85' : '#f59e0b'};
    border-radius: 8px;
    padding: 12px 18px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 14px;
    font-weight: 500;
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.4);
    display: flex;
    align-items: center;
    gap: 10px;
    transition: opacity 0.3s ease, transform 0.3s ease;
    opacity: 0;
    transform: translateY(-10px);
  `;
  toast.textContent = text;
  document.body.appendChild(toast);

  requestAnimationFrame(() => {
    toast.style.opacity = '1';
    toast.style.transform = 'translateY(0)';
  });

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(-10px)';
    setTimeout(() => toast.remove(), 300);
  }, 2500);
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'FILL_CREDENTIALS') {
    const pwdInput = findPasswordInput();
    const loginInput = findLoginInput(pwdInput);

    let filled = false;
    if (message.login && loginInput) {
      setInputValue(loginInput, message.login);
      filled = true;
    }
    if (message.password && pwdInput) {
      setInputValue(pwdInput, message.password);
      filled = true;
    }

    if (filled) {
      showBanner('✓ Данные успешно подставлены из TeamVault', 'success');
      sendResponse({ success: true });
    } else {
      showBanner('Поля входа на странице не найдены', 'warning');
      sendResponse({ success: false });
    }
  } else if (message.action === 'FILL_TOTP') {
    const totpInput = findTotpInput();
    if (totpInput && message.code) {
      setInputValue(totpInput, message.code);
      showBanner('✓ Одноразовый код TOTP вставлен', 'success');
      sendResponse({ success: true });
    } else {
      showBanner('Поле для кода подтверждения не найдено', 'warning');
      sendResponse({ success: false });
    }
  }
  return true;
});
