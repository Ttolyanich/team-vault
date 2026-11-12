"use strict";
(() => {
  const icon = path => {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24"); svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("fill", "none"); svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "1.8"); svg.setAttribute("stroke-linecap", "round"); svg.setAttribute("stroke-linejoin", "round");
    const line = document.createElementNS(svg.namespaceURI, "path"); line.setAttribute("d", path); svg.append(line); return svg;
  };
  let serial = 0;
  document.querySelectorAll("select[data-search-select]").forEach(select => {
    if (select.disabled) return;
    const source = new URL(select.dataset.source, location.href);
    if (source.origin !== location.origin) return;
    const required = select.required;
    const oldId = select.id || `entity-${++serial}`;
    const root = document.createElement("div"); root.className = "search-choice";
    select.before(root); root.append(select); select.hidden = true; select.required = false; select.id = `${oldId}-value`;
    const input = document.createElement("input"); input.type = "text"; input.id = oldId; input.className = "search-choice-input";
    input.autocomplete = "off"; input.required = required; input.placeholder = "Начните вводить имя или название";
    input.setAttribute("role", "combobox"); input.setAttribute("aria-autocomplete", "list"); input.setAttribute("aria-expanded", "false");
    ["aria-describedby", "aria-invalid", "aria-label"].forEach(name => { if (select.hasAttribute(name)) input.setAttribute(name, select.getAttribute(name)); });
    input.value = (select.value && select.selectedOptions && select.selectedOptions[0]) ? select.selectedOptions[0].textContent : "";
    const clear = document.createElement("button"); clear.type = "button"; clear.className = "search-choice-clear"; clear.append(icon("M7 7l10 10M17 7L7 17")); clear.setAttribute("aria-label", "Снять выбор"); clear.hidden = required || !select.value;
    const toggle = document.createElement("button"); toggle.type = "button"; toggle.className = "search-choice-toggle"; toggle.append(icon("M6 9l6 6 6-6")); toggle.setAttribute("aria-label", "Открыть список вариантов");
    const panel = document.createElement("div"); panel.className = "search-choice-panel"; panel.setAttribute("popover", "manual");
    const list = document.createElement("div"); list.id = `${oldId}-options`; list.setAttribute("role", "listbox"); input.setAttribute("aria-controls", list.id);
    const status = document.createElement("div"); status.className = "search-choice-status"; status.setAttribute("role", "status");
    const more = document.createElement("button"); more.type = "button"; more.className = "text-button search-choice-more"; more.textContent = "Показать ещё"; more.hidden = true;
    panel.append(list, status, more); root.append(input, clear, toggle, panel);
    let opened = false, options = [], active = -1, page = 1, currentQuery = "", controller, timer, generation = 0;
    const validity = () => input.setCustomValidity(!select.value && (required || input.value.trim()) ? "Выберите вариант из результатов поиска." : "");
    const place = () => {
      const box = input.getBoundingClientRect(); const below = innerHeight - box.bottom - 12, above = box.top - 12;
      const height = Math.min(320, Math.max(below, above));
      panel.style.width = `${Math.min(box.width + 2, innerWidth - 16)}px`; panel.style.left = `${Math.max(8, Math.min(box.left, innerWidth - box.width - 8))}px`;
      panel.style.maxHeight = `${Math.max(100, height)}px`;
      if (below >= 180 || below >= above) { panel.style.top = `${box.bottom + 6}px`; panel.style.bottom = "auto"; }
      else { panel.style.top = "auto"; panel.style.bottom = `${innerHeight - box.top + 6}px`; }
    };
    const close = () => { opened = false; input.setAttribute("aria-expanded", "false"); input.removeAttribute("aria-activedescendant"); if (panel.hidePopover) { if (panel.matches(":popover-open")) panel.hidePopover(); } else panel.classList.remove("is-open"); };
    const setActive = index => {
      active = index;
      Array.from(list.children).forEach((element, n) => element.classList.toggle("is-active", n === index));
      if (list.children[index]) { input.setAttribute("aria-activedescendant", list.children[index].id); list.children[index].scrollIntoView({block:"nearest"}); }
      else input.removeAttribute("aria-activedescendant");
    };
    const commit = item => {
      select.replaceChildren(new Option("Не выбрано", ""), new Option(item.label, item.id, true, true));
      input.value = item.label; clear.hidden = required || !item.id; validity(); close();
      select.dispatchEvent(new Event("change", {bubbles:true}));
      if (select.hasAttribute("data-auto-submit")) select.form?.requestSubmit();
    };
    const render = () => {
      list.replaceChildren();
      options.forEach((item, index) => {
        const option = document.createElement("div"); option.className = "search-choice-option"; option.id = `${oldId}-option-${index}`;
        option.setAttribute("role", "option"); option.setAttribute("aria-selected", String(select.value === item.id));
        const name = document.createElement("strong"); name.textContent = item.label;
        const detail = document.createElement("small"); detail.textContent = item.detail || "";
        option.append(name, detail); option.addEventListener("pointerdown", event => event.preventDefault());
        option.addEventListener("pointermove", () => setActive(index)); option.addEventListener("click", () => commit(item)); list.append(option);
      });
      if (options.length) setActive(select.value ? options.findIndex(item => item.id === select.value) : 0);
    };
    const fetchOptions = async (query, next = false) => {
      controller?.abort(); controller = new AbortController(); const request = ++generation;
      if (!next) { page = 1; options = []; list.replaceChildren(); currentQuery = query; }
      status.textContent = "Поиск…"; more.hidden = true;
      const url = new URL(source); url.searchParams.set("q", query); url.searchParams.set("page", String(page));
      try {
        const response = await fetch(url, {credentials:"same-origin", signal:controller.signal});
        if (!response.ok) throw new Error();
        const result = await response.json(); if (request !== generation) return;
        options = next ? options.concat(result.results) : result.results;
        render(); status.textContent = options.length ? "" : "Ничего не найдено. Уточните имя или название."; more.hidden = !result.more;
      } catch (error) { if (error.name !== "AbortError" && request === generation) status.textContent = "Не удалось загрузить список. Попробуйте ещё раз."; }
    };
    const open = () => {
      if (opened) return;
      opened = true; input.setAttribute("aria-expanded", "true"); place();
      if (panel.showPopover) panel.showPopover(); else panel.classList.add("is-open");
      fetchOptions(select.value ? "" : input.value.trim());
    };
    input.addEventListener("focus", () => { open(); if (select.value) input.select(); });
    input.addEventListener("click", open);
    input.addEventListener("input", () => { select.value = ""; clear.hidden = required || !input.value; validity(); open(); clearTimeout(timer); timer = setTimeout(() => fetchOptions(input.value.trim()), 200); });
    input.addEventListener("keydown", event => {
      if (event.key === "ArrowDown" || event.key === "ArrowUp") { event.preventDefault(); if (!opened) open(); if (options.length) setActive(active < 0 ? (event.key === "ArrowDown" ? 0 : options.length - 1) : (active + (event.key === "ArrowDown" ? 1 : -1) + options.length) % options.length); }
      else if (opened && event.key === "Enter") { event.preventDefault(); if (options[active]) commit(options[active]); }
      else if (opened && event.key === "Escape") { event.preventDefault(); event.stopPropagation(); close(); }
      else if (opened && ["Home", "End"].includes(event.key)) { event.preventDefault(); setActive(event.key === "Home" ? 0 : options.length - 1); }
      else if (event.key === "Tab") close();
    });
    clear.addEventListener("click", event => { event.preventDefault(); commit({id:"",label:""}); });
    toggle.addEventListener("click", event => { event.preventDefault(); if (opened) close(); else { input.focus(); open(); } });
    more.addEventListener("pointerdown", event => event.preventDefault()); more.addEventListener("click", () => { page += 1; fetchOptions(currentQuery, true); });
    document.addEventListener("pointerdown", event => { if (!root.contains(event.target)) close(); });
    root.addEventListener("focusout", () => setTimeout(() => { if (!root.contains(document.activeElement)) close(); }, 0));
    window.addEventListener("resize", () => { if (opened) place(); });
    document.addEventListener("scroll", event => { if (opened && !panel.contains(event.target)) place(); }, true);
    validity();
  });
  document.querySelectorAll("[data-department-search]").forEach(input => input.addEventListener("input", () => {
    const query = input.value.toLocaleLowerCase().trim(); document.querySelectorAll("[data-department-link]").forEach(link => { link.hidden = !link.textContent.toLocaleLowerCase().includes(query); });
  }));
})();
