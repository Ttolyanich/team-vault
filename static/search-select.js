"use strict";
(() => {
  const icon = path => {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "1.8");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    const line = document.createElementNS(svg.namespaceURI, "path");
    line.setAttribute("d", path);
    svg.append(line);
    return svg;
  };

  let serial = 0;
  document.querySelectorAll("select[data-search-select]").forEach(select => {
    if (select.disabled) return;
    const source = new URL(select.dataset.source, location.href);
    if (source.origin !== location.origin) return;

    const required = select.required;
    const allowEmptyLabel = select.hasAttribute("data-allow-empty-label");
    const emptyOption = select.querySelector('option[value=""]');
    const emptyLabel = emptyOption ? emptyOption.textContent.trim() : "";
    const placeholder = select.dataset.placeholder || emptyLabel || "Нажмите для выбора";
    const oldId = select.id || `entity-${++serial}`;

    const root = document.createElement("div");
    root.className = "search-choice";
    select.before(root);
    root.append(select);
    select.hidden = true;
    select.required = false;
    select.id = `${oldId}-value`;

    // 1. Trigger button (селектор)
    const trigger = document.createElement("button");
    trigger.type = "button";
    trigger.id = oldId;
    trigger.className = "search-choice-trigger";
    trigger.setAttribute("aria-haspopup", "listbox");
    trigger.setAttribute("aria-expanded", "false");
    ["aria-describedby", "aria-label"].forEach(name => {
      if (select.hasAttribute(name)) trigger.setAttribute(name, select.getAttribute(name));
    });

    const labelSpan = document.createElement("span");
    labelSpan.className = "search-choice-label";
    if (select.value && select.selectedOptions && select.selectedOptions[0]) {
      labelSpan.textContent = select.selectedOptions[0].textContent;
    } else if (allowEmptyLabel && emptyLabel) {
      labelSpan.textContent = emptyLabel;
    } else {
      labelSpan.textContent = placeholder;
    }

    const arrowSpan = document.createElement("span");
    arrowSpan.className = "search-choice-arrow";
    arrowSpan.append(icon("M6 9l6 6 6-6"));
    trigger.append(labelSpan, arrowSpan);

    // 2. Dropdown panel
    const panel = document.createElement("div");
    panel.className = "search-choice-panel";
    panel.setAttribute("popover", "manual");
    panel.id = `${oldId}-panel`;

    // Search input inside panel
    const searchBox = document.createElement("div");
    searchBox.className = "search-choice-search-box";
    const searchIcon = document.createElement("span");
    searchIcon.className = "search-choice-search-icon";
    searchIcon.append(icon("M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"));
    const searchInput = document.createElement("input");
    searchInput.type = "text";
    searchInput.className = "search-choice-search-input";
    searchInput.placeholder = "Поиск по названию…";
    searchInput.autocomplete = "off";
    searchBox.append(searchIcon, searchInput);

    const list = document.createElement("div");
    list.id = `${oldId}-options`;
    list.className = "search-choice-options";
    list.setAttribute("role", "listbox");
    searchInput.setAttribute("aria-controls", list.id);

    const status = document.createElement("div");
    status.className = "search-choice-status";
    status.setAttribute("role", "status");

    const more = document.createElement("button");
    more.type = "button";
    more.className = "text-button search-choice-more";
    more.textContent = "Показать ещё";
    more.hidden = true;

    panel.append(searchBox, list, status, more);
    root.append(trigger, panel);

    let opened = false, options = [], active = -1, page = 1, currentQuery = "", controller, timer, generation = 0;

    const place = () => {
      const box = trigger.getBoundingClientRect();
      const below = innerHeight - box.bottom - 12, above = box.top - 12;
      const height = Math.min(340, Math.max(below, above));
      panel.style.width = `${Math.min(box.width, innerWidth - 16)}px`;
      panel.style.left = `${Math.max(8, Math.min(box.left, innerWidth - box.width - 8))}px`;
      panel.style.maxHeight = `${Math.max(120, height)}px`;
      if (below >= 200 || below >= above) {
        panel.style.top = `${box.bottom + 6}px`;
        panel.style.bottom = "auto";
      } else {
        panel.style.top = "auto";
        panel.style.bottom = `${innerHeight - box.top + 6}px`;
      }
    };

    const close = () => {
      if (!opened) return;
      opened = false;
      trigger.setAttribute("aria-expanded", "false");
      searchInput.removeAttribute("aria-activedescendant");
      if (panel.hidePopover) {
        if (panel.matches(":popover-open")) panel.hidePopover();
      }
      panel.classList.remove("is-open");
    };

    const setActive = index => {
      active = index;
      Array.from(list.children).forEach((element, n) => element.classList.toggle("is-active", n === index));
      if (list.children[index]) {
        searchInput.setAttribute("aria-activedescendant", list.children[index].id);
        list.children[index].scrollIntoView({block: "nearest"});
      } else {
        searchInput.removeAttribute("aria-activedescendant");
      }
    };

    const commit = item => {
      select.replaceChildren(
        new Option(emptyLabel || "Не выбрано", ""),
        item.id ? new Option(item.label, item.id, true, true) : null
      );
      if (!item.id) select.value = "";
      labelSpan.textContent = item.label || (allowEmptyLabel ? emptyLabel : placeholder);
      trigger.classList.remove("is-invalid");
      close();
      trigger.focus();
      select.dispatchEvent(new Event("change", {bubbles: true}));
      if (select.hasAttribute("data-auto-submit")) select.form?.requestSubmit();
    };

    const render = () => {
      list.replaceChildren();
      options.forEach((item, index) => {
        const option = document.createElement("div");
        option.className = "search-choice-option";
        option.id = `${oldId}-option-${index}`;
        option.setAttribute("role", "option");
        option.setAttribute("aria-selected", String(select.value === item.id));
        const name = document.createElement("strong");
        name.textContent = item.label;
        const detail = document.createElement("small");
        detail.textContent = item.detail || "";
        option.append(name, detail);
        option.addEventListener("pointerdown", event => event.preventDefault());
        option.addEventListener("pointermove", () => setActive(index));
        option.addEventListener("click", () => commit(item));
        list.append(option);
      });
      if (options.length) {
        setActive(select.value ? Math.max(0, options.findIndex(item => item.id === select.value)) : 0);
      }
    };

    const fetchOptions = async (query, next = false) => {
      controller?.abort();
      controller = new AbortController();
      const request = ++generation;
      if (!next) { page = 1; options = []; list.replaceChildren(); currentQuery = query; }
      status.textContent = "Поиск…";
      more.hidden = true;
      const url = new URL(source);
      url.searchParams.set("q", query);
      url.searchParams.set("page", String(page));
      try {
        const response = await fetch(url, {credentials: "same-origin", signal: controller.signal});
        if (!response.ok) throw new Error();
        const result = await response.json();
        if (request !== generation) return;
        let fetched = result.results;
        if (!next && allowEmptyLabel && emptyLabel && (!query || emptyLabel.toLowerCase().includes(query.toLowerCase()))) {
          fetched = [{ id: "", label: emptyLabel, detail: "Все секреты из всех доступных хранилищ" }].concat(fetched);
        }
        options = next ? options.concat(fetched) : fetched;
        render();
        status.textContent = options.length ? "" : "Ничего не найдено. Уточните запрос.";
        more.hidden = !result.more;
      } catch (error) {
        if (error.name !== "AbortError" && request === generation) {
          status.textContent = "Не удалось загрузить список. Попробуйте ещё раз.";
        }
      }
    };

    const open = () => {
      if (opened) return;
      opened = true;
      trigger.setAttribute("aria-expanded", "true");
      place();
      if (panel.showPopover) panel.showPopover();
      panel.classList.add("is-open");
      searchInput.value = "";
      fetchOptions("");
      setTimeout(() => searchInput.focus(), 50);
    };

    trigger.addEventListener("click", () => {
      if (opened) close(); else open();
    });
    trigger.addEventListener("keydown", event => {
      if (["Enter", " ", "ArrowDown"].includes(event.key)) {
        event.preventDefault();
        open();
      }
    });

    searchInput.addEventListener("input", () => {
      clearTimeout(timer);
      timer = setTimeout(() => fetchOptions(searchInput.value.trim()), 180);
    });
    searchInput.addEventListener("keydown", event => {
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        if (options.length) {
          setActive(active < 0 ? (event.key === "ArrowDown" ? 0 : options.length - 1) : (active + (event.key === "ArrowDown" ? 1 : -1) + options.length) % options.length);
        }
      } else if (event.key === "Enter") {
        event.preventDefault();
        if (options[active]) commit(options[active]);
      } else if (event.key === "Escape") {
        event.preventDefault();
        close();
        trigger.focus();
      }
    });

    more.addEventListener("pointerdown", event => event.preventDefault());
    more.addEventListener("click", () => { page += 1; fetchOptions(currentQuery, true); });

    document.addEventListener("pointerdown", event => {
      if (!root.contains(event.target)) close();
    });
    root.addEventListener("focusout", () => {
      setTimeout(() => { if (!root.contains(document.activeElement)) close(); }, 0);
    });
    window.addEventListener("resize", () => { if (opened) place(); });
    document.addEventListener("scroll", event => { if (opened && !panel.contains(event.target)) place(); }, true);

    if (required && select.form) {
      select.form.addEventListener("submit", event => {
        if (!select.value) {
          event.preventDefault();
          trigger.classList.add("is-invalid");
          open();
        }
      });
    }
  });

  document.querySelectorAll("[data-department-search]").forEach(input => input.addEventListener("input", () => {
    const query = input.value.toLocaleLowerCase().trim();
    document.querySelectorAll("[data-department-link]").forEach(link => {
      link.hidden = !link.textContent.toLocaleLowerCase().includes(query);
    });
  }));
})();
