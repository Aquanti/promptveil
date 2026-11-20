(() => {
  const RULES_KEY = 'promptveil_rules_v1';
  const AUDIT_KEY = 'promptveil_audit_v1';
  const LANG_KEY = 'promptveil_lang_v1';

  const PRESETS = {
    client_contract: 'Договор: почта legal@example.com, счёт IBAN DE89 3704 0044 0532 0130 00, карта 4111 1111 1111 1111',
    prod_env_trace: 'API_KEY=AKIAIOSFODNN7EXAMPLE host 203.0.113.42',
    bilingual_cis_hr: 'Кандидат Иван, тел +7 (916) 555-01-23, почта hr@example.com'
  };

  const I18N = {
    ru: {
      badge: 'Гарантия 0 хранения • Проверить',
      tabSan: '1. Скрыть данные',
      tabReh: '2. Вернуть в ответ ИИ',
      rulesBtn: (n) => `Свои слова (${n})`,
      auditBtn: 'Журнал',
      heroTitle: 'Скройте личные данные перед отправкой текста в ИИ',
      heroDesc: '1. Вставьте текст → 2. Скопируйте безопасную версию для ИИ → 3. Вставьте ответ ИИ и верните исходные значения.',
      presetLabel: 'Попробовать пример:',
      presetContract: 'Договор',
      presetHr: 'Резюме',
      presetEnv: 'Логи и ключи',
      applyPreset: 'Скрыть предложенные имена',
      allCats: 'Все категории',
      upload: 'Загрузить файл',
      autoLabel: 'Автоматически скрывать при вводе',
      sanNow: 'Проверить сейчас',
      clear: 'Очистить',
      rawLabel: 'Исходный текст',
      sanOutLabel: 'Безопасный текст для ИИ',
      copy: 'Скопировать',
      copied: 'Скопировано',
      download: 'Скачать',
      goReh: 'Перейти к ответу ИИ',
      vaultHeading: 'Что скрыто',
      hideVals: 'Скрыть значения',
      showVals: 'Показать значения',
      emptyVault: 'Пока пусто — вставьте текст или загрузите файл.',
      backSan: 'Назад к шагу 1',
      rehNow: 'Вернуть исходные данные',
      rehInLabel: 'Ответ ИИ с метками',
      rehOutLabel: 'Готовый ответ',
      rulesHeading: 'Свои слова для скрытия',
      add: 'Добавить',
      exportRules: 'Сохранить список',
      importRules: 'Загрузить список',
      close: 'Закрыть',
      del: 'Удалить',
      auditHeading: 'Журнал проверок',
      exportAudit: 'Сохранить журнал',
      clearAuditConfirm: 'Очистить журнал проверок?',
      unresolvedPrefix: 'Не удалось найти исходные значения для: ',
      cats: { EMAIL: 'Почта', IPV4: 'IP-адреса', CUSTOM: 'Свои слова', PHONE: 'Телефоны', IBAN: 'Счета (IBAN)' }
    },
    en: {
      badge: 'Zero-Retention • Verify',
      tabSan: '1. Sanitize Prompt',
      tabReh: '2. Re-Hydrate Reply',
      rulesBtn: (n) => `Rulebook (${n})`,
      auditBtn: 'Audit Receipts',
      heroTitle: 'Hide sensitive data before sending text to AI',
      heroDesc: '1. Paste text → 2. Copy safe version → 3. Paste AI reply and restore original values.',
      presetLabel: 'Try an example:',
      presetContract: 'Contract',
      presetHr: 'HR Brief',
      presetEnv: 'Logs & keys',
      applyPreset: 'Apply Preset Rules',
      allCats: 'All categories',
      upload: 'Upload local file',
      autoLabel: 'Live auto-sanitize',
      sanNow: 'Sanitize Now',
      clear: 'Clear',
      rawLabel: 'Prompt Input',
      sanOutLabel: 'Sanitized Output',
      copy: 'Copy',
      copied: 'Copied',
      download: 'Download',
      goReh: 'Go to Step 2',
      vaultHeading: 'Vault Mappings',
      hideVals: 'Hide values',
      showVals: 'Show values',
      emptyVault: 'No entities detected yet.',
      backSan: 'Back to Step 1',
      rehNow: 'Re-Hydrate Reply',
      rehInLabel: 'Masked LLM Reply',
      rehOutLabel: 'Restored Output',
      rulesHeading: 'Custom Rulebook',
      add: 'Add',
      exportRules: 'Export JSON',
      importRules: 'Import JSON',
      close: 'Close',
      del: 'Delete',
      auditHeading: 'Audit Receipts',
      exportAudit: 'Export JSON',
      clearAuditConfirm: 'Clear audit receipts?',
      unresolvedPrefix: 'Unresolved tokens: ',
      cats: { EMAIL: 'EMAIL', IPV4: 'IPV4', CUSTOM: 'CUSTOM', PHONE: 'PHONE', IBAN: 'IBAN' }
    }
  };

  let currentLang = 'ru';
  let vault = [];
  let disabledCategories = new Set();
  let hideValues = false;
  let showAllCats = false;
  let counters = {};

  function loadJson(key, fallback) {
    try {
      const raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch (_err) {
      return fallback;
    }
  }

  function saveJson(key, value) {
    localStorage.setItem(key, JSON.stringify(value));
  }

  function applyLang(lang) {
    currentLang = lang === 'en' ? 'en' : 'ru';
    document.documentElement.lang = currentLang;
    try {
      localStorage.setItem(LANG_KEY, currentLang);
    } catch (_err) {}
    const t = I18N[currentLang];
    const rules = loadJson(RULES_KEY, []);
    document.querySelector('[data-testid="brand-badge"]').textContent = t.badge;
    document.querySelector('[data-testid="mode-sanitize"]').textContent = t.tabSan;
    document.querySelector('[data-testid="mode-rehydrate"]').textContent = t.tabReh;
    document.querySelector('[data-testid="open-rulebook-btn"]').textContent = t.rulesBtn(rules.length);
    document.querySelector('[data-testid="open-audit-btn"]').textContent = t.auditBtn;
    document.getElementById('hero-title').textContent = t.heroTitle;
    document.getElementById('hero-desc').textContent = t.heroDesc;
    document.getElementById('preset-label').textContent = t.presetLabel;
    document.querySelector('[data-testid="preset-btn-client_contract"]').textContent = t.presetContract;
    document.querySelector('[data-testid="preset-btn-bilingual_cis_hr"]').textContent = t.presetHr;
    document.querySelector('[data-testid="preset-btn-prod_env_trace"]').textContent = t.presetEnv;
    document.getElementById('apply-preset-rules-btn').textContent = t.applyPreset;
    document.getElementById('toggle-all-categories-btn').textContent = t.allCats;
    document.getElementById('upload-file-btn').textContent = t.upload;
    document.getElementById('auto-sanitize-label').textContent = t.autoLabel;
    document.getElementById('sanitize-now-btn').textContent = t.sanNow;
    document.getElementById('clear-input-btn').textContent = t.clear;
    document.getElementById('raw-input-label').textContent = t.rawLabel;
    document.getElementById('sanitized-output-label').textContent = t.sanOutLabel;
    document.getElementById('btn-copy-sanitize').textContent = t.copy;
    document.getElementById('btn-download-sanitize').textContent = t.download;
    document.getElementById('btn-go-rehydrate').textContent = t.goReh;
    document.getElementById('vault-heading').textContent = t.vaultHeading;
    document.getElementById('toggle-hide-values-btn').textContent = hideValues ? t.showVals : t.hideVals;
    document.getElementById('back-sanitize-btn').textContent = t.backSan;
    document.getElementById('rehydrate-now-btn').textContent = t.rehNow;
    document.getElementById('rehydrate-input-label').textContent = t.rehInLabel;
    document.getElementById('rehydrate-output-label').textContent = t.rehOutLabel;
    document.getElementById('copy-restored-btn').textContent = t.copy;
    document.getElementById('download-restored-btn').textContent = t.download;
    document.getElementById('rules-heading').textContent = t.rulesHeading;
    document.getElementById('btn-add-rule').textContent = t.add;
    document.getElementById('btn-export-rules').textContent = t.exportRules;
    document.getElementById('import-rules-label').textContent = t.importRules;
    document.getElementById('btn-close-rules').textContent = t.close;
    document.getElementById('audit-heading').textContent = t.auditHeading;
    document.getElementById('btn-export-audit').textContent = t.exportAudit;
    document.getElementById('btn-clear-audit').textContent = t.clear;
    document.getElementById('btn-close-audit').textContent = t.close;
    document.querySelector('[data-testid="lang-ru"]').setAttribute('aria-pressed', String(currentLang === 'ru'));
    document.querySelector('[data-testid="lang-en"]').setAttribute('aria-pressed', String(currentLang === 'en'));
    renderVaultAndChips();
    renderRules();
  }

  async function sha256Hex(text) {
    const bytes = new TextEncoder().encode(text);
    const buf = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  function scanText(input) {
    if (!input) {
      vault = [];
      counters = {};
      return '';
    }
    const rules = loadJson(RULES_KEY, []);
    const candidates = [];
    const emailRe = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
    const ipRe = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    const phoneRe = /\+7\s*\(\d{3}\)\s*\d{3}-\d{2}-\d{2}/g;
    const ibanRe = /\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,6}\b/g;

    for (const m of input.matchAll(emailRe)) candidates.push({ cat: 'EMAIL', prefix: 'EMAIL', val: m[0], idx: m.index });
    for (const m of input.matchAll(ipRe)) candidates.push({ cat: 'IPV4', prefix: 'IP', val: m[0], idx: m.index });
    for (const m of input.matchAll(phoneRe)) candidates.push({ cat: 'PHONE', prefix: 'PHONE', val: m[0], idx: m.index });
    for (const m of input.matchAll(ibanRe)) candidates.push({ cat: 'IBAN', prefix: 'IBAN', val: m[0], idx: m.index });
    for (const r of rules) {
      const term = r.term || r;
      if (!term) continue;
      let pos = input.indexOf(term);
      while (pos !== -1) {
        candidates.push({ cat: 'CUSTOM', prefix: 'CUSTOM', val: term, idx: pos });
        pos = input.indexOf(term, pos + term.length);
      }
    }
    candidates.sort((a, b) => a.idx - b.idx);

    const prevMap = new Map(vault.map((v) => [`${v.category}:${v.original}`, v]));
    counters = {};
    const seen = new Map();
    const newVault = [];

    for (const c of candidates) {
      const k = `${c.cat}:${c.val}`;
      if (!seen.has(k)) {
        counters[c.prefix] = (counters[c.prefix] || 0) + 1;
        const tok = `[${c.prefix}_${counters[c.prefix]}]`;
        const old = prevMap.get(k);
        const item = { category: c.cat, token: tok, original: c.val, enabled: old ? old.enabled : true };
        seen.set(k, item);
        newVault.push(item);
      }
    }
    vault = newVault;
    return renderMasked(input);
  }

  function renderMasked(input) {
    let out = input;
    for (const item of vault) {
      if (item.enabled && !disabledCategories.has(item.category)) {
        out = out.split(item.original).join(item.token);
      }
    }
    return out;
  }

  function renderSanitizedOutput(text) {
    const outEl = document.getElementById('sanitize-output');
    outEl.textContent = '';
    const tokenRe = /(\[[A-Z_]+_\d+\])/g;
    const parts = String(text || '').split(tokenRe);
    for (const part of parts) {
      if (!part) continue;
      if (/^\[[A-Z_]+_\d+\]$/.test(part)) {
        const mark = document.createElement('mark');
        mark.setAttribute('data-token', part);
        mark.textContent = part;
        outEl.appendChild(mark);
      } else {
        outEl.appendChild(document.createTextNode(part));
      }
    }
  }

  function renderVaultAndChips() {
    const t = I18N[currentLang];
    const listEl = document.getElementById('entity-vault-list');
    listEl.textContent = '';
    document.getElementById('telemetry-masked-count').textContent = String(
      vault.filter((v) => v.enabled && !disabledCategories.has(v.category)).length
    );

    if (vault.length === 0) {
      const p = document.createElement('p');
      p.id = 'vault-empty';
      p.setAttribute('data-empty', 'true');
      p.className = 'empty-state';
      p.textContent = t.emptyVault;
      listEl.appendChild(p);
    }

    const counts = { EMAIL: 0, IPV4: 0, CUSTOM: 0, PHONE: 0, IBAN: 0 };
    for (const item of vault) {
      counts[item.category] = (counts[item.category] || 0) + 1;
      const row = document.createElement('div');
      row.className = 'vault-item';
      row.setAttribute('data-testid', 'vault-item');
      row.setAttribute('data-category', item.category);
      row.setAttribute('data-token', item.token);
      row.setAttribute('data-value', item.original);
      const isEnabled = item.enabled && !disabledCategories.has(item.category);
      row.setAttribute('data-enabled', String(isEnabled));

      const tokSpan = document.createElement('span');
      tokSpan.setAttribute('data-testid', 'vault-token');
      tokSpan.textContent = item.token;

      const catSpan = document.createElement('span');
      catSpan.textContent = t.cats[item.category] || item.category;

      const valSpan = document.createElement('span');
      valSpan.setAttribute('data-testid', 'vault-value');
      valSpan.textContent = hideValues ? '••••••••' : item.original;

      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.setAttribute('data-testid', 'vault-item-toggle');
      cb.checked = isEnabled;
      cb.addEventListener('change', () => {
        item.enabled = cb.checked;
        renderSanitizedOutput(renderMasked(document.getElementById('sanitize-input').value));
        renderVaultAndChips();
      });

      row.append(tokSpan, catSpan, valSpan, cb);
      listEl.appendChild(row);
    }

    for (const cat of Object.keys(counts)) {
      const chip = document.querySelector(`[data-category="${cat}"]`);
      if (chip) {
        chip.setAttribute('data-count', String(counts[cat]));
        chip.textContent = `${t.cats[cat] || cat} (${counts[cat]})`;
        if (cat === 'IBAN') {
          chip.classList.toggle('hidden', !showAllCats && counts[cat] === 0);
        }
      }
    }
  }

  async function recordAudit(input, output) {
    if (!input.trim()) return;
    const list = loadJson(AUDIT_KEY, []);
    list.unshift({
      ts: new Date().toISOString(),
      inputSha256: await sha256Hex(input),
      outputSha256: await sha256Hex(output),
      entities: vault.length
    });
    saveJson(AUDIT_KEY, list);
  }

  function renderRules() {
    const t = I18N[currentLang];
    const ul = document.getElementById('rules-list');
    ul.textContent = '';
    const rules = loadJson(RULES_KEY, []);
    const btnOpen = document.getElementById('btn-open-rules');
    if (btnOpen) btnOpen.textContent = t.rulesBtn(rules.length);
    for (const r of rules) {
      const li = document.createElement('li');
      const span = document.createElement('span');
      span.textContent = r.term;
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.textContent = t.del;
      btn.addEventListener('click', () => {
        saveJson(RULES_KEY, loadJson(RULES_KEY, []).filter((x) => x.term !== r.term));
        renderRules();
      });
      li.append(span, ' ', btn);
      ul.appendChild(li);
    }
  }

  function renderAudit() {
    const ul = document.getElementById('audit-list');
    ul.textContent = '';
    const list = loadJson(AUDIT_KEY, []);
    for (const item of list) {
      const li = document.createElement('li');
      li.textContent = `${item.ts} | ${item.inputSha256} | entities=${item.entities}`;
      ul.appendChild(li);
    }
  }

  function downloadBlob(filename, content, mime) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 500);
  }

  function showMode(nextMode) {
    const sanPane = document.getElementById('pane-sanitize');
    const rehPane = document.getElementById('pane-rehydrate');
    const sanTab = document.getElementById('tab-sanitize');
    const rehTab = document.getElementById('tab-rehydrate');
    const isSan = nextMode === 'sanitize';
    sanPane.classList.toggle('hidden', !isSan);
    sanPane.hidden = !isSan;
    rehPane.classList.toggle('hidden', isSan);
    rehPane.hidden = isSan;
    sanTab.setAttribute('aria-selected', String(isSan));
    rehTab.setAttribute('aria-selected', String(!isSan));
  }

  document.getElementById('tab-sanitize').addEventListener('click', () => showMode('sanitize'));
  document.getElementById('tab-rehydrate').addEventListener('click', () => showMode('rehydrate'));
  document.getElementById('btn-go-rehydrate').addEventListener('click', () => showMode('rehydrate'));
  document.getElementById('back-sanitize-btn').addEventListener('click', () => showMode('sanitize'));

  document.querySelector('[data-testid="lang-ru"]').addEventListener('click', () => applyLang('ru'));
  document.querySelector('[data-testid="lang-en"]').addEventListener('click', () => applyLang('en'));

  async function runSanitize() {
    const inp = document.getElementById('sanitize-input').value;
    const out = scanText(inp);
    renderSanitizedOutput(out);
    renderVaultAndChips();
    await recordAudit(inp, out);
  }

  document.getElementById('sanitize-input').addEventListener('input', () => {
    if (document.getElementById('auto-sanitize-toggle').checked) {
      runSanitize();
    }
  });
  document.getElementById('sanitize-now-btn').addEventListener('click', runSanitize);
  document.getElementById('clear-input-btn').addEventListener('click', () => {
    document.getElementById('sanitize-input').value = '';
    runSanitize();
  });

  function runRehydrate() {
    const t = I18N[currentLang];
    const text = document.getElementById('rehydrate-input').value;
    const map = Object.fromEntries(vault.map((v) => [v.token, v.original]));
    const keys = Object.keys(map).sort((a, b) => b.length - a.length);
    let out = text;
    if (keys.length) {
      const re = new RegExp(keys.map((k) => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'g');
      out = text.replace(re, (m) => map[m] ?? m);
    }
    document.getElementById('rehydrate-output').textContent = out;
    document.getElementById('copy-restored-btn').disabled = !out;
    document.getElementById('download-restored-btn').disabled = !out;
    const unresolved = out.match(/\[[A-Z_]+_\d+\]/g) || [];
    const warnEl = document.getElementById('unresolved-box');
    warnEl.textContent = unresolved.length ? `${t.unresolvedPrefix}${unresolved.join(', ')}` : '';
    warnEl.classList.toggle('hidden', unresolved.length === 0);
  }

  document.getElementById('rehydrate-input').addEventListener('input', runRehydrate);
  document.getElementById('rehydrate-now-btn').addEventListener('click', runRehydrate);

  document.querySelectorAll('[data-testid^="preset-btn-"]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const key = btn.getAttribute('data-testid').replace('preset-btn-', '');
      if (!PRESETS[key]) return;
      document.getElementById('sanitize-input').value = PRESETS[key];
      runSanitize();
    });
  });

  document.getElementById('toggle-all-categories-btn').addEventListener('click', () => {
    showAllCats = !showAllCats;
    renderVaultAndChips();
  });

  document.getElementById('toggle-hide-values-btn').addEventListener('click', () => {
    hideValues = !hideValues;
    document.getElementById('toggle-hide-values-btn').textContent = hideValues
      ? I18N[currentLang].showVals
      : I18N[currentLang].hideVals;
    renderVaultAndChips();
  });

  document.querySelectorAll('[data-category]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const cat = btn.getAttribute('data-category');
      if (disabledCategories.has(cat)) disabledCategories.delete(cat);
      else disabledCategories.add(cat);
      renderSanitizedOutput(renderMasked(document.getElementById('sanitize-input').value));
      renderVaultAndChips();
    });
  });

  document.getElementById('file-upload').addEventListener('change', (ev) => {
    const file = ev.target.files && ev.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      document.getElementById('sanitize-input').value = String(reader.result || '');
      runSanitize();
    };
    reader.readAsText(file, 'utf-8');
  });

  document.getElementById('btn-open-rules').addEventListener('click', () => {
    renderRules();
    document.getElementById('drawer-rules').setAttribute('open', '');
    document.getElementById('btn-open-rules').setAttribute('aria-expanded', 'true');
  });

  document.getElementById('btn-close-rules').addEventListener('click', () => {
    document.getElementById('drawer-rules').removeAttribute('open');
    document.getElementById('btn-open-rules').setAttribute('aria-expanded', 'false');
  });

  document.getElementById('btn-add-rule').addEventListener('click', () => {
    const term = document.getElementById('rule-term-input').value.trim();
    if (!term) return;
    const category = document.getElementById('rule-category-input').value || 'CUSTOM';
    const rules = loadJson(RULES_KEY, []);
    if (!rules.some((r) => r.term === term)) {
      rules.push({ term, category });
      saveJson(RULES_KEY, rules);
    }
    document.getElementById('rule-term-input').value = '';
    renderRules();
  });

  document.getElementById('btn-export-rules').addEventListener('click', () => {
    downloadBlob('promptveil_rules.json', JSON.stringify(loadJson(RULES_KEY, []), null, 2), 'application/json');
  });

  document.getElementById('rules-import-input').addEventListener('change', (ev) => {
    const file = ev.target.files && ev.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const parsed = JSON.parse(String(reader.result || '[]'));
        if (Array.isArray(parsed)) {
          const existing = loadJson(RULES_KEY, []);
          for (const item of parsed) {
            const term = typeof item === 'string' ? item : item.term;
            if (term && !existing.some((x) => x.term === term)) existing.push({ term });
          }
          saveJson(RULES_KEY, existing);
          renderRules();
        }
      } catch (_err) {}
    };
    reader.readAsText(file, 'utf-8');
  });

  document.getElementById('btn-open-audit').addEventListener('click', () => {
    renderAudit();
    document.getElementById('drawer-audit').setAttribute('open', '');
    document.getElementById('btn-open-audit').setAttribute('aria-expanded', 'true');
  });

  document.getElementById('btn-close-audit').addEventListener('click', () => {
    document.getElementById('drawer-audit').removeAttribute('open');
    document.getElementById('btn-open-audit').setAttribute('aria-expanded', 'false');
  });

  document.getElementById('btn-export-audit').addEventListener('click', () => {
    downloadBlob('promptveil_audit.json', JSON.stringify(loadJson(AUDIT_KEY, []), null, 2), 'application/json');
  });

  document.getElementById('btn-clear-audit').addEventListener('click', () => {
    if (!window.confirm(I18N[currentLang].clearAuditConfirm)) return;
    saveJson(AUDIT_KEY, []);
    renderAudit();
  });

  document.getElementById('btn-copy-sanitize').addEventListener('click', () => {
    const text = document.getElementById('sanitize-output').textContent || '';
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).catch(() => {});
    }
    const banner = document.getElementById('status-banner');
    banner.textContent = I18N[currentLang].copied;
    banner.classList.remove('hidden');
  });

  document.getElementById('btn-download-sanitize').addEventListener('click', () => {
    downloadBlob('sanitized.txt', document.getElementById('sanitize-output').textContent || '', 'text/plain');
  });

  document.getElementById('copy-restored-btn').addEventListener('click', () => {
    const text = document.getElementById('rehydrate-output').textContent || '';
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).catch(() => {});
    }
    const banner = document.getElementById('status-banner');
    banner.textContent = I18N[currentLang].copied;
    banner.classList.remove('hidden');
  });

  document.getElementById('download-restored-btn').addEventListener('click', () => {
    downloadBlob('restored.txt', document.getElementById('rehydrate-output').textContent || '', 'text/plain');
  });

  const savedLang = (() => {
    try {
      return localStorage.getItem(LANG_KEY);
    } catch (_err) {
      return 'ru';
    }
  })();
  applyLang(savedLang === 'en' ? 'en' : 'ru');
})();
