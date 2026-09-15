/* Code Review Agent — frontend controller. No framework, no build step. */
(function () {
  'use strict';

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  const state = {
    config: null,
    providers: [],
    activeProvider: 'demo',
    activeModel: '',
    review: null,
    findings: [],
    filters: { search: '', severities: new Set(), categories: new Set(), file: '' },
    inputTab: 'code',
    running: false,
    examples: [],
    traces: new Map(),
    sortBySeverity: true,
  };

  const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
  const CATEGORIES = ['security', 'bug', 'quality', 'performance', 'best_practices'];
  const SEV_ICON = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };
  const VERDICT_LABEL = {
    approve: '✅ Approve', approve_with_nits: '👍 Approve with nits',
    request_changes: '🔁 Request changes', block: '⛔ Block',
  };

  // ============================== utilities ==============================
  function toast(message, kind) {
    const stack = $('#toast-stack');
    const el = document.createElement('div');
    el.className = 'toast' + (kind ? ' ' + kind : '');
    el.textContent = message;
    stack.appendChild(el);
    setTimeout(() => {
      el.style.transition = 'opacity .25s, transform .25s';
      el.style.opacity = '0';
      el.style.transform = 'translateX(14px)';
      setTimeout(() => el.remove(), 260);
    }, kind === 'err' ? 7000 : 3800);
  }

  async function copyText(text, label) {
    try {
      await navigator.clipboard.writeText(text);
      toast((label || 'Text') + ' copied to clipboard', 'ok');
    } catch (err) {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); toast((label || 'Text') + ' copied', 'ok'); }
      catch (e) { toast('Copy failed — select the text manually', 'err'); }
      ta.remove();
    }
  }

  async function api(path, options) {
    const response = await fetch(path, options);
    const text = await response.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (e) { data = { detail: text }; }
    if (!response.ok) {
      const message = (data && (data.detail && (data.detail.message || data.detail))) || response.statusText;
      throw new Error(typeof message === 'string' ? message : JSON.stringify(message));
    }
    return data;
  }

  function setStatus(text, kind) {
    $('#status-text').textContent = text;
    const dot = $('#provider-dot');
    dot.className = 'dot' + (kind ? ' ' + kind : '');
  }

  function fmtDuration(ms) {
    if (ms == null) return '–';
    return ms < 1000 ? ms + ' ms' : (ms / 1000).toFixed(1) + ' s';
  }

  // ============================ config / providers ============================
  async function loadConfig() {
    try {
      state.config = await api('/api/config');
      state.providers = state.config.providers || [];
      state.activeProvider = state.config.provider || 'demo';
      state.activeModel = state.config.model || '';
      renderProviderSelect();
      renderProviderList();
      updateStatusStrip();
    } catch (err) {
      setStatus('Could not load config: ' + err.message, 'err');
    }
  }

  function updateStatusStrip() {
    const spec = state.providers.find((p) => p.id === state.activeProvider) || {};
    const offline = state.activeProvider === 'demo';
    const local = spec.local && !offline;
    setStatus(
      offline
        ? 'Offline static engine — no API key needed. Add a free key in Settings for full semantic review.'
        : `${spec.label || state.activeProvider} · ${state.activeModel || spec.default_model || ''}` +
          (local ? ' (local runtime)' : '') + (spec.configured ? '' : ' — key missing'),
      offline ? 'ok' : (spec.configured ? 'ok' : 'warn')
    );
    $('#footer-meta').textContent =
      `v${(state.config && state.config.version) || '1.0'} · effort ${state.config ? state.config.effort : 'standard'}` +
      (state.config && state.config.github_token_set ? ' · GitHub token set' : '');
  }

  function renderProviderSelect() {
    const select = $('#provider-select');
    select.innerHTML = '';
    state.providers.forEach((p) => {
      const option = document.createElement('option');
      option.value = p.id;
      const tag = p.id === 'demo' ? 'offline' : (p.configured ? 'key ✓' : 'no key');
      option.textContent = `${p.label} — ${tag}`;
      option.selected = p.id === state.activeProvider;
      select.appendChild(option);
    });
    renderModelSelect();
  }

  function renderModelSelect() {
    const select = $('#model-select');
    const spec = state.providers.find((p) => p.id === state.activeProvider);
    select.innerHTML = '';
    select.disabled = !spec;
    if (!spec) return;
    (spec.models || []).forEach((m) => {
      const option = document.createElement('option');
      option.value = m.id;
      option.textContent = m.label + (m.recommended ? ' ★' : '');
      option.selected = m.id === state.activeModel || (!state.activeModel && m.recommended);
      select.appendChild(option);
    });
    if (!state.activeModel) {
      state.activeModel = spec.default_model || (spec.models[0] || {}).id || '';
    }
  }

  function renderProviderList() {
    const container = $('#provider-list');
    container.innerHTML = '';
    state.providers.forEach((p) => {
      const row = document.createElement('div');
      row.className = 'provider-row' +
        (p.id === state.activeProvider ? ' active' : '') +
        (p.configured && p.requires_key ? ' configured' : '');

      const head = document.createElement('div');
      head.className = 'provider-row-head';
      head.innerHTML =
        `<span class="provider-name">${p.label}</span>` +
        (p.id === 'demo' ? '<span class="provider-badge badge-local">offline</span>' : '') +
        (p.local && p.id !== 'demo' ? '<span class="provider-badge badge-local">local</span>' : '') +
        (!p.requires_key && p.id !== 'demo' ? '<span class="provider-badge badge-free">free</span>' : '') +
        (p.configured && p.requires_key ? '<span class="provider-badge badge-free">key set</span>' : '') +
        (p.id === state.activeProvider ? '<span class="provider-badge badge-active">active</span>' : '');
      row.appendChild(head);

      const note = document.createElement('div');
      note.className = 'provider-note';
      const links = [];
      if (p.signup_url) links.push(`<a href="${p.signup_url}" target="_blank" rel="noopener noreferrer">get a key</a>`);
      if (p.docs_url) links.push(`<a href="${p.docs_url}" target="_blank" rel="noopener noreferrer">docs</a>`);
      note.innerHTML = p.free_note + (links.length ? ' · ' + links.join(' · ') : '');
      row.appendChild(note);

      if (p.id !== 'demo') {
        const keyRow = document.createElement('div');
        keyRow.className = 'provider-key-row';

        const keyInput = document.createElement('input');
        keyInput.type = 'password';
        keyInput.placeholder = (state.config.api_keys_masked || {})[p.id]
          ? 'saved: ' + state.config.api_keys_masked[p.id]
          : (p.requires_key ? 'paste API key…' : 'optional key');
        keyInput.dataset.provider = p.id;
        keyInput.autocomplete = 'off';
        keyInput.spellcheck = false;

        const urlInput = document.createElement('input');
        urlInput.type = 'text';
        urlInput.placeholder = p.base_url || 'base URL override';
        urlInput.value = (state.config.base_urls || {})[p.id] || '';
        urlInput.style.maxWidth = '200px';
        urlInput.dataset.baseurl = p.id;
        urlInput.spellcheck = false;

        const saveBtn = document.createElement('button');
        saveBtn.className = 'btn small';
        saveBtn.textContent = 'Save';
        saveBtn.type = 'button';
        saveBtn.addEventListener('click', async () => {
          const payload = { provider: p.id };
          const keys = {};
          const urls = {};
          if (keyInput.value.trim()) keys[p.id] = keyInput.value.trim();
          urls[p.id] = urlInput.value.trim() || '';
          payload.api_keys = keys;
          payload.base_urls = urls;
          const modelSelect = row.querySelector('select[data-model]');
          if (modelSelect && modelSelect.value) payload.model = modelSelect.value;
          try {
            state.config = await api('/api/config', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload),
            });
            state.providers = state.config.providers || [];
            state.activeProvider = state.config.provider;
            state.activeModel = state.config.model || '';
            renderProviderSelect();
            renderProviderList();
            updateStatusStrip();
            $('#settings-status').textContent = 'Saved. ' + p.label + ' is now the active provider.';
            toast(p.label + ' configured', 'ok');
          } catch (err) {
            toast('Save failed: ' + err.message, 'err');
          }
        });

        keyRow.append(keyInput, urlInput, saveBtn);
        row.appendChild(keyRow);

        const modelRow = document.createElement('div');
        modelRow.className = 'provider-key-row';
        const modelSelect = document.createElement('select');
        modelSelect.dataset.model = p.id;
        (p.models || []).forEach((m) => {
          const option = document.createElement('option');
          option.value = m.id;
          option.textContent = `${m.label} · ${Math.round(m.context_window / 1000)}k ctx`;
          if (m.recommended) option.selected = true;
          modelSelect.appendChild(option);
        });
        const useBtn = document.createElement('button');
        useBtn.className = 'btn small ghost';
        useBtn.type = 'button';
        useBtn.textContent = 'Use this model';
        useBtn.addEventListener('click', async () => {
          try {
            state.config = await api('/api/config', {
              method: 'POST', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ provider: p.id, model: modelSelect.value }),
            });
            state.providers = state.config.providers || [];
            state.activeProvider = state.config.provider;
            state.activeModel = state.config.model;
            renderProviderSelect(); renderProviderList(); updateStatusStrip();
            toast(p.label + ' / ' + modelSelect.value + ' selected', 'ok');
          } catch (err) { toast('Failed: ' + err.message, 'err'); }
        });
        modelRow.append(modelSelect, useBtn);
        row.appendChild(modelRow);
      }

      const activate = document.createElement('button');
      activate.className = 'btn small ghost';
      activate.type = 'button';
      activate.textContent = p.id === state.activeProvider ? 'Active provider' : 'Make active';
      activate.disabled = p.id === state.activeProvider;
      activate.addEventListener('click', async () => {
        try {
          state.config = await api('/api/config', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ provider: p.id, model: p.default_model }),
          });
          state.providers = state.config.providers || [];
          state.activeProvider = state.config.provider;
          state.activeModel = state.config.model;
          renderProviderSelect(); renderProviderList(); updateStatusStrip();
        } catch (err) { toast('Failed: ' + err.message, 'err'); }
      });
      if (p.id !== 'demo') row.appendChild(activate);

      container.appendChild(row);
    });
  }

  // ================================ inputs ================================
  function activeInput() {
    if (state.inputTab === 'diff') return { diff: $('#diff-input').value, kind: 'diff' };
    if (state.inputTab === 'pr') return { pull_request: $('#pr-input').value.trim(), kind: 'pr' };
    return { code: $('#code-input').value, path: $('#file-path').value.trim() || 'input', kind: 'code' };
  }

  function updateCodeStats() {
    const code = $('#code-input').value;
    const lines = code ? code.split('\n').length : 0;
    $('#code-stats').textContent = `${lines} line${lines === 1 ? '' : 's'} · ${code.length} chars · ~${Math.ceil(code.length / 3.6)} tokens`;
    if (code.length > 90000) {
      $('#code-stats').textContent += ' — will be trimmed for small models';
    }
  }

  function updateDiffStats() {
    const diff = $('#diff-input').value;
    if (!diff.trim()) { $('#diff-stats').textContent = 'no diff'; return; }
    const files = (diff.match(/^diff --git /gm) || []).length ||
      (diff.match(/^\+\+\+ /gm) || []).length;
    const adds = (diff.match(/^\+(?!\+\+)/gm) || []).length;
    const dels = (diff.match(/^-(?!--)/gm) || []).length;
    $('#diff-stats').textContent = `${files} file${files === 1 ? '' : 's'} · +${adds} / -${dels}`;
  }

  async function loadExamples() {
    try {
      const data = await api('/api/examples');
      state.examples = data.examples || [];
      const list = $('#example-list');
      list.innerHTML = '';
      if (!state.examples.length) { list.innerHTML = '<span class="muted">none</span>'; return; }
      state.examples.forEach((ex) => {
        const chip = document.createElement('button');
        chip.className = 'example-chip';
        chip.type = 'button';
        chip.textContent = ex.name;
        chip.title = `Load the ${ex.name} example`;
        chip.addEventListener('click', () => {
          if (ex.kind === 'diff') {
            switchInputTab('diff');
            $('#diff-input').value = ex.content;
            updateDiffStats();
          } else {
            switchInputTab('code');
            $('#code-input').value = ex.content;
            $('#file-path').value = ex.name;
            updateCodeStats();
          }
          toast('Loaded example: ' + ex.name, 'ok');
        });
        list.appendChild(chip);
      });
    } catch (err) {
      $('#example-list').innerHTML = '<span class="muted">unavailable</span>';
    }
  }

  function switchInputTab(tab) {
    state.inputTab = tab;
    $$('.tab[data-input-tab]').forEach((b) => b.classList.toggle('active', b.dataset.inputTab === tab));
    $$('.input-tab-panel').forEach((p) => { p.hidden = p.dataset.panel !== tab; });
  }

  async function populateLanguages() {
    try {
      const data = await api('/api/detect', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: '' }),
      });
      void data;
    } catch (e) { /* non-fatal */ }
    const select = $('#language-select');
    const langs = (window.Highlight && window.Highlight.languages) || [];
    ['python', 'javascript', 'typescript', 'go', 'rust', 'java', 'ruby', 'php', 'sql', 'bash',
     'c', 'cpp', 'csharp', 'kotlin', 'swift', 'html', 'css', 'json', 'yaml'].forEach((lang) => {
      const option = document.createElement('option');
      option.value = lang; option.textContent = lang;
      select.appendChild(option);
    });
    void langs;
  }

  // ============================ SSE review run ============================
  function sseFrames(text) {
    return text.split(/\n\n+/).filter(Boolean).map((frame) => {
      let event = 'message';
      const dataLines = [];
      frame.split('\n').forEach((line) => {
        if (line.startsWith('event:')) event = line.slice(6).trim();
        else if (line.startsWith('data:')) dataLines.push(line.slice(5).trim());
      });
      let data = null;
      try { data = JSON.parse(dataLines.join('\n')); } catch (e) { data = { raw: dataLines.join('\n') }; }
      return { event, data };
    });
  }

  async function runReview(body) {
    if (state.running) return;
    state.running = true;
    setRunning(true);
    resetPipeline();
    clearResults();
    setStatus('Reviewing…', 'busy');

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 300000);
    let buffer = '';
    let sawDone = false;

    try {
      const response = await fetch('/api/review', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (!response.ok || !response.body) {
        const errText = await response.text();
        throw new Error(errText.slice(0, 400) || `HTTP ${response.status}`);
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const frames = buffer.split('\n\n');
        buffer = frames.pop();
        frames.forEach((frame) => {
          if (!frame.trim()) return;
          sseFrames(frame).forEach(handleEvent);
        });
      }
      if (buffer.trim()) sseFrames(buffer).forEach(handleEvent);
      if (!sawDone) setStatus('Stream ended without a final review.', 'warn');
    } catch (err) {
      const message = err.name === 'AbortError' ? 'Review timed out after 5 minutes.' : err.message;
      setStatus('Failed: ' + message, 'err');
      toast(message, 'err');
      showFatal(message);
    } finally {
      clearTimeout(timeout);
      state.running = false;
      setRunning(false);
      if (sawDone) setStatus('Review complete.', 'ok');
    }
  }

  function handleEvent(frame) {
    const { event, data } = frame;
    switch (event) {
      case 'ping': break;
      case 'start':
        state.reviewId = data.review_id;
        setStatus('Starting review…', 'busy');
        break;
      case 'provider':
        $('#usage-text').textContent = `provider ${data.provider} · ${data.model}`;
        break;
      case 'log':
        if (data.level === 'warn') toast(data.message, 'warn');
        break;
      case 'agent:start':
        upsertAgentCard(data.agent, data.label, data.emoji || '🤖', 'running', 'working…');
        setStatus('Agent running: ' + data.label, 'busy');
        break;
      case 'agent:done': {
        const label = state.traces.get(data.agent) ? state.traces.get(data.agent).label : data.agent;
        const emoji = state.traces.get(data.agent) ? state.traces.get(data.agent).emoji : '🤖';
        if (data.status === 'error') {
          upsertAgentCard(data.agent, label, emoji, 'error', truncate(data.error, 42));
          toast(label + ' failed: ' + truncate(data.error, 140), 'warn');
        } else if (data.status === 'skipped') {
          upsertAgentCard(data.agent, label, emoji, 'skipped', 'skipped');
        } else {
          const bits = [];
          if (typeof data.findings === 'number') bits.push(data.findings + ' finding' + (data.findings === 1 ? '' : 's'));
          if (data.duration_ms != null) bits.push(fmtDuration(data.duration_ms));
          if (data.tokens) bits.push(data.tokens + ' tok');
          upsertAgentCard(data.agent, label, emoji, 'done', bits.join(' · ') || 'done');
        }
        if (data.payload && data.agent === 'synthesizer') state.synthPayload = data.payload;
        if (data.payload && data.agent === 'summarizer') state.summaryPayload = data.payload;
        break;
      }
      case 'findings':
        streamFindings(data.findings || [], data.agent);
        break;
      case 'done':
        renderReview(data.review);
        state.reviewCompleted = true;
        break;
      case 'error':
        setStatus('Error: ' + data.message, 'err');
        toast(data.message, 'err');
        showFatal(data.message);
        break;
      case 'end':
        break;
      default: break;
    }
  }

  function truncate(text, max) {
    const s = String(text == null ? '' : text);
    return s.length > max ? s.slice(0, max - 1) + '…' : s;
  }

  function setRunning(running) {
    const btn = $('#run-btn');
    btn.disabled = running;
    btn.classList.toggle('running', running);
    $('.btn-label', btn).textContent = running ? 'Reviewing…' : 'Run review';
    $('#scan-btn').disabled = running;
  }

  // ============================== pipeline UI ==============================
  function resetPipeline() {
    state.traces = new Map();
    state.streamed = [];
    $('#pipeline').innerHTML = '';
    $('#pipeline').classList.remove('has-cards');
    $('#verdict-bar').hidden = true;
    $('#result-tabs').hidden = true;
    $('#ask-panel').hidden = true;
    $('#filters').hidden = true;
    $('#findings-list').innerHTML =
      '<div class="empty-state"><div class="empty-icon">⏳</div><h3>Review in progress</h3>' +
      '<p class="muted">Agents are working. Findings appear here as each one finishes.</p></div>';
  }

  function upsertAgentCard(key, label, emoji, status, stateText) {
    const pipeline = $('#pipeline');
    const empty = $('.pipeline-empty', pipeline);
    if (empty) empty.remove();
    let card = pipeline.querySelector(`[data-agent="${CSS.escape(key)}"]`);
    if (!card) {
      card = document.createElement('div');
      card.dataset.agent = key;
      card.className = 'agent-card';
      card.innerHTML =
        '<span class="emoji"></span><span class="meta"><span class="name"></span>' +
        '<span class="state"></span></span>';
      pipeline.appendChild(card);
      state.traces.set(key, { label, emoji });
    }
    card.className = 'agent-card ' + status;
    $('.emoji', card).textContent = emoji;
    $('.name', card).textContent = label;
    $('.state', card).innerHTML = '';
    if (status === 'running') {
      const spin = document.createElement('span');
      spin.className = 'spinner';
      card.querySelector('.state').appendChild(spin);
      card.querySelector('.state').appendChild(document.createTextNode(' ' + stateText));
    } else {
      $('.state', card).textContent = stateText;
    }
    card.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'nearest' });
  }

  function streamFindings(findings, agent) {
    const list = $('#findings-list');
    if (!state.streamed.length) {
      list.innerHTML = '';
      $('#filters').hidden = false;
    }
    findings.forEach((f) => {
      f.agent = f.agent || agent || '';
      f.streaming = true;
      state.streamed.push(f);
      list.appendChild(findingCard(f));
    });
    $('#badge-findings').textContent = state.streamed.length;
  }

  function showFatal(message) {
    $('#result-tabs').hidden = false;
    $('#findings-list').innerHTML =
      `<div class="empty-state"><div class="empty-icon">⚠️</div><h3>Review failed</h3>` +
      `<p>${Markdown.escapeHtml(message)}</p>` +
      `<p class="muted">Check the provider and key in Settings, or switch to the offline static engine.</p></div>`;
    switchTab('findings');
  }

  // ============================== findings UI ==============================
  function findingCard(f) {
    const card = document.createElement('article');
    card.className = `finding sev-${f.severity}`;
    card.dataset.severity = f.severity;
    card.dataset.category = f.category;
    card.dataset.file = f.file || '';
    card.dataset.search = [f.title, f.description, f.file, f.line, f.agent, (f.references || []).join(' ')]
      .join(' ').toLowerCase();

    const location = (f.file && f.file !== 'input' ? f.file : '') + (f.line ? ':' + f.line : '');
    const head = document.createElement('button');
    head.type = 'button';
    head.className = 'finding-head';
    head.innerHTML =
      `<span class="sev-tag v-${f.severity}">${f.severity}</span>` +
      `<span class="finding-title-wrap">` +
        `<span class="finding-title">${Markdown.escapeHtml(f.title || '(untitled)')}</span>` +
        `<span class="finding-loc">` +
          `<span class="cat">${f.category.replace('_', ' ')}</span>` +
          (location ? `<code>${Markdown.escapeHtml(location)}</code>` : '') +
          (f.source && f.source !== 'llm' ? `<span class="src">[${f.source}]</span>` : '') +
          (f.upvotes ? `<span class="src">corroborated ×${f.upvotes + 1}</span>` : '') +
        `</span>` +
      `</span>` +
      `<span class="chev">▶</span>`;

    const body = document.createElement('div');
    body.className = 'finding-body';

    body.appendChild(section('Why it matters', paragraph(f.description)));
    if (f.snippet) body.appendChild(codeSection('Code', f.snippet, guessLang(f.file)));
    if (f.suggestion) {
      const box = document.createElement('div');
      box.className = 'suggestion-box';
      box.appendChild(section('Suggested fix', paragraph(f.suggestion)));
      body.appendChild(box);
    }
    if (f.code_after) body.appendChild(codeSection('Proposed change', f.code_after, guessLang(f.file)));

    if (f.references && f.references.length) {
      const refs = document.createElement('div');
      refs.className = 'refs';
      f.references.forEach((r) => {
        const span = document.createElement('span');
        span.className = 'ref';
        span.textContent = r;
        refs.appendChild(span);
      });
      body.appendChild(refs);
    }

    const actions = document.createElement('div');
    actions.className = 'finding-actions';

    const conf = document.createElement('span');
    conf.className = 'confidence';
    conf.innerHTML = `<span class="conf-bar"><i style="width:${Math.round((f.confidence || 0.8) * 100)}%"></i></span>` +
      `${Math.round((f.confidence || 0.8) * 100)}% confidence · ${Markdown.escapeHtml(f.agent || 'agent')}`;
    actions.appendChild(conf);

    const spacer = document.createElement('span');
    spacer.className = 'spacer';
    actions.appendChild(spacer);

    if (f.code_after) {
      actions.appendChild(actionBtn('Copy fix', () => copyText(f.code_after, 'Fix')));
    }
    actions.appendChild(actionBtn('Copy comment', () =>
      copyText(f.line_comment || f.description, 'Comment')));
    actions.appendChild(actionBtn('Ask about this', () => askAbout(f)));
    body.appendChild(actions);

    head.addEventListener('click', () => card.classList.toggle('open'));
    card.append(head, body);
    return card;
  }

  function actionBtn(label, handler) {
    const button = document.createElement('button');
    button.className = 'btn ghost small';
    button.type = 'button';
    button.textContent = label;
    button.addEventListener('click', (event) => { event.stopPropagation(); handler(); });
    return button;
  }

  function section(title, node) {
    const wrap = document.createElement('div');
    const heading = document.createElement('h5');
    heading.textContent = title;
    wrap.append(heading, node);
    return wrap;
  }

  function paragraph(text) {
    const p = document.createElement('p');
    p.className = 'desc';
    p.innerHTML = Markdown.inline(text || '').replace(/\n/g, '<br>');
    return p;
  }

  function codeSection(title, code, lang) {
    const wrap = document.createElement('div');
    const heading = document.createElement('h5');
    heading.textContent = title;
    const block = document.createElement('div');
    block.className = 'codeblock';
    block.dataset.lang = lang || '';
    const copy = document.createElement('button');
    copy.className = 'copy-code';
    copy.type = 'button';
    copy.textContent = 'Copy';
    copy.addEventListener('click', (event) => { event.stopPropagation(); copyText(code, 'Code'); });
    const pre = document.createElement('pre');
    const codeEl = document.createElement('code');
    codeEl.innerHTML = Highlight.highlight(code, lang);
    pre.appendChild(codeEl);
    block.append(copy, pre);
    wrap.append(heading, block);
    return wrap;
  }

  function guessLang(path) {
    const match = /\.([a-z0-9]+)$/i.exec(String(path || ''));
    return match ? match[1].toLowerCase() : '';
  }

  function renderFindings(findings) {
    const list = $('#findings-list');
    list.innerHTML = '';
    state.findings = findings;
    if (!findings.length) {
      list.innerHTML =
        '<div class="empty-state"><div class="empty-icon">🎉</div><h3>No issues found</h3>' +
        '<p>Nothing met the reporting bar for this submission.</p>' +
        '<p class="muted">A clean review is a valid review — but remember findings are AI-generated.</p></div>';
      return;
    }
    buildFilters(findings);
    findings.forEach((f) => list.appendChild(findingCard(f)));
    applyFilters();
    $('#badge-findings').textContent = findings.length;
  }

  function buildFilters(findings) {
    const sevCounts = {}; const catCounts = {}; const files = new Set();
    findings.forEach((f) => {
      sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1;
      catCounts[f.category] = (catCounts[f.category] || 0) + 1;
      if (f.file) files.add(f.file);
    });

    const sevChips = $('#severity-chips');
    sevChips.innerHTML = '';
    SEVERITIES.forEach((s) => {
      if (!sevCounts[s]) return;
      const chip = document.createElement('button');
      chip.type = 'button';
      chip.className = 'chip';
      chip.dataset.severity = s;
      chip.innerHTML = `${SEV_ICON[s]} ${s} <strong>${sevCounts[s]}</strong>`;
      chip.addEventListener('click', () => {
        toggleSet(state.filters.severities, s);
        chip.classList.toggle('active', state.filters.severities.has(s));
        applyFilters();
      });
      sevChips.appendChild(chip);
    });

    const catChips = $('#category-chips');
    catChips.innerHTML = '';
    CATEGORIES.forEach((c) => {
      if (!catCounts[c]) return;
      const chip = document.createElement('button');
      chip.type = 'button';
      chip.className = 'chip';
      chip.dataset.category = c;
      chip.textContent = `${c.replace('_', ' ')} ${catCounts[c]}`;
      chip.addEventListener('click', () => {
        toggleSet(state.filters.categories, c);
        chip.classList.toggle('active', state.filters.categories.has(c));
        applyFilters();
      });
      catChips.appendChild(chip);
    });

    const fileSelect = $('#file-filter');
    fileSelect.innerHTML = '<option value="">All files</option>';
    Array.from(files).sort().forEach((file) => {
      const option = document.createElement('option');
      option.value = file; option.textContent = file;
      fileSelect.appendChild(option);
    });
    fileSelect.style.display = files.size > 1 ? '' : 'none';
    $('#filters').hidden = false;
  }

  function toggleSet(set, value) { set.has(value) ? set.delete(value) : set.add(value); }

  function applyFilters() {
    const { search, severities, categories, file } = state.filters;
    const term = search.trim().toLowerCase();
    let visible = 0;
    $$('#findings-list .finding').forEach((card) => {
      const okSev = !severities.size || severities.has(card.dataset.severity);
      const okCat = !categories.size || categories.has(card.dataset.category);
      const okFile = !file || card.dataset.file === file;
      const okSearch = !term || card.dataset.search.includes(term);
      const show = okSev && okCat && okFile && okSearch;
      card.style.display = show ? '' : 'none';
      if (show) visible++;
    });
    const counter = $('#filter-count');
    if (counter) counter.textContent = `${visible} shown`;
  }

  // =============================== results ===============================
  function clearResults() {
    state.review = null;
    state.synthPayload = null;
    state.summaryPayload = null;
    $('#badge-findings').textContent = '0';
    $('#walkthrough-body').innerHTML = '';
    $('#diagram-body').innerHTML = '';
    $('#checklist-body').innerHTML = '';
    $('#metrics-body').innerHTML = '';
    $('#trace-body').innerHTML = '';
    $('#markdown-body').textContent = '';
    $('#ask-log').innerHTML = '';
  }

  function renderReview(review) {
    state.review = review;
    const counts = review.by_severity || {};

    // verdict bar
    $('#verdict-bar').hidden = false;
    const ring = $('#score-ring');
    ring.style.setProperty('--ring', review.score);
    ring.style.setProperty('--ring-color', ringColor(review.score));
    $('#score-value').textContent = review.score;
    $('#verdict-label').textContent = VERDICT_LABEL[review.verdict] || review.verdict;
    $('#verdict-summary').textContent = review.summary || '';
    $('#verdict-summary').title = review.summary || '';

    const countsEl = $('#verdict-counts');
    countsEl.innerHTML = '';
    SEVERITIES.forEach((s) => {
      const n = counts[s] || 0;
      const pill = document.createElement('span');
      pill.className = 'count-pill pill-' + s + (n ? '' : ' zero');
      pill.innerHTML = `${SEV_ICON[s]} ${n}`;
      pill.title = s + ': ' + n;
      countsEl.appendChild(pill);
    });

    $('#result-tabs').hidden = false;
    $('#ask-panel').hidden = false;
    renderFindings(review.findings || []);
    renderWalkthrough(review);
    renderMetrics(review);
    renderTrace(review);
    $('#markdown-body').textContent = review.review_markdown || '';
    switchTab('findings');
    setStatus(
      `Done in ${fmtDuration(review.elapsed_ms)} · ${review.findings.length} findings · ` +
      `${review.provider}/${review.model}`, 'ok');
    $('#usage-text').textContent = review.usage && review.usage.calls
      ? `${review.usage.calls} LLM calls · ${review.usage.prompt_tokens || 0}+${review.usage.completion_tokens || 0} tokens`
      : 'no LLM calls (offline engine)';
    if (review.errors && review.errors.length) {
      toast(`${review.errors.length} agent note(s): ${truncate(review.errors[0], 120)}`, 'warn');
    }
  }

  function ringColor(score) {
    if (score >= 85) return 'var(--ok)';
    if (score >= 70) return 'var(--accent)';
    if (score >= 50) return 'var(--medium)';
    return 'var(--critical)';
  }

  function renderWalkthrough(review) {
    const body = $('#walkthrough-body');
    const stats = review.stats || {};
    let md = '';
    if (stats.title) md += `# ${stats.title}\n\n`;
    if (review.summary) md += `## Summary\n\n${review.summary}\n\n`;
    if (review.walkthrough) md += review.walkthrough + '\n\n';
    if (stats.risk_areas && stats.risk_areas.length) {
      md += '## Risk areas\n\n' + stats.risk_areas.map((r) => `- ${r}`).join('\n') + '\n\n';
    }
    if (review.positives && review.positives.length) {
      md += "## What's done well\n\n" + review.positives.map((p) => `- ${p}`).join('\n') + '\n\n';
    }
    if (review.test_recommendations && review.test_recommendations.length) {
      md += '## Test coverage recommendations\n\n' +
        review.test_recommendations.map((t) => `- ${t}`).join('\n') + '\n\n';
    }
    body.innerHTML = Markdown.render(md || '_No walkthrough was produced._');
    wireCopyButtons(body);

    // diagram
    const diagramHost = $('#diagram-body');
    diagramHost.innerHTML = '';
    if (stats.sequence_diagram) {
      const frame = document.createElement('div');
      frame.className = 'diagram-frame';
      const heading = document.createElement('h4');
      heading.textContent = 'Flow';
      frame.appendChild(heading);
      frame.appendChild(renderDiagram(stats.sequence_diagram));
      const toggle = document.createElement('button');
      toggle.className = 'btn ghost small';
      toggle.type = 'button';
      toggle.textContent = 'Show mermaid source';
      toggle.style.marginTop = '10px';
      const src = document.createElement('pre');
      src.className = 'snippet';
      src.innerHTML = '<pre>' + Highlight.highlight(stats.sequence_diagram, '') + '</pre>';
      src.hidden = true;
      toggle.addEventListener('click', () => {
        src.hidden = !src.hidden;
        toggle.textContent = src.hidden ? 'Show mermaid source' : 'Hide source';
      });
      frame.append(toggle, src);
      diagramHost.appendChild(frame);
    }

    // checklist
    const checklistHost = $('#checklist-body');
    checklistHost.innerHTML = '';
    if (stats.checklist && stats.checklist.length) {
      const frame = document.createElement('div');
      frame.className = 'diagram-frame';
      frame.style.margin = '0 18px 18px';
      const heading = document.createElement('h4');
      heading.textContent = 'Merge checklist';
      frame.appendChild(heading);
      const list = document.createElement('div');
      list.className = 'markdown-body';
      list.style.padding = '0';
      list.innerHTML = Markdown.render(stats.checklist.map((c) => `- [ ] ${c}`).join('\n'));
      frame.appendChild(list);
      checklistHost.appendChild(frame);
    }
  }

  /** Tiny renderer for the two diagram shapes the summarizer emits.
   *  Anything it does not recognise falls back to showing the source. */
  function renderDiagram(source) {
    const wrap = document.createElement('div');
    wrap.className = 'dg';
    const lines = source.split('\n').map((l) => l.trim()).filter(Boolean);
    const kind = /sequenceDiagram/i.test(lines[0] || '') ? 'sequence'
      : /flowchart|graph\s/i.test(lines[0] || '') ? 'flow' : 'unknown';

    if (kind === 'flow') {
      const labels = {};
      lines.slice(1).forEach((line) => {
        const def = line.match(/^([A-Za-z0-9_]+)\s*[\[{]([^\]}]+)[\]}]$/);
        if (def) labels[def[1]] = def[2];
      });
      lines.slice(1).forEach((line, index) => {
        const edge = line.match(/^([A-Za-z0-9_]+)(?:\[[^\]]*\]|\{[^}]*\})?\s*(-+>|--+>\|([^|]*)\|)\s*([A-Za-z0-9_]+)/);
        if (edge) {
          if (index === 0) wrap.appendChild(flowNode(edge[1], labels));
          const arrow = document.createElement('div');
          arrow.className = 'dg-arrow';
          arrow.textContent = edge[3] ? `↓ ${edge[3]}` : '↓';
          wrap.appendChild(arrow);
          wrap.appendChild(flowNode(edge[4], labels));
        } else {
          const solo = line.match(/^([A-Za-z0-9_]+)\s*[\[{]([^\]}]+)[\]}]$/);
          if (solo && !Object.keys(labels).length) wrap.appendChild(flowNode(solo[1], { [solo[1]]: solo[2] }));
        }
      });
      if (!wrap.children.length) return fallbackDiagram(source);
      return wrap;
    }

    if (kind === 'sequence') {
      const seq = document.createElement('div');
      seq.className = 'dg-seq';
      lines.slice(1).forEach((line) => {
        const participant = line.match(/^participant\s+(\S+)\s+as\s+(.+)$/i);
        if (participant) return;
        const message = line.match(/^(\S+?)\s*(->>|-->>|-)|(\S+?)\s*(->>|-->>|-)\s*(\S+?)\s*:\s*(.*)$/);
        const full = line.match(/^(\S+)\s*(->>|-->>)\s*(\S+)\s*:\s*(.+)$/);
        if (full) {
          const row = document.createElement('div');
          row.className = 'dg-seq-row' + (full[2] === '-->>' ? ' ret' : '');
          row.innerHTML =
            `<span class="dg-seq-actor">${Markdown.escapeHtml(full[1])}</span>` +
            `<span class="dg-seq-msg">${full[2] === '-->>' ? '⇠' : '⇢'}</span>` +
            `<span class="dg-seq-target"><strong>${Markdown.escapeHtml(full[3])}</strong> ${Markdown.escapeHtml(full[4])}</span>`;
          seq.appendChild(row);
        }
        void message;
      });
      if (!seq.children.length) return fallbackDiagram(source);
      wrap.appendChild(seq);
      return wrap;
    }

    return fallbackDiagram(source);
  }

  function flowNode(id, labels) {
    const node = document.createElement('div');
    const text = labels[id] || id;
    node.className = 'dg-node' + (/\?/.test(text) ? ' decision' : '');
    node.textContent = text;
    return node;
  }

  function fallbackDiagram(source) {
    const pre = document.createElement('pre');
    pre.className = 'snippet';
    pre.innerHTML = '<pre>' + Highlight.highlight(source, '') + '</pre>';
    return pre;
  }

  function renderMetrics(review) {
    const host = $('#metrics-body');
    host.innerHTML = '';
    const metrics = review.metrics || [];
    if (!metrics.length) {
      host.innerHTML = '<div class="empty-state"><p class="muted">No metrics collected.</p></div>';
      return;
    }
    const grid = document.createElement('div');
    grid.className = 'metrics-grid';
    metrics.forEach((m) => {
      const card = document.createElement('div');
      card.className = 'metric-card';
      const commentRatio = m.code_lines ? Math.round((m.comment_lines / m.code_lines) * 100) : 0;
      const rows = [
        ['Lines', m.lines, ''],
        ['Code lines', m.code_lines, ''],
        ['Comment lines', `${m.comment_lines} (${commentRatio}%)`, commentRatio < 5 && m.lines > 40 ? 'warn' : ''],
        ['Max nesting', m.max_nesting, m.max_nesting > 6 ? 'bad' : m.max_nesting > 4 ? 'warn' : ''],
        ['Longest function', m.longest_function + ' lines', m.longest_function > 80 ? 'bad' : m.longest_function > 50 ? 'warn' : ''],
        ['Functions', m.functions, ''],
        ['Complexity index', m.complexity, m.complexity > 60 ? 'warn' : ''],
        ['Max line length', m.max_line_length, m.max_line_length > 120 ? 'warn' : ''],
        ['TODO markers', m.todo_count, m.todo_count ? 'warn' : ''],
        ['Duplicated blocks', m.duplicated_blocks, m.duplicated_blocks ? 'warn' : ''],
      ];
      card.innerHTML =
        `<div class="lang">${Markdown.escapeHtml(m.language)}</div>` +
        `<h4>${Markdown.escapeHtml(m.path)}</h4>` +
        '<dl class="metric-rows">' +
        rows.map(([label, value, cls]) =>
          `<dt>${label}</dt><dd class="${cls}">${value}</dd>`).join('') +
        '</dl>' +
        `<div class="bar"><i style="width:${Math.min(100, m.complexity)}%"></i></div>`;
      grid.appendChild(card);
    });
    host.appendChild(grid);

    const stats = review.stats || {};
    if (stats.diff_stats) {
      const note = document.createElement('div');
      note.className = 'callout';
      note.style.margin = '0 18px 18px';
      note.innerHTML = `<strong>Diff:</strong> ${stats.diff_stats.files} file(s), ` +
        `+${stats.diff_stats.additions} / −${stats.diff_stats.deletions} · ` +
        `static pre-scan found ${stats.static_findings || 0}, agents added ${stats.llm_findings || 0}.`;
      host.appendChild(note);
    }
  }

  function renderTrace(review) {
    const host = $('#trace-body');
    const traces = review.trace || [];
    if (!traces.length) { host.innerHTML = '<p class="muted" style="padding:16px">No trace.</p>'; return; }
    const total = traces.reduce((a, t) => a + (t.prompt_tokens || 0) + (t.completion_tokens || 0), 0);
    const wall = traces.reduce((a, t) => a + (t.duration_ms || 0), 0);
    host.innerHTML =
      `<div class="trace-table-wrap">
        <div class="callout" style="margin:0 0 14px">
          <strong>${traces.length} stages</strong> · ${fmtDuration(wall)} of agent work in
          ${fmtDuration(review.elapsed_ms)} wall clock (specialists run concurrently) ·
          ${total.toLocaleString()} tokens · ${review.provider}/${review.model}
        </div>
        <table class="trace-table">
          <thead><tr><th>Agent</th><th>Status</th><th>Findings</th><th>Time</th>
          <th>Tokens</th><th>Attempts</th><th>Notes</th></tr></thead>
          <tbody>
            ${traces.map((t) => `<tr>
              <td><strong>${Markdown.escapeHtml(t.label)}</strong>
                <div class="muted" style="font-size:10.5px">${Markdown.escapeHtml(t.model || '')}</div></td>
              <td><span class="status-tag st-${t.status}">${t.status}</span></td>
              <td class="num">${t.findings || 0}</td>
              <td class="num">${fmtDuration(t.duration_ms)}</td>
              <td class="num">${((t.prompt_tokens || 0) + (t.completion_tokens || 0)).toLocaleString()}</td>
              <td class="num">${t.attempts || 1}</td>
              <td class="trace-error">${Markdown.escapeHtml(truncate(t.error, 220))}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>` +
      (review.errors && review.errors.length
        ? `<div class="callout" style="margin:0 18px 18px;border-left-color:var(--medium)">
             <strong>Notes from this run</strong><ul style="margin:6px 0 0">
             ${review.errors.map((e) => `<li>${Markdown.escapeHtml(e)}</li>`).join('')}</ul></div>`
        : '');
  }

  function switchTab(name) {
    $$('#result-tabs .tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
    $$('.tab-panel').forEach((p) => { p.hidden = p.dataset.panel !== name; });
  }

  function wireCopyButtons(root) {
    $$('.copy-code', root).forEach((btn) => {
      if (btn.dataset.wired) return;
      btn.dataset.wired = '1';
      btn.addEventListener('click', () => {
        const pre = btn.parentElement.querySelector('pre');
        copyText(pre ? pre.textContent : '', 'Code');
      });
    });
  }

  // ================================ ask ================================
  async function askAbout(finding) {
    switchTab('findings');
    $('#ask-panel').hidden = false;
    $('#ask-input').value = `About "${finding.title}" at ${finding.file}:${finding.line || '?'} — ` +
      'can you show me the corrected code and explain the failure mode?';
    $('#ask-input').focus();
  }

  function pushAskMessage(role, html, meta) {
    const log = $('#ask-log');
    const el = document.createElement('div');
    el.className = 'ask-msg ' + role;
    el.innerHTML = html + (meta ? `<div class="meta">${Markdown.escapeHtml(meta)}</div>` : '');
    log.appendChild(el);
    log.scrollTop = log.scrollHeight;
    wireCopyButtons(el);
    return el;
  }

  async function submitAsk(question) {
    const input = activeInput();
    const code = input.code || (input.diff ? input.diff : '');
    if (!code && !state.review) {
      toast('Load some code first.', 'warn');
      return;
    }
    pushAskMessage('user', Markdown.escapeHtml(question));
    const pending = pushAskMessage('bot', '<span class="muted">Thinking…</span>');
    try {
      const data = await api('/api/ask', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          question, code: input.code || input.diff || '',
          path: input.path || 'input',
          review_id: state.review ? state.review.id : null,
        }),
      });
      pending.innerHTML = Markdown.render(data.answer || '(empty response)') +
        `<div class="meta">${data.provider}/${data.model} · ${fmtDuration(data.elapsed_ms)} · ` +
        `${(data.tokens.prompt || 0) + (data.tokens.completion || 0)} tokens</div>`;
      wireCopyButtons(pending);
    } catch (err) {
      pending.innerHTML = `<span class="v-critical">Ask failed:</span> ${Markdown.escapeHtml(err.message)}`;
    }
  }

  // ================================ PR ================================
  async function fetchPr() {
    const ref = $('#pr-input').value.trim();
    if (!ref) { toast('Enter owner/repo#123 or a PR URL', 'warn'); return; }
    const host = $('#pr-preview');
    host.innerHTML = '<span class="spinner" style="display:inline-block;vertical-align:middle"></span> Fetching pull request…';
    try {
      const pr = await api('/api/github/pr', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pull_request: ref }),
      });
      host.innerHTML =
        `<h4>${Markdown.escapeHtml(pr.title)}</h4>` +
        `<div>#${pr.number} by ${Markdown.escapeHtml(pr.author)} · ${pr.state} · ` +
        `${pr.base} ← ${pr.head}</div>` +
        `<div style="margin-top:6px">${pr.changed_files} files · ` +
        `<span style="color:var(--ok)">+${pr.additions}</span> / ` +
        `<span style="color:var(--critical)">−${pr.deletions}</span></div>` +
        `<div style="margin-top:8px;font-family:var(--mono);font-size:11px">` +
        pr.files.slice(0, 12).map((f) => `${Markdown.escapeHtml(f.filename)} <span class="muted">(${f.language})</span>`).join('<br>') +
        (pr.files.length > 12 ? `<br><span class="muted">…and ${pr.files.length - 12} more</span>` : '') +
        `</div>`;
      toast('PR fetched — press Run review', 'ok');
    } catch (err) {
      host.innerHTML = `<span class="v-critical">Fetch failed:</span> ${Markdown.escapeHtml(err.message)}`;
    }
  }

  // ================================ boot ================================
  function buildRequestBody() {
    const input = activeInput();
    const categories = $$('.option-grid .checkbox[data-cat] input:checked').map((c) => c.value);
    if (!categories.length) { toast('Select at least one review dimension', 'warn'); return null; }

    const body = {
      effort: $('#effort-select').value,
      provider: state.activeProvider,
      model: state.activeModel,
      categories,
      include_summary: $('#include-summary').checked,
      focus_changed_lines: $('#focus-changed').checked,
      min_severity: $('#min-severity').value,
      max_findings: parseInt($('#max-findings').value, 10) || 40,
      instructions: $('#instructions').value.trim() || null,
      stream: true,
    };
    const language = $('#language-select').value;
    if (language) body.language = language;

    if (input.kind === 'pr') {
      if (!input.pull_request) { toast('Enter a pull request reference', 'warn'); return null; }
      body.pull_request = input.pull_request;
    } else if (input.kind === 'diff') {
      if (!input.diff.trim()) { toast('Paste a diff first', 'warn'); return null; }
      body.diff = input.diff;
    } else {
      if (!input.code.trim()) { toast('Paste some code first', 'warn'); return null; }
      body.code = input.code;
      body.files = [{ path: input.path, content: input.code }];
    }
    return body;
  }

  async function runStaticScan() {
    const input = activeInput();
    if (!input.code && !input.diff) { toast('Paste some code or a diff first', 'warn'); return; }
    setStatus('Running static scan…', 'busy');
    try {
      const data = await api('/api/scan', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: input.code || '', diff: input.diff || '', path: input.path || 'input' }),
      });
      const review = {
        id: 'scan-' + Date.now(),
        verdict: 'approve_with_nits',
        score: Math.max(5, 100 - data.findings.length * 4),
        summary: `Static scan of ${Object.keys(data.metrics).length || 1} file(s) — ` +
          `${data.findings.length} rule hit(s). No LLM was used.`,
        walkthrough: '### Pre-scan only\n\nDeterministic rules, no model. Run a full review for semantic findings.',
        findings: data.findings,
        by_severity: data.by_severity, by_category: data.by_category,
        metrics: Object.values(data.metrics).map((m) => { const c = { ...m }; delete c.classes; return c; }),
        trace: [{ agent: 'prescan', label: 'Static pre-scan', status: 'done', findings: data.findings.length,
                  duration_ms: 0, model: 'rule-engine-v1', provider: 'local', attempts: 1 }],
        usage: { calls: 0 }, provider: 'static', model: 'rule-engine-v1', elapsed_ms: 0,
        errors: [], stats: {}, review_markdown: '', positives: [], test_recommendations: [],
      };
      $('#pipeline').innerHTML = '';
      upsertAgentCard('prescan', 'Static pre-scan', '🔍', 'done', data.findings.length + ' hits');
      $('#result-tabs').hidden = false;
      renderReview(review);
      toast('Static scan complete — ' + data.findings.length + ' hits', 'ok');
    } catch (err) {
      toast('Scan failed: ' + err.message, 'err');
      setStatus('Scan failed', 'err');
    }
  }

  function bindEvents() {
    // input tabs
    $$('.tab[data-input-tab]').forEach((btn) =>
      btn.addEventListener('click', () => switchInputTab(btn.dataset.inputTab)));

    // result tabs
    $$('#result-tabs .tab').forEach((btn) =>
      btn.addEventListener('click', () => switchTab(btn.dataset.tab)));

    $('#code-input').addEventListener('input', updateCodeStats);
    $('#diff-input').addEventListener('input', updateDiffStats);
    $('#file-path').addEventListener('input', () => {
      const path = $('#file-path').value.trim();
      const ext = (/\.([a-z0-9]+)$/i.exec(path) || [])[1];
      if (ext && Highlight.normalise(ext) !== ext) return;
    });

    // tab key inserts a real tab in the editor
    $('#code-input').addEventListener('keydown', (event) => {
      if (event.key === 'Tab') {
        event.preventDefault();
        const el = event.target;
        const start = el.selectionStart; const end = el.selectionEnd;
        el.value = el.value.slice(0, start) + '    ' + el.value.slice(end);
        el.selectionStart = el.selectionEnd = start + 4;
        updateCodeStats();
      }
      if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') $('#run-btn').click();
    });

    // file drop
    const dropTargets = [$('#code-input'), $('#diff-input')];
    dropTargets.forEach((area) => {
      area.addEventListener('dragover', (e) => { e.preventDefault(); area.classList.add('drag-over'); });
      area.addEventListener('dragleave', () => area.classList.remove('drag-over'));
      area.addEventListener('drop', async (e) => {
        e.preventDefault();
        area.classList.remove('drag-over');
        const file = e.dataTransfer.files && e.dataTransfer.files[0];
        if (!file) return;
        const text = await file.text();
        area.value = text;
        if (area.id === 'code-input') { $('#file-path').value = file.name; updateCodeStats(); }
        else updateDiffStats();
        toast('Loaded ' + file.name, 'ok');
      });
    });
    $('#file-drop').addEventListener('change', async (event) => {
      const file = event.target.files && event.target.files[0];
      if (!file) return;
      const text = await file.text();
      const isDiff = /^diff --git |^@@ -\d/m.test(text);
      if (isDiff) { switchInputTab('diff'); $('#diff-input').value = text; updateDiffStats(); }
      else { switchInputTab('code'); $('#code-input').value = text; $('#file-path').value = file.name; updateCodeStats(); }
      toast('Loaded ' + file.name, 'ok');
      event.target.value = '';
    });

    // run
    $('#run-btn').addEventListener('click', () => {
      const body = buildRequestBody();
      if (body) runReview(body);
    });
    $('#scan-btn').addEventListener('click', runStaticScan);
    $('#clear-btn').addEventListener('click', () => {
      $('#code-input').value = ''; $('#diff-input').value = ''; $('#pr-input').value = '';
      $('#instructions').value = '';
      updateCodeStats(); updateDiffStats();
      clearResults(); resetPipeline();
      $('#pipeline').innerHTML =
        '<div class="pipeline-empty muted"><strong>Agents idle.</strong> Submit code and press ' +
        '<em>Run review</em> to watch the pipeline work.</div>';
      $('#findings-list').innerHTML =
        '<div class="empty-state"><div class="empty-icon">🔍</div><h3>No review yet</h3>' +
        '<p>Paste code, a diff, or a GitHub PR reference and press <strong>Run review</strong>.</p></div>';
      $('#verdict-bar').hidden = true;
      $('#result-tabs').hidden = true;
      $('#ask-panel').hidden = true;
      $('#filters').hidden = true;
      setStatus('Cleared.', 'ok');
    });

    // filters
    $('#filter-search').addEventListener('input', (e) => {
      state.filters.search = e.target.value; applyFilters();
    });
    $('#file-filter').addEventListener('change', (e) => {
      state.filters.file = e.target.value; applyFilters();
    });
    $('#sort-severity').addEventListener('change', (e) => {
      state.sortBySeverity = e.target.checked;
      const list = $('#findings-list');
      const cards = $$('.finding', list);
      const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      cards.sort((a, b) => state.sortBySeverity
        ? (order[a.dataset.severity] - order[b.dataset.severity])
        : (parseInt(a.dataset.line || 0, 10) - parseInt(b.dataset.line || 0, 10)));
      cards.forEach((c) => list.appendChild(c));
    });

    // provider / model / effort
    $('#provider-select').addEventListener('change', async (e) => {
      state.activeProvider = e.target.value;
      const spec = state.providers.find((p) => p.id === state.activeProvider);
      state.activeModel = spec ? spec.default_model : '';
      renderModelSelect();
      try {
        await api('/api/config', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ provider: state.activeProvider, model: state.activeModel }),
        });
        await loadConfig();
      } catch (err) { toast('Provider switch failed: ' + err.message, 'err'); }
    });
    $('#model-select').addEventListener('change', async (e) => {
      state.activeModel = e.target.value;
      try {
        await api('/api/config', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ provider: state.activeProvider, model: state.activeModel }),
        });
        updateStatusStrip();
      } catch (err) { toast('Model switch failed: ' + err.message, 'err'); }
    });
    $('#effort-select').addEventListener('change', async (e) => {
      try {
        await api('/api/config', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ effort: e.target.value }),
        });
        updateStatusStrip();
      } catch (err) { /* non-fatal */ }
    });
    $('#temperature').addEventListener('change', async (e) => {
      const value = parseFloat(e.target.value);
      if (isNaN(value)) return;
      try {
        await api('/api/config', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ temperature: value }),
        });
      } catch (err) { /* non-fatal */ }
    });

    // PR
    $('#pr-fetch-btn').addEventListener('click', fetchPr);
    $('#pr-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); fetchPr(); } });
    $('#use-git-btn').addEventListener('click', () => {
      $('#diff-input').value =
        '# Generate a diff in your terminal and paste it here:\n' +
        '#   git diff main...HEAD\n' +
        '#   git diff --staged\n';
      toast('Copy the output of `git diff` and paste it in', 'warn');
    });

    // markdown export
    const copyMd = () => copyText((state.review && state.review.review_markdown) || '', 'Review');
    const downloadMd = () => {
      const md = (state.review && state.review.review_markdown) || '';
      if (!md) { toast('No review to download', 'warn'); return; }
      const blob = new Blob([md], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `code-review-${(state.review && state.review.id) || 'export'}.md`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1500);
      toast('Downloaded review.md', 'ok');
    };
    $('#copy-md-btn').addEventListener('click', copyMd);
    $('#copy-md-btn-2').addEventListener('click', copyMd);
    $('#download-btn').addEventListener('click', downloadMd);
    $('#download-btn-2').addEventListener('click', downloadMd);

    // ask
    $('#ask-form').addEventListener('submit', (event) => {
      event.preventDefault();
      const question = $('#ask-input').value.trim();
      if (!question) return;
      $('#ask-input').value = '';
      submitAsk(question);
    });

    // modals
    $('#settings-btn').addEventListener('click', () => { $('#settings-modal').hidden = false; renderProviderList(); });
    $('#prompt-btn').addEventListener('click', loadPrompt);
    $('#copy-prompt-btn').addEventListener('click', () =>
      copyText($('#prompt-core').textContent, 'System prompt'));
    $$('[data-close]').forEach((btn) =>
      btn.addEventListener('click', () => { $('#' + btn.dataset.close).hidden = true; }));
    $$('.modal-backdrop').forEach((backdrop) =>
      backdrop.addEventListener('click', (e) => { if (e.target === backdrop) backdrop.hidden = true; }));
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') $$('.modal-backdrop').forEach((m) => { m.hidden = true; });
    });
  }

  async function loadPrompt() {
    const modal = $('#prompt-modal');
    modal.hidden = false;
    if (modal.dataset.loaded) return;
    try {
      const data = await api('/api/system-prompt');
      $('#prompt-core').textContent = data.core;
      const host = $('#prompt-agents');
      host.innerHTML = '';
      Object.entries(data.agents).forEach(([key, text]) => {
        const details = document.createElement('details');
        details.className = 'agent-focus';
        const summary = document.createElement('summary');
        summary.textContent = key;
        const pre = document.createElement('pre');
        pre.textContent = text;
        details.append(summary, pre);
        host.appendChild(details);
      });
      modal.dataset.loaded = '1';
    } catch (err) {
      $('#prompt-core').textContent = 'Could not load the system prompt: ' + err.message;
    }
  }

  async function boot() {
    bindEvents();
    await loadConfig();
    await populateLanguages();
    await loadExamples();
    updateCodeStats();
    updateDiffStats();

    const first = state.examples[0];
    if (first && !$('#code-input').value) {
      // Preload the first example so the app is demonstrably alive on arrival.
      if (first.kind === 'diff') {
        $('#diff-input').value = first.content; updateDiffStats();
      } else {
        $('#code-input').value = first.content;
        $('#file-path').value = first.name; updateCodeStats();
      }
    }
    if (state.activeProvider === 'demo') {
      toast('Running the offline static engine — add a free Groq or Gemini key in Settings for full AI review.', 'warn');
    }
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
