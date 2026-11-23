const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

const CHUNK = 768 * 1024;
const MAX_DROP = 1073741824;
const OPTION_FIELDS = { autoScan: '#optAuto', notify: '#optNotify', preScan: '#optPre' };
const LINKS = {
  'discord-link': 'https://discord.com/users/1373443184599760896',
  'virustotal-link': 'https://www.virustotal.com/gui/home/',
  'test-link': chrome.runtime.getURL('eicar.html')
};
const views = { home: $('#viewHome'), scan: $('#viewScan'), settings: $('#viewSettings') };

let current = 'home';
let queue = Promise.resolve();
let pickMode = null;
let dragDepth = 0;

function startJob(msg, onProgress) {
  const port = chrome.runtime.connectNative(HOST);
  let settled = false;
  let stop = () => {};

  const promise = new Promise((res, rej) => {
    const end = (fn, value) => {
      if (settled) return;
      settled = true;
      try { port.disconnect(); } catch (e) {}
      fn(value);
    };

    port.onMessage.addListener((m) => {
      if (m && m.progress) {
        if (onProgress) onProgress(m);
        return;
      }
      end(res, m);
    });
    port.onDisconnect.addListener(() => {
      end(rej, new Error(chrome.runtime.lastError?.message || 'Helper disconnected'));
    });
    stop = () => end(res, { cancelled: true });
    port.postMessage(msg);
  });

  return {
    promise,
    cancel: () => {
      stop();
      if (msg.path && (msg.action === 'scan' || msg.action === 'scanfolder')) {
        quiet(send({ action: 'cancel', path: msg.path }));
      }
    }
  };
}

function ago(ts) {
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 10) return t('ago.now');
  if (s < 60) return t('ago.sec', { n: s });
  const m = Math.floor(s / 60);
  if (m < 60) return t('ago.min', { n: m });
  const h = Math.floor(m / 60);
  if (h < 24) return t('ago.hour', { n: h });
  return t('ago.day', { n: Math.floor(h / 24) });
}

function stamp(li, ts) {
  li.dataset.t = String(ts);
  let when = li.querySelector('.when');
  if (!when) {
    when = document.createElement('span');
    when.className = 'when';
    li.querySelector('.name').after(when);
  }
  when.textContent = ago(ts);
}

function shortPath(p, max = 34) {
  if (p.length <= max) return p;
  const parts = p.split(/[\\/]/).filter(Boolean);
  let out = parts.pop() || '';
  while (parts.length && out.length + parts[parts.length - 1].length + 3 <= max) {
    out = parts.pop() + '\\' + out;
  }
  return '…\\' + out.slice(-(max - 2));
}

function setState(s, title, sub = '') {
  $('#state').dataset.s = s;
  $('#stateTitle').textContent = title;
  $('#stateSub').textContent = sub;
  $('#homeState').dataset.s = s;
  $('#homeStateText').textContent = title;
  $('#homeState').title = sub;
}

const helperMissing = (detail = '') => setState('err', t('state.helperNotInstalled'), t('state.helperHint') + detail);

function markSeen() {
  quiet(chrome.runtime.sendMessage({ type: 'seen' }));
}

function showView(name) {
  if (!views[name]) return;
  current = name;
  document.body.style.width = name === 'home' ? '280px' : '356px';

  for (const [key, el] of Object.entries(views)) {
    const on = key === name;
    el.hidden = !on;
    if (on) {
      el.classList.remove('enter');
      void el.offsetWidth;
      el.classList.add('enter');
    }
  }

  window.scrollTo(0, 0);
  if (name === 'scan') markSeen();
}

async function loadPip() {
  const { unseenThreat } = await chrome.storage.local.get({ unseenThreat: false });
  $('#scanPip').hidden = !unseenThreat;
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  $$('.theme-btn').forEach((btn) => {
    const active = btn.dataset.theme === theme;
    btn.classList.toggle('active', active);
    btn.setAttribute('aria-pressed', String(active));
  });
}

async function loadTheme() {
  const { theme = 'dark' } = await chrome.storage.local.get('theme');
  applyTheme(theme);
}

function applyLangButtons(lang) {
  $$('.lang-btn').forEach((btn) => {
    const active = btn.dataset.lang === lang;
    btn.classList.toggle('active', active);
    btn.setAttribute('aria-pressed', String(active));
  });
}

function applyI18n() {
  $('#tagline').textContent = t('home.tagline');
  $('#menuScan').firstChild.textContent = t('home.scanBtn') + ' ';
  $('#menuSettings').textContent = t('home.settingsBtn');
  $('#discord-link').title = t('home.discordTitle');
  $('#virustotal-link').title = t('home.vtTitle');
  $('#test-link').title = t('home.testTitle');

  $$('.icon-btn[data-go="home"]').forEach((btn) => {
    btn.title = t('common.back');
    btn.setAttribute('aria-label', t('common.backAria'));
  });

  $('#hDownloadedFile').textContent = t('scan.sectionDownloaded');
  applyPickMode(pickMode);
  $('#pickToggle').title = t('scan.pickToggleTitle');
  $('#pickToggle').setAttribute('aria-label', t('scan.pickToggleTitle'));
  $('#pickPanelTitle').textContent = t('scan.pickPanelTitle');
  $('#pickFilesLabel').textContent = t('scan.pickFiles');
  $('#pickFolderLabel').textContent = t('scan.pickFolder');
  $('#path').placeholder = t('scan.pathPlaceholder');
  $('#scanPath').textContent = t('scan.scanBtnShort');

  $('#hLink').textContent = t('scan.sectionLink');
  $('#url').placeholder = t('scan.urlPlaceholder');
  $('#scanUrl').textContent = t('scan.scanBtnShort');
  $('#keepLabelText').textContent = t('scan.keepLabel');
  $('.keep').title = t('scan.keepTitle');

  $('#resultsHeading').textContent = t('scan.resultsTitle');
  $('#cancelAll').textContent = t('scan.cancelAll');
  $('#clearResults').textContent = t('scan.clear');
  const resultsEmpty = $('#results .empty');
  if (resultsEmpty) resultsEmpty.textContent = t('scan.empty');

  $('#downloadsHeading').textContent = t('scan.downloadsTitle');
  const downloadsEmpty = $('#downloads .empty');
  if (downloadsEmpty) downloadsEmpty.textContent = t('scan.downloadsEmpty');

  $('#settingsTitle').textContent = t('settings.title');
  $('#languageHeading').textContent = t('settings.languageTitle');
  $('#themeHeading').textContent = t('settings.themeTitle');
  $$('.theme-btn').forEach((btn) => {
    btn.textContent = btn.dataset.theme === 'dark' ? t('settings.themeDark') : t('settings.themeLight');
  });
  $('#autoScanHeading').textContent = t('settings.autoTitle');
  $('#optPreLabel').textContent = t('settings.optPre');
  $('#optAutoLabel').textContent = t('settings.optAuto');
  $('#optNotifyLabel').textContent = t('settings.optNotify');
  $('#watchHeading').textContent = t('settings.watchTitle');
  $('#watchAdd').textContent = t('settings.addFolder');

  $('#drop').textContent = t('drop.text');

  applyLangButtons(i18nGetLang());
}

async function loadLanguage() {
  await i18nInit();
  applyI18n();
}

async function loadOptions() {
  const options = await chrome.storage.local.get(OPTION_DEFAULTS);
  for (const [key, selector] of Object.entries(OPTION_FIELDS)) {
    const input = $(selector);
    input.checked = options[key];
    input.addEventListener('change', () => chrome.storage.local.set({ [key]: input.checked }));
  }
}

const setWatches = (list) => chrome.storage.local.set({ watches: list.slice(0, MAX_WATCH) });

async function patchWatch(id, patch) {
  const list = await getWatches();
  await setWatches(list.map((w) => (w.id === id ? { ...w, ...patch } : w)));
}

function buildWatchCard(w) {
  const card = document.createElement('div');
  card.className = 'watch-card';
  card.innerHTML =
    '<div class="watch-top"><span class="watch-path"></span><button class="watch-remove" type="button">✕</button></div>' +
    '<label class="opt small"><input type="checkbox" data-k="recurse"> <span></span></label>' +
    '<label class="opt small"><input type="checkbox" data-k="notify"> <span></span></label>' +
    '<div class="warn-note" hidden></div>';

  const pathEl = card.querySelector('.watch-path');
  const remove = card.querySelector('.watch-remove');
  const recurse = card.querySelector('[data-k="recurse"]');
  const notify = card.querySelector('[data-k="notify"]');
  const warn = card.querySelector('.warn-note');
  const recurseLabel = card.querySelectorAll('.opt.small span')[0];
  const notifyLabel = card.querySelectorAll('.opt.small span')[1];

  pathEl.textContent = shortPath(w.path);
  pathEl.title = w.path;
  recurseLabel.textContent = t('settings.includeSubfolders');
  notifyLabel.textContent = t('settings.optNotify');
  warn.textContent = t('settings.watchWarn');
  remove.title = t('settings.removeWatchTitle');
  remove.setAttribute('aria-label', t('settings.removeWatchAria', { path: w.path }));
  recurse.checked = !!w.recurse;
  notify.checked = w.notify !== false;
  warn.hidden = notify.checked;

  remove.addEventListener('click', async () => {
    const list = await getWatches();
    await setWatches(list.filter((x) => x.id !== w.id));
    renderWatches(await getWatches());
  });
  recurse.addEventListener('change', () => patchWatch(w.id, { recurse: recurse.checked }));
  notify.addEventListener('change', () => {
    warn.hidden = notify.checked;
    patchWatch(w.id, { notify: notify.checked });
  });

  return card;
}

function renderWatches(list) {
  const box = $('#watchList');
  box.textContent = '';
  list.forEach((w) => box.append(buildWatchCard(w)));
  $('#watchCount').textContent = list.length + '/' + MAX_WATCH;
  $('#watchAdd').disabled = list.length >= MAX_WATCH;
}

async function loadWatches() {
  renderWatches(await getWatches());
}

async function addWatch() {
  const list = await getWatches();
  if (list.length >= MAX_WATCH) return;

  try {
    const r = await send({ action: 'pickfolder' });
    if (!r || !r.path) return;

    if (list.some((x) => x.path.toLowerCase() === r.path.toLowerCase())) {
      const count = $('#watchCount');
      count.textContent = t('scan.alreadyWatched');
      setTimeout(() => { count.textContent = list.length + '/' + MAX_WATCH; }, 2000);
      return;
    }

    const id = Math.random().toString(36).slice(2, 10);
    const next = [...list, { id, path: r.path, recurse: false, notify: true, added: Date.now() }];
    await setWatches(next);
    renderWatches(next);
  } catch (e) {
    helperMissing();
  }
}

function syncClear() {
  const ul = $('#results');
  $('#clearResults').hidden = !ul.querySelector('li:not(.empty)');
  $('#cancelAll').hidden = !ul.querySelector('li[data-s="scanning"]');
}

function ensureEmpty() {
  const ul = $('#results');
  if (!ul.querySelector('li')) {
    const li = document.createElement('li');
    li.className = 'empty';
    li.textContent = t('scan.empty');
    ul.append(li);
  }
  syncClear();
}

function addRow(label, title) {
  const ul = $('#results');
  ul.querySelector('.empty')?.remove();

  const li = document.createElement('li');
  li.dataset.s = 'scanning';
  li.title = title;
  li.innerHTML = '<span class="spin"></span><div class="name"><b></b><span></span></div><button class="cancel" type="button"></button>';
  li.querySelector('b').textContent = label;
  li.querySelector('.name span').textContent = t('scan.waiting');
  li.querySelector('.cancel').textContent = t('common.cancel');

  ul.prepend(li);
  syncClear();
  return li;
}

function finish(li, s, text, extra = {}) {
  li.dataset.s = s;
  li.querySelector('.spin')?.remove();
  li.querySelector('.cancel')?.remove();
  li.querySelector('.name span').textContent = text;

  for (const detail of [extra.raw, extra.info]) {
    if (detail) li.title = li.title ? li.title + '\n' + detail : detail;
  }
  stamp(li, Number(li.dataset.t) || Date.now());

  if (extra.url && !li.querySelector('button')) {
    const details = document.createElement('button');
    details.textContent = t('common.details');
    details.addEventListener('click', () => chrome.tabs.create({ url: extra.url }));
    li.append(details);
  }
  syncClear();
}

function renderEntry(e) {
  const ul = $('#results');
  ul.querySelector('.empty')?.remove();

  const li = document.createElement('li');
  li.dataset.ts = e.ts;
  li.dataset.t = String(e.ts);
  li.title = e.title || '';
  li.innerHTML = '<div class="name"><b></b><span></span></div>';
  li.querySelector('b').textContent = e.label;
  finish(li, e.s, e.text, e);

  ul.prepend(li);
  syncClear();
}

async function loadHistory() {
  const { history = [] } = await chrome.storage.local.get('history');
  history.slice().reverse().forEach(renderEntry);
}

async function loadDownloads() {
  const ul = $('#downloads');
  const items = await chrome.downloads.search({ state: 'complete', exists: true, orderBy: ['-startTime'], limit: 5 });
  ul.textContent = '';

  if (!items.length) {
    const li = document.createElement('li');
    li.className = 'empty';
    li.textContent = t('scan.downloadsEmpty');
    ul.append(li);
    return;
  }

  for (const item of items) {
    const li = document.createElement('li');
    li.title = item.filename;
    li.innerHTML = '<div class="name"><b></b><span></span></div><button></button>';
    li.querySelector('b').textContent = base(item.filename);
    li.querySelector('span').textContent = item.filename;
    const btn = li.querySelector('button');
    btn.textContent = t('scan.scanBtnShort');
    btn.addEventListener('click', () => scan(item.filename));

    const time = Date.parse(item.endTime || item.startTime);
    if (!Number.isNaN(time)) stamp(li, time);
    ul.append(li);
  }
}

async function init() {
  let r;
  try {
    r = await send({ action: 'status' });
  } catch (e) {
    return helperMissing(' (' + e.message + ')');
  }
  if (!r || !r.ok) return setState('err', t('state.defenderUnavailable'), (r && r.error) || t('state.helperNoAnswer'));
  if (!r.antivirus) return setState('warn', t('state.defenderOff'), t('state.scansMayFail'));
  setState('ok', t('state.defenderConnected'), r.limited
    ? t('state.statusUnavailable')
    : t('state.realtimeInfo', { state: r.realtime ? t('state.on') : t('state.off'), sig: r.signatures || t('state.unknown') }));
}

function threatText(r) {
  return r.threats?.length ? t('scan.threatLabel', { names: r.threats.join(', ') }) : t('common.threatFound');
}

function folderText(r) {
  if (r.threat) {
    if (!r.infected) return threatText(r);
    const names = r.threats?.length ? r.threats.join(', ') : t('common.threatFound');
    return t('scan.infectedOfTotal', { infected: r.infected, total: r.total, names });
  }
  const extra = r.failed ? t('scan.couldNotBeRead', { n: r.failed }) : '';
  return t('scan.noThreatsInFolder', { scanned: r.scanned }) + extra;
}

function finishScan(li, r, took) {
  if (r.threat) finish(li, 'threat', threatText(r));
  else finish(li, 'clean', r.kept ? t('common.cleanSaved') : t('common.noThreats'));
  if (r.kept) li.title += '\n' + r.kept;
  li.title += '\n' + infoLine(r.size, took);
}

function createJob(li) {
  const job = { cancelled: false, run: null, port: null };
  li.querySelector('.cancel').addEventListener('click', () => {
    job.cancelled = true;
    job.run?.cancel();
    job.port?.close();
    finish(li, 'error', t('scan.cancelled'));
  });
  return job;
}

function startText(action) {
  if (action === 'scanurl') return t('scan.downloadingThenScanning');
  if (action === 'scanfolder') return t('scan.countingFiles');
  return t('common.scanning');
}

function enqueue(label, title, msg) {
  const li = addRow(label, title);
  const job = createJob(li);

  queue = queue.then(async () => {
    if (job.cancelled) return;

    const status = li.querySelector('.name span');
    status.textContent = startText(msg.action);
    const startedAt = Date.now();

    try {
      job.run = startJob(msg, (m) => {
        if (job.cancelled) return;
        status.textContent = m.whole
          ? t('scan.scanningProgressNoCount', { total: m.total })
          : t('scan.scanningProgressCount', { done: m.done, total: m.total });
      });
      const r = await job.run.promise;
      if (job.cancelled || r.cancelled) return;

      const took = Date.now() - startedAt;
      if (!r.ok) {
        finish(li, 'error', r.error || t('common.scanFailed'));
        return;
      }
      if (msg.action === 'scanfolder') {
        finish(li, r.threat ? 'threat' : 'clean', folderText(r));
        if (r.files?.length) li.title += '\n' + r.files.join('\n');
        li.title += '\n' + infoLine(r.bytes, took, r.total);
        return;
      }
      finishScan(li, r, took);
    } catch (e) {
      if (!job.cancelled) finish(li, 'error', t('common.helperNotReachable'));
    }
  });
}

const readB64 = (blob) => new Promise((res, rej) => {
  const reader = new FileReader();
  reader.onload = () => res(String(reader.result).split(',')[1] || '');
  reader.onerror = () => rej(reader.error);
  reader.readAsDataURL(blob);
});

function enqueueDrop(file) {
  const li = addRow(file.name, file.name);
  const job = createJob(li);

  queue = queue.then(async () => {
    if (job.cancelled) return;
    if (file.size > MAX_DROP) {
      finish(li, 'error', t('scan.largerThan1gb'));
      return;
    }

    const id = crypto.randomUUID();
    const port = openPort();
    job.port = port;
    const status = li.querySelector('.name span');
    const startedAt = Date.now();

    try {
      const total = Math.max(1, Math.ceil(file.size / CHUNK));
      let r = null;

      for (let i = 0; i < total; i++) {
        if (job.cancelled) return;
        const last = i === total - 1;
        status.textContent = last ? t('common.scanning') : t('scan.sendingProgress', { pct: Math.round((i / total) * 100) });
        const data = await readB64(file.slice(i * CHUNK, (i + 1) * CHUNK));
        if (job.cancelled) return;
        r = await port.ask({ action: 'dropchunk', id, name: file.name, index: i, last, data });
        if (!r.ok || !r.more) break;
      }
      if (job.cancelled) return;

      if (!r.ok) {
        finish(li, 'error', r.error || t('common.scanFailed'));
        return;
      }
      finishScan(li, r, Date.now() - startedAt);
    } catch (e) {
      if (!job.cancelled) finish(li, 'error', t('common.helperNotReachable'));
    } finally {
      port.close();
    }
  });
}

const cleanPath = (p) => p.trim().replace(/^"|"$/g, '');

function scan(path) {
  path = cleanPath(path);
  if (path) enqueue(base(path), path, { action: 'scan', path });
}

function scanFolder(path) {
  path = cleanPath(path);
  if (path) enqueue(base(path) || path, path, { action: 'scanfolder', path });
}

function scanUrl(url) {
  url = url.trim();
  if (!url) return;
  if (!/^https?:\/\//i.test(url)) {
    finish(addRow(url, url), 'error', t('scan.enterValidLink'));
    return;
  }
  enqueue(urlLabel(url), url, { action: 'scanurl', url, keep: $('#keep').checked });
}

const hasFiles = (e) => [...(e.dataTransfer?.types || [])].includes('Files');

function handleDrop(e) {
  showView('scan');
  const items = [...(e.dataTransfer.items || [])];
  [...e.dataTransfer.files].forEach((file, i) => {
    const entry = items[i]?.webkitGetAsEntry?.();
    if (entry?.isDirectory) finish(addRow(file.name, file.name), 'error', t('scan.folderNotSupported'));
    else enqueueDrop(file);
  });
}

const browseBtn = $('#browse');
const pickToggle = $('#pickToggle');
const pickPanel = $('#pickPanel');
const isOpen = (el) => el.classList.contains('open');

function setPickPanel(open) {
  pickPanel.classList.toggle('open', open);
  pickPanel.setAttribute('aria-hidden', String(!open));
  pickToggle.setAttribute('aria-expanded', String(open));
}

function applyPickMode(mode) {
  pickMode = mode;
  $$('input[name="pickMode"]').forEach((r) => { r.checked = r.value === mode; });
  browseBtn.textContent = mode === 'files' ? t('scan.browseFiles')
    : mode === 'folder' ? t('scan.browseFolder')
    : t('scan.browseDefault');
}

async function loadPickMode() {
  const { pickMode: saved } = await chrome.storage.local.get({ pickMode: null });
  applyPickMode(saved === 'files' || saved === 'folder' ? saved : null);
}

async function pickFiles() {
  try {
    const r = await send({ action: 'pick' });
    (r.paths || []).forEach(scan);
  } catch (e) {
    helperMissing();
  }
}

async function pickFolder() {
  try {
    const r = await send({ action: 'pickfolder' });
    if (r && r.path) scanFolder(r.path);
  } catch (e) {
    helperMissing();
  }
}

$$('[data-go]').forEach((b) => {
  b.addEventListener('click', () => showView(b.dataset.go));
});

$$('.theme-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    chrome.storage.local.set({ theme: btn.dataset.theme });
    applyTheme(btn.dataset.theme);
  });
});

$$('.lang-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    i18nSetLang(btn.dataset.lang);
    applyI18n();
  });
});

$$('input[name="pickMode"]').forEach((r) => {
  r.addEventListener('change', () => {
    applyPickMode(r.value);
    chrome.storage.local.set({ pickMode: r.value });
  });
});

pickToggle.addEventListener('click', () => setPickPanel(!isOpen(pickPanel)));

browseBtn.addEventListener('click', () => {
  if (pickMode === 'files') pickFiles();
  else if (pickMode === 'folder') pickFolder();
  else setPickPanel(true);
});

$('#watchAdd').addEventListener('click', addWatch);

$('#cancelAll').addEventListener('click', () => {
  $('#results').querySelectorAll('li[data-s="scanning"] .cancel').forEach((b) => b.click());
});

$('#clearResults').addEventListener('click', async () => {
  $('#results').querySelectorAll('li:not([data-s="scanning"])').forEach((li) => li.remove());
  ensureEmpty();
  await chrome.storage.local.set({ history: [] });
});

$('#scanPath').addEventListener('click', () => { scan($('#path').value); $('#path').value = ''; });
$('#scanUrl').addEventListener('click', () => { scanUrl($('#url').value); $('#url').value = ''; });
$('#path').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#scanPath').click(); });
$('#url').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#scanUrl').click(); });

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && current !== 'home') showView('home');
});

document.addEventListener('click', (e) => {
  const outside = ![pickPanel, pickToggle, browseBtn].some((el) => el.contains(e.target));
  if (isOpen(pickPanel) && outside) setPickPanel(false);
});

window.addEventListener('dragenter', (e) => {
  if (!hasFiles(e)) return;
  e.preventDefault();
  dragDepth++;
  $('#drop').hidden = false;
});

window.addEventListener('dragover', (e) => {
  if (hasFiles(e)) e.preventDefault();
});

window.addEventListener('dragleave', (e) => {
  if (!hasFiles(e)) return;
  dragDepth = Math.max(0, dragDepth - 1);
  if (!dragDepth) $('#drop').hidden = true;
});

window.addEventListener('drop', (e) => {
  if (!hasFiles(e)) return;
  e.preventDefault();
  dragDepth = 0;
  $('#drop').hidden = true;
  handleDrop(e);
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  if (changes.unseenThreat) $('#scanPip').hidden = !changes.unseenThreat.newValue;
  if (!changes.history) return;

  const seen = new Set([...$('#results').querySelectorAll('li[data-ts]')].map((x) => x.dataset.ts));
  (changes.history.newValue || [])
    .slice()
    .reverse()
    .filter((e) => !seen.has(String(e.ts)))
    .forEach(renderEntry);
  if (current === 'scan') markSeen();
});

setInterval(() => {
  $$('li[data-t]').forEach((li) => {
    const when = li.querySelector('.when');
    if (when) when.textContent = ago(Number(li.dataset.t));
  });
}, 20000);

for (const [id, url] of Object.entries(LINKS)) {
  const a = document.getElementById(id);
  if (!a) continue;
  a.href = url;
  a.addEventListener('click', (e) => {
    e.preventDefault();
    chrome.tabs.create({ url });
  });
}

(async () => {
  await loadLanguage();
  loadTheme();
  loadOptions();
  loadWatches();
  loadPickMode();
  loadHistory();
  loadPip();
  loadDownloads();
  init();
})();