importScripts('i18n.js', 'common.js');

const WATCH_ALARM = 'watch-folder';
const COLORS = { busy: '#3b8cff', threat: '#ff5d5d', warn: '#f0b24a', ok: '#35c98a' };

let queue = Promise.resolve();
let lock = Promise.resolve();
let pending = 0;
let polling = false;
let draining = false;
const skipUrls = new Set();

const langReady = i18nInit();
i18nOnChange();

const getOptions = () => chrome.storage.local.get(OPTION_DEFAULTS);

function withLock(fn) {
  const run = lock.then(fn);
  lock = run.catch(() => {});
  return run;
}

async function nativeCall(msg) {
  const port = openPort();
  try {
    return await port.ask(msg);
  } finally {
    port.close();
  }
}

function setBadge(text, color) {
  chrome.action.setBadgeText({ text });
  if (color) chrome.action.setBadgeBackgroundColor({ color });
}

function startBusy() {
  pending++;
  setBadge('…', COLORS.busy);
}

function endBusy() {
  pending = Math.max(0, pending - 1);
}

async function refreshBadge(lastState) {
  if (pending > 0) return;
  const { unseenThreat } = await chrome.storage.local.get({ unseenThreat: false });
  if (unseenThreat) setBadge('!', COLORS.threat);
  else if (lastState === 'error') setBadge('?', COLORS.warn);
  else setBadge('✓', COLORS.ok);
}

function makeEntry(label, title, s, text, { url, raw, info, path } = {}) {
  return {
    ts: Date.now(),
    label,
    title,
    s,
    text,
    url: url || null,
    raw: raw || '',
    info: info || '',
    path: path || ''
  };
}

function addHistory(entry) {
  return withLock(async () => {
    const { history = [] } = await chrome.storage.local.get('history');
    history.unshift(entry);
    await chrome.storage.local.set({ history: history.slice(0, 10) });
  });
}

async function rememberNotification(id, path) {
  const { notifPaths = {} } = await chrome.storage.session.get('notifPaths');
  notifPaths[id] = path || '';
  const ids = Object.keys(notifPaths);
  ids.slice(0, Math.max(0, ids.length - 30)).forEach((old) => delete notifPaths[old]);
  await chrome.storage.session.set({ notifPaths });
}

async function shouldNotify(entry, mode) {
  if (mode === 'threat-only') return entry.s === 'threat';
  if (mode === 'always') return true;
  return (await getOptions()).notify;
}

function notifTitleFor(s) {
  if (s === 'threat') return t('common.threatFound');
  if (s === 'clean') return t('notif.cleanTitle');
  if (s === 'error') return t('notif.errorTitle');
  return t('notif.defaultTitle');
}

async function notify(entry, mode) {
  if (!(await shouldNotify(entry, mode))) return;
  await langReady;

  const id = 'n-' + entry.ts + '-' + Math.random().toString(36).slice(2, 6);
  try {
    await rememberNotification(id, entry.path);
    await chrome.notifications.create(id, {
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: notifTitleFor(entry.s),
      message: entry.label + '\n' + entry.text,
      priority: entry.s === 'threat' ? 2 : 0
    });
  } catch (e) {
    console.error('Notification failed', e);
  }
}

async function record(entry, mode) {
  if (entry.s === 'threat') await chrome.storage.local.set({ unseenThreat: true });
  await addHistory(entry);
  await refreshBadge(entry.s);
  await notify(entry, mode);
}

async function scanOnce(msg) {
  await langReady;
  const startedAt = Date.now();
  try {
    const reply = await nativeCall(msg);
    return {
      reply,
      res: interpret(reply),
      info: infoLine(reply ? reply.size : null, Date.now() - startedAt)
    };
  } catch (e) {
    console.error('Scan failed', e);
    return {
      reply: null,
      res: { s: 'error', text: t('common.helperNotReachable'), url: null, raw: '' },
      info: ''
    };
  }
}

async function runScan(label, title, msg, expectFile, mode) {
  let { reply, res, info } = await scanOnce(msg);

  if (expectFile && reply && !reply.ok && reply.error === 'File not found') {
    res = {
      s: 'error',
      text: t('notif.fileGone'),
      url: null,
      raw: ''
    };
    info = '';
  }

  endBusy();
  try {
    const path = msg.action === 'scan' ? msg.path : '';
    await record(makeEntry(label, title, res.s, res.text, { url: res.url, raw: res.raw, info, path }), mode);
  } catch (e) {
    console.error('Record failed', e);
  }
}

function enqueueScan(label, title, msg, expectFile, mode) {
  startBusy();
  const run = queue.then(() => runScan(label, title, msg, expectFile, mode));
  queue = run.catch(() => {});
  return run;
}

function claimPath(path) {
  return withLock(async () => {
    const key = path.toLowerCase();
    const now = Date.now();
    const { recentScans = {} } = await chrome.storage.session.get('recentScans');

    for (const [known, time] of Object.entries(recentScans)) {
      if (now - time > 180000) delete recentScans[known];
    }
    if (recentScans[key] && now - recentScans[key] < 120000) return false;

    recentScans[key] = now;
    await chrome.storage.session.set({ recentScans });
    return true;
  });
}

async function readScanQueue() {
  const { scanQueue = [] } = await chrome.storage.local.get('scanQueue');
  return scanQueue;
}

function addToScanQueue(items) {
  return withLock(async () => {
    const waiting = await readScanQueue();
    for (const item of items) {
      const known = waiting.some((x) => x.path.toLowerCase() === item.path.toLowerCase());
      if (!known) waiting.push(item);
    }
    await chrome.storage.local.set({ scanQueue: waiting.slice(-500) });
  });
}

function removeFromScanQueue(path) {
  return withLock(async () => {
    const waiting = (await readScanQueue()).filter((x) => x.path !== path);
    await chrome.storage.local.set({ scanQueue: waiting });
  });
}

async function drainScanQueue() {
  if (draining) return;
  draining = true;
  try {
    for (;;) {
      const [item] = await readScanQueue();
      if (!item) break;
      await enqueueScan(base(item.path), item.path, { action: 'scan', path: item.path }, true, item.mode);
      await removeFromScanQueue(item.path);
    }
  } finally {
    draining = false;
  }
}

async function resumeOrRestart(id, url) {
  try {
    await chrome.downloads.resume(id);
    return;
  } catch (e) {}

  skipUrls.add(url);
  try {
    await chrome.downloads.download({ url });
  } catch (e) {
    skipUrls.delete(url);
  }
}

async function preScan(item, url) {
  await langReady;
  const label = urlLabel(url);
  const { res, info } = await scanOnce({ action: 'scanurl', url, keep: false });
  endBusy();

  if (res.s === 'threat') {
    await quiet(chrome.downloads.cancel(item.id));
    await record(makeEntry(label, url, 'threat', t('notif.blockedBeforeDownload', { text: res.text }), {
      url: res.url,
      raw: res.raw,
      info
    }));
    return;
  }

  await resumeOrRestart(item.id, url);
  if (res.s === 'clean') {
    await record(makeEntry(label, url, 'clean', t('notif.cleanResumed'), { info }));
  } else {
    await record(makeEntry(label, url, 'error', t('notif.couldNotCheckFirst', { text: res.text })));
  }
}

async function recordInterruptedDownload(delta, item, label, path) {
  await langReady;
  const reason = (delta.error && delta.error.current) || item.error || '';
  const title = path || item.url || '';

  if (reason === 'FILE_VIRUS_INFECTED') {
    await record(makeEntry(label, title, 'threat', t('notif.blockedWhileDownloading'), { raw: reason, path }));
  } else if (reason === 'FILE_SECURITY_CHECK_FAILED' || reason === 'FILE_BLOCKED') {
    await record(makeEntry(label, title, 'error', t('notif.downloadBlocked', { reason }), { raw: reason, path }));
  }
}

async function readWatchState() {
  return (await chrome.storage.local.get('watchState')).watchState || {};
}

async function setWatchState(id, value) {
  const state = await readWatchState();
  state[id] = value;
  await chrome.storage.local.set({ watchState: state });
}

async function pruneWatchState(watches) {
  const state = await readWatchState();
  const known = new Set(watches.map((w) => w.id));
  const stale = Object.keys(state).filter((id) => !known.has(id));
  if (!stale.length) return;

  stale.forEach((id) => delete state[id]);
  await chrome.storage.local.set({ watchState: state });
}

async function reportWatchProblem(watch, previous, problem) {
  if (previous.err === problem) return;
  await setWatchState(watch.id, { ...previous, err: problem });
  await langReady;
  await record(makeEntry(base(watch.path) || watch.path, watch.path, 'error', t('notif.watchedFolderProblem', { problem })));
}

async function pollWatch(watch) {
  const previous = (await readWatchState())[watch.id] || { since: watch.added || Date.now() };

  let reply;
  try {
    reply = await nativeCall({
      action: 'newfiles',
      path: watch.path,
      since: previous.since,
      recurse: !!watch.recurse
    });
  } catch (e) {
    console.error('Watch failed', e);
    return;
  }

  const stillWatched = (await getWatches()).some((w) => w.id === watch.id && w.path === watch.path);
  if (!stillWatched) return;

  if (!reply || !reply.ok) {
    await reportWatchProblem(watch, previous, (reply && reply.error) || 'no answer');
    return;
  }

  const mode = watch.notify === false ? 'threat-only' : 'always';
  const items = [];
  for (const path of reply.files || []) {
    if (await claimPath(path)) items.push({ path, mode });
  }
  if (items.length) await addToScanQueue(items);

  await setWatchState(watch.id, { since: reply.until, err: null });
}

async function pollWatches() {
  if (polling) return;
  polling = true;
  try {
    const watches = await getWatches();
    await pruneWatchState(watches);
    for (const watch of watches) await pollWatch(watch);
  } finally {
    polling = false;
  }
  drainScanQueue();
}

async function syncAlarm() {
  const watches = await getWatches();
  if (!watches.length) {
    await chrome.alarms.clear(WATCH_ALARM);
    return;
  }
  if (!(await chrome.alarms.get(WATCH_ALARM))) {
    await chrome.alarms.create(WATCH_ALARM, { periodInMinutes: 0.5 });
  }
}

function setupMenu() {
  langReady.then(() => {
    chrome.contextMenus.removeAll(() => {
      chrome.contextMenus.create(
        { id: 'scan-link', title: t('notif.scanLinkMenu'), contexts: ['link'] },
        () => { void chrome.runtime.lastError; }
      );
    });
  });
}

chrome.downloads.onCreated.addListener(async (item) => {
  const url = item.finalUrl || item.url || '';
  if (!/^https?:\/\//i.test(url) || skipUrls.delete(url)) return;
  if (!(await getOptions()).preScan) return;

  try {
    await chrome.downloads.pause(item.id);
  } catch (e) {
    return;
  }

  startBusy();
  queue = queue.then(() => preScan(item, url)).catch((e) => {
    console.error(e);
    endBusy();
  });
});

chrome.downloads.onChanged.addListener(async (delta) => {
  const state = delta.state && delta.state.current;
  if (state !== 'complete' && state !== 'interrupted') return;
  if (!(await getOptions()).autoScan) return;

  const [item] = await chrome.downloads.search({ id: delta.id });
  if (!item) return;

  const path = item.filename || '';
  const label = path ? base(path) : urlLabel(item.url || '');

  if (state === 'interrupted') {
    await recordInterruptedDownload(delta, item, label, path);
    return;
  }

  if (!path || !(await claimPath(path))) return;
  enqueueScan(label, path, { action: 'scan', path }, true);
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === WATCH_ALARM) pollWatches();
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && (changes.watches || changes.watch)) syncAlarm();
  if (area === 'local' && changes.language) setupMenu();
});

chrome.runtime.onStartup.addListener(() => {
  syncAlarm();
  drainScanQueue();
});

chrome.runtime.onMessage.addListener((msg) => {
  if (!msg || msg.type !== 'seen') return;
  chrome.storage.local.set({ unseenThreat: false });
  if (pending === 0) setBadge('');
});

chrome.notifications.onClicked.addListener(async (id) => {
  const { notifPaths = {} } = await chrome.storage.session.get('notifPaths');
  const path = notifPaths[id];
  chrome.notifications.clear(id);

  if (!path) {
    await quiet(chrome.action.openPopup());
    return;
  }

  try {
    await nativeCall({ action: 'reveal', path });
  } catch (e) {
    console.error('Reveal failed', e);
  }
});

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId !== 'scan-link' || !info.linkUrl) return;

  const url = info.linkUrl;
  if (!/^https?:\/\//i.test(url)) {
    langReady.then(() => record(makeEntry(url, url, 'error', t('notif.onlyHttpLinks'))));
    return;
  }
  enqueueScan(urlLabel(url), url, { action: 'scanurl', url, keep: false }, false);
});

setupMenu();
syncAlarm();
drainScanQueue();