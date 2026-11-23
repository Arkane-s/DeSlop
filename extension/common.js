const HOST = 'com.defender.scan';
const MAX_WATCH = 4;
const OPTION_DEFAULTS = { autoScan: true, notify: true, preScan: false };
const THREAT_PAGE = 'https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=';

const base = (path) => path.split(/[\\/]/).pop();
const quiet = (promise) => promise.catch(() => {});
const isSet = (value) => value !== null && value !== undefined;

function urlLabel(url) {
  try {
    const u = new URL(url);
    return decodeURIComponent(u.pathname.split('/').filter(Boolean).pop() || '') || u.hostname;
  } catch (e) {
    return url;
  }
}

function send(msg) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendNativeMessage(HOST, msg, (reply) => {
      const error = chrome.runtime.lastError;
      error ? reject(new Error(error.message)) : resolve(reply);
    });
  });
}

function openPort() {
  const port = chrome.runtime.connectNative(HOST);
  let waiting = null;
  let failure = null;

  const settle = (method, value) => {
    if (!waiting) return;
    const pending = waiting;
    waiting = null;
    pending[method](value);
  };

  port.onMessage.addListener((msg) => {
    if (msg && msg.progress) return;
    settle('res', msg);
  });

  port.onDisconnect.addListener(() => {
    failure = new Error(chrome.runtime.lastError?.message || 'Helper disconnected');
    settle('rej', failure);
  });

  return {
    ask: (msg) => new Promise((res, rej) => {
      if (failure) return rej(failure);
      waiting = { res, rej };
      port.postMessage(msg);
    }),
    close: () => {
      failure = failure || new Error('Closed');
      settle('rej', failure);
      try {
        port.disconnect();
      } catch (e) {}
    }
  };
}

async function getWatches() {
  const { watches, watch } = await chrome.storage.local.get(['watches', 'watch']);
  if (Array.isArray(watches)) return watches.slice(0, MAX_WATCH);
  if (!watch || !watch.path) return [];

  const migrated = [{
    id: 'w0',
    path: watch.path,
    recurse: !!watch.recurse,
    notify: watch.notify !== false,
    added: watch.since || Date.now()
  }];
  await chrome.storage.local.set({ watches: migrated });
  await chrome.storage.local.remove('watch');
  return migrated;
}

function fmtSize(bytes) {
  if (!isSet(bytes)) return '';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = Number(bytes);
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  const text = unit === 0 ? String(value) : value.toFixed(value >= 100 ? 0 : 1);
  return text + ' ' + units[unit];
}

function fmtTime(ms) {
  if (ms < 1000) return ms + ' ms';
  if (ms < 60000) return (ms / 1000).toFixed(1) + ' s';
  return Math.floor(ms / 60000) + ' min ' + Math.floor((ms % 60000) / 1000) + ' s';
}

function infoLine(size, ms, files) {
  const parts = [];
  if (isSet(files)) parts.push(t('size.files', { n: files }));
  if (isSet(size)) parts.push(t('size.sizeLabel', { size: fmtSize(size) }));
  if (isSet(ms)) parts.push(t('size.took', { time: fmtTime(ms) }));
  return parts.join(' · ');
}

function parseThreat(raw) {
  const full = String(raw).trim();
  const match = full.match(/^(?:([A-Za-z]+):)?(?:([A-Za-z0-9_.]+)\/)?([^!]+?)(?:!(.+))?$/);
  if (!match) {
    return { raw: full, type: null, platform: null, name: full, eicar: false, url: null };
  }
  const [, type, platform, name] = match;
  return {
    raw: full,
    type: type ? tType(type) : null,
    platform: platform ? tPlatform(platform) : null,
    name,
    eicar: /eicar/i.test(full),
    url: /\s/.test(full) ? null : THREAT_PAGE + encodeURIComponent(full)
  };
}

function describeThreats(names) {
  const threats = [].concat(names || []).filter(Boolean).map(parseThreat);
  if (!threats.length) return { text: t('common.threatFound'), raw: '', url: null };

  const first = threats[0];
  let text = first.eicar
    ? t('notif.eicarText')
    : [first.type, first.name, first.platform].filter(Boolean).join(' · ');
  if (threats.length > 1) text += t('common.moreThreats', { n: threats.length - 1 });

  return { text, raw: threats.map((th) => th.raw).join(', '), url: first.url };
}

function interpret(reply) {
  if (!reply || !reply.ok) {
    return { s: 'error', text: (reply && reply.error) || t('common.scanFailed'), url: null, raw: '' };
  }
  if (reply.threat) {
    const { text, url, raw } = describeThreats(reply.threats);
    return { s: 'threat', text, url, raw };
  }
  return {
    s: 'clean',
    text: reply.kept ? t('common.cleanSaved') : t('common.noThreats'),
    url: null,
    raw: ''
  };
}