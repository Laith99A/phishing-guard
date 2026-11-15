// Phishing Guard – Service Worker (Manifest V3)
//
// Einzige Stelle, die mit dem Backend spricht. Content-Script und Popup
// schicken Nachrichten hierher; Ergebnisse werden pro URL gecacht, damit
// dieselben Links auf vielen Seiten nicht immer neu bewertet werden.

const DEFAULTS = {
  apiUrl: "http://127.0.0.1:8000",
  highlightLinks: true,
};

const CACHE_TTL_MS = 30 * 60 * 1000; // 30 Minuten
const cache = new Map(); // url -> { result, ts }

// Zähler verdächtiger Links pro Tab (für das Badge und das Popup).
const tabStats = new Map(); // tabId -> { suspicious, dangerous, pageVerdict }

async function getSettings() {
  const stored = await chrome.storage.sync.get(DEFAULTS);
  return { ...DEFAULTS, ...stored };
}

async function apiPost(path, body) {
  const { apiUrl } = await getSettings();
  const res = await fetch(`${apiUrl}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

async function analyzeUrls(urls) {
  const now = Date.now();
  const fresh = [];
  const results = new Map();

  for (const u of urls) {
    const hit = cache.get(u);
    if (hit && now - hit.ts < CACHE_TTL_MS) results.set(u, hit.result);
    else fresh.push(u);
  }

  // Backend nimmt max. 300 URLs pro Anfrage – in Blöcken schicken.
  for (let i = 0; i < fresh.length; i += 200) {
    const chunk = fresh.slice(i, i + 200);
    const data = await apiPost("/analyze/urls", { urls: chunk });
    for (const r of data.results) {
      cache.set(r.url, { result: r, ts: now });
      results.set(r.url, r);
    }
  }
  return urls.map((u) => results.get(u)).filter(Boolean);
}

function updateBadge(tabId, stats) {
  const n = stats.suspicious + stats.dangerous;
  const text = n > 0 ? String(n) : "";
  const color = stats.dangerous > 0 || stats.pageVerdict === "dangerous" ? "#d32f2f" : "#f9a825";
  chrome.action.setBadgeText({ tabId, text: stats.pageVerdict === "dangerous" ? "!" : text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      switch (msg.type) {
        case "ANALYZE_URLS": {
          const results = await analyzeUrls(msg.urls);
          sendResponse({ ok: true, results });
          break;
        }
        case "ANALYZE_TEXT": {
          const data = await apiPost("/analyze/text", { text: msg.text });
          sendResponse({ ok: true, data });
          break;
        }
        case "REPORT_STATS": {
          const tabId = sender.tab?.id;
          if (tabId != null) {
            tabStats.set(tabId, msg.stats);
            updateBadge(tabId, msg.stats);
          }
          sendResponse({ ok: true });
          break;
        }
        case "GET_STATS": {
          sendResponse({ ok: true, stats: tabStats.get(msg.tabId) ?? null });
          break;
        }
        case "GET_SETTINGS": {
          sendResponse({ ok: true, settings: await getSettings() });
          break;
        }
        case "HEALTH": {
          const { apiUrl } = await getSettings();
          const res = await fetch(`${apiUrl}/health`);
          sendResponse({ ok: res.ok, data: res.ok ? await res.json() : null });
          break;
        }
        default:
          sendResponse({ ok: false, error: "unknown message" });
      }
    } catch (e) {
      sendResponse({ ok: false, error: String(e?.message || e) });
    }
  })();
  return true; // asynchrone Antwort
});

chrome.tabs.onRemoved.addListener((tabId) => tabStats.delete(tabId));
chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === "loading") {
    tabStats.delete(tabId);
    chrome.action.setBadgeText({ tabId, text: "" });
  }
});
