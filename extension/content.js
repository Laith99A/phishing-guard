// Phishing Guard – Content-Script
//
// Läuft auf jeder Seite: sammelt externe Links, lässt sie im Hintergrund
// bewerten und markiert verdächtige. Außerdem wird die Seiten-URL selbst
// geprüft – ist sie gefährlich, erscheint ein Banner oben.
//
// Es wird NICHTS in die Seite eingegeben oder abgeschickt; nur Links gelesen.

(() => {
  if (window.top !== window) return; // keine iframes
  if (document.documentElement.dataset.pgInjected) return;
  document.documentElement.dataset.pgInjected = "1";

  const MAX_LINKS_PER_SCAN = 150;
  const SCAN_DEBOUNCE_MS = 800;
  const SKIP_HOSTS_RE = /(^|\.)(localhost|127\.0\.0\.1)$/;

  const pageHost = location.hostname;
  const pageDomain = registrableDomain(pageHost);
  const resultsByUrl = new Map(); // bereits bewertete URLs → Ergebnis
  let enabled = true;
  let stats = { suspicious: 0, dangerous: 0, pageVerdict: null };

  // --- Hilfsfunktionen ---------------------------------------------------

  function registrableDomain(host) {
    const parts = host.toLowerCase().split(".");
    if (parts.length <= 2) return parts.join(".");
    const second = new Set(["co", "com", "org", "net", "gov", "ac", "edu"]);
    if (second.has(parts[parts.length - 2]) && parts[parts.length - 1].length === 2) {
      return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
  }

  function send(msg) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(msg, (res) => {
          if (chrome.runtime.lastError) resolve({ ok: false, error: chrome.runtime.lastError.message });
          else resolve(res ?? { ok: false });
        });
      } catch (e) {
        resolve({ ok: false, error: String(e) });
      }
    });
  }

  function collectLinks() {
    const anchors = document.querySelectorAll("a[href]");
    const byUrl = new Map(); // url -> [anchor, ...]
    for (const a of anchors) {
      if (a.dataset.pgChecked) continue;
      let url;
      try {
        url = new URL(a.href, location.href);
      } catch {
        continue;
      }
      if (url.protocol !== "http:" && url.protocol !== "https:") continue;
      if (SKIP_HOSTS_RE.test(url.hostname)) continue;
      // Links innerhalb derselben Domain überspringen (Navigation der Seite).
      if (registrableDomain(url.hostname) === pageDomain) {
        a.dataset.pgChecked = "same";
        continue;
      }
      const key = url.href.split("#")[0];
      if (!byUrl.has(key)) byUrl.set(key, []);
      byUrl.get(key).push(a);
      if (byUrl.size >= MAX_LINKS_PER_SCAN) break;
    }
    return byUrl;
  }

  function markAnchor(a, result) {
    a.dataset.pgChecked = result.verdict;
    if (result.verdict === "safe") return;

    a.classList.add("pg-link", `pg-${result.verdict}`);
    const pct = Math.round(result.score * 100);
    const label = result.verdict === "dangerous" ? "Gefährlich" : "Verdächtig";
    const reasons = result.reasons.length ? "\n• " + result.reasons.join("\n• ") : "";
    a.title = `Phishing Guard: ${label} (${pct} %)${reasons}`;

    const badge = document.createElement("span");
    badge.className = `pg-badge pg-badge-${result.verdict}`;
    badge.textContent = result.verdict === "dangerous" ? "⚠" : "?";
    badge.setAttribute("aria-label", `${label}: ${result.reasons[0] ?? ""}`);
    a.appendChild(badge);
  }

  function showPageBanner(result) {
    if (document.getElementById("pg-banner")) return;
    const banner = document.createElement("div");
    banner.id = "pg-banner";
    banner.setAttribute("role", "alert");
    const pct = Math.round(result.score * 100);
    const reasons = result.reasons.slice(0, 3).map((r) => `<li>${escapeHtml(r)}</li>`).join("");
    banner.innerHTML = `
      <div class="pg-banner-inner">
        <strong>⚠ Phishing Guard:</strong> Diese Seite sieht nach Phishing aus (${pct} %).
        Gib hier keine Zugangsdaten ein.
        <ul>${reasons}</ul>
        <button type="button" id="pg-banner-close" aria-label="Hinweis schließen">×</button>
      </div>`;
    document.documentElement.appendChild(banner);
    document.getElementById("pg-banner-close").addEventListener("click", () => banner.remove());
  }

  function escapeHtml(s) {
    return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  // --- Scan --------------------------------------------------------------

  let scanTimer = null;
  let scanning = false;

  async function scan() {
    if (!enabled || scanning) return;
    scanning = true;
    try {
      const byUrl = collectLinks();
      if (byUrl.size === 0) return;

      const apply = (r) => {
        const anchors = byUrl.get(r.url) ?? [];
        anchors.forEach((a) => markAnchor(a, r));
        if (r.verdict === "suspicious") stats.suspicious += anchors.length;
        if (r.verdict === "dangerous") stats.dangerous += anchors.length;
      };

      // Schon bekannte URLs (z. B. neu nachgeladene Anker) sofort markieren.
      const urls = [];
      for (const u of byUrl.keys()) {
        if (resultsByUrl.has(u)) apply(resultsByUrl.get(u));
        else urls.push(u);
      }

      if (urls.length) {
        const res = await send({ type: "ANALYZE_URLS", urls });
        if (!res.ok) return; // Backend nicht erreichbar → still bleiben
        for (const r of res.results) {
          resultsByUrl.set(r.url, r);
          apply(r);
        }
      }
      send({ type: "REPORT_STATS", stats });
    } finally {
      scanning = false;
    }
  }

  function scheduleScan() {
    clearTimeout(scanTimer);
    scanTimer = setTimeout(scan, SCAN_DEBOUNCE_MS);
  }

  async function checkPageUrl() {
    if (SKIP_HOSTS_RE.test(pageHost)) return;
    const res = await send({ type: "ANALYZE_URLS", urls: [location.href.split("#")[0]] });
    if (!res.ok || !res.results?.length) return;
    const r = res.results[0];
    stats.pageVerdict = r.verdict;
    if (r.verdict === "dangerous") showPageBanner(r);
    send({ type: "REPORT_STATS", stats });
  }

  // --- Start -------------------------------------------------------------

  (async () => {
    const res = await send({ type: "GET_SETTINGS" });
    enabled = res.ok ? res.settings.highlightLinks !== false : true;

    await checkPageUrl();
    if (!enabled) return;
    await scan();

    // Dynamische Seiten (Gmail, Outlook Web, SPAs): neue Links nachscannen.
    const observer = new MutationObserver((mutations) => {
      for (const m of mutations) {
        if (m.addedNodes.length) {
          scheduleScan();
          return;
        }
      }
    });
    observer.observe(document.body ?? document.documentElement, { childList: true, subtree: true });
  })();
})();
