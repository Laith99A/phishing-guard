// Phishing Guard – Popup

const $ = (id) => document.getElementById(id);
const LABEL = { safe: "Unauffällig", suspicious: "Verdächtig", dangerous: "Gefährlich" };

function send(msg) {
  return new Promise((resolve) => chrome.runtime.sendMessage(msg, (r) => resolve(r ?? { ok: false })));
}

function setPill(el, verdict) {
  el.textContent = LABEL[verdict] ?? verdict;
  el.className = `pill ${verdict}`;
}

function li(text) {
  const el = document.createElement("li");
  el.textContent = text;
  return el;
}

function renderLink(r) {
  const el = document.createElement("li");
  el.className = "link-item";
  const pill = document.createElement("span");
  setPill(pill, r.verdict);
  const url = document.createElement("span");
  url.className = "url";
  url.textContent = ` ${r.url}`;
  el.append(pill, url);
  if (r.reasons.length && r.verdict !== "safe") {
    const ul = document.createElement("ul");
    ul.className = "reasons";
    r.reasons.slice(0, 4).forEach((x) => ul.appendChild(li(x)));
    el.appendChild(ul);
  }
  return el;
}

function renderResult(data) {
  $("result").classList.remove("hidden");
  $("error").classList.add("hidden");
  setPill($("verdict"), data.verdict);

  const pct = Math.round(data.score * 100);
  const fill = $("meter-fill");
  fill.style.width = `${pct}%`;
  fill.className = data.verdict;
  $("score").textContent = `Phishing-Wahrscheinlichkeit: ${pct} %`;

  const tr = $("text-reasons");
  tr.replaceChildren();
  if (data.text_reasons?.length) {
    data.text_reasons.forEach((r) => tr.appendChild(li(r)));
    $("text-reasons-wrap").classList.remove("hidden");
  } else {
    $("text-reasons-wrap").classList.add("hidden");
  }

  const links = $("links");
  links.replaceChildren();
  if (data.links?.length) {
    data.links.forEach((r) => links.appendChild(renderLink(r)));
    $("links-wrap").classList.remove("hidden");
  } else {
    $("links-wrap").classList.add("hidden");
  }
}

async function analyze() {
  const text = $("text").value.trim();
  if (!text) return;
  $("analyze").disabled = true;
  $("analyze").textContent = "Prüfe …";
  try {
    const res = await send({ type: "ANALYZE_TEXT", text });
    if (!res.ok) throw new Error(res.error || "Backend nicht erreichbar");
    renderResult(res.data);
  } catch (e) {
    $("result").classList.add("hidden");
    $("error").textContent = `Fehler: ${e.message}. Läuft das Backend? (uvicorn app.main:app --port 8000)`;
    $("error").classList.remove("hidden");
  } finally {
    $("analyze").disabled = false;
    $("analyze").textContent = "Prüfen";
  }
}

async function loadPageStats() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;
  const res = await send({ type: "GET_STATS", tabId: tab.id });
  if (!res.ok || !res.stats) return;
  const s = res.stats;
  $("page-stats").classList.remove("hidden");
  setPill($("page-verdict"), s.pageVerdict ?? "safe");
  const n = s.suspicious + s.dangerous;
  $("link-summary").textContent =
    n === 0
      ? "Keine verdächtigen Links auf dieser Seite gefunden."
      : `${n} markierte${n === 1 ? "r" : ""} Link${n === 1 ? "" : "s"}: ${s.dangerous} gefährlich, ${s.suspicious} verdächtig.`;
}

async function checkHealth() {
  const res = await send({ type: "HEALTH" });
  const el = $("status");
  el.classList.toggle("ok", !!res.ok);
  el.classList.toggle("down", !res.ok);
  el.title = res.ok
    ? `Backend erreichbar · URL-Modell: ${res.data?.url_model?.kind ?? "?"}`
    : "Backend nicht erreichbar – bitte starten";
}

$("analyze").addEventListener("click", analyze);
$("clear").addEventListener("click", () => {
  $("text").value = "";
  $("result").classList.add("hidden");
  $("error").classList.add("hidden");
});
$("text").addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") analyze();
});
$("open-options").addEventListener("click", (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

checkHealth();
loadPageStats();
