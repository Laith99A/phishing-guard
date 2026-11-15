const DEFAULTS = { apiUrl: "http://127.0.0.1:8000", highlightLinks: true };

async function load() {
  const s = await chrome.storage.sync.get(DEFAULTS);
  document.getElementById("apiUrl").value = s.apiUrl;
  document.getElementById("highlightLinks").checked = s.highlightLinks !== false;
}

async function save() {
  const apiUrl = document.getElementById("apiUrl").value.trim().replace(/\/+$/, "") || DEFAULTS.apiUrl;
  const highlightLinks = document.getElementById("highlightLinks").checked;
  await chrome.storage.sync.set({ apiUrl, highlightLinks });
  const el = document.getElementById("saved");
  el.classList.remove("hidden");
  setTimeout(() => el.classList.add("hidden"), 1500);
}

document.getElementById("save").addEventListener("click", save);
load();
