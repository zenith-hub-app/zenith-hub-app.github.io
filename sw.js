// Guarda só a casca do app (código e ícones) para abrir rápido e sem rede. Nunca guarda dados do mural nem
// respostas da API do GitHub (essas ficam no IndexedDB do app, por sha).
const VERSAO = "hub-1.0.0";
const CASCA = ["./", "index.html", "estilo.css", "app.js", "md.js", "manifest.webmanifest",
  "icone-192.png", "icone-512.png", "icone-maskable.png"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(VERSAO).then((c) => c.addAll(CASCA)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== VERSAO).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});
self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.origin !== self.location.origin) return;
  // rede primeiro (pega versão nova), casca guardada se estiver sem internet
  e.respondWith(fetch(e.request).then((r) => {
    if (r.ok) { const copia = r.clone(); caches.open(VERSAO).then((c) => c.put(e.request, copia)); }
    return r;
  }).catch(() => caches.match(e.request, { ignoreSearch: true })));
});
