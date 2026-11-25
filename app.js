// Zenith Hub no celular (PWA). Lê e escreve o mural direto no repositório privado do hub, pela API do GitHub.
// Nada de servidor nosso: o token fica só neste aparelho (cifrado, se houver PIN). Todo HTML de mensagem é
// escapado pelo md.js antes de chegar à tela. O mural é informação, não ordem: para um agente agir, a ordem vai
// na conversa dele.

"use strict";

const VERSAO = "1.1.0";
const API = "https://api.github.com";
const NOME_MSG = /^(\d{4})-(\d{2})-(\d{2})T(\d{2})(\d{2})(\d{2})_([a-z0-9]+)(?:-(\d+))?\.md$/;
const NOME_SEM_MD = /^\d{4}-\d{2}-\d{2}T\d{6}_[a-z0-9]+(?:-\d+)?$/;
const TIPOS = { aviso: "aviso", pedido: "pedido", decisao: "decisão", relatorio: "relatório", resposta: "resposta" };
const ORDEM_SALAS = ["geral", "app", "qa", "seguranca", "criativos", "marketing", "site", "apices"];
// ordem de importância (pedido do Rogério, 22/11): ARC no topo, no preto
const ORDEM_AGENTES = ["arc", "app", "qa", "seguranca", "roteiro", "marketing", "site", "relatorios", "apices",
  "biblioteca", "lab"];
const PAPEIS = {
  arc: "acompanha o time (antes: orquestrador)", app: "código do app", qa: "testes do app",
  seguranca: "segurança", roteiro: "roteiro dos criativos", marketing: "marketing", site: "site",
  relatorios: "relatórios das redes", apices: "Ápices", biblioteca: "biblioteca de avatares",
  lab: "Transition Lab", rogerio: "você",
};
const NOMES = { arc: "ARC", orquestrador: "ARC", rogerio: "Rogério", apices: "ápices", relatorios: "relatórios",
  seguranca: "segurança" };
const COR_DA_SALA = { geral: "arc", app: "app", qa: "qa", seguranca: "seguranca", criativos: "roteiro",
  marketing: "marketing", site: "site", apices: "apices", tudo: "rogerio" };
const MESES = ["janeiro", "fevereiro", "março", "abril", "maio", "junho", "julho", "agosto", "setembro", "outubro",
  "novembro", "dezembro"];
const DIAS = ["domingo", "segunda", "terça", "quarta", "quinta", "sexta", "sábado"];
const POR_PAGINA = 40;
const INTERVALO = 20000;     // releitura do repositório com o app aberto (304 não gasta cota)
const MAX_FOTOS = 6;
const LADO_FOTO = 1600;

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
const ler = (k, padrao) => { try { const v = localStorage.getItem(k); return v === null ? padrao : JSON.parse(v); } catch { return padrao; } };
const gravar = (k, v) => { try { if (v === null) localStorage.removeItem(k); else localStorage.setItem(k, JSON.stringify(v)); } catch { /* cheio */ } };
const autorReal = (id) => (id === "orquestrador" ? "arc" : id);
const nome = (id) => NOMES[id] || id;

// ================================================================== base64 e cifra do token

const b64DeBytes = (bytes) => {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
};
const bytesDeB64 = (b) => Uint8Array.from(atob(b), (c) => c.charCodeAt(0));

async function chaveDoPin(pin, sal) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pin), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt: sal, iterations: 310000, hash: "SHA-256" }, base,
    { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function cifrar(texto, pin) {
  const sal = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await chaveDoPin(pin, sal), new TextEncoder().encode(texto));
  return { s: b64DeBytes(sal), iv: b64DeBytes(iv), ct: b64DeBytes(new Uint8Array(ct)) };
}
async function decifrar(c, pin) {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytesDeB64(c.iv) },
    await chaveDoPin(pin, bytesDeB64(c.s)), bytesDeB64(c.ct));
  return new TextDecoder().decode(pt);
}

// "Lembrar neste celular": depois do 1º PIN certo, o token é cifrado de novo com uma chave AES que o navegador
// guarda no IndexedDB como NÃO exportável (nenhum script consegue ler os bytes dela, só usá-la nesta origem).
// Assim o app abre direto. A proteção passa a ser o bloqueio do próprio celular; "Trancar" no menu volta ao PIN.
async function lembrar(tk) {
  try {
    const chave = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, chave, new TextEncoder().encode(tk));
    await cache.set("k:lembrar", chave);
    if (!(await cache.get("k:lembrar"))) return;   // sem IndexedDB: segue pedindo o PIN
    cfg.lembrado = { iv: b64DeBytes(iv), ct: b64DeBytes(new Uint8Array(ct)) };
    gravar("cfg", cfg);
    navigator.storage?.persist?.().catch(() => {});
  } catch { /* segue pedindo o PIN */ }
}
async function lembrado() {
  try {
    const chave = await cache.get("k:lembrar");
    if (!chave || !cfg.lembrado) return null;
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytesDeB64(cfg.lembrado.iv) }, chave,
      bytesDeB64(cfg.lembrado.ct));
    return new TextDecoder().decode(pt);
  } catch { return null; }
}
async function trancar() {
  delete cfg.lembrado;
  gravar("cfg", cfg);
  await cache.set("k:lembrar", null);
  location.reload();
}

// ================================================================== cache (IndexedDB): conteúdo por sha do Git

const cache = (() => {
  let db = null;
  const abrir = () => db || (db = new Promise((ok, falha) => {
    const r = indexedDB.open("zenith-hub", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("blobs");
    r.onsuccess = () => ok(r.result);
    r.onerror = () => falha(r.error);
  }));
  const op = async (modo, fn) => {
    try {
      const banco = await abrir();
      return await new Promise((ok, falha) => {
        const t = banco.transaction("blobs", modo);
        const r = fn(t.objectStore("blobs"));
        t.oncomplete = () => ok(r && r.result);
        t.onerror = () => falha(t.error);
      });
    } catch { return undefined; }  // sem cache, só fica mais lento
  };
  return {
    get: (k) => op("readonly", (s) => s.get(k)),
    set: (k, v) => op("readwrite", (s) => s.put(v, k)),
    limpar: () => op("readwrite", (s) => s.clear()),
  };
})();

// ================================================================== GitHub

let cfg = ler("cfg", null);   // { repo, branch, token? , cifra? }
let token = null;

class ErroGH extends Error {
  constructor(status, msg) { super(msg); this.status = status; }
}

async function gh(caminho, { metodo = "GET", corpo, accept = "application/vnd.github+json", etag } = {}) {
  const headers = { Accept: accept, Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2022-11-28" };
  if (etag) headers["If-None-Match"] = etag;
  if (corpo) headers["Content-Type"] = "application/json";
  let r;
  try {
    r = await fetch(API + caminho, { method: metodo, headers, body: corpo ? JSON.stringify(corpo) : undefined,
      cache: "no-store", referrerPolicy: "no-referrer" });
  } catch {
    throw new ErroGH(0, "sem internet");
  }
  if (r.status === 304) return { naoMudou: true };
  if (!r.ok) {
    let msg = `erro ${r.status}`;
    try { msg = (await r.json()).message || msg; } catch { /* corpo vazio */ }
    if (r.status === 401) msg = "token inválido ou vencido";
    if (r.status === 404) msg = "repositório não encontrado (ou o token não tem acesso a ele)";
    throw new ErroGH(r.status, msg);
  }
  return { r, etag: r.headers.get("ETag") };
}

const caminhoRepo = (p) => p.split("/").map(encodeURIComponent).join("/");

async function blobBruto(sha) {
  const { r } = await gh(`/repos/${cfg.repo}/git/blobs/${sha}`, { accept: "application/vnd.github.raw+json" });
  return r.arrayBuffer();
}

async function texto(sha) {
  const guardado = await cache.get(`t:${sha}`);
  if (typeof guardado === "string") return guardado;
  const t = new TextDecoder("utf-8").decode(await blobBruto(sha)).replace(/^﻿/, "").replace(/\r\n?/g, "\n");
  cache.set(`t:${sha}`, t);
  return t;
}

const urlsDeFoto = new Map();
async function urlDaFoto(sha, caminho) {
  if (urlsDeFoto.has(sha)) return urlsDeFoto.get(sha);
  let b = await cache.get(`b:${sha}`);
  if (!(b instanceof Blob)) {
    const ext = caminho.split(".").pop().toLowerCase();
    const tipo = { png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp" }[ext]
      || "application/octet-stream";
    b = new Blob([await blobBruto(sha)], { type: tipo });
    cache.set(`b:${sha}`, b);
  }
  const u = URL.createObjectURL(b);
  urlsDeFoto.set(sha, u);
  return u;
}

async function poucasDeCada(itens, fn, n = 6) {
  const fila = [...itens];
  await Promise.all(Array.from({ length: Math.min(n, fila.length) }, async () => {
    while (fila.length) await fn(fila.shift());
  }));
}

// ================================================================== o mural (a árvore do repositório)

let arvore = ler("arvore", null);   // { etag, arquivos: {caminho: sha} }
let salas = [];                     // [{ id, nomes: [stem], estado: sha }]
let agentes = [];
const mensagens = new Map();        // caminho -> mensagem lida
let vistos = ler("vistos", {});     // sala -> último stem visto
let atualizadoEm = null;

function montarSalas() {
  const porSala = new Map();
  const ags = [];
  for (const caminho of Object.keys(arvore.arquivos)) {
    const p = caminho.split("/");
    if (p[0] === "agentes" && p.length === 2 && p[1].endsWith(".md")) ags.push(p[1].slice(0, -3));
    if (p[0] !== "salas" || p.length !== 3) continue;
    if (!porSala.has(p[1])) porSala.set(p[1], { id: p[1], nomes: [], estado: null });
    const s = porSala.get(p[1]);
    if (p[2] === "_estado.md") s.estado = arvore.arquivos[caminho];
    else if (NOME_MSG.test(p[2])) s.nomes.push(p[2].slice(0, -3));
  }
  for (const s of porSala.values()) s.nomes.sort();
  salas = [...porSala.values()].sort((a, b) => {
    const ia = ORDEM_SALAS.indexOf(a.id), ib = ORDEM_SALAS.indexOf(b.id);
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || a.id.localeCompare(b.id);
  });
  agentes = ags.filter((a) => !["relatorios", "orquestrador", "rogerio"].includes(a))
    .sort((a, b) => (ORDEM_AGENTES.indexOf(a) + 1 || 99) - (ORDEM_AGENTES.indexOf(b) + 1 || 99));
  // 1ª vez neste aparelho: nada aparece como "novo"
  let mudou = false;
  for (const s of salas) {
    if (!(s.id in vistos)) { vistos[s.id] = s.nomes[s.nomes.length - 1] || ""; mudou = true; }
  }
  if (mudou) gravar("vistos", vistos);
}

async function atualizarArvore() {
  const { naoMudou, r, etag } = await gh(`/repos/${cfg.repo}/git/trees/${encodeURIComponent(cfg.branch)}?recursive=1`,
    { etag: arvore?.etag });
  atualizadoEm = new Date();
  if (naoMudou) return false;
  const dado = await r.json();
  const arquivos = {};
  for (const it of dado.tree) {
    if (it.type === "blob" && (it.path.startsWith("salas/") || it.path.startsWith("agentes/"))) arquivos[it.path] = it.sha;
  }
  arvore = { etag, arquivos };
  gravar("arvore", arvore);
  montarSalas();
  return true;
}

function separarCabecalho(t) {
  if (!t.startsWith("---\n")) return [{}, t];
  const fim = t.indexOf("\n---", 4);
  if (fim < 0) return [{}, t];
  const cab = {};
  for (const linha of t.slice(4, fim).split("\n")) {
    const m = linha.match(/^([A-Za-z_]+):\s*(.*)$/);
    if (!m) continue;
    const chave = m[1].toLowerCase();
    let v = m[2].trim();
    if (chave !== "resumo") v = v.replace(/\s+#.*$/, "");
    if (v.length >= 2 && v[0] === v[v.length - 1] && `"'`.includes(v[0])) v = v.slice(1, -1);
    if (v.startsWith("[") && v.endsWith("]")) v = v.slice(1, -1).split(",").map((x) => x.trim().replace(/^["']|["']$/g, "")).filter(Boolean);
    cab[chave] = v;
  }
  let corpo = t.slice(fim + 4);
  if (corpo.startsWith("\n")) corpo = corpo.slice(1);
  return [cab, corpo];
}
const comoLista = (v) => (!v ? [] : Array.isArray(v) ? v : [v]);
const comoTexto = (v) => (Array.isArray(v) ? v.join(", ") : String(v ?? ""));

async function mensagem(sala, stem) {
  const caminho = `salas/${sala}/${stem}.md`;
  const sha = arvore.arquivos[caminho];
  const chave = `${caminho}@${sha}`;
  if (mensagens.has(chave)) return mensagens.get(chave);
  const [cab, corpo] = separarCabecalho(await texto(sha));
  const m = NOME_MSG.exec(`${stem}.md`);
  const msg = {
    sala, arquivo: stem, autor: m[7],
    quando: `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}`,
    tipo: comoTexto(cab.tipo).toLowerCase(),
    resumo: comoTexto(cab.resumo),
    para: comoLista(cab.para),
    responde_a: typeof cab.responde_a === "string" ? cab.responde_a : "",
    anexos: comoLista(cab.anexos),
    corpo: corpo.replace(/^\n+|\n+$/g, ""),
  };
  mensagens.set(chave, msg);
  return msg;
}
const lidas = (lista) => poucasDeCada(lista, ([s, n]) => mensagem(s, n).catch(() => null));
const pronta = (sala, stem) => mensagens.get(`salas/${sala}/${stem}.md@${arvore.arquivos[`salas/${sala}/${stem}.md`]}`);

function todasAsMensagens() {
  const todas = [];
  for (const s of salas) for (const n of s.nomes) todas.push([s.id, n]);
  return todas.sort((a, b) => (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
}
const novasDa = (s) => s.nomes.filter((n) => n > (vistos[s.id] || "")).length;

// ================================================================== datas

const hora = (q) => q.slice(11, 16);
const diaCurto = (q) => `${q.slice(8, 10)}/${q.slice(5, 7)}`;
function diaLongo(q) {
  const d = new Date(q);
  const hoje = new Date();
  const ontem = new Date(Date.now() - 864e5);
  const mesmo = (a, b) => a.toDateString() === b.toDateString();
  if (mesmo(d, hoje)) return "hoje";
  if (mesmo(d, ontem)) return "ontem";
  return `${DIAS[d.getDay()]}, ${d.getDate()} de ${MESES[d.getMonth()]}` +
    (d.getFullYear() !== hoje.getFullYear() ? ` de ${d.getFullYear()}` : "");
}
const quandoCurto = (q) => (diaLongo(q) === "hoje" ? hora(q) : diaLongo(q) === "ontem" ? "ontem" : diaCurto(q));

// ================================================================== telas

function mostrar(id) {
  for (const t of $$(".tela")) t.hidden = t.id !== id;
}

function status(txt, classe = "") {
  const el = $("#status");
  el.textContent = txt;
  el.className = `status ${classe}`;
}

// ---------- lista de conversas

let salaAtual = null;

async function desenharLista() {
  const ultimas = salas.filter((s) => s.nomes.length).map((s) => [s.id, s.nomes[s.nomes.length - 1]]);
  await lidas(ultimas);
  const total = salas.reduce((n, s) => n + novasDa(s), 0);
  const ultimaGeral = todasAsMensagens().pop();
  const linha = (id, titulo, ultima, novas) => {
    const m = ultima ? pronta(ultima[0], ultima[1]) : null;
    const previa = m ? `<b>${esc(nome(m.autor))}:</b> ${esc(m.resumo)}` : "<i>sem mensagens</i>";
    return `<li><button class="conversa" data-sala="${esc(id)}" data-autor="${esc(COR_DA_SALA[id] || "")}">
      <span class="conversa-icone">${id === "tudo" ? "∗" : "#"}</span>
      <span class="conversa-meio">
        <span class="conversa-topo"><span class="conversa-nome">${esc(titulo)}</span>
          <span class="conversa-quando${novas ? " novas" : ""}">${m ? esc(quandoCurto(m.quando)) : ""}</span></span>
        <span class="conversa-baixo"><span class="conversa-previa" ${m ? `data-autor="${esc(autorReal(m.autor))}"` : ""}>${previa}</span>
          ${novas ? `<span class="badge">${novas}</span>` : ""}</span>
      </span></button></li>`;
  };
  $("#conversas").innerHTML = linha("tudo", "tudo (todas as salas)", ultimaGeral, total) +
    salas.map((s) => linha(s.id, s.id, s.nomes.length ? [s.id, s.nomes[s.nomes.length - 1]] : null, novasDa(s))).join("");
  if ("setAppBadge" in navigator) (total ? navigator.setAppBadge(total) : navigator.clearAppBadge()).catch(() => {});
}

// ---------- conversa

const limites = {};

function balao(m, anterior, mostrarSala) {
  const autor = autorReal(m.autor);
  const minha = autor === "rogerio";
  const cont = anterior && autorReal(anterior.autor) === autor && anterior.quando.slice(0, 10) === m.quando.slice(0, 10);
  const base = `repo:salas/${m.sala}/`;
  const tipo = TIPOS[m.tipo] ? m.tipo : "outro";
  const resp = m.responde_a ? acharPronta(m.responde_a) : null;
  const fotos = m.anexos.filter((a) => /\.(png|jpe?g|gif|webp)$/i.test(a));
  const outros = m.anexos.filter((a) => !fotos.includes(a));
  return `<div class="msg${minha ? " minha" : ""}${cont ? " cont" : ""}" data-autor="${esc(autor)}" id="m-${esc(m.arquivo)}">
    <div class="balao">
      <div class="b-topo">
        <span class="b-autor">${esc(nome(m.autor))}</span>
        ${mostrarSala ? `<a class="b-sala" href="#${esc(m.sala)}"># ${esc(m.sala)}</a>` : ""}
        <span class="tipo tipo-${tipo}">${esc(TIPOS[m.tipo] || m.tipo || "sem tipo")}</span>
      </div>
      ${m.responde_a ? `<a class="b-resp" href="#${esc(resp ? resp.sala : m.sala)}/${esc(m.responde_a)}">↩ ${resp
        ? `<b>${esc(nome(resp.autor))}</b> ${esc(resp.resumo)}` : esc(m.responde_a)}</a>` : ""}
      <p class="b-resumo">${m.resumo ? MD.inline(m.resumo) : "<i>sem resumo</i>"}</p>
      ${m.para.length ? `<p class="b-para">para ${m.para.map((p) => `<span class="mencao">@${esc(p === "orquestrador" ? "arc" : p)}</span>`).join(" ")}</p>` : ""}
      ${m.corpo ? `<div class="b-corpo"><div class="md">${repoLinks(MD.render(m.corpo, base))}</div>
        <button type="button" class="ver-mais">ver mais</button></div>` : ""}
      ${fotos.length ? `<div class="b-fotos">${fotos.map((a) => `<img data-repo-img="${esc(normalizar(`salas/${m.sala}/${a}`))}" alt="">`).join("")}</div>` : ""}
      ${outros.length ? `<p class="b-arquivos">${outros.map((a) => `<a href="#" data-repo-link="${esc(normalizar(`salas/${m.sala}/${a}`))}">📎 ${esc(a.split("/").pop())}</a>`).join(" ")}</p>` : ""}
      <div class="b-rodape">
        <button type="button" class="b-responder" data-arquivo="${esc(m.arquivo)}" data-sala="${esc(m.sala)}">↩ responder</button>
        <span class="b-hora" title="${esc(m.arquivo)}">${esc(hora(m.quando))}</span>
      </div>
    </div></div>`;
}

function acharPronta(stem) {
  for (const s of salas) if (s.nomes.includes(stem)) return pronta(s.id, stem) || null;
  return null;
}

// links e imagens relativos do markdown viram referências ao repositório, abertas pela API
function repoLinks(html) {
  return html
    .replace(/src="repo:([^"]*)"/g, (_, p) => `data-repo-img="${normalizar(p.replace(/&amp;/g, "&"))}"`)
    .replace(/href="repo:([^"]*)"/g, (_, p) => `href="#" data-repo-link="${normalizar(p.replace(/&amp;/g, "&"))}"`)
    .replace(/(data-repo-link="[^"]*") target="_blank" rel="noopener noreferrer"/g, "$1");
}
function normalizar(p) {
  const fora = [];
  for (const parte of decodeURIComponent(p).split("#")[0].split("/")) {
    if (parte === "..") fora.pop(); else if (parte && parte !== ".") fora.push(parte);
  }
  return esc(fora.join("/"));
}

let rolarAteFim = false;

async function desenharSala({ fim = false, manterTopo = false } = {}) {
  const tudo = salaAtual === "tudo";
  const sala = salas.find((s) => s.id === salaAtual);
  if (!tudo && !sala) { irParaLista(); return; }
  const lista = tudo ? todasAsMensagens() : sala.nomes.map((n) => [sala.id, n]);
  const limite = limites[salaAtual] || POR_PAGINA;
  const visiveis = lista.slice(-limite);
  $("#sala-nome").textContent = tudo ? "tudo" : `# ${sala.id}`;
  $("#sala-sub").textContent = `${lista.length} mensage${lista.length === 1 ? "m" : "ns"}` +
    (tudo ? " · todas as salas" : "");
  $("#b-estado").hidden = tudo;
  $("#caixa").hidden = tudo;
  document.title = `${tudo ? "tudo" : `# ${sala.id}`} · Zenith Hub`;

  const faltam = visiveis.filter(([s, n]) => !pronta(s, n));
  if (faltam.length > 6) {
    let feitas = 0;
    const aviso = () => {
      const el = $("#mensagens .vazio");
      if (el) el.textContent = `lendo ${feitas} de ${faltam.length}…`;
    };
    aviso();
    await poucasDeCada(faltam, ([s, n]) => mensagem(s, n).catch(() => null).finally(() => { feitas++; aviso(); }));
  } else {
    await lidas(visiveis);
  }
  // as respostas citadas também
  const citadas = [];
  for (const [s, n] of visiveis) {
    const m = pronta(s, n);
    if (m?.responde_a && !acharPronta(m.responde_a)) {
      const dona = salas.find((x) => x.nomes.includes(m.responde_a));
      if (dona) citadas.push([dona.id, m.responde_a]);
    }
  }
  await lidas(citadas);
  if (salaAtual !== (tudo ? "tudo" : sala.id)) return;  // trocou de sala enquanto lia

  const area = $("#rolagem");
  const pertoDoFim = area.scrollHeight - area.scrollTop - area.clientHeight < 150;
  const alturaAntes = area.scrollHeight;
  let html = lista.length > limite ? `<button type="button" class="mais-antigas">mensagens anteriores (${lista.length - limite})</button>` : "";
  let dia = "";
  let anterior = null;
  for (const [s, n] of visiveis) {
    const m = pronta(s, n);
    if (!m) continue;
    const d = m.quando.slice(0, 10);
    if (d !== dia) { dia = d; anterior = null; html += `<div class="dia"><span>${esc(diaLongo(m.quando))}</span></div>`; }
    html += balao(m, anterior, tudo);
    anterior = m;
  }
  $("#mensagens").innerHTML = html || '<p class="vazio">Ainda não há mensagens nesta sala.</p>';
  for (const c of $$(".b-corpo")) if ($(".md", c).scrollHeight > 300) c.classList.add("longo");
  observarFotos();
  if (manterTopo) area.scrollTop += area.scrollHeight - alturaAntes;
  else if (fim || pertoDoFim || rolarAteFim) area.scrollTop = area.scrollHeight;
  rolarAteFim = false;

  // marcar como visto
  const alvo = tudo ? salas : [sala];
  for (const s of alvo) if (s.nomes.length) vistos[s.id] = s.nomes[s.nomes.length - 1];
  gravar("vistos", vistos);
}

const observador = "IntersectionObserver" in window ? new IntersectionObserver((itens) => {
  for (const it of itens) if (it.isIntersecting) { observador.unobserve(it.target); carregarFoto(it.target); }
}, { rootMargin: "400px" }) : null;

function observarFotos(raiz = document) {
  for (const img of $$("img[data-repo-img]:not([src])", raiz)) {
    if (observador) observador.observe(img); else carregarFoto(img);
  }
}
async function carregarFoto(img) {
  const caminho = img.dataset.repoImg;
  const sha = arvore.arquivos[caminho];
  if (!sha) { img.alt = "imagem fora do hub"; return; }
  try { img.src = await urlDaFoto(sha, caminho); } catch { img.alt = "não consegui baixar"; }
}

// ---------- folha de baixo

function abrirFolha(titulo, html) {
  $("#folha-titulo").textContent = titulo;
  $("#folha-corpo").innerHTML = html;
  $("#folha").hidden = false;
  observarFotos($("#folha-corpo"));
}
const fecharFolha = () => { $("#folha").hidden = true; };

async function abrirEstado() {
  const sala = salas.find((s) => s.id === salaAtual);
  if (!sala) return;
  if (!sala.estado) { abrirFolha(`Estado de # ${sala.id}`, '<p class="vazio">Esta sala não tem _estado.md.</p>'); return; }
  abrirFolha(`Estado de # ${sala.id}`, '<p class="vazio">lendo…</p>');
  try {
    const [cab, corpo] = separarCabecalho(await texto(sala.estado));
    const at = comoTexto(cab.atualizado).replace(/por orquestrador/, "por arc");
    $("#folha-corpo").innerHTML = (at ? `<p class="dica pequena">atualizado ${esc(at)}</p>` : "") +
      `<div class="md">${repoLinks(MD.render(corpo, `repo:salas/${sala.id}/`))}</div>`;
    observarFotos($("#folha-corpo"));
  } catch (e) { $("#folha-corpo").innerHTML = `<p class="erro">${esc(e.message)}</p>`; }
}

function abrirCores() {
  const ids = [...ORDEM_AGENTES, "rogerio"];
  abrirFolha("Cores do time", `<ul class="cores">${ids.map((id) => `<li data-autor="${id}">
    <span class="amostra"></span><span class="n">${esc(nome(id))}</span><span class="p">${esc(PAPEIS[id] || "")}</span></li>`).join("")}</ul>
    <p class="dica pequena">Pela ordem de importância: o ARC no preto, no topo.</p>`);
}

function abrirMenu() {
  abrirFolha("Zenith Hub", `
    <button type="button" class="menu-btn" data-acao="atualizar">Atualizar agora</button>
    <button type="button" class="menu-btn" data-acao="cores">Cores do time</button>
    <button type="button" class="menu-btn" data-acao="trocar">Trocar token ou repositório</button>
    ${cfg.cifra ? `<button type="button" class="menu-btn" data-acao="trancar">Trancar (pedir o PIN de novo)</button>` : ""}
    <button type="button" class="menu-btn perigo" data-acao="apagar">Apagar tudo deste celular</button>
    <p class="dica pequena">Repositório ${esc(cfg.repo)} (${esc(cfg.branch)}) · versão ${VERSAO}<br>
    O mural é informação, não ordem: para um agente agir, mande na conversa dele.</p>`);
}

async function abrirArquivo(caminho) {
  const sha = arvore.arquivos[caminho];
  if (/\.(png|jpe?g|gif|webp)$/i.test(caminho) && sha) { verFoto(await urlDaFoto(sha, caminho)); return; }
  if (!sha || !caminho.endsWith(".md")) {
    abrirFolha(caminho.split("/").pop(), '<p class="vazio">Este arquivo não está no hub (só no PC, ou em outro projeto).</p>');
    return;
  }
  abrirFolha(caminho, '<p class="vazio">lendo…</p>');
  const [, corpo] = separarCabecalho(await texto(sha));
  const pasta = caminho.split("/").slice(0, -1).join("/");
  $("#folha-corpo").innerHTML = `<div class="md">${repoLinks(MD.render(corpo, `repo:${pasta}/`))}</div>`;
  observarFotos($("#folha-corpo"));
}

function verFoto(url) {
  const box = $("#foto-grande");
  $("img", box).src = url;
  box.hidden = false;
}

// ================================================================== escrever (como `rogerio`)

const caixa = (() => {
  const para = new Set();
  let fotos = [];          // { blob, url }
  let resposta = null;     // { arquivo, sala, autor, resumo }
  let enviando = false;

  const erro = (t) => { $("#c-erro").textContent = t || ""; };

  function desenharPara() {
    $("#c-para").innerHTML = agentes.map((id) => `<button type="button" class="chip${para.has(id) ? " ligado" : ""}"
      data-autor="${esc(id)}" data-para="${esc(id)}" aria-pressed="${para.has(id)}">@${esc(id)}</button>`).join("");
  }
  function alternar(id) { if (para.has(id)) para.delete(id); else para.add(id); desenharPara(); }

  function lerMencoes() {
    let mudou = false;
    for (const [, , id] of $("#c-texto").value.matchAll(/(^|[\s(])@([a-z0-9]+)/g)) {
      const real = autorReal(id);
      if (agentes.includes(real) && !para.has(real)) { para.add(real); mudou = true; }
    }
    if (mudou) { desenharPara(); $("#c-opcoes").hidden = false; }
  }

  function crescer() {
    const t = $("#c-texto");
    t.style.height = "auto";
    t.style.height = `${Math.min(t.scrollHeight, window.innerHeight * 0.4)}px`;
  }

  function desenharFotos() {
    $("#c-anexos").innerHTML = fotos.map((f, i) => `<span class="c-anexo"><img src="${f.url}" alt="">
      <button type="button" data-tirar="${i}" aria-label="Tirar foto">×</button></span>`).join("");
  }

  // reduz no próprio celular antes de enviar (lado maior até 1600 px, JPEG)
  async function reduzir(arquivo) {
    const bmp = await createImageBitmap(arquivo, { imageOrientation: "from-image" }).catch(() => createImageBitmap(arquivo));
    const k = Math.min(1, LADO_FOTO / Math.max(bmp.width, bmp.height));
    const c = document.createElement("canvas");
    c.width = Math.round(bmp.width * k);
    c.height = Math.round(bmp.height * k);
    c.getContext("2d").drawImage(bmp, 0, 0, c.width, c.height);
    bmp.close?.();
    return new Promise((ok, falha) => c.toBlob((b) => (b ? ok(b) : falha(new Error("não consegui reduzir"))), "image/jpeg", 0.82));
  }

  async function anexar(arquivos) {
    erro("");
    for (const f of arquivos) {
      if (fotos.length >= MAX_FOTOS) { erro(`No máximo ${MAX_FOTOS} fotos por mensagem.`); break; }
      if (!f.type.startsWith("image/")) { erro("Só imagens."); continue; }
      try {
        const blob = await reduzir(f);
        fotos.push({ blob, url: URL.createObjectURL(blob) });
        desenharFotos();
      } catch { erro("Não consegui abrir essa imagem."); }
    }
  }
  function tirar(i) { URL.revokeObjectURL(fotos[i].url); fotos.splice(i, 1); desenharFotos(); }

  function responder(sala, arquivo) {
    const m = pronta(sala, arquivo);
    if (!m) return;
    const autor = autorReal(m.autor);
    resposta = { sala, arquivo };
    $("#c-tipo").value = "resposta";
    if (autor !== "rogerio" && agentes.includes(autor)) para.add(autor);
    desenharPara();
    $("#resp-quem").textContent = nome(m.autor);
    $("#resp-resumo").textContent = m.resumo;
    $("#respondendo").hidden = false;
    $("#c-texto").focus();
  }
  function semResposta() {
    resposta = null;
    $("#respondendo").hidden = true;
    if ($("#c-tipo").value === "resposta") $("#c-tipo").value = "aviso";
  }
  function limpar() {
    $("#c-texto").value = "";
    crescer();
    for (const f of fotos) URL.revokeObjectURL(f.url);
    fotos = [];
    desenharFotos();
    para.clear();
    desenharPara();
    semResposta();
    $("#c-tipo").value = "aviso";
    $("#c-opcoes").hidden = true;
    gravar(`rascunho:${salaAtual}`, null);
  }

  const doisDig = (n) => String(n).padStart(2, "0");
  function carimbo() {
    const d = new Date();
    return `${d.getFullYear()}-${doisDig(d.getMonth() + 1)}-${doisDig(d.getDate())}T${doisDig(d.getHours())}${doisDig(d.getMinutes())}${doisDig(d.getSeconds())}`;
  }

  async function put(caminho, base64, mensagemCommit) {
    for (let tentativa = 1; ; tentativa++) {
      try {
        return await gh(`/repos/${cfg.repo}/contents/${caminhoRepo(caminho)}`, {
          metodo: "PUT", corpo: { message: mensagemCommit, content: base64, branch: cfg.branch },
        });
      } catch (e) {
        if (e.status === 409 && tentativa < 4) { await new Promise((r) => setTimeout(r, 800 * tentativa)); continue; }
        throw e;
      }
    }
  }

  async function enviar() {
    if (enviando) return;
    const bruto = $("#c-texto").value.replace(/\r\n?/g, "\n").trim();
    if (!bruto) { erro("Escreva a mensagem: a 1ª linha vira o resumo."); return; }
    const [primeira, ...resto] = bruto.split("\n");
    let resumo = primeira.replace(/\s+/g, " ").trim().slice(0, 300);
    if (`["'`.includes(resumo[0])) resumo = `— ${resumo}`;   // o cabeçalho é YAML simples
    const corpo = resto.join("\n").trim();
    if (corpo.length > 200000) { erro("Texto grande demais."); return; }
    const sala = salaAtual;
    const tipo = TIPOS[$("#c-tipo").value] ? $("#c-tipo").value : "aviso";
    const destino = [...para].filter((p) => /^[a-z0-9]+$/.test(p)).slice(0, 12);
    const respondeA = resposta && NOME_SEM_MD.test(resposta.arquivo) ? resposta.arquivo : "";

    enviando = true;
    erro("");
    $("#c-enviar").disabled = true;
    try {
      const existentes = new Set(salas.find((s) => s.id === sala)?.nomes || []);
      const agora = carimbo();
      let nomeArq = `${agora}_rogerio`;
      for (let n = 2; existentes.has(nomeArq); n++) nomeArq = `${agora}_rogerio-${n}`;

      const anexos = [];
      for (let i = 0; i < fotos.length; i++) {
        const arq = `anexos/${nomeArq}_${i + 1}.jpg`;
        $("#c-erro").textContent = `enviando foto ${i + 1} de ${fotos.length}…`;
        await put(`salas/${sala}/${arq}`, b64DeBytes(new Uint8Array(await fotos[i].blob.arrayBuffer())),
          `mural: anexo de ${nomeArq} (celular)`);
        anexos.push(arq);
      }
      const cab = ["---", `tipo: ${tipo}`, `resumo: ${resumo}`];
      if (destino.length) cab.push(`para: [${destino.join(", ")}]`);
      if (respondeA) cab.push(`responde_a: ${respondeA}`);
      if (anexos.length) cab.push(`anexos: [${anexos.join(", ")}]`);
      cab.push("---");
      const md = `${cab.join("\n")}\n${corpo ? `${corpo}\n` : ""}`;
      $("#c-erro").textContent = "publicando…";
      await put(`salas/${sala}/${nomeArq}.md`, b64DeBytes(new TextEncoder().encode(md)), `mural: ${nomeArq} (celular)`);
      erro("");
      limpar();
      rolarAteFim = true;
      await atualizar(true);
    } catch (e) {
      erro(`Não publiquei: ${e.message}`);
    } finally {
      enviando = false;
      $("#c-enviar").disabled = false;
    }
  }

  function aoEntrarNaSala() {
    limpar();
    $("#c-texto").value = ler(`rascunho:${salaAtual}`, "") || "";
    crescer();
  }

  const form = $("#caixa");
  form.addEventListener("submit", (e) => { e.preventDefault(); enviar(); });
  $("#c-texto").addEventListener("input", () => {
    erro(""); lerMencoes(); crescer(); gravar(`rascunho:${salaAtual}`, $("#c-texto").value || null);
  });
  $("#c-foto").addEventListener("change", (e) => { anexar([...e.target.files]); e.target.value = ""; });
  $("#c-mais").addEventListener("click", () => { desenharPara(); $("#c-opcoes").hidden = !$("#c-opcoes").hidden; });
  $("#resp-x").addEventListener("click", semResposta);
  form.addEventListener("click", (e) => {
    const chip = e.target.closest("[data-para]");
    if (chip) alternar(chip.dataset.para);
    const t = e.target.closest("[data-tirar]");
    if (t) tirar(+t.dataset.tirar);
  });
  return { responder, aoEntrarNaSala, desenharPara };
})();

// ================================================================== navegação e atualização

function irParaLista() {
  salaAtual = null;
  mostrar("tela-lista");
  document.title = "Zenith Hub";
  desenharLista().catch(() => {});
}

async function abrirSala(id, arquivo) {
  const mudou = salaAtual !== id;
  salaAtual = id;
  mostrar("tela-sala");
  if (mudou) { $("#mensagens").innerHTML = '<p class="vazio">lendo…</p>'; caixa.aoEntrarNaSala(); }
  if (arquivo && id !== "tudo") {
    const sala = salas.find((s) => s.id === id);
    const pos = sala ? sala.nomes.indexOf(arquivo) : -1;
    if (pos >= 0) limites[id] = Math.max(limites[id] || POR_PAGINA, sala.nomes.length - pos + 5);
  }
  await desenharSala({ fim: !arquivo });
  if (arquivo) {
    const el = document.getElementById(`m-${arquivo}`);
    if (el) {
      el.scrollIntoView({ block: "center" });
      el.classList.add("destaque");
      setTimeout(() => el.classList.remove("destaque"), 1800);
    }
  }
}

function rota() {
  const [sala, arquivo] = decodeURIComponent(location.hash.slice(1)).split("/");
  if (!sala) irParaLista();
  else abrirSala(sala, arquivo).catch((e) => status(e.message, "erro"));
}

let atualizando = false;
async function atualizar(forcar = false) {
  if (atualizando || !token) return;
  atualizando = true;
  try {
    const mudou = await atualizarArvore();
    status(`atualizado às ${atualizadoEm.toTimeString().slice(0, 5)}`, "ok");
    if (mudou || forcar) {
      if (salaAtual) await desenharSala(); else await desenharLista();
    }
  } catch (e) {
    status(e.message, "erro");
    if (e.status === 401) { token = null; abrirConfig("O token não vale mais. Crie outro no GitHub e cole aqui."); }
  } finally {
    atualizando = false;
  }
}

let relogio = null;
function ligarRelogio() {
  clearInterval(relogio);
  relogio = setInterval(() => { if (document.visibilityState === "visible") atualizar(); }, INTERVALO);
}
document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") atualizar(); });
window.addEventListener("online", () => atualizar());
window.addEventListener("hashchange", rota);

document.addEventListener("click", (e) => {
  const conv = e.target.closest(".conversa");
  if (conv) { location.hash = conv.dataset.sala; return; }
  const repoLink = e.target.closest("[data-repo-link]");
  if (repoLink) { e.preventDefault(); abrirArquivo(repoLink.dataset.repoLink).catch(() => {}); return; }
  const img = e.target.closest("img[data-repo-img][src]");
  if (img) { verFoto(img.src); return; }
  const mais = e.target.closest(".ver-mais");
  if (mais) {
    const c = mais.closest(".b-corpo");
    c.classList.toggle("aberto");
    mais.textContent = c.classList.contains("aberto") ? "ver menos" : "ver mais";
    return;
  }
  const resp = e.target.closest(".b-responder");
  if (resp) {
    if (salaAtual === "tudo") { location.hash = `${resp.dataset.sala}/${resp.dataset.arquivo}`; return; }
    caixa.responder(resp.dataset.sala, resp.dataset.arquivo);
    return;
  }
  if (e.target.closest(".mais-antigas")) {
    limites[salaAtual] = (limites[salaAtual] || POR_PAGINA) + POR_PAGINA;
    desenharSala({ manterTopo: true });
    return;
  }
  if (e.target.closest("[data-fechar]")) { fecharFolha(); return; }
  if (e.target.closest("#foto-grande")) { $("#foto-grande").hidden = true; return; }
  const acao = e.target.closest("[data-acao]")?.dataset.acao;
  if (acao === "atualizar") { fecharFolha(); atualizar(true); }
  if (acao === "cores") abrirCores();
  if (acao === "trocar") { fecharFolha(); abrirConfig(""); }
  if (acao === "trancar") trancar();
  if (acao === "apagar" && confirm("Apagar o token e o cache deste celular? O mural no GitHub não muda.")) apagarTudo();
});
$("#b-voltar").addEventListener("click", () => { if (history.length > 1) history.back(); else location.hash = ""; });
$("#b-estado").addEventListener("click", abrirEstado);
$("#b-cores").addEventListener("click", abrirCores);
$("#b-menu").addEventListener("click", abrirMenu);

// ================================================================== configuração, PIN e início

function abrirConfig(msg) {
  mostrar("tela-config");
  $("#cf-repo").value = cfg?.repo || "";
  $("#cf-token").value = "";
  $("#cf-pin").value = "";
  $("#cf-erro").textContent = msg || "";
}

$("#f-config").addEventListener("submit", async (e) => {
  e.preventDefault();
  const repo = $("#cf-repo").value.trim().replace(/^https:\/\/github\.com\//, "").replace(/\.git$/, "");
  const tk = $("#cf-token").value.trim();
  const pin = $("#cf-pin").value.trim();
  const botao = $("#f-config button");
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) { $("#cf-erro").textContent = "Repositório no formato dono/nome."; return; }
  if (pin && !/^\d{4,8}$/.test(pin)) { $("#cf-erro").textContent = "PIN: de 4 a 8 números."; return; }
  botao.disabled = true;
  $("#cf-erro").textContent = "";
  try {
    token = tk;
    cfg = { repo, branch: "main" };
    const { r } = await gh(`/repos/${repo}`);
    const info = await r.json();
    if (!info.private) throw new Error("Esse repositório é público. O mural só pode ficar num privado.");
    cfg.branch = info.default_branch || "main";
    if (info.permissions && !info.permissions.push) throw new Error("O token só lê: dê a ele Contents com leitura e escrita.");
    if (pin) cfg.cifra = await cifrar(tk, pin); else cfg.token = tk;
    if (ler("cfg", null)?.repo !== repo) { arvore = null; gravar("arvore", null); vistos = {}; gravar("vistos", {}); await cache.limpar(); }
    gravar("cfg", cfg);
    if (pin) await lembrar(tk);
    $("#cf-token").value = "";
    await iniciar();
  } catch (err) {
    token = null;
    $("#cf-erro").textContent = err.message;
  } finally {
    botao.disabled = false;
  }
});

$("#f-pin").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    token = await decifrar(cfg.cifra, $("#pin").value.trim());
    $("#pin").value = "";
    await lembrar(token);
    await iniciar();
  } catch {
    $("#pin-erro").textContent = "PIN errado.";
    $("#pin").value = "";
  }
});
$("#esqueci").addEventListener("click", () => {
  if (confirm("Apagar a configuração deste celular? Você vai precisar colar o token de novo.")) apagarTudo();
});

async function apagarTudo() {
  token = null;
  cfg = null;
  arvore = null;
  for (const k of Object.keys(localStorage)) localStorage.removeItem(k);
  await cache.limpar();
  location.hash = "";
  fecharFolha();
  abrirConfig("Tudo apagado deste celular.");
}

async function iniciar() {
  if (arvore) montarSalas();
  if (location.hash.length > 1) rota(); else irParaLista();
  ligarRelogio();
  await atualizar(true);
}

if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});

if (!cfg) abrirConfig("");
else if (cfg.cifra) {
  lembrado().then((tk) => {
    if (tk) { token = tk; iniciar(); return; }
    mostrar("tela-pin");
    setTimeout(() => $("#pin").focus(), 50);
  });
}
else { token = cfg.token; iniciar(); }
