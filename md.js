// Markdown -> HTML, pequeno e seguro de saída: TODO o texto é escapado antes de virar HTML, então nenhum HTML
// escrito numa mensagem chega à tela. Cobre o que os agentes usam: títulos, parágrafos, negrito, itálico, código,
// listas (aninhadas), citações, tabelas, links, imagens e linhas. Links só http(s), mailto, âncora ou relativos
// (relativos apontam para dentro da sala da mensagem).

const MD = (() => {
  const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");

  function urlSegura(bruta, base) {
    const u = bruta.trim().replace(/&amp;/g, "&");
    if (/^(https?:|mailto:)/i.test(u)) return u;
    if (u.startsWith("#")) return u;
    if (/^[a-z][a-z0-9+.-]*:/i.test(u) || u.startsWith("//") || u.startsWith("/")) return null;
    return base + u.replace(/^\.\//, "");
  }

  function inline(texto, base) {
    const guardados = [];
    const guardar = (html) => `\u0000${guardados.push(html) - 1}\u0000`;
    let s = esc(texto);
    s = s.replace(/(`+)([^`]|[^`][\s\S]*?[^`])\1(?!`)/g, (_, __, c) => guardar(`<code>${c.trim()}</code>`));
    s = s.replace(/!\[([^\]]*)\]\(([^)\s]+)\)/g, (m, alt, url) => {
      const u = urlSegura(url, base);
      return u ? guardar(`<img src="${esc(u)}" alt="${alt}" loading="lazy">`) : m;
    });
    s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (m, txt, url) => {
      const u = urlSegura(url, base);
      return u ? guardar(`<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${txt}</a>`) : m;
    });
    s = s.replace(/(^|[\s(])(https?:\/\/[^\s<)]+[^\s<).,;:!?])/g,
      (_, a, url) => a + guardar(`<a href="${url}" target="_blank" rel="noopener noreferrer">${url}</a>`));
    s = s.replace(/\*\*(?=\S)([\s\S]*?\S)\*\*/g, "<strong>$1</strong>");
    s = s.replace(/__(?=\S)([\s\S]*?\S)__(?!\w)/g, "<strong>$1</strong>");
    s = s.replace(/(^|[^*\w])\*(?=\S)([^*]*?\S)\*(?!\*)/g, "$1<em>$2</em>");
    s = s.replace(/(^|[^\w])_(?=\S)([^_]*?\S)_(?!\w)/g, "$1<em>$2</em>");
    s = s.replace(/~~(?=\S)([\s\S]*?\S)~~/g, "<del>$1</del>");
    s = s.replace(/(^|[\s(\[])@([a-z0-9]+)\b/g, '$1<span class="mencao">@$2</span>');
    return s.replace(/\u0000(\d+)\u0000/g, (_, i) => guardados[+i]);
  }

  const RE_LISTA = /^(\s*)([-*+]|\d+[.)])\s+(.*)$/;
  const RE_TABELA_SEP = /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/;
  const celulas = (l) => l.trim().replace(/^\|/, "").replace(/\|$/, "").split(/(?<!\\)\|/).map((c) => c.trim().replace(/\\\|/g, "|"));

  function lista(linhas, base) {
    // pilha de níveis: cada um com o recuo e o tipo; texto de continuação vai para o último item
    let html = "";
    const pilha = [];
    let itemAberto = false;
    for (const l of linhas) {
      const m = l.match(RE_LISTA);
      if (!m) {
        html = html.replace(/<\/li>$/, "") + " " + inline(l.trim(), base) + "</li>";
        continue;
      }
      const recuo = m[1].replace(/\t/g, "    ").length;
      const tipo = /\d/.test(m[2]) ? "ol" : "ul";
      while (pilha.length && recuo < pilha[pilha.length - 1].recuo) {
        html += `</${pilha.pop().tipo}></li>`;
      }
      const topo = pilha[pilha.length - 1];
      if (!topo || recuo > topo.recuo) {
        if (topo) html = html.replace(/<\/li>$/, "");
        pilha.push({ recuo, tipo });
        html += `<${tipo}>`;
      }
      let texto = m[3];
      const caixa = texto.match(/^\[([ xX])\]\s+(.*)$/);
      if (caixa) {
        texto = caixa[2];
        html += `<li class="tarefa${caixa[1] === " " ? "" : " feita"}"><span class="caixa"></span><span class="tarefa-texto">${inline(texto, base)}</span></li>`;
      } else {
        html += `<li>${inline(texto, base)}</li>`;
      }
      itemAberto = true;
    }
    while (pilha.length) {
      const nivel = pilha.pop();
      html += `</${nivel.tipo}>` + (pilha.length ? "</li>" : "");
    }
    return itemAberto ? html : "";
  }

  function blocos(texto, base) {
    const linhas = texto.replace(/\r\n?/g, "\n").split("\n");
    let html = "";
    let i = 0;
    while (i < linhas.length) {
      const l = linhas[i];
      if (!l.trim()) { i++; continue; }

      const cerca = l.match(/^\s*(```+|~~~+)\s*([\w-]*)/);
      if (cerca) {
        const fim = cerca[1];
        const corpo = [];
        i++;
        while (i < linhas.length && !linhas[i].trim().startsWith(fim)) corpo.push(linhas[i++]);
        i++;
        html += `<pre><code>${esc(corpo.join("\n"))}</code></pre>`;
        continue;
      }
      const titulo = l.match(/^(#{1,6})\s+(.*?)\s*#*\s*$/);
      if (titulo) {
        const n = Math.min(titulo[1].length + 2, 6);  // h1 da mensagem vira h3: o balão não é a página
        html += `<h${n}>${inline(titulo[2], base)}</h${n}>`;
        i++;
        continue;
      }
      if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(l)) { html += "<hr>"; i++; continue; }
      if (/^\s*>/.test(l)) {
        const dentro = [];
        while (i < linhas.length && /^\s*>/.test(linhas[i])) dentro.push(linhas[i++].replace(/^\s*>\s?/, ""));
        html += `<blockquote>${blocos(dentro.join("\n"), base)}</blockquote>`;
        continue;
      }
      if (l.includes("|") && i + 1 < linhas.length && RE_TABELA_SEP.test(linhas[i + 1])) {
        const cab = celulas(l);
        const alinha = celulas(linhas[i + 1]).map((c) => (/:$/.test(c) ? (/^:/.test(c) ? "center" : "right") : ""));
        i += 2;
        let t = "<div class=\"tabela\"><table><thead><tr>" +
          cab.map((c, k) => `<th${alinha[k] ? ` style="text-align:${alinha[k]}"` : ""}>${inline(c, base)}</th>`).join("") +
          "</tr></thead><tbody>";
        while (i < linhas.length && linhas[i].includes("|") && linhas[i].trim()) {
          const cs = celulas(linhas[i++]);
          t += "<tr>" + cab.map((_, k) => `<td${alinha[k] ? ` style="text-align:${alinha[k]}"` : ""}>${inline(cs[k] || "", base)}</td>`).join("") + "</tr>";
        }
        html += t + "</tbody></table></div>";
        continue;
      }
      if (RE_LISTA.test(l)) {
        const itens = [];
        while (i < linhas.length && linhas[i].trim() &&
               (RE_LISTA.test(linhas[i]) || /^\s{2,}\S/.test(linhas[i]))) itens.push(linhas[i++]);
        html += lista(itens, base);
        continue;
      }
      const par = [];
      while (i < linhas.length && linhas[i].trim() && !/^(#{1,6}\s|\s*>|\s*```|\s*~~~)/.test(linhas[i]) &&
             !RE_LISTA.test(linhas[i]) && !/^\s*([-*_])(\s*\1){2,}\s*$/.test(linhas[i])) {
        if (linhas[i].includes("|") && i + 1 < linhas.length && RE_TABELA_SEP.test(linhas[i + 1])) break;
        par.push(linhas[i++]);
      }
      if (!par.length) { html += `<p>${inline(linhas[i++], base)}</p>`; continue; }
      html += `<p>${par.map((p) => inline(p.trim(), base) + (/ {2}$/.test(p) ? "<br>" : "")).join(" ")}</p>`;
    }
    return html;
  }

  return { render: (texto, base = "") => blocos(texto || "", base), inline: (t) => inline(t || "", "") };
})();
