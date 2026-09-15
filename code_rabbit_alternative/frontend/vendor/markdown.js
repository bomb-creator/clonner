/* Minimal, dependency-free Markdown renderer.
 * Everything is HTML-escaped before emission, so model output can never
 * inject markup into the page (a code reviewer with its own XSS would be ironic).
 */
(function (global) {
  'use strict';

  function escapeHtml(text) {
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function escapeAttr(text) {
    return escapeHtml(text).replace(/\s+/g, '%20');
  }

  function inline(text) {
    let out = escapeHtml(text);
    // inline code first, protecting its contents from further processing
    const codes = [];
    out = out.replace(/`([^`]+)`/g, (_, code) => {
      codes.push(code);
      return `\u0000CODE${codes.length - 1}\u0000`;
    });
    // images ![alt](src)
    out = out.replace(/!\[([^\]]*)\]\(([^)\s]+)\)/g,
      (_, alt, src) => `<img alt="${alt}" src="${escapeAttr(src)}" loading="lazy">`);
    // links [text](href)
    out = out.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_, label, href) => {
      const safe = /^(https?:|mailto:|#|\/)/i.test(href) ? href : '#';
      return `<a href="${escapeAttr(safe)}" target="_blank" rel="noopener noreferrer">${label}</a>`;
    });
    // bold / italic / strike
    out = out
      .replace(/\*\*\*([^*]+)\*\*\*/g, '<strong><em>$1</em></strong>')
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/(^|[^*])\*([^*\n]+)\*/g, '$1<em>$2</em>')
      .replace(/(^|[^_])_([^_\n]+)_/g, '$1<em>$2</em>')
      .replace(/~~([^~]+)~~/g, '<del>$1</del>');
    // restore code spans
    out = out.replace(/\u0000CODE(\d+)\u0000/g, (_, i) =>
      `<code class="inline">${global.Highlight ? global.Highlight.highlightInline(codes[+i]) : codes[+i]}</code>`);
    return out;
  }

  function renderTable(rows) {
    const cells = (row) => row.replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
    const header = cells(rows[0]);
    const body = rows.slice(2).map(cells);
    let html = '<div class="md-table-wrap"><table class="md-table"><thead><tr>';
    header.forEach((h) => { html += `<th>${inline(h)}</th>`; });
    html += '</tr></thead><tbody>';
    body.forEach((row) => {
      html += '<tr>';
      header.forEach((_, i) => { html += `<td>${inline(row[i] || '')}</td>`; });
      html += '</tr>';
    });
    return html + '</tbody></table></div>';
  }

  function isTableSeparator(line) {
    return /^\s*\|?[\s:-]*-{2,}[\s:|-]*\|?\s*$/.test(line) && line.includes('-');
  }

  function render(markdown, options) {
    options = options || {};
    const src = String(markdown || '').replace(/\r\n/g, '\n');
    const lines = src.split('\n');
    const out = [];
    let i = 0;

    const listStack = []; // {type: 'ul'|'ol', indent: number}

    function closeLists(depth) {
      while (listStack.length > depth) {
        out.push(listStack.pop().type === 'ol' ? '</ol>' : '</ul>');
      }
    }

    while (i < lines.length) {
      const line = lines[i];

      // fenced code block
      const fence = line.match(/^\s*(```|~~~)\s*([\w+#.-]*)\s*$/);
      if (fence) {
        closeLists(0);
        const marker = fence[1];
        const lang = fence[2] || '';
        const buf = [];
        i++;
        while (i < lines.length && !new RegExp('^\\s*' + marker).test(lines[i])) {
          buf.push(lines[i]);
          i++;
        }
        i++; // skip closing fence
        const code = buf.join('\n');
        if (lang === 'mermaid') {
          out.push(`<div class="mermaid-source" data-diagram="${escapeAttr(code)}"></div>`);
        } else {
          const highlighted = global.Highlight
            ? global.Highlight.highlight(code, lang)
            : escapeHtml(code);
          out.push(
            `<div class="codeblock" data-lang="${escapeHtml(lang)}">` +
            `<button class="copy-code" type="button">Copy</button>` +
            `<pre><code>${highlighted}</code></pre></div>`
          );
        }
        continue;
      }

      // blank
      if (!line.trim()) { closeLists(0); i++; continue; }

      // heading
      const heading = line.match(/^(#{1,6})\s+(.*)$/);
      if (heading) {
        closeLists(0);
        const level = heading[1].length;
        const id = heading[2].toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
        out.push(`<h${level} id="${id}">${inline(heading[2])}</h${level}>`);
        i++;
        continue;
      }

      // horizontal rule
      if (/^\s*(---|\*\*\*|___)\s*$/.test(line)) { closeLists(0); out.push('<hr>'); i++; continue; }

      // table
      if (line.includes('|') && i + 1 < lines.length && isTableSeparator(lines[i + 1])) {
        closeLists(0);
        const rows = [];
        while (i < lines.length && lines[i].includes('|') && lines[i].trim()) { rows.push(lines[i]); i++; }
        if (rows.length >= 2) out.push(renderTable(rows));
        continue;
      }

      // blockquote
      if (/^\s*>/.test(line)) {
        closeLists(0);
        const buf = [];
        while (i < lines.length && /^\s*>/.test(lines[i])) { buf.push(lines[i].replace(/^\s*>\s?/, '')); i++; }
        out.push(`<blockquote>${render(buf.join('\n'), options)}</blockquote>`);
        continue;
      }

      // list item (supports nesting by indentation and task lists)
      const item = line.match(/^(\s*)([-*+]|\d+[.)])\s+(.*)$/);
      if (item) {
        const indent = item[1].replace(/\t/g, '  ').length;
        const type = /^\d/.test(item[2]) ? 'ol' : 'ul';
        const depth = Math.floor(indent / 2) + 1;
        let content = item[3];

        while (listStack.length < depth) {
          out.push(type === 'ol' ? '<ol>' : '<ul>');
          listStack.push({ type, indent });
        }
        while (listStack.length > depth) {
          out.push(listStack.pop().type === 'ol' ? '</ol>' : '</ul>');
        }

        const task = content.match(/^\[( |x|X)\]\s*(.*)$/);
        if (task) {
          const checked = task[1].toLowerCase() === 'x' ? ' checked' : '';
          content = `<span class="task"><input type="checkbox"${checked} disabled>${inline(task[2])}</span>`;
        } else {
          content = inline(content);
        }
        out.push(`<li>${content}</li>`);
        i++;
        continue;
      }

      // paragraph (gather contiguous plain lines)
      closeLists(0);
      const buf = [line];
      i++;
      while (
        i < lines.length && lines[i].trim() &&
        !/^(#{1,6}\s|\s*>|\s*([-*+]|\d+[.)])\s|\s*```|\s*~~~)/.test(lines[i]) &&
        !/^\s*(---|\*\*\*|___)\s*$/.test(lines[i])
      ) { buf.push(lines[i]); i++; }
      out.push(`<p>${inline(buf.join(' '))}</p>`);
    }

    closeLists(0);
    return out.join('\n');
  }

  global.Markdown = { render, escapeHtml, inline };
})(window);
