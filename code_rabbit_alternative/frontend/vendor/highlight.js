/* Small tokenizer-based syntax highlighter.
 * No dependencies, no CDN, no regex-per-token blowups on big files.
 */
(function (global) {
  'use strict';

  const KEYWORDS = {
    python: 'and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield match case self None True False',
    javascript: 'async await break case catch class const continue debugger default delete do else export extends finally for function if import in instanceof let new of return static super switch this throw try typeof var void while yield null true false undefined get set',
    typescript: 'abstract as async await break case catch class const constructor continue declare default delete do else enum export extends finally for from function get if implements import in infer interface keyof let namespace new of private protected public readonly return satisfies set static super switch this throw try type typeof var void while yield null true false undefined',
    java: 'abstract assert boolean break byte case catch char class continue default do double else enum extends final finally float for if implements import instanceof int interface long native new package private protected public return short static strictfp super switch synchronized this throw throws transient try void volatile while var record sealed null true false',
    go: 'break case chan const continue default defer else fallthrough for func go goto if import interface map package range return select struct switch type var nil true false iota',
    rust: 'as async await break const continue crate dyn else enum extern fn for if impl in let loop match mod move mut pub ref return self Self static struct super trait type unsafe use where while None Some Ok Err true false',
    ruby: 'alias and begin break case class def defined? do else elsif end ensure for if in module next not or redo rescue retry return self super then undef unless until when while yield nil true false require attr_accessor',
    php: 'abstract and array as break callable case catch class clone const continue declare default do echo else elseif empty enddeclare endfor endforeach endif endswitch endwhile enum extends final finally fn for foreach function global goto if implements include include_once instanceof insteadof interface isset list match namespace new or print private protected public readonly require require_once return static switch throw trait try unset use var while xor yield null true false',
    csharp: 'abstract as base bool break byte case catch char checked class const continue decimal default delegate do double else enum event explicit extern finally fixed float for foreach goto if implicit in int interface internal is lock long namespace new object operator out override params private protected public readonly ref return sbyte sealed short sizeof stackalloc static string struct switch this throw try typeof uint ulong unchecked unsafe ushort using var virtual void volatile while yield null true false async await record',
    c: 'auto break case char const continue default do double else enum extern float for goto if inline int long register restrict return short signed sizeof static struct switch typedef union unsigned void volatile while NULL',
    cpp: 'alignas alignof and asm auto bool break case catch char class compl const constexpr continue decltype default delete do double else enum explicit export extern float for friend goto if inline int long mutable namespace new noexcept not or private protected public register reinterpret_cast return short signed sizeof static static_assert struct switch template this thread_local throw try typedef typeid typename union unsigned using virtual void volatile while nullptr true false',
    kotlin: 'abstract actual annotation as break by catch class companion const constructor continue crossinline data do else enum expect external final finally for fun get if import in infix init inline interface internal is lateinit noinline object open operator out override package private protected public reified return sealed set super suspend this throw try typealias val var vararg when where while null true false',
    swift: 'associatedtype break case catch class continue default defer deinit do else enum extension fallthrough fileprivate final for func guard if import in init inout internal is let mutating open operator private protocol public repeat required return self static struct subscript super switch throw throws try typealias var weak where while nil true false',
    bash: 'if then else elif fi for while until do done case esac function in select return break continue export local readonly declare typeset shift source alias eval exec set unset true false',
    sql: 'select from where insert into values update set delete create table alter drop index view join left right inner outer full on group by order having limit offset distinct as and or not null primary key foreign references unique check default constraint union all case when then else end count sum avg min max begin commit rollback transaction grant revoke with recursive',
    yaml: 'true false null yes no on off',
    terraform: 'resource variable output provider data module locals terraform for_each count depends_on',
    diff: '',
    html: '',
    css: '',
    json: 'true false null',
  };

  const LINE_COMMENT = {
    python: ['#'], ruby: ['#'], bash: ['#'], yaml: ['#'], terraform: ['#'], sql: ['--'],
    javascript: ['//'], typescript: ['//'], java: ['//'], go: ['//'], rust: ['//'],
    c: ['//'], cpp: ['//'], csharp: ['//'], php: ['//', '#'], kotlin: ['//'], swift: ['//'],
    json: [], html: [], css: [], diff: [],
  };

  const ALIASES = {
    js: 'javascript', jsx: 'javascript', mjs: 'javascript', node: 'javascript',
    ts: 'typescript', tsx: 'typescript', py: 'python', python3: 'python',
    sh: 'bash', shell: 'bash', zsh: 'bash', console: 'bash',
    yml: 'yaml', golang: 'go', rs: 'rust', rb: 'ruby', cs: 'csharp',
    'c++': 'cpp', hpp: 'cpp', kt: 'kotlin', dockerfile: 'bash', patch: 'diff',
    suggestion: 'diff',
  };

  function normalise(lang) {
    const key = String(lang || '').toLowerCase().trim();
    return ALIASES[key] || key;
  }

  function esc(text) {
    return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function span(cls, text) {
    return `<span class="tok-${cls}">${esc(text)}</span>`;
  }

  function highlightDiff(code) {
    return code.split('\n').map((line) => {
      if (/^@@/.test(line)) return span('meta', line);
      if (/^(\+\+\+|---)/.test(line)) return span('meta', line);
      if (/^\+/.test(line)) return span('add', line);
      if (/^-/.test(line)) return span('del', line);
      if (/^diff --git/.test(line)) return span('keyword', line);
      return esc(line);
    }).join('\n');
  }

  function highlight(code, lang) {
    const language = normalise(lang);
    if (!code) return '';
    if (language === 'diff' || language === 'patch') return highlightDiff(code);
    if (!KEYWORDS[language]) return esc(code);

    const keywords = new Set((KEYWORDS[language] || '').split(/\s+/).filter(Boolean));
    const commentStarts = LINE_COMMENT[language] || [];
    const hasBlockComment = !['python', 'bash', 'ruby', 'yaml', 'sql'].includes(language);
    const decorators = ['python', 'java', 'typescript', 'javascript', 'kotlin', 'csharp'].includes(language);
    const out = [];
    let i = 0;
    const n = code.length;

    while (i < n) {
      const ch = code[i];
      const rest = code.slice(i);

      // block comment
      if (hasBlockComment && (rest.startsWith('/*') || (language === 'html' && rest.startsWith('<!--')))) {
        const endToken = language === 'html' ? '-->' : '*/';
        const end = code.indexOf(endToken, i + (language === 'html' ? 4 : 2));
        const stop = end === -1 ? n : end + endToken.length;
        out.push(span('comment', code.slice(i, stop)));
        i = stop;
        continue;
      }

      // line comment
      const commentHit = commentStarts.find((marker) => rest.startsWith(marker));
      if (commentHit) {
        const end = code.indexOf('\n', i);
        const stop = end === -1 ? n : end;
        out.push(span('comment', code.slice(i, stop)));
        i = stop;
        continue;
      }

      // python docstring
      if (language === 'python' && (rest.startsWith('"""') || rest.startsWith("'''"))) {
        const marker = rest.slice(0, 3);
        const end = code.indexOf(marker, i + 3);
        const stop = end === -1 ? n : end + 3;
        out.push(span('string', code.slice(i, stop)));
        i = stop;
        continue;
      }

      // strings (incl. template literals)
      if (ch === '"' || ch === "'" || ch === '`') {
        let j = i + 1;
        while (j < n) {
          if (code[j] === '\\') { j += 2; continue; }
          if (code[j] === ch) { j++; break; }
          if (ch !== '`' && code[j] === '\n') break;
          j++;
        }
        out.push(span('string', code.slice(i, j)));
        i = j;
        continue;
      }

      // numbers
      if (/[0-9]/.test(ch) && (i === 0 || !/[\w$]/.test(code[i - 1]))) {
        const match = rest.match(/^(0[xXbBoO][0-9a-fA-F_]+|\d[\d_]*\.?[\d_]*([eE][+-]?\d+)?[fFlLuU]*)/);
        if (match) {
          out.push(span('number', match[0]));
          i += match[0].length;
          continue;
        }
      }

      // decorators / attributes
      if (decorators && ch === '@' && /[A-Za-z_]/.test(code[i + 1] || '')) {
        const match = rest.match(/^@[A-Za-z_][\w.]*/);
        if (match) {
          out.push(span('decorator', match[0]));
          i += match[0].length;
          continue;
        }
      }

      // identifiers & keywords
      if (/[A-Za-z_$]/.test(ch)) {
        const match = rest.match(/^[A-Za-z_$][\w$]*/);
        const word = match[0];
        const after = code.slice(i + word.length).match(/^\s*\(/);
        let cls = 'ident';
        if (keywords.has(word)) cls = 'keyword';
        else if (/^(true|false|null|nil|None|True|False|undefined|NaN)$/.test(word)) cls = 'literal';
        else if (after) cls = 'func';
        else if (/^[A-Z][A-Za-z0-9_]*$/.test(word) && word.length > 1) cls = 'type';
        out.push(span(cls, word));
        i += word.length;
        continue;
      }

      // operators & punctuation
      if (/[+\-*/%=<>!&|^~?:]/.test(ch)) {
        const match = rest.match(/^(<<=|>>=|=>|===|!==|==|!=|<=|>=|&&|\|\||\?\?|\.\.\.|\*\*|[+\-*/%=<>!&|^~?:])/);
        out.push(span('op', match ? match[0] : ch));
        i += match ? match[0].length : 1;
        continue;
      }

      out.push(esc(ch));
      i++;
    }

    return out.join('');
  }

  function highlightInline(text) {
    return esc(text);
  }

  global.Highlight = { highlight, highlightInline, normalise, languages: Object.keys(KEYWORDS) };
})(window);
