import secrets

from scanner.core.result import ScanReport

# Findings hold untrusted text, so the page renders it with textContent only and a CSP
# allows just this file's own nonce-tagged script and style.
_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-__NONCE__'; script-src 'nonce-__NONCE__'">
<title>Code Scan Report</title>
<style nonce="__NONCE__">
:root {
  color-scheme: light;
  --bg: #f4f5f7; --card: #ffffff; --text: #1b1f24; --muted: #667085; --border: #d9dde3;
  --hover: #eef1f5; --code-bg: #f6f8fa; --hit: #fff1b8; --link: #0b63ce;
  --critical: #b42318; --high: #e5532d; --medium: #d98a00; --low: #2f7fd1; --info: #7a8594;
  --pass: #1a7f4b; --fail: #b42318;
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --bg: #0f1318; --card: #171c23; --text: #e6e8eb; --muted: #9aa4b2; --border: #2c333d;
  --hover: #1f2630; --code-bg: #0d1117; --hit: #4a3f12; --link: #6cb0ff;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --bg: #0f1318; --card: #171c23; --text: #e6e8eb; --muted: #9aa4b2; --border: #2c333d;
    --hover: #1f2630; --code-bg: #0d1117; --hit: #4a3f12; --link: #6cb0ff;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 14px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 1200px; margin: 0 auto; padding: 24px 16px 64px; }
h1 { margin: 0 0 4px; font-size: 24px; }
h2 { margin: 28px 0 10px; font-size: 16px; }
.muted { color: var(--muted); }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; }
.header { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 12px; align-items: center; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 999px; color: #fff;
  font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: .03em; }
.badge.pass { background: var(--pass); }
.badge.fail { background: var(--fail); }
.gate { font-size: 15px; padding: 6px 16px; }
.banner { margin-top: 12px; padding: 10px 14px; border-radius: 8px; border: 1px solid var(--medium); }
.banner ul { margin: 6px 0 0; padding-left: 20px; }
.bar { display: flex; height: 14px; border-radius: 7px; overflow: hidden; background: var(--border); margin: 8px 0 14px; }
.bar > div { height: 100%; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }
.sev-card { text-align: left; cursor: pointer; font: inherit; color: inherit; border-left: 5px solid var(--info); }
.sev-card[aria-pressed="false"] { opacity: .4; }
.sev-card .n { font-size: 26px; font-weight: 700; line-height: 1.1; }
.sev-card .p { color: var(--muted); font-size: 12px; }
.critical { --c: var(--critical); } .high { --c: var(--high); } .medium { --c: var(--medium); }
.low { --c: var(--low); } .info { --c: var(--info); }
.sev-card.critical { border-left-color: var(--critical); } .sev-card.high { border-left-color: var(--high); }
.sev-card.medium { border-left-color: var(--medium); } .sev-card.low { border-left-color: var(--low); }
.sev-card.info { border-left-color: var(--info); }
.sev { background: var(--c); color: #fff; padding: 1px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
.chips { display: flex; flex-wrap: wrap; gap: 8px; }
.chip { padding: 4px 12px; border: 1px solid var(--border); border-radius: 999px; background: var(--card); }
table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border); border-radius: 8px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
tr:last-child td { border-bottom: 0; }
code { font: 12px ui-monospace, SFMono-Regular, Consolas, monospace; word-break: break-all; }
.status-ok { color: var(--pass); font-weight: 600; } .status-failed, .status-timeout { color: var(--fail); font-weight: 600; }
.status-skipped { color: var(--muted); }
.filters { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 10px; }
.filters input, .filters select, .filters button { font: inherit; padding: 6px 10px; color: var(--text);
  background: var(--card); border: 1px solid var(--border); border-radius: 6px; }
.filters input { min-width: 240px; }
.title { font-weight: 600; }
.detail { color: var(--muted); font-size: 12px; }
.table-wrap { overflow-x: auto; }
a { color: var(--link); }
.controls { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
.theme { display: inline-flex; border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
.theme button { font: inherit; padding: 4px 12px; border: 0; background: var(--card); color: var(--text);
  cursor: pointer; }
.theme button + button { border-left: 1px solid var(--border); }
.theme button[aria-pressed="true"] { background: var(--link); color: var(--bg); font-weight: 600; }
button:focus-visible, tr.finding:focus-visible { outline: 2px solid var(--link); outline-offset: -2px; }
tr.finding { cursor: pointer; }
tr.finding:hover, tr.finding[aria-expanded="true"] { background: var(--hover); }
tr.finding .chev { display: inline-block; width: 1em; color: var(--muted); }
tr.detail-row > td { background: var(--hover); padding: 0; }
.detail-panel { padding: 14px 18px 18px; }
.detail-panel h3 { margin: 0 0 6px; font-size: 16px; }
.detail-panel .message { margin: 0 0 12px; white-space: pre-wrap; overflow-wrap: anywhere; }
.facts { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; margin: 0 0 14px; }
.facts dt { color: var(--muted); }
.facts dd { margin: 0; overflow-wrap: anywhere; }
.snippet { border: 1px solid var(--border); border-radius: 6px; overflow: hidden; background: var(--code-bg); }
.snippet .path { padding: 6px 10px; border-bottom: 1px solid var(--border); color: var(--muted); font-size: 12px; }
.code { overflow-x: auto; padding: 4px 0; font: 12px/1.6 ui-monospace, SFMono-Regular, Consolas, monospace; }
.code .line { display: flex; white-space: pre; tab-size: 4; }
.code .line.hit { background: var(--hit); }
.code .ln { flex: none; width: 4.5em; padding: 0 10px; text-align: right; color: var(--muted); user-select: none; }
.code .src { padding-right: 12px; }
.score-head { display: flex; flex-wrap: wrap; align-items: baseline; gap: 6px 16px; }
.score-value { font-size: 40px; font-weight: 700; line-height: 1.1; }
.score-value.good, .fill.good { color: var(--pass); }
.score-value.ok { color: var(--medium); }
.score-value.bad { color: var(--critical); }
.meter { height: 12px; border-radius: 6px; background: var(--border); overflow: hidden; margin: 10px 0; }
.fill { height: 100%; background: currentColor; }
.fill.ok { color: var(--medium); }
.fill.bad { color: var(--critical); }
.score details { margin-top: 10px; color: var(--muted); }
.score summary { cursor: pointer; }
.banner.info { border-color: var(--link); }
.new-tag, .old-tag { margin-left: 6px; padding: 0 6px; border-radius: 4px; font-size: 11px; }
.new-tag { background: var(--link); color: var(--bg); font-weight: 600; }
.old-tag { border: 1px solid var(--border); color: var(--muted); }
.filters input[type="checkbox"] { min-width: 0; }
</style>
<script nonce="__NONCE__">
(function () {
  try {
    const theme = localStorage.getItem('scanner-report-theme');
    if (theme === 'light' || theme === 'dark') document.documentElement.setAttribute('data-theme', theme);
  } catch (e) { /* storage unavailable: follow the system theme */ }
})();
</script>
</head>
<body>
<main id="app"></main>
<script id="report-data" type="application/json">__DATA__</script>
<script nonce="__NONCE__">
(function () {
  'use strict';
  const data = JSON.parse(document.getElementById('report-data').textContent);
  const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
  const MAX_ROWS = 1000;
  const diff = data.diff;
  const allFindings = data.findings;
  const baseline = data.baseline;
  const findings = allFindings.filter((f) => !f.suppressed && f.is_new !== false);
  const hidden = allFindings.length - findings.length;
  const scoped = Boolean(diff || baseline);
  const state = { severities: new Set(SEVERITIES), tool: '', category: '', query: '', selected: null, showExisting: false };

  function h(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }
  function add(parent, ...children) {
    children.forEach((child) => parent.appendChild(child));
    return parent;
  }
  function countBy(list, key) {
    const counts = {};
    list.forEach((item) => { counts[item[key]] = (counts[item[key]] || 0) + 1; });
    return counts;
  }
  function percent(n, total) { return total ? Math.round((n * 1000) / total) / 10 : 0; }
  function location(f) {
    if (!f.file) return '-';
    return f.line_start ? f.file + ':' + f.line_start : f.file;
  }

  const app = document.getElementById('app');
  const passed = data.gate.passed;
  const anyRan = data.tools.some((t) => t.status === 'ok');
  const bySeverity = countBy(findings, 'severity');
  const bySeverityAll = countBy(allFindings, 'severity');
  const byCategory = countBy(findings, 'category');

  const header = h('div', 'header');
  const titleBox = add(h('div'), h('h1', '', 'Code Scan Report'),
    h('div', 'muted', data.target + ' \u2022 ' + new Date(data.started_at).toLocaleString() +
      ' \u2022 ' + data.duration_seconds.toFixed(1) + 's'));
  const themeButtons = {};
  function setTheme(mode) {
    if (mode === 'auto') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', mode);
    try {
      if (mode === 'auto') localStorage.removeItem('scanner-report-theme');
      else localStorage.setItem('scanner-report-theme', mode);
    } catch (e) { /* storage unavailable: the choice just won't persist */ }
    Object.keys(themeButtons).forEach((m) => themeButtons[m].setAttribute('aria-pressed', String(m === mode)));
  }
  const themeSwitch = h('div', 'theme');
  themeSwitch.setAttribute('role', 'group');
  themeSwitch.setAttribute('aria-label', 'Colour theme');
  ['auto', 'light', 'dark'].forEach((mode) => {
    const button = h('button', '', mode.charAt(0).toUpperCase() + mode.slice(1));
    button.type = 'button';
    button.addEventListener('click', () => setTheme(mode));
    themeButtons[mode] = button;
    add(themeSwitch, button);
  });
  add(header, titleBox, add(h('div', 'controls'), themeSwitch, h('span', 'badge gate ' + (passed ? 'pass' : 'fail'),
    'Quality gate: ' + (passed ? 'passed' : 'failed'))));
  add(app, header);
  setTheme(document.documentElement.getAttribute('data-theme') || 'auto');

  if (diff) {
    add(app, add(h('div', 'banner info'), h('strong', '', 'Diff scan: '),
      document.createTextNode(diff.base + ' \u2192 ' + diff.head + ' \u2022 ' + diff.changed_total +
        ' changed file(s) \u2022 ' + diff.new_count + ' new, ' + diff.existing_count + ' existing, ' +
        diff.fixed_count + ' fixed')));
  }
  if (baseline) {
    add(app, add(h('div', 'banner info'), h('strong', '', 'Baseline: '),
      document.createTextNode(baseline.size + ' finding(s) recorded \u2022 ' + baseline.new_count + ' new, ' +
        baseline.existing_count + ' already accepted')));
  }
  if (data.notices && data.notices.length) {
    const list = h('ul');
    data.notices.forEach((notice) => add(list, h('li', '', notice)));
    add(app, add(h('div', 'banner'), h('strong', '', 'Notices'), list));
  }
  if (!anyRan) {
    add(app, add(h('div', 'banner'), h('strong', '', 'No scanner ran successfully, so this result is not meaningful.')));
  }
  if (data.gate.reasons.length) {
    const list = h('ul');
    data.gate.reasons.forEach((reason) => add(list, h('li', '', reason)));
    add(app, add(h('div', 'banner'), h('strong', '', 'Gate failures'), list));
  }

  const score = data.score;
  const scoreCard = h('div', 'card score');
  add(app, h('h2', '', 'Health score'), scoreCard);
  if (score.percent === null) {
    add(scoreCard, h('div', 'score-value muted', 'n/a'),
      h('div', 'muted', 'No scanner ran successfully, so no score can be given.'));
  } else {
    const tier = score.percent >= 90 ? 'good' : score.percent >= 70 ? 'ok' : 'bad';
    const gap = Math.round((100 - score.percent) * 10) / 10;
    const fill = h('div', 'fill ' + tier);
    fill.style.width = score.percent + '%';
    add(scoreCard,
      add(h('div', 'score-head'), h('span', 'score-value ' + tier, score.percent + '%'),
        h('span', 'muted', gap === 0 ? 'Clean: nothing left to fix.' : gap + ' points away from 100% clean and safe')),
      add(h('div', 'meter'), fill));
    const left = SEVERITIES.filter((sev) => score.points_lost[sev] > 0);
    if (left.length) {
      const chips = h('div', 'chips');
      left.forEach((sev) => add(chips, add(h('span', 'chip'), h('span', 'sev ' + sev, sev),
        document.createTextNode(' ' + (bySeverity[sev] || 0) + ' finding(s): \u2212' + score.points_lost[sev] + ' points'))));
      add(scoreCard, h('div', 'muted', 'What is left to fix:'), chips);
    }
  }
  let coverage = 'Based on ' + score.scanners_ok + ' of ' + score.scanners_total + ' scanners.';
  if (score.scanners_ok < score.scanners_total) {
    coverage += ' Scanners that were skipped, failed or timed out may be hiding findings, so the real score could be lower.';
  }
  const how = h('details');
  add(how, h('summary', '', 'How is this calculated?'),
    h('p', '', 'It starts at 100%. Each finding costs points by severity: ' +
      SEVERITIES.map((sev) => sev + ' ' + score.weights[sev]).join(', ') +
      '. One category can cost at most ' + Object.entries(score.category_caps || {}).map(([k, v]) => k + ' ' + v).join(', ') +
      ' points, so a flood of minor findings in one place cannot hide everything else. The score stops at 0%. It counts findings only, so it is separate from the quality gate result.'));
  add(scoreCard, h('div', 'muted', coverage), how);

  add(app, h('h2', '', (scoped ? 'New findings by severity (' : 'Severity breakdown (') + findings.length + ' findings)'));
  const bar = h('div', 'bar');
  const cards = h('div', 'cards');
  const cardNodes = {};
  SEVERITIES.forEach((sev) => {
    const n = bySeverity[sev] || 0;
    if (n) {
      const seg = h('div', sev);
      seg.style.width = percent(n, findings.length) + '%';
      seg.style.background = 'var(--' + sev + ')';
      seg.title = sev + ': ' + n;
      add(bar, seg);
    }
    const card = h('button', 'card sev-card ' + sev);
    card.type = 'button';
    card.setAttribute('aria-pressed', 'true');
    add(card, h('div', 'muted', sev), h('div', 'n', n), h('div', 'p', percent(n, findings.length) + '% of findings'));
    card.addEventListener('click', () => {
      if (state.severities.has(sev)) state.severities.delete(sev); else state.severities.add(sev);
      update();
    });
    cardNodes[sev] = card;
    add(cards, card);
  });
  add(app, bar, cards);

  add(app, h('h2', '', 'By category'));
  const chips = h('div', 'chips');
  const categories = Object.keys(byCategory).sort();
  if (!categories.length) add(chips, h('span', 'muted', 'No findings'));
  categories.forEach((c) => add(chips, h('span', 'chip', c + ': ' + byCategory[c])));
  Object.keys(data.metrics).forEach((key) => add(chips, h('span', 'chip', key + ': ' + data.metrics[key])));
  add(app, chips);

  add(app, h('h2', '', 'Scanners'));
  const toolTable = h('table');
  const toolHead = h('tr');
  ['Tool', 'Status', 'Findings', 'Duration', 'Details'].forEach((t) => add(toolHead, h('th', '', t)));
  add(toolTable, add(h('thead'), toolHead));
  const toolBody = h('tbody');
  data.tools.forEach((t) => {
    add(toolBody, add(h('tr'), h('td', '', t.tool), h('td', 'status-' + t.status, t.status),
      h('td', '', t.finding_count), h('td', '', t.duration_seconds.toFixed(1) + 's'), h('td', 'muted', t.message)));
  });
  add(toolTable, toolBody);
  add(app, add(h('div', 'table-wrap'), toolTable));

  add(app, h('h2', '', scoped ? 'New findings' : 'Findings'));
  const filters = h('div', 'filters');
  const search = h('input');
  search.type = 'search';
  search.placeholder = 'Search rule, file, message, package';
  const toolSelect = h('select');
  const categorySelect = h('select');
  const tools = Array.from(new Set(allFindings.flatMap((f) => f.sources))).sort();
  const selectCategories = Array.from(new Set(allFindings.map((f) => f.category))).sort();
  add(toolSelect, new Option('All tools', ''), ...tools.map((t) => new Option(t, t)));
  add(categorySelect, new Option('All categories', ''), ...selectCategories.map((c) => new Option(c, c)));
  const reset = h('button', '', 'Reset filters');
  reset.type = 'button';
  const summary = h('span', 'muted');
  add(filters, search, toolSelect, categorySelect, reset, summary);
  if (hidden) {
    const existing = h('label', 'muted');
    const box = h('input');
    box.type = 'checkbox';
    box.addEventListener('change', () => { state.showExisting = box.checked; update(); });
    add(existing, box, document.createTextNode(' Show ' + hidden + ' existing or suppressed finding(s)'));
    add(filters, existing);
  }
  add(app, filters);

  const table = h('table');
  const head = h('tr');
  ['Severity', 'Category', 'Rule', 'Location', 'Finding', 'Sources'].forEach((t) => add(head, h('th', '', t)));
  add(table, add(h('thead'), head));
  const body = h('tbody');
  add(table, body);
  add(app, add(h('div', 'table-wrap'), table));

  function matches(f) {
    if (!state.severities.has(f.severity)) return false;
    if (state.tool && !f.sources.includes(state.tool)) return false;
    if (state.category && f.category !== state.category) return false;
    if (!state.query) return true;
    const haystack = [f.rule_id, f.title, f.message, f.file, f.package, f.version].join(' ').toLowerCase();
    return haystack.includes(state.query);
  }

  const ORIGIN = {
    dependency: 'A dependency declared in this file has a known vulnerability.',
    code: 'A code pattern in this file matched a static-analysis rule.',
    secret: 'A credential-like value was found here. The value is not stored in this report.',
    pii: 'Personal data, such as an email address or card number, was detected here. The value is not stored in this report.',
    iac: 'A Dockerfile or infrastructure setting in this file failed a policy check.',
    duplication: 'This block of code is duplicated elsewhere in the codebase.',
    complexity: 'This function exceeds the configured complexity limits.',
    license: 'License reported for a dependency.',
  };
  const ADVISORY = /^(CVE-\d{4}-\d{4,}|GHSA(-[a-z0-9]{4}){3})$/i;
  const rowNodes = new Map();
  let pendingFocus = null;

  function whereText(f) {
    if (!f.file) return 'Not tied to a specific file';
    if (!f.line_start) return f.file;
    const end = f.line_end && f.line_end !== f.line_start ? '\u2013' + f.line_end : '';
    return f.file + ', line ' + f.line_start + end;
  }

  function fact(list, label, value) {
    add(list, h('dt', '', label));
    const dd = h('dd');
    if (value instanceof Node) dd.appendChild(value); else dd.textContent = value;
    add(list, dd);
  }

  function snippetBlock(f) {
    const s = f.snippet;
    if (!s) {
      return h('p', 'muted', f.category === 'secret' || f.category === 'pii'
        ? 'Source lines are hidden because this finding involves sensitive data.'
        : 'No source snippet is available for this finding.');
    }
    const code = h('div', 'code');
    s.lines.forEach((text, i) => {
      const n = s.start_line + i;
      const hit = n >= s.highlight_start && n <= s.highlight_end;
      add(code, add(h('div', 'line' + (hit ? ' hit' : '')), h('span', 'ln', n), h('span', 'src', text === '' ? ' ' : text)));
    });
    return add(h('div', 'snippet'), h('div', 'path', f.file), code);
  }

  function detailRow(f) {
    const facts = h('dl', 'facts');
    fact(facts, 'Where', whereText(f));
    fact(facts, 'What it is', ORIGIN[f.category] || f.category);
    const found = f.sources.join(', ');
    fact(facts, 'Found by', f.sources.length > 1
      ? found + ' (' + f.sources.length + ' scanners reported it; merged into one finding)' : found);
    fact(facts, 'Rule', f.rule_id);
    fact(facts, 'Severity', f.severity + ' \u2022 ' + f.category);
    if (f.suppressed) fact(facts, 'Suppressed', f.suppressed.reason + ' (until ' + f.suppressed.expires + ')');
    fact(facts, 'Fingerprint', f.fingerprint);
    if (f.package) {
      fact(facts, 'Package', f.package + (f.version ? ' ' + f.version : ''));
      fact(facts, 'Fix', f.fixed_version ? 'Upgrade to ' + f.fixed_version + ' or later' : 'No fixed version reported');
    }
    if (ADVISORY.test(f.rule_id)) {
      const link = h('a', '', 'osv.dev/vulnerability/' + f.rule_id);
      link.href = 'https://osv.dev/vulnerability/' + encodeURIComponent(f.rule_id);
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      fact(facts, 'Advisory', link);
    }
    const panel = add(h('div', 'detail-panel'), h('h3', '', f.title));
    if (f.message && f.message !== f.title) add(panel, h('p', 'message', f.message));
    add(panel, facts, snippetBlock(f));
    const cell = add(h('td'), panel);
    cell.colSpan = 6;
    return add(h('tr', 'detail-row'), cell);
  }

  function toggle(f) {
    state.selected = state.selected === f ? null : f;
    pendingFocus = f;
    update();
  }

  function row(f) {
    const open = state.selected === f;
    const text = h('td');
    add(text, h('div', 'title', f.title));
    if (f.message && f.message !== f.title) add(text, h('div', 'detail', f.message));
    if (f.package) {
      add(text, h('div', 'detail', f.package + ' ' + (f.version || '') + (f.fixed_version ? ' \u2192 fixed in ' + f.fixed_version : '')));
    }
    const sev = add(h('td'), h('span', 'chev', open ? '\u25BE' : '\u25B8'), h('span', 'sev ' + f.severity, f.severity));
    if (f.suppressed) add(sev, h('span', 'old-tag', 'suppressed'));
    else if (scoped) add(sev, h('span', f.is_new === false ? 'old-tag' : 'new-tag', f.is_new === false ? 'existing' : 'new'));
    const tr = add(h('tr', 'finding'), sev, h('td', '', f.category), add(h('td'), h('code', '', f.rule_id)),
      add(h('td'), h('code', '', location(f))), text, h('td', '', f.sources.join(', ')));
    tr.tabIndex = 0;
    tr.setAttribute('aria-expanded', String(open));
    tr.addEventListener('click', () => toggle(f));
    tr.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); toggle(f); }
    });
    rowNodes.set(f, tr);
    return tr;
  }

  function update() {
    SEVERITIES.forEach((sev) => cardNodes[sev].setAttribute('aria-pressed', String(state.severities.has(sev))));
    const pool = state.showExisting ? allFindings : findings;
    const visible = pool.filter(matches);
    if (state.selected && !visible.includes(state.selected)) state.selected = null;
    rowNodes.clear();
    body.replaceChildren(...visible.slice(0, MAX_ROWS).flatMap((f) => (
      state.selected === f ? [row(f), detailRow(f)] : [row(f)])));
    if (pendingFocus && rowNodes.has(pendingFocus)) rowNodes.get(pendingFocus).focus();
    pendingFocus = null;
    let label = 'Showing ' + visible.length + ' of ' + pool.length;
    if (visible.length > MAX_ROWS) label += ' (first ' + MAX_ROWS + ' rendered)';
    summary.textContent = label;
  }

  search.addEventListener('input', () => { state.query = search.value.trim().toLowerCase(); update(); });
  toolSelect.addEventListener('change', () => { state.tool = toolSelect.value; update(); });
  categorySelect.addEventListener('change', () => { state.category = categorySelect.value; update(); });
  reset.addEventListener('click', () => {
    state.severities = new Set(SEVERITIES);
    state.tool = state.category = state.query = '';
    state.selected = null;
    search.value = toolSelect.value = categorySelect.value = '';
    update();
  });
  update();
})();
</script>
</body>
</html>
"""

_JSON_ESCAPES = {
    "<": "\\u003c",
    ">": "\\u003e",
    "&": "\\u0026",
    "\u2028": "\\u2028",
    "\u2029": "\\u2029",
}


def _embed(report: ScanReport) -> str:
    """JSON safe to place inside a script element; the escapes only occur inside strings."""
    text = report.model_dump_json()
    for char, escape in _JSON_ESCAPES.items():
        text = text.replace(char, escape)
    return text


def render(report: ScanReport) -> str:
    nonce = secrets.token_urlsafe(16)
    return _TEMPLATE.replace("__NONCE__", nonce).replace("__DATA__", _embed(report))
