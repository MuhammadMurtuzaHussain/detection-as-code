(function () {
  'use strict';

  var data = JSON.parse(document.getElementById('data').textContent);
  var root = document.documentElement;

  // ------------------------------------------------------------------ helpers

  function h(tag, attrs) {
    var el = document.createElement(tag);
    var attributes = attrs || {};
    Object.keys(attributes).forEach(function (key) {
      var value = attributes[key];
      if (value === null || value === undefined || value === false) return;
      if (key === 'class') el.className = value;
      else if (key.slice(0, 2) === 'on') el.addEventListener(key.slice(2), value);
      else el.setAttribute(key, value === true ? '' : value);
    });
    Array.prototype.slice.call(arguments, 2).forEach(function add(child) {
      if (child === null || child === undefined || child === false) return;
      if (Array.isArray(child)) child.forEach(add);
      else el.append(child.nodeType ? child : document.createTextNode(String(child)));
    });
    return el;
  }

  function $(selector) { return document.querySelector(selector); }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }
  function capitalise(text) { return text ? text.charAt(0).toUpperCase() + text.slice(1) : text; }
  function plural(count, one, many) { return count + ' ' + (count === 1 ? one : many); }

  // Constant markup only: nothing from the data is ever passed to innerHTML.
  var ICONS = {
    ok: '<svg viewBox="0 0 16 16" aria-hidden="true" focusable="false"><path d="M3 8.5l3.2 3.2L13 4.8" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    bad: '<svg viewBox="0 0 16 16" aria-hidden="true" focusable="false"><path d="M4 4l8 8M12 4l-8 8" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
    fire: '<svg viewBox="0 0 16 16" aria-hidden="true" focusable="false"><circle cx="8" cy="8" r="4.2" fill="currentColor"/></svg>',
    quiet: '<svg viewBox="0 0 16 16" aria-hidden="true" focusable="false"><circle cx="8" cy="8" r="3.6" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>'
  };

  function icon(name) {
    var span = h('span', { class: 'icon' });
    span.innerHTML = ICONS[name];
    return span;
  }

  function chip(kind, label) {
    return h('span', { class: 'chip chip--' + kind }, icon(kind === 'quiet' ? 'quiet' : kind), label);
  }

  document.querySelectorAll('[data-icon]').forEach(function (el) { el.innerHTML = ICONS[el.getAttribute('data-icon')]; });

  // --------------------------------------------------------------- the model

  var rules = data.rules.map(function (rule) {
    var match = null;
    var error = null;
    try { match = DAC.compileDetection(rule.detection); } catch (err) { error = err.message; }
    return Object.assign({}, rule, { match: match, compileError: error });
  });

  var logs = [];
  data.rules.forEach(function (rule) {
    rule.cases.forEach(function (c) {
      logs.push({
        owner: rule.slug, kind: c.kind, name: c.name, file: c.file, event: c.event,
        pythonMatched: c.matched, key: rule.slug + '/' + c.kind + '/' + c.name
      });
    });
  });

  function fires(rule, event) { return rule.match ? Boolean(rule.match(event)) : false; }

  // --------------------------------------------------------------- the verdict

  function renderVerdict() {
    var total = rules.length;
    var failing = rules.filter(function (r) { return !r.passed; });
    var heading;
    if (total === 0) heading = 'No rules found.';
    else if (data.passed) {
      heading = total === 1
        ? 'The detection catches its attack logs and ignores the benign ones.'
        : 'All ' + total + ' detections catch their attack logs and ignore the benign ones.';
    } else if (failing.length > 0) {
      heading = failing.length + ' of ' + plural(total, 'detection', 'detections') + (failing.length === 1 ? ' is' : ' are') + ' failing.';
    } else {
      heading = 'The detections pass, but the repository has problems to fix.';
    }
    $('#verdict').textContent = heading;

    var s = data.summary;
    var built = data.commit === 'local' ? 'Built locally on ' + data.generated_at : 'Built from commit ' + data.commit + ' on ' + data.generated_at;
    var status = h('span', { class: 'status' + (data.passed ? '' : ' status--bad') }, data.passed ? 'Passing' : 'Failing');
    clear($('#meta'));
    $('#meta').append(status, h('span', null,
      built + '. ' + plural(s.rules, 'rule', 'rules') + ', ' + plural(s.logs, 'log', 'logs') +
      ' (' + s.malicious + ' malicious, ' + s.benign + ' benign), ' + plural(s.techniques, 'ATT&CK technique', 'ATT&CK techniques') + '.'));

    var problems = [];
    data.global_problems.forEach(function (p) { problems.push(p); });
    data.fp_violations.forEach(function (v) { problems.push(v.rule + ' fires on the benign log ' + v.log); });
    var list = $('#problems');
    clear(list);
    problems.forEach(function (p) { list.append(h('li', null, p)); });
    list.hidden = problems.length === 0;

    // Integrity check: the in-page engine must reproduce Python's verdict for every owned log.
    var disagreements = logs.filter(function (log) {
      var owner = rules.find(function (r) { return r.slug === log.owner; });
      return owner && owner.match && fires(owner, log.event) !== log.pythonMatched;
    }).length;
    var warning = $('#engine-warning');
    if (disagreements > 0) {
      warning.textContent = 'The engine in this page disagrees with the Python results for ' + plural(disagreements, 'log', 'logs') +
        '. The matrix below is computed in your browser, so treat it with care and check the parity tests.';
      warning.hidden = false;
    }

    if (data.repo_url) {
      var link = $('#repo-link');
      link.href = data.repo_url;
      link.hidden = false;
    }
  }

  // --------------------------------------------------------------- the matrix

  function verdictFor(rule, log) {
    var fired = fires(rule, log.event);
    var own = log.owner === rule.slug;
    if (log.kind === 'malicious') {
      if (own) return fired ? { kind: 'ok', label: 'Detected' } : { kind: 'bad', label: 'Missed' };
      return fired ? { kind: 'fire', label: 'Also fires' } : { kind: 'none', label: 'Quiet' };
    }
    if (fired) return { kind: 'bad', label: 'False alarm' };
    return own ? { kind: 'ok', label: 'Clean' } : { kind: 'dot', label: 'Quiet' };
  }

  function cell(rule, log) {
    var v = verdictFor(rule, log);
    if (v.kind === 'dot') return [h('span', { class: 'dot', 'aria-hidden': 'true' }), h('span', { class: 'sr-only' }, v.label)];
    if (v.kind === 'none') return h('span', { class: 'sr-only' }, v.label);
    return chip(v.kind, v.label);
  }

  function renderMatrix() {
    var host = $('#matrix');
    clear(host);
    if (rules.length === 0) { host.append(h('p', { class: 'result-note' }, 'Add a rule under rules/ to see it here.')); return; }

    var table = h('table', { class: 'mx' });
    table.append(h('caption', { class: 'sr-only' },
      'Each row is a test log and each column is a rule. A chip marks the result for the rule that owns the log. A dot means another rule stayed quiet.'));

    var headRow = h('tr', null, h('th', { class: 'mx-corner', scope: 'col' }, 'Test log'));
    rules.forEach(function (rule) {
      headRow.append(h('th', { class: 'mx-col', scope: 'col' },
        h('a', { href: '#rule-' + rule.slug }, rule.title),
        h('span', { class: 'mx-sev' }, capitalise(rule.level) + ' severity')));
    });
    table.append(h('thead', null, headRow));

    [
      { kind: 'malicious', title: 'Malicious logs: the rule that owns the log must fire' },
      { kind: 'benign', title: 'Benign logs: no rule may fire' }
    ].forEach(function (group) {
      var members = logs.filter(function (log) { return log.kind === group.kind; });
      if (members.length === 0) return;
      var body = h('tbody');
      body.append(h('tr', null, h('th', { class: 'mx-group', colspan: rules.length + 1, scope: 'rowgroup' }, group.title)));
      members.forEach(function (log) {
        var row = h('tr', null, h('th', { class: 'mx-log', scope: 'row' },
          h('button', {
            type: 'button', class: 'link-button', title: log.file + ' (open in the tester)',
            onclick: function () { openLog(log.key, true); }
          }, log.name)));
        rules.forEach(function (rule) { row.append(h('td', { class: 'mx-cell' }, cell(rule, log))); });
        body.append(row);
      });
      table.append(body);
    });
    host.append(table);
  }

  // --------------------------------------------------------------- the tester

  var input = $('#log-input');
  var select = $('#log-select');
  var result = $('#log-result');

  function renderResult() {
    clear(result);
    var text = input.value.trim();
    if (!text) { result.append(h('p', { class: 'result-note' }, 'Paste a JSON log to see which rules fire.')); return; }
    var event;
    try { event = JSON.parse(text); }
    catch (err) { result.append(h('p', { class: 'result-error' }, 'This is not valid JSON: ' + err.message)); return; }
    if (event === null || typeof event !== 'object' || Array.isArray(event)) {
      result.append(h('p', { class: 'result-error' }, 'A log must be one JSON object.'));
      return;
    }
    var rows = rules.map(function (rule) { return { rule: rule, fired: fires(rule, event) }; });
    var hits = rows.filter(function (row) { return row.fired; }).length;
    result.append(h('p', { class: 'result-line' }, hits === 0 ? 'No rule fires on this log.' : hits + ' of ' + plural(rules.length, 'rule fires', 'rules fire') + ' on this log.'));
    var list = h('ul', { class: 'result-list' });
    rows.forEach(function (row) {
      list.append(h('li', { class: 'result-item' },
        h('a', { class: 'result-name', href: '#rule-' + row.rule.slug }, row.rule.title),
        row.fired ? chip('fire', 'Fires') : chip('quiet', 'Quiet')));
    });
    result.append(list);
  }

  function openLog(key, scroll) {
    var log = logs.find(function (l) { return l.key === key; });
    if (!log) return;
    input.value = JSON.stringify(log.event, null, 2);
    select.value = key;
    renderResult();
    if (scroll) {
      var calm = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      $('#tester').scrollIntoView({ behavior: calm ? 'auto' : 'smooth', block: 'start' });
      input.focus({ preventScroll: true });
    }
  }

  function renderTester() {
    clear(select);
    select.append(h('option', { value: '' }, 'Choose a log'));
    ['malicious', 'benign'].forEach(function (kind) {
      var members = logs.filter(function (log) { return log.kind === kind; });
      if (members.length === 0) return;
      var group = h('optgroup', { label: capitalise(kind) + ' logs' });
      members.forEach(function (log) { group.append(h('option', { value: log.key }, log.name)); });
      select.append(group);
    });
    select.addEventListener('change', function () { if (select.value) openLog(select.value, false); });
    input.addEventListener('input', function () { select.value = ''; renderResult(); });
    var first = logs.find(function (log) { return log.kind === 'malicious'; });
    if (first) openLog(first.key, false); else renderResult();
  }

  // --------------------------------------------------------------- coverage

  function renderCoverage() {
    var covered = data.tactics.filter(function (t) { return t.count > 0; }).length;
    $('#coverage-summary').textContent = covered + ' of ' + data.tactics.length +
      ' ATT&CK tactics have a rule. The empty ones are where to write the next detection.';
    var list = $('#coverage');
    clear(list);
    data.tactics.forEach(function (tactic) {
      var owners = rules.filter(function (r) { return r.tactics.some(function (t) { return t.id === tactic.id; }); });
      var item = h('li', { class: 'kill-item' + (owners.length ? ' kill-item--hit' : '') },
        h('span', { class: 'kill-name' }, tactic.name));
      if (owners.length) {
        item.append(h('ul', { class: 'kill-rules' }, owners.map(function (r) {
          return h('li', null, h('a', { href: '#rule-' + r.slug }, r.title));
        })));
      } else {
        item.append(h('div', { class: 'kill-rules' }, 'No rule yet'));
      }
      list.append(item);
    });
  }

  // --------------------------------------------------------------- the rules

  function facts(rule) {
    var source = [rule.logsource.product, rule.logsource.service, rule.logsource.category].filter(Boolean).join(' / ');
    var techniques = rule.techniques.map(function (t, i) {
      return [i ? ', ' : '', h('a', { class: 'tech', href: t.url, rel: 'noopener' }, t.id)];
    });
    return h('dl', { class: 'facts' },
      h('dt', null, 'Severity'), h('dd', null, capitalise(rule.level)),
      h('dt', null, 'Status'), h('dd', null, capitalise(rule.status)),
      h('dt', null, 'Log source'), h('dd', null, source),
      h('dt', null, 'ATT&CK'), h('dd', null, rule.tactics.map(function (t) { return t.name; }).join(', '), ' (', techniques, ')'),
      h('dt', null, 'Author'), h('dd', null, rule.author + ', ' + rule.date),
      h('dt', null, 'File'), h('dd', null, h('span', { class: 'mono' }, rule.file)));
  }

  function renderRules() {
    var host = $('#rule-list');
    clear(host);
    rules.forEach(function (rule) {
      var caseItems = rule.cases.map(function (c) {
        var label = c.passed ? (c.kind === 'malicious' ? 'Detected' : 'Clean') : (c.kind === 'malicious' ? 'Missed' : 'False alarm');
        return h('details', { class: 'disclosure disclosure--nested' },
          h('summary', null,
            h('span', { class: 'case-kind' }, capitalise(c.kind)),
            h('span', { class: 'mono' }, c.name),
            chip(c.passed ? 'ok' : 'bad', label)),
          h('pre', { class: 'code' }, JSON.stringify(c.event, null, 2)));
      });

      host.append(h('article', { class: 'rule', id: 'rule-' + rule.slug },
        h('div', { class: 'rule-head' },
          h('h3', { class: 'rule-title' }, rule.title),
          rule.passed ? chip('ok', 'Passing') : chip('bad', 'Failing')),
        h('p', { class: 'rule-desc' }, rule.description),
        facts(rule),
        rule.problems.length ? h('ul', { class: 'problems' }, rule.problems.map(function (p) { return h('li', null, p); })) : null,
        rule.falsepositives.length ? [
          h('p', { class: 'fp-title' }, 'Known false positives'),
          h('ul', { class: 'fp-list' }, rule.falsepositives.map(function (fp) { return h('li', null, fp); }))
        ] : null,
        h('details', { class: 'disclosure' },
          h('summary', null, 'Rule file'),
          h('pre', { class: 'code' }, rule.yaml)),
        h('details', { class: 'disclosure' },
          h('summary', null, 'Test logs (' + rule.cases.length + ')'),
          caseItems)));
    });
  }

  // ------------------------------------------------------------------- theme

  var toggle = $('#theme-toggle');
  function isDark() {
    var forced = root.getAttribute('data-theme');
    if (forced) return forced === 'dark';
    return Boolean(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
  }
  function syncToggle() {
    toggle.textContent = isDark() ? 'Light mode' : 'Dark mode';
    toggle.setAttribute('aria-pressed', String(isDark()));
  }
  toggle.addEventListener('click', function () {
    var next = isDark() ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    try { localStorage.setItem('dac-theme', next); } catch (err) { /* storage can be blocked */ }
    syncToggle();
  });
  syncToggle();

  // ------------------------------------------------------------------- go

  renderVerdict();
  renderMatrix();
  renderTester();
  renderCoverage();
  renderRules();
})();
