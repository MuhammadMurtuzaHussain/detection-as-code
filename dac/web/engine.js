/*
 * JavaScript port of dac/engine.py: the same strict Sigma subset, for the browser and Node.
 * Keep the two in step. tests/engine_vectors.json and tests/parity.test.js fail CI if they drift.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.DAC = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  class SigmaError extends Error {
    constructor(message) { super(message); this.name = 'SigmaError'; }
  }
  class UnsupportedFeature extends SigmaError {
    constructor(message) { super(message); this.name = 'UnsupportedFeature'; }
  }

  const MISSING = Symbol('missing');
  const MATCH_MODIFIERS = ['contains', 'startswith', 'endswith', 're'];
  const REGEX_FLAGS = ['i', 'm', 's'];
  const has = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

  // ------------------------------------------------------------------ fields

  function parseField(key) {
    const parts = key.split('|');
    const field = parts[0];
    if (!field) throw new SigmaError(`'${key}': empty field name`);
    let match = null;
    let requireAll = false;
    let flags = '';
    for (const modifier of parts.slice(1)) {
      if (MATCH_MODIFIERS.includes(modifier)) {
        if (match) throw new SigmaError(`'${key}': only one of contains/startswith/endswith/re is allowed`);
        match = modifier;
      } else if (modifier === 'all') {
        requireAll = true;
      } else if (REGEX_FLAGS.includes(modifier)) {
        if (match !== 're') throw new SigmaError(`'${key}': regex flag '${modifier}' is only valid after 're'`);
        if (!flags.includes(modifier)) flags += modifier;
      } else {
        throw new UnsupportedFeature(`'${key}': modifier '${modifier}' is not supported`);
      }
    }
    return { field, match, requireAll, flags };
  }

  function lookup(event, field) {
    if (has(event, field)) return event[field];
    let current = event;
    for (const part of field.split('.')) {
      if (current !== null && typeof current === 'object' && !Array.isArray(current) && has(current, part)) {
        current = current[part];
      } else {
        return MISSING;
      }
    }
    return current;
  }

  function escapeRegex(text) {
    return text.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  }

  function globToRegex(pattern) {
    let out = '';
    let i = 0;
    while (i < pattern.length) {
      const ch = pattern[i];
      if (ch === '\\' && i + 1 < pattern.length) {
        const next = pattern[i + 1];
        if (next === '*' || next === '?') { out += escapeRegex(next); i += 2; continue; }
        if (next === '\\' && i + 2 < pattern.length && (pattern[i + 2] === '*' || pattern[i + 2] === '?')) {
          out += escapeRegex('\\'); i += 2; continue;
        }
      }
      if (ch === '*') out += '.*';
      else if (ch === '?') out += '.';
      else out += escapeRegex(ch);
      i += 1;
    }
    return out;
  }

  function toStr(value) {
    if (typeof value === 'string') return value;
    if (typeof value === 'boolean') return value ? 'True' : 'False';
    return String(value);
  }

  function stringTest(value, modifier, flags) {
    if (modifier === 're') {
      let source = value;
      let applied = flags;
      const inline = /^\(\?([ims]+)\)/.exec(source);
      if (inline) {
        for (const flag of inline[1]) if (!applied.includes(flag)) applied += flag;
        source = source.slice(inline[0].length);
      }
      let pattern;
      try { pattern = new RegExp(source, applied); }
      catch (err) { throw new SigmaError(`invalid regular expression ${JSON.stringify(value)}: ${err.message}`); }
      return (text) => pattern.test(text);
    }
    const body = globToRegex(value);
    let source;
    if (modifier === 'contains') source = body;
    else if (modifier === 'startswith') source = '^(?:' + body + ')';
    else if (modifier === 'endswith') source = '(?:' + body + ')$';
    else source = '^(?:' + body + ')$';
    const pattern = new RegExp(source, 'is');
    return (text) => pattern.test(text);
  }

  function valueMatcher(key, raw, modifier, flags) {
    if (raw === null) {
      if (modifier) throw new SigmaError(`'${key}': null cannot be combined with '${modifier}'`);
      return (found) => found === MISSING || found === null;
    }
    if (typeof raw === 'object') throw new SigmaError(`'${key}': nested values are not allowed here`);
    const test = stringTest(toStr(raw), modifier, flags);
    return (found) => {
      if (found === MISSING || found === null) return false;
      if (Array.isArray(found)) return found.some((item) => test(toStr(item)));
      return test(toStr(found));
    };
  }

  function compileField(key, spec) {
    const { field, match, requireAll, flags } = parseField(key);
    const values = Array.isArray(spec) ? spec : [spec];
    if (values.length === 0) throw new SigmaError(`'${key}': empty value list`);
    const matchers = values.map((value) => valueMatcher(key, value, match, flags));
    return (event) => {
      const found = lookup(event, field);
      return requireAll ? matchers.every((m) => m(found)) : matchers.some((m) => m(found));
    };
  }

  function compileSelection(name, body) {
    if (body !== null && typeof body === 'object' && !Array.isArray(body)) {
      const keys = Object.keys(body);
      if (keys.length === 0) throw new SigmaError(`selection '${name}' is empty and would match every event`);
      const predicates = keys.map((key) => compileField(key, body[key]));
      return (event) => predicates.every((p) => p(event));
    }
    if (Array.isArray(body) && body.length > 0 &&
        body.every((item) => item !== null && typeof item === 'object' && !Array.isArray(item))) {
      const alternatives = body.map((item) => compileSelection(name, item));
      return (event) => alternatives.some((p) => p(event));
    }
    throw new UnsupportedFeature(`selection '${name}': keyword (free-text) searches are not supported`);
  }

  // -------------------------------------------------------------- conditions

  const anyOf = (predicates) => (event) => predicates.some((p) => p(event));
  const allOf = (predicates) => (event) => predicates.every((p) => p(event));

  class ConditionParser {
    constructor(text, selections) {
      if (text.includes('|')) throw new UnsupportedFeature('aggregations (count, near, ...) are not supported');
      this.tokens = text.match(/\(|\)|[^\s()]+/g) || [];
      this.pos = 0;
      this.selections = selections; // Map: name -> predicate
    }
    peek() { return this.pos < this.tokens.length ? this.tokens[this.pos] : null; }
    peekWord() { const t = this.peek(); return t === null ? '' : t.toLowerCase(); }
    take() { const t = this.peek(); this.pos += 1; return t; }

    parse() {
      if (this.tokens.length === 0) throw new SigmaError('condition is empty');
      const node = this.or();
      if (this.peek() !== null) throw new SigmaError(`unexpected '${this.peek()}' in condition`);
      return node;
    }
    or() {
      const parts = [this.and()];
      while (this.peekWord() === 'or') { this.take(); parts.push(this.and()); }
      return parts.length === 1 ? parts[0] : anyOf(parts);
    }
    and() {
      const parts = [this.not()];
      while (this.peekWord() === 'and') { this.take(); parts.push(this.not()); }
      return parts.length === 1 ? parts[0] : allOf(parts);
    }
    not() {
      if (this.peekWord() === 'not') {
        this.take();
        const inner = this.not();
        return (event) => !inner(event);
      }
      return this.atom();
    }
    atom() {
      const token = this.take();
      if (token === null) throw new SigmaError('condition ended unexpectedly');
      if (token === '(') {
        const node = this.or();
        if (this.take() !== ')') throw new SigmaError("missing ')' in condition");
        return node;
      }
      const word = token.toLowerCase();
      if ((word === '1' || word === 'all') && this.peekWord() === 'of') {
        this.take();
        const target = this.take();
        if (target === null) throw new SigmaError(`'${token} of' needs a selection name, pattern or 'them'`);
        const predicates = this.resolve(target).map((name) => this.selections.get(name));
        return token === '1' ? anyOf(predicates) : allOf(predicates);
      }
      if (word === 'and' || word === 'or' || token === ')') throw new SigmaError(`unexpected '${token}' in condition`);
      if (!this.selections.has(token)) throw new SigmaError(`condition references unknown selection '${token}'`);
      return this.selections.get(token);
    }
    resolve(target) {
      const names = [...this.selections.keys()];
      let found;
      if (target.toLowerCase() === 'them') found = names;
      else {
        const pattern = new RegExp('^(?:' + globToRegex(target) + ')$', 's');
        found = names.filter((name) => pattern.test(name));
      }
      if (found.length === 0) throw new SigmaError(`'${target}' matches no selection`);
      return found;
    }
  }

  // ------------------------------------------------------------------ public

  function compileDetection(detection) {
    if (detection === null || typeof detection !== 'object' || Array.isArray(detection) || !has(detection, 'condition')) {
      throw new SigmaError("detection needs a 'condition'");
    }
    if (has(detection, 'timeframe')) throw new UnsupportedFeature("'timeframe' (aggregation) is not supported");
    const selections = new Map();
    for (const name of Object.keys(detection)) {
      if (name !== 'condition') selections.set(name, compileSelection(name, detection[name]));
    }
    if (selections.size === 0) throw new SigmaError('detection has no selections');
    let conditions = detection.condition;
    if (!Array.isArray(conditions)) conditions = [conditions];
    if (!conditions.every((c) => typeof c === 'string')) throw new SigmaError('condition must be a string or a list of strings');
    const compiled = conditions.map((c) => new ConditionParser(c, selections).parse());
    return compiled.length === 1 ? compiled[0] : anyOf(compiled);
  }

  return { compileDetection, SigmaError, UnsupportedFeature };
});
