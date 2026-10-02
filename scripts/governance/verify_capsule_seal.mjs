#!/usr/bin/env node

/**
 * Synthesis CMS mini — Command Capsule Seal & Payload Hash Verifier
 * 
 * Cryptographic payload hash verification using RFC 8785 JSON Canonicalization
 * Scheme (JCS) and strict I-JSON / duplicate-key input parsing.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import child_process from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Reuse production functions from existing structural validator
import {
  loadSchema,
  validateCapsuleComplete,
  buildSampleProvisionalCapsule
} from './validate_command_capsule.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ============================================================
// STRICT I-JSON & DUPLICATE KEY PARSER
// ============================================================

export function parseStrictIJson(rawText, maxDepth = 50, maxLength = 1024 * 1024) {
  if (typeof rawText !== 'string') {
    throw new Error('I_JSON_ERROR: Raw input must be a string');
  }
  if (rawText.length > maxLength) {
    throw new Error(`I_JSON_ERROR: Oversized input (${rawText.length} bytes > limit ${maxLength})`);
  }

  // Check lone surrogates in input text
  if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(rawText)) {
    throw new Error('I_JSON_ERROR: Lone surrogate code point detected in raw input');
  }

  let pos = 0;

  function skipWhitespace() {
    while (pos < rawText.length) {
      const c = rawText[pos];
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r') {
        pos++;
      } else {
        break;
      }
    }
  }

  function parseString() {
    if (rawText[pos] !== '"') throw new Error(`I_JSON_ERROR: Expected string at position ${pos}`);
    pos++;
    let result = '';
    while (pos < rawText.length) {
      const c = rawText[pos];
      if (c === '"') {
        pos++;
        return result;
      }
      if (c === '\\') {
        pos++;
        if (pos >= rawText.length) throw new Error('I_JSON_ERROR: Unterminated escape sequence');
        const esc = rawText[pos];
        if (esc === '"' || esc === '\\' || esc === '/') {
          result += esc;
          pos++;
        } else if (esc === 'b') { result += '\b'; pos++; }
        else if (esc === 'f') { result += '\f'; pos++; }
        else if (esc === 'n') { result += '\n'; pos++; }
        else if (esc === 'r') { result += '\r'; pos++; }
        else if (esc === 't') { result += '\t'; pos++; }
        else if (esc === 'u') {
          pos++;
          const hex = rawText.slice(pos, pos + 4);
          if (hex.length < 4 || !/^[0-9a-fA-F]{4}$/.test(hex)) {
            throw new Error(`I_JSON_ERROR: Invalid unicode escape \\u${hex}`);
          }
          const code = parseInt(hex, 16);
          if (code >= 0xD800 && code <= 0xDBFF) {
            pos += 4;
            if (rawText.slice(pos, pos + 2) !== '\\u') {
              throw new Error('I_JSON_ERROR: Lone high surrogate in string escape');
            }
            pos += 2;
            const lowHex = rawText.slice(pos, pos + 4);
            const lowCode = parseInt(lowHex, 16);
            if (lowCode < 0xDC00 || lowCode > 0xDFFF) {
              throw new Error('I_JSON_ERROR: Invalid low surrogate in string escape');
            }
            result += String.fromCharCode(code, lowCode);
            pos += 4;
          } else if (code >= 0xDC00 && code <= 0xDFFF) {
            throw new Error('I_JSON_ERROR: Lone low surrogate in string escape');
          } else {
            result += String.fromCharCode(code);
            pos += 4;
          }
        } else {
          throw new Error(`I_JSON_ERROR: Invalid escape character \\${esc}`);
        }
      } else {
        if (c.charCodeAt(0) < 0x20) {
          throw new Error(`I_JSON_ERROR: Unescaped control character in string: ${c.charCodeAt(0)}`);
        }
        result += c;
        pos++;
      }
    }
    throw new Error('I_JSON_ERROR: Unterminated string');
  }

  function parseNumber() {
    const start = pos;
    if (rawText[pos] === '-') pos++;
    if (pos >= rawText.length) throw new Error('I_JSON_ERROR: Invalid number');
    if (rawText[pos] === '0') {
      pos++;
    } else if (rawText[pos] >= '1' && rawText[pos] <= '9') {
      while (pos < rawText.length && rawText[pos] >= '0' && rawText[pos] <= '9') pos++;
    } else {
      throw new Error(`I_JSON_ERROR: Invalid number character at position ${pos}`);
    }
    if (pos < rawText.length && rawText[pos] === '.') {
      pos++;
      if (pos >= rawText.length || !(rawText[pos] >= '0' && rawText[pos] <= '9')) {
        throw new Error('I_JSON_ERROR: Invalid fractional number');
      }
      while (pos < rawText.length && rawText[pos] >= '0' && rawText[pos] <= '9') pos++;
    }
    if (pos < rawText.length && (rawText[pos] === 'e' || rawText[pos] === 'E')) {
      pos++;
      if (pos < rawText.length && (rawText[pos] === '+' || rawText[pos] === '-')) pos++;
      if (pos >= rawText.length || !(rawText[pos] >= '0' && rawText[pos] <= '9')) {
        throw new Error('I_JSON_ERROR: Invalid exponent in number');
      }
      while (pos < rawText.length && rawText[pos] >= '0' && rawText[pos] <= '9') pos++;
    }
    const numStr = rawText.slice(start, pos);
    const num = Number(numStr);
    if (!Number.isFinite(num)) throw new Error(`I_JSON_ERROR: Unsafe number (NaN or Infinity): ${numStr}`);
    if (!numStr.includes('.') && !numStr.includes('e') && !numStr.includes('E')) {
      if (num > Number.MAX_SAFE_INTEGER || num < Number.MIN_SAFE_INTEGER) {
        throw new Error(`I_JSON_ERROR: Unsafe integer exceeding IEEE-754 precision limits: ${numStr}`);
      }
    }
    return num;
  }

  function parseValue(depth) {
    if (depth > maxDepth) {
      throw new Error(`I_JSON_ERROR: Excessive nesting depth (${depth} > limit ${maxDepth})`);
    }
    skipWhitespace();
    if (pos >= rawText.length) throw new Error('I_JSON_ERROR: Unexpected end of input');
    const c = rawText[pos];
    if (c === '{') return parseObject(depth + 1);
    if (c === '[') return parseArray(depth + 1);
    if (c === '"') return parseString();
    if (c === '-' || (c >= '0' && c <= '9')) return parseNumber();
    if (rawText.startsWith('true', pos)) { pos += 4; return true; }
    if (rawText.startsWith('false', pos)) { pos += 5; return false; }
    if (rawText.startsWith('null', pos)) { pos += 4; return null; }
    throw new Error(`I_JSON_ERROR: Unexpected token "${c}" at position ${pos}`);
  }

  function parseObject(depth) {
    pos++;
    skipWhitespace();
    const obj = Object.create(null);
    const seenKeys = new Set();
    if (pos < rawText.length && rawText[pos] === '}') {
      pos++;
      return obj;
    }
    while (pos < rawText.length) {
      skipWhitespace();
      if (rawText[pos] !== '"') throw new Error(`I_JSON_ERROR: Expected string key at position ${pos}`);
      const key = parseString();
      if (seenKeys.has(key)) {
        throw new Error(`I_JSON_ERROR: Duplicate object key detected: "${key}"`);
      }
      seenKeys.add(key);
      skipWhitespace();
      if (pos >= rawText.length || rawText[pos] !== ':') {
        throw new Error(`I_JSON_ERROR: Expected ":" after key at position ${pos}`);
      }
      pos++;
      const val = parseValue(depth);
      Object.defineProperty(obj, key, {
        value: val,
        writable: true,
        enumerable: true,
        configurable: true
      });
      skipWhitespace();
      if (pos < rawText.length && rawText[pos] === ',') {
        pos++;
      } else if (pos < rawText.length && rawText[pos] === '}') {
        pos++;
        return obj;
      } else {
        throw new Error(`I_JSON_ERROR: Expected "," or "}" at position ${pos}`);
      }
    }
    throw new Error('I_JSON_ERROR: Unterminated object');
  }

  function parseArray(depth) {
    pos++;
    skipWhitespace();
    const arr = [];
    if (pos < rawText.length && rawText[pos] === ']') {
      pos++;
      return arr;
    }
    while (pos < rawText.length) {
      arr.push(parseValue(depth));
      skipWhitespace();
      if (pos < rawText.length && rawText[pos] === ',') {
        pos++;
      } else if (pos < rawText.length && rawText[pos] === ']') {
        pos++;
        return arr;
      } else {
        throw new Error(`I_JSON_ERROR: Expected "," or "]" at position ${pos}`);
      }
    }
    throw new Error('I_JSON_ERROR: Unterminated array');
  }

  const result = parseValue(0);
  skipWhitespace();
  if (pos < rawText.length) {
    throw new Error(`I_JSON_ERROR: Trailing data after JSON root at position ${pos}`);
  }
  return result;
}

// ============================================================
// RFC 8785 CANONICALIZATION SCHEME (JCS)
// ============================================================

export function canonicalizeRfc8785(data) {
  if (data === null) return 'null';
  if (typeof data === 'boolean') return data ? 'true' : 'false';
  if (typeof data === 'number') {
    if (!Number.isFinite(data)) {
      throw new Error('RFC8785_ERROR: Number is not finite (NaN or Infinity)');
    }
    if (Object.is(data, -0)) return '0';
    return data.toString();
  }
  if (typeof data === 'string') {
    if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(data)) {
      throw new Error('RFC8785_ERROR: Lone surrogate detected in string');
    }
    return JSON.stringify(data);
  }
  if (Array.isArray(data)) {
    return '[' + data.map(item => canonicalizeRfc8785(item)).join(',') + ']';
  }
  if (typeof data === 'object') {
    const keys = Object.keys(data).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const parts = [];
    for (const key of keys) {
      if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(key)) {
        throw new Error('RFC8785_ERROR: Lone surrogate in object key');
      }
      const val = data[key];
      if (val === undefined) continue;
      parts.push(JSON.stringify(key) + ':' + canonicalizeRfc8785(val));
    }
    return '{' + parts.join(',') + '}';
  }
  throw new Error(`RFC8785_ERROR: Unsupported data type "${typeof data}"`);
}

export function computePayloadSha256(payload) {
  const canonicalStr = canonicalizeRfc8785(payload);
  const payloadBytes = Buffer.from(canonicalStr, 'utf-8');
  return {
    canonicalStr,
    payloadBytes,
    sha256Hex: crypto.createHash('sha256').update(payloadBytes).digest('hex')
  };
}

export function timingSafeHexCompare(aHex, bHex) {
  if (typeof aHex !== 'string' || typeof bHex !== 'string') return false;
  if (!/^[0-9a-f]{64}$/.test(aHex) || !/^[0-9a-f]{64}$/.test(bHex)) return false;
  const aBuf = Buffer.from(aHex, 'hex');
  const bBuf = Buffer.from(bHex, 'hex');
  return crypto.timingSafeEqual(aBuf, bBuf);
}

// ============================================================
// CAPSULE VERIFICATION POLICY
// ============================================================

export function verifyCapsuleSeal(schema, capsule) {
  // 1. Mandatory structural & semantic schema validation
  const structRes = validateCapsuleComplete(schema, capsule);
  if (!structRes.valid) {
    return {
      valid: false,
      stage: structRes.stage || 'STRUCTURAL_SCHEMA',
      error: structRes.error,
      payloadHashMatch: false,
      isSealed: false
    };
  }

  const seal = capsule.seal;
  const payload = capsule.payload;

  // Unverified digital signatures policy: fail closed on non-null seal_signature
  if (seal.seal_signature !== null) {
    return {
      valid: false,
      stage: 'UNVERIFIED_SIGNATURE_REJECTED',
      error: 'Digital signature verification is not implemented; seal_signature must be null.',
      payloadHashMatch: false,
      isSealed: false
    };
  }

  // Handle PROVISIONAL capsule
  if (seal.status === 'PROVISIONAL') {
    return {
      valid: true,
      stage: 'PROVISIONAL_RECORD',
      isSealed: false,
      payloadHashMatch: false,
      status: 'STRUCTURE_VALID_PROVISIONAL',
      message: 'PROVISIONAL capsule validated structurally; PAYLOAD_HASH_NOT_SEALED'
    };
  }

  // Handle SEALED capsule
  if (seal.status === 'SEALED') {
    if (seal.hash_algorithm !== 'SHA-256') {
      return {
        valid: false,
        stage: 'SEAL_ALGORITHM',
        error: `Unsupported hash_algorithm: "${seal.hash_algorithm}", expected "SHA-256"`,
        payloadHashMatch: false,
        isSealed: true
      };
    }
    if (seal.canonicalization_algorithm !== 'RFC-8785') {
      return {
        valid: false,
        stage: 'CANONICALIZATION_ALGORITHM',
        error: `Unsupported canonicalization_algorithm: "${seal.canonicalization_algorithm}", expected "RFC-8785"`,
        payloadHashMatch: false,
        isSealed: true
      };
    }

    if (!seal.payload_sha256 || typeof seal.payload_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(seal.payload_sha256)) {
      return {
        valid: false,
        stage: 'SEAL_HASH_FORMAT',
        error: `SEALED capsule must contain a lowercase 64-character hex payload_sha256`,
        payloadHashMatch: false,
        isSealed: true
      };
    }

    // Compute expected RFC 8785 SHA-256
    let computed;
    try {
      computed = computePayloadSha256(payload);
    } catch (err) {
      return {
        valid: false,
        stage: 'CANONICALIZATION_FAILED',
        error: err.message,
        payloadHashMatch: false,
        isSealed: true
      };
    }

    const matches = timingSafeHexCompare(computed.sha256Hex, seal.payload_sha256);
    if (!matches) {
      return {
        valid: false,
        stage: 'PAYLOAD_HASH_MISMATCH',
        error: `Payload SHA-256 mismatch! Computed: ${computed.sha256Hex}, Sealed: ${seal.payload_sha256}`,
        payloadHashMatch: false,
        isSealed: true
      };
    }

    return {
      valid: true,
      stage: 'PAYLOAD_HASH_MATCH',
      isSealed: true,
      payloadHashMatch: true,
      computedSha256: computed.sha256Hex,
      status: 'PAYLOAD_HASH_MATCH',
      message: 'SEALED capsule payload matches independently computed RFC-8785 SHA-256 hash'
    };
  }

  return {
    valid: false,
    stage: 'UNKNOWN_SEAL_STATUS',
    error: `Unknown seal status: ${seal.status}`,
    payloadHashMatch: false,
    isSealed: false
  };
}

// ============================================================
// BEHAVIORAL SELF-TEST SUITE
// ============================================================

export function runSelfTests(repoRoot) {
  const schema = loadSchema(repoRoot);
  let positivePassed = 0;
  let negativePassed = 0;
  let failedTests = 0;

  function assertPositive(name, fn) {
    try {
      const res = fn();
      if (res.valid) {
        positivePassed++;
      } else {
        console.error(`FAIL: ${name} -> ${res.error || res.message}`);
        failedTests++;
      }
    } catch (err) {
      console.error(`FAIL (exception): ${name} -> ${err.message}`);
      failedTests++;
    }
  }

  function assertNegative(name, fn, expectedErrFragment) {
    try {
      const res = fn();
      if (!res.valid) {
        if (!expectedErrFragment || (res.error && res.error.includes(expectedErrFragment))) {
          negativePassed++;
        } else {
          console.error(`FAIL: ${name} -> wrong error message. Expected fragment "${expectedErrFragment}", got "${res.error}"`);
          failedTests++;
        }
      } else {
        console.error(`FAIL: ${name} -> expected invalid, but was accepted!`);
        failedTests++;
      }
    } catch (err) {
      if (expectedErrFragment && err.message.includes(expectedErrFragment)) {
        negativePassed++;
      } else {
        console.error(`FAIL (unexpected exception): ${name} -> ${err.message}`);
        failedTests++;
      }
    }
  }

  // POSITIVE TESTS
  // POSITIVE A: Canonicalization matches RFC 8785 published serialization example
  assertPositive('POSITIVE A: Canonicalization matches RFC 8785 published serialization example', () => {
    const inputJson = `{
   "numbers": [333333333.3333333, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
   "string": "\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\\"\\/",
   "literals": [null, true, false]
}`;
    const expected = "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"\u20ac$\\u000f\\nA\'B\\\"\\\\\\\\\\\"/\"}";
    const parsed = parseStrictIJson(inputJson);
    const actual = canonicalizeRfc8785(parsed);
    if (actual !== expected) {
      return { valid: false, error: `Canonical mismatch: got ${actual}, expected ${expected}` };
    }
    return { valid: true };
  });

  // POSITIVE B: Reordering object properties does not change calculated SHA-256
  assertPositive('POSITIVE B: Reordering object properties produces identical SHA-256', () => {
    const obj1 = { a: 1, b: 2, c: { x: 10, y: 20 } };
    const obj2 = { c: { y: 20, x: 10 }, b: 2, a: 1 };
    const hash1 = computePayloadSha256(obj1).sha256Hex;
    const hash2 = computePayloadSha256(obj2).sha256Hex;
    if (hash1 !== hash2) {
      return { valid: false, error: `Hash mismatch across property reordering: ${hash1} !== ${hash2}` };
    }
    return { valid: true };
  });

  // POSITIVE C: Changing insignificant source JSON whitespace does not change SHA-256
  assertPositive('POSITIVE C: Insignificant source whitespace changes produce identical SHA-256', () => {
    const rawCompact = '{"task_id":"SYN-MINI","count":42}';
    const rawSpaced = '{\n  "task_id" :  "SYN-MINI" ,\n  "count" : 42\n}';
    const parsed1 = parseStrictIJson(rawCompact);
    const parsed2 = parseStrictIJson(rawSpaced);
    const hash1 = computePayloadSha256(parsed1).sha256Hex;
    const hash2 = computePayloadSha256(parsed2).sha256Hex;
    if (hash1 !== hash2) {
      return { valid: false, error: 'Whitespace altered canonical hash' };
    }
    return { valid: true };
  });

  // POSITIVE D: Nested objects and arrays canonicalize correctly
  assertPositive('POSITIVE D: Nested objects and arrays canonicalize correctly', () => {
    const nested = {
      arr: [{ z: 1, a: 2 }, [3, 4]],
      obj: { nested: { k: 'val' } }
    };
    const c = canonicalizeRfc8785(nested);
    const expected = '{"arr":[{"a":2,"z":1},[3,4]],"obj":{"nested":{"k":"val"}}}';
    if (c !== expected) {
      return { valid: false, error: `Nested canonical mismatch: got ${c}` };
    }
    return { valid: true };
  });

  // POSITIVE E: Unicode and numeric-looking property names follow RFC 8785 UTF-16 ordering
  assertPositive('POSITIVE E: Unicode and numeric-looking keys follow RFC 8785 ordering', () => {
    const obj = { '10': 1, '2': 2, 'b': 3, 'B': 4, '\u00e9': 5, 'a': 6 };
    const c = canonicalizeRfc8785(obj);
    const expected = '{"10":1,"2":2,"B":4,"a":6,"b":3,"\u00e9":5}';
    if (c !== expected) {
      return { valid: false, error: `UTF-16 key ordering mismatch: got ${c}` };
    }
    return { valid: true };
  });

  // POSITIVE F: Structurally valid SEALED capsule with matching hash passes PAYLOAD_HASH_MATCH
  assertPositive('POSITIVE F: SEALED capsule with genuinely calculated hash passes PAYLOAD_HASH_MATCH', () => {
    const c = buildSampleProvisionalCapsule();
    c.seal.status = 'SEALED';
    c.seal.sealed_at = '2026-10-02T02:00:00Z';
    c.seal.sealed_by = 'jirisar7-eng';
    c.payload.lineage.parent_capsules[0].payload_sha256 = 'b'.repeat(64);
    const computed = computePayloadSha256(c.payload).sha256Hex;
    c.seal.payload_sha256 = computed;
    const res = verifyCapsuleSeal(schema, c);
    if (!res.valid || !res.payloadHashMatch) {
      return { valid: false, error: res.error || 'Expected payloadHashMatch true' };
    }
    return { valid: true };
  });

  // POSITIVE REAL 010: Actual committed root capsule 010 passes
  assertPositive('POSITIVE REAL 010: Actual committed root capsule 010 passes verification', () => {
    const capPath = path.join(repoRoot, '.synthesis', 'task-capsules', 'CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010.json');
    const raw = fs.readFileSync(capPath, 'utf-8');
    const parsed = parseStrictIJson(raw);
    const res = verifyCapsuleSeal(schema, parsed);
    if (!res.valid || !res.payloadHashMatch) {
      return { valid: false, error: res.error || 'Expected valid root capsule 010' };
    }
    return { valid: true };
  });

  // POSITIVE REAL 013: Actual committed child capsule 013 passes
  assertPositive('POSITIVE REAL 013: Actual committed child capsule 013 passes verification', () => {
    const capPath = path.join(repoRoot, '.synthesis', 'task-capsules', 'CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-013.json');
    const raw = fs.readFileSync(capPath, 'utf-8');
    const parsed = parseStrictIJson(raw);
    const res = verifyCapsuleSeal(schema, parsed);
    if (!res.valid || !res.payloadHashMatch) {
      return { valid: false, error: res.error || 'Expected valid child capsule 013' };
    }
    return { valid: true };
  });

  // POSITIVE G: Structurally valid PROVISIONAL capsule remains acceptable to structural validation without crypto PASS
  assertPositive('POSITIVE G: PROVISIONAL capsule validates structurally but is not cryptographically sealed', () => {
    const c = buildSampleProvisionalCapsule();
    const res = verifyCapsuleSeal(schema, c);
    if (!res.valid || res.payloadHashMatch || res.isSealed) {
      return { valid: false, error: 'PROVISIONAL capsule should have payloadHashMatch=false and isSealed=false' };
    }
    return { valid: true };
  });

  // POSITIVE H (PARSER_A): "__proto__" is preserved as an own property with null prototype
  assertPositive('POSITIVE H (PARSER_A): "__proto__" is preserved as an own property with null prototype', () => {
    const raw = '{"__proto__": {"injected": "val"}, "normal": 123}';
    const parsed = parseStrictIJson(raw);
    if (Object.getPrototypeOf(parsed) !== null) {
      return { valid: false, error: 'Parsed object prototype is not null' };
    }
    if (!Object.hasOwn(parsed, '__proto__')) {
      return { valid: false, error: '__proto__ is not an own property' };
    }
    if (!Object.keys(parsed).includes('__proto__')) {
      return { valid: false, error: '__proto__ not present in Object.keys' };
    }
    if (parsed.__proto__.injected !== 'val') {
      return { valid: false, error: 'Value of __proto__ was not preserved' };
    }
    return { valid: true };
  });

  // POSITIVE I (PARSER_B): "constructor", "prototype", "toString", "valueOf" are ordinary own properties
  assertPositive('POSITIVE I (PARSER_B): "constructor" and "toString" are preserved as ordinary own properties', () => {
    const raw = '{"constructor": "custom_ctor", "prototype": "custom_proto", "toString": "custom_str", "valueOf": 42}';
    const parsed = parseStrictIJson(raw);
    if (!Object.hasOwn(parsed, 'constructor') || parsed.constructor !== 'custom_ctor') {
      return { valid: false, error: 'constructor own property not preserved' };
    }
    if (!Object.hasOwn(parsed, 'prototype') || parsed.prototype !== 'custom_proto') {
      return { valid: false, error: 'prototype own property not preserved' };
    }
    if (!Object.hasOwn(parsed, 'toString') || parsed.toString !== 'custom_str') {
      return { valid: false, error: 'toString own property not preserved' };
    }
    if (!Object.hasOwn(parsed, 'valueOf') || parsed.valueOf !== 42) {
      return { valid: false, error: 'valueOf own property not preserved' };
    }
    return { valid: true };
  });

  // POSITIVE J (PARSER_C): Parsing does not mutate Object.prototype or any global prototype
  assertPositive('POSITIVE J (PARSER_C): Parsing does not mutate Object.prototype or any global prototype', () => {
    const beforeObjProto = Object.getOwnPropertyNames(Object.prototype);
    const raw = '{"__proto__": {"polluted": true, "admin": true}, "constructor": {"prototype": {"polluted": true}}}';
    const parsed = parseStrictIJson(raw);
    if (Object.prototype.polluted !== undefined || Object.prototype.admin !== undefined) {
      return { valid: false, error: 'Object.prototype was polluted!' };
    }
    if (({}).polluted !== undefined || ({}).admin !== undefined) {
      return { valid: false, error: 'Plain object prototype was polluted!' };
    }
    const afterObjProto = Object.getOwnPropertyNames(Object.prototype);
    if (beforeObjProto.length !== afterObjProto.length) {
      return { valid: false, error: 'Object.prototype property count changed' };
    }
    return { valid: true };
  });

  // POSITIVE K (PARSER_D): Nested JSON objects and objects inside arrays remain protected with null prototype
  assertPositive('POSITIVE K (PARSER_D): Nested JSON objects and objects inside arrays remain protected with null prototype', () => {
    const raw = '{"outer": {"nested": {"__proto__": {"deep": 1}}}, "list": [{"__proto__": "in_arr"}]}';
    const parsed = parseStrictIJson(raw);
    if (Object.getPrototypeOf(parsed.outer) !== null) {
      return { valid: false, error: 'parsed.outer prototype is not null' };
    }
    if (Object.getPrototypeOf(parsed.outer.nested) !== null) {
      return { valid: false, error: 'parsed.outer.nested prototype is not null' };
    }
    if (Object.getPrototypeOf(parsed.list[0]) !== null) {
      return { valid: false, error: 'parsed.list[0] prototype is not null' };
    }
    if (!Object.hasOwn(parsed.outer.nested, '__proto__')) {
      return { valid: false, error: 'nested __proto__ is not an own property' };
    }
    if (!Object.hasOwn(parsed.list[0], '__proto__') || parsed.list[0].__proto__ !== 'in_arr') {
      return { valid: false, error: 'array object __proto__ not preserved' };
    }
    return { valid: true };
  });

  // POSITIVE L (PARSER_E): Escaped "__proto__" (\u005f\u005fproto\u005f\u005f) is preserved as an own property
  assertPositive('POSITIVE L (PARSER_E): Escaped "__proto__" is preserved correctly as an own property', () => {
    const raw = '{"\u005f\u005fproto\u005f\u005f": "escaped_proto_val"}';
    const parsed = parseStrictIJson(raw);
    if (!Object.hasOwn(parsed, '__proto__')) {
      return { valid: false, error: 'Escaped __proto__ not preserved as own property' };
    }
    if (parsed.__proto__ !== 'escaped_proto_val') {
      return { valid: false, error: `Expected escaped_proto_val, got ${parsed.__proto__}` };
    }
    return { valid: true };
  });

  // POSITIVE M (PARSER_G): Canonicalization includes "__proto__" and sorts keys correctly
  assertPositive('POSITIVE M (PARSER_G): Canonicalization includes "__proto__" and sorts keys correctly', () => {
    const raw = '{"b": 2, "__proto__": "proto_val", "a": 1}';
    const parsed = parseStrictIJson(raw);
    const canonical = canonicalizeRfc8785(parsed);
    const expected = '{"__proto__":"proto_val","a":1,"b":2}';
    if (canonical !== expected) {
      return { valid: false, error: `Expected ${expected}, got ${canonical}` };
    }
    return { valid: true };
  });

  // POSITIVE N (PARSER_H): Changing the value of "__proto__" changes the canonical payload SHA-256
  assertPositive('POSITIVE N (PARSER_H): Changing the value of "__proto__" changes the canonical payload SHA-256', () => {
    const raw1 = '{"task_id":"SYN-MINI","__proto__":"version_1"}';
    const raw2 = '{"task_id":"SYN-MINI","__proto__":"version_2"}';
    const parsed1 = parseStrictIJson(raw1);
    const parsed2 = parseStrictIJson(raw2);
    const hash1 = computePayloadSha256(parsed1).sha256Hex;
    const hash2 = computePayloadSha256(parsed2).sha256Hex;
    if (hash1 === hash2) {
      return { valid: false, error: 'Changing __proto__ value failed to change SHA-256 hash!' };
    }
    return { valid: true };
  });

  // NEGATIVE TESTS
  // 1. Change one payload field without updating the hash
  assertNegative('1. Modified payload field without hash update causes mismatch', () => {
    const c = buildSampleProvisionalCapsule();
    c.seal.status = 'SEALED';
    c.seal.sealed_at = '2026-10-02T02:00:00Z';
    c.seal.sealed_by = 'jirisar7-eng';
    c.payload.lineage.parent_capsules[0].payload_sha256 = 'b'.repeat(64);
    c.seal.payload_sha256 = computePayloadSha256(c.payload).sha256Hex;
    // Tamper with payload
    c.payload.roadmap_step = '2/60 — TAMPERED';
    return verifyCapsuleSeal(schema, c);
  }, 'Payload SHA-256 mismatch');

  // 2. Replace expected hash with another valid-looking SHA-256
  assertNegative('2. Valid-looking but incorrect SHA-256 hash causes mismatch', () => {
    const c = buildSampleProvisionalCapsule();
    c.seal.status = 'SEALED';
    c.seal.sealed_at = '2026-10-02T02:00:00Z';
    c.seal.sealed_by = 'jirisar7-eng';
    c.payload.lineage.parent_capsules[0].payload_sha256 = 'b'.repeat(64);
    c.seal.payload_sha256 = 'c'.repeat(64);
    return verifyCapsuleSeal(schema, c);
  }, 'Payload SHA-256 mismatch');

  // 3. Null hash on a SEALED capsule
  assertNegative('3. Null hash on SEALED capsule rejected', () => {
    const c = buildSampleProvisionalCapsule();
    c.seal.status = 'SEALED';
    c.seal.sealed_at = '2026-10-02T02:00:00Z';
    c.seal.sealed_by = 'jirisar7-eng';
    c.payload.lineage.parent_capsules[0].payload_sha256 = 'b'.repeat(64);
    c.seal.payload_sha256 = null;
    return verifyCapsuleSeal(schema, c);
  }, 'Type mismatch');

  // 4. Invalid hash format
  assertNegative('4. Invalid hash format rejected', () => {
    const c = buildSampleProvisionalCapsule();
    c.seal.status = 'SEALED';
    c.seal.sealed_at = '2026-10-02T02:00:00Z';
    c.seal.sealed_by = 'jirisar7-eng';
    c.payload.lineage.parent_capsules[0].payload_sha256 = 'b'.repeat(64);
    c.seal.payload_sha256 = 'not-a-valid-sha';
    return verifyCapsuleSeal(schema, c);
  }, 'Pattern mismatch');

  // 5. Wrong hash algorithm
  assertNegative('5. Wrong hash algorithm rejected', () => {
    const c = buildSampleProvisionalCapsule();
    c.seal.status = 'SEALED';
    c.seal.hash_algorithm = 'MD5';
    c.seal.sealed_at = '2026-10-02T02:00:00Z';
    c.seal.sealed_by = 'jirisar7-eng';
    c.payload.lineage.parent_capsules[0].payload_sha256 = 'b'.repeat(64);
    c.seal.payload_sha256 = 'b'.repeat(64);
    return verifyCapsuleSeal(schema, c);
  }, 'Const value mismatch');

  // 6. Wrong canonicalization algorithm
  assertNegative('6. Wrong canonicalization algorithm rejected', () => {
    const c = buildSampleProvisionalCapsule();
    c.seal.status = 'SEALED';
    c.seal.canonicalization_algorithm = 'CUSTOM';
    c.seal.sealed_at = '2026-10-02T02:00:00Z';
    c.seal.sealed_by = 'jirisar7-eng';
    c.payload.lineage.parent_capsules[0].payload_sha256 = 'b'.repeat(64);
    c.seal.payload_sha256 = 'b'.repeat(64);
    return verifyCapsuleSeal(schema, c);
  }, 'Const value mismatch');

  // 7. Malformed JSON
  assertNegative('7. Malformed JSON text rejected by strict I-JSON parser', () => {
    try {
      parseStrictIJson('{ "malformed json');
      return { valid: true };
    } catch (e) {
      return { valid: false, error: e.message };
    }
  }, 'I_JSON_ERROR');

  // 8. Duplicate JSON object keys
  assertNegative('8. Duplicate JSON object keys rejected', () => {
    try {
      parseStrictIJson('{"task_id":"SYN-MINI","task_id":"DUPLICATE"}');
      return { valid: true };
    } catch (e) {
      return { valid: false, error: e.message };
    }
  }, 'Duplicate object key detected');

  // 9. Escaped-equivalent duplicate keys
  assertNegative('9. Escaped-equivalent duplicate keys rejected', () => {
    try {
      parseStrictIJson('{"\\u0074ask_id":"SYN-MINI","task_id":"DUPLICATE"}');
      return { valid: true };
    } catch (e) {
      return { valid: false, error: e.message };
    }
  }, 'Duplicate object key detected');

  // 10. Malformed Unicode / lone surrogate
  assertNegative('10. Lone UTF-16 surrogate rejected in I-JSON parsing', () => {
    try {
      parseStrictIJson('{"key":"\\uD800"}');
      return { valid: true };
    } catch (e) {
      return { valid: false, error: e.message };
    }
  }, 'Lone high surrogate');

  // 11. Unsafe numeric input
  assertNegative('11. Unsafe numeric input exceeding safe integer limits rejected', () => {
    try {
      parseStrictIJson('{"big": 9007199254740999999999999}');
      return { valid: true };
    } catch (e) {
      return { valid: false, error: e.message };
    }
  }, 'Unsafe integer exceeding IEEE-754');

  // 12. Invalid capsule rejected by existing structural validator
  assertNegative('12. Invalid capsule structure rejected before cryptographic check', () => {
    const c = buildSampleProvisionalCapsule();
    delete c.payload.task_id;
    return verifyCapsuleSeal(schema, c);
  }, 'Missing required property "task_id"');

  // 13. Changed Genesis anchor
  assertNegative('13. Changed Genesis anchor hash rejected by structural validator', () => {
    const c = buildSampleProvisionalCapsule();
    c.payload.lineage.genesis_anchor_reference.pinned_sha256 = '0'.repeat(64);
    return verifyCapsuleSeal(schema, c);
  }, 'Const value mismatch');

  // 14. Oversized or excessively nested input
  assertNegative('14. Excessively nested JSON input rejected', () => {
    let deeplyNested = '{"a":';
    for (let i = 0; i < 60; i++) deeplyNested += '{"b":';
    deeplyNested += '1';
    for (let i = 0; i < 61; i++) deeplyNested += '}';
    try {
      parseStrictIJson(deeplyNested, 50);
      return { valid: true };
    } catch (e) {
      return { valid: false, error: e.message };
    }
  }, 'Excessive nesting depth');

  // 15. Unknown or surplus CLI arguments
  assertNegative('15. Surplus CLI arguments rejected with nonzero exit status', () => {
    const testCases = [
      ['--self-test', '--extra'],
      ['--verify', 'capsule.json', '--extra'],
      ['--unknown-arg']
    ];
    for (const testArgs of testCases) {
      const run = child_process.spawnSync(process.execPath, [__filename, ...testArgs], { encoding: 'utf-8' });
      if (run.status === 0) {
        return { valid: true };
      }
    }
    return { valid: false, error: 'CLI_SURPLUS_ARGUMENTS_REJECTED' };
  }, 'CLI_SURPLUS_ARGUMENTS_REJECTED');

  // 16. Raw and escaped-equivalent duplicate "__proto__" keys rejected (PARSER_F)
  assertNegative('16. Raw and escaped-equivalent duplicate "__proto__" keys rejected', () => {
    try {
      parseStrictIJson('{"__proto__": 1, "\u005f\u005fproto\u005f\u005f": 2}');
      return { valid: true };
    } catch (e) {
      return { valid: false, error: e.message };
    }
  }, 'Duplicate object key detected: "__proto__"');

  // 17. Structurally valid SEALED capsule with matching hash but non-null seal_signature rejected (FAIL-CLOSED)
  assertNegative('17. Structurally valid SEALED capsule with non-null seal_signature rejected (UNVERIFIED_SIGNATURE_REJECTED)', () => {
    const c = buildSampleProvisionalCapsule();
    c.seal.status = 'SEALED';
    c.seal.sealed_at = '2026-10-02T02:00:00Z';
    c.seal.sealed_by = 'jirisar7-eng';
    c.payload.lineage.parent_capsules[0].payload_sha256 = 'b'.repeat(64);
    c.seal.payload_sha256 = computePayloadSha256(c.payload).sha256Hex;
    c.seal.seal_signature = 'dummy-sig';
    return verifyCapsuleSeal(schema, c);
  }, 'Digital signature verification is not implemented; seal_signature must be null.');

  // 18. Structurally valid PROVISIONAL capsule with non-null seal_signature rejected (FAIL-CLOSED)
  assertNegative('18. Structurally valid PROVISIONAL capsule with non-null seal_signature rejected (UNVERIFIED_SIGNATURE_REJECTED)', () => {
    const c = buildSampleProvisionalCapsule();
    c.seal.seal_signature = 'dummy-sig';
    return verifyCapsuleSeal(schema, c);
  }, 'Digital signature verification is not implemented; seal_signature must be null.');

  // 19. Production CLI execution rejects disposable fixture with non-null signature with nonzero exit status
  assertNegative('19. CLI execution rejects synthetic fixture with non-null signature (nonzero exit code)', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'syn-mini-seal-sig-test-'));
    const fixturePath = path.join(tmpDir, 'capsule-with-signature.json');
    try {
      const c = buildSampleProvisionalCapsule();
      c.seal.status = 'SEALED';
      c.seal.sealed_at = '2026-10-02T02:00:00Z';
      c.seal.sealed_by = 'jirisar7-eng';
      c.payload.lineage.parent_capsules[0].payload_sha256 = 'b'.repeat(64);
      c.seal.payload_sha256 = computePayloadSha256(c.payload).sha256Hex;
      c.seal.seal_signature = 'unverified-signature-claim-string';
      fs.writeFileSync(fixturePath, JSON.stringify(c, null, 2), 'utf-8');

      const run = child_process.spawnSync(process.execPath, [__filename, '--verify', fixturePath], { encoding: 'utf-8' });
      if (run.status === 0) {
        return { valid: true };
      }
      if (run.stderr.includes('UNVERIFIED_SIGNATURE_REJECTED') || run.stdout.includes('UNVERIFIED_SIGNATURE_REJECTED')) {
        return { valid: false, error: 'UNVERIFIED_SIGNATURE_REJECTED' };
      }
      return { valid: false, error: `CLI exited nonzero with stderr: ${run.stderr}` };
    } finally {
      if (fs.existsSync(tmpDir)) {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    }
  }, 'UNVERIFIED_SIGNATURE_REJECTED');

  return {
    positivePassed,
    negativePassed,
    failedTests
  };
}

// ============================================================
// CLI ENTRY POINT
// ============================================================

function main() {
  const args = process.argv.slice(2);
  const repoRoot = path.resolve(__dirname, '..', '..');

  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    if (args.length > 1) {
      console.error(`Error: Unsupported surplus arguments after --help: ${args.slice(1).join(', ')}`);
      process.exit(1);
    }
    console.log(`Synthesis CMS mini — Command Capsule Seal & Payload Hash Verifier`);
    console.log(`Usage:`);
    console.log(`  node scripts/governance/verify_capsule_seal.mjs --self-test`);
    console.log(`  node scripts/governance/verify_capsule_seal.mjs --verify <path-to-capsule.json>`);
    console.log(`  node scripts/governance/verify_capsule_seal.mjs --help`);
    process.exit(args.length === 0 ? 1 : 0);
  }

  if (args[0] === '--self-test') {
    if (args.length !== 1) {
      console.error(`Error: Unexpected arguments after --self-test: ${args.slice(1).join(', ')}`);
      process.exit(1);
    }
    console.log(`Running Command Capsule Seal Verifier self-tests...`);
    const results = runSelfTests(repoRoot);
    console.log(`POSITIVE_TESTS_PASSED: ${results.positivePassed}`);
    console.log(`NEGATIVE_TESTS_PASSED: ${results.negativePassed}`);
    console.log(`FAILED_TESTS: ${results.failedTests}`);
    console.log(`RFC8785_CANONICALIZATION_STATUS: ${results.failedTests === 0 ? 'PASS' : 'FAIL'}`);

    if (results.failedTests > 0 || results.positivePassed < 7 || results.negativePassed < 15) {
      process.exit(1);
    }
    process.exit(0);
  }

  if (args[0] === '--verify') {
    if (args.length !== 2) {
      console.error(`Error: --verify requires exactly one file path. Got ${args.length - 1} arguments.`);
      process.exit(1);
    }
    const targetFile = path.resolve(process.cwd(), args[1]);
    if (!fs.existsSync(targetFile)) {
      console.error(`Error: Capsule file not found: ${targetFile}`);
      process.exit(1);
    }

    try {
      const schema = loadSchema(repoRoot);
      const rawText = fs.readFileSync(targetFile, 'utf-8');
      const capsule = parseStrictIJson(rawText);
      const res = verifyCapsuleSeal(schema, capsule);

      if (!res.valid) {
        console.error(`VERIFICATION FAILED [${res.stage}]: ${res.error}`);
        process.exit(1);
      }

      if (res.isSealed) {
        console.log(`STRUCTURAL_VALIDATION: PASS`);
        console.log(`PAYLOAD_HASH_MATCH: YES`);
        console.log(`SIGNATURE_VERIFICATION: NOT_IMPLEMENTED`);
        console.log(`PARENT_CHAIN_VERIFICATION: NOT_IMPLEMENTED`);
        console.log(`LEDGER_VERIFICATION: NOT_IMPLEMENTED`);
        process.exit(0);
      } else {
        console.log(`STRUCTURAL_VALIDATION: PASS`);
        console.log(`PAYLOAD_HASH_NOT_SEALED: PROVISIONAL_RECORD`);
        console.log(`CRYPTOGRAPHIC_VERIFICATION: NOT_APPLICABLE`);
        process.exit(0);
      }
    } catch (err) {
      console.error(`VERIFICATION FAILED: ${err.message}`);
      process.exit(1);
    }
  }

  console.error(`Error: Unsupported argument "${args[0]}". See --help.`);
  process.exit(1);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  main();
}
