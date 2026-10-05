#!/usr/bin/env node
/**
 * SYNTHESIS CMS MINI — GOVERNANCE LOCKFILE VERIFIER
 *
 * Verifies cryptographic pinning and integrity of governance files in governance.lock.json.
 * Prevents in-place mutation and anti-drift gate bypass.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

import {
  parseStrictIJson,
  timingSafeHexCompare
} from './verify_capsule_seal.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_REPO_ROOT = path.resolve(__dirname, '..', '..');

export const VALID_HEALTH_GATES = new Set(['BOOTSTRAP_NOT_YET_ACTIVE', 'PASS', 'FAIL']);
export const VALID_ITEM_TYPES = new Set(['SCHEMA', 'CONTRACT_SNAPSHOT', 'REGISTRY', 'VERIFIER_SCRIPT']);

export function computeFileSha256(filePath) {
  const bytes = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

export function validateSafeRelativePath(relPath) {
  if (typeof relPath !== 'string' || !relPath) {
    throw new Error('PATH_ERROR: Path must be a non-empty string');
  }
  if (path.isAbsolute(relPath)) {
    throw new Error(`PATH_ERROR: Absolute path forbidden: ${relPath}`);
  }
  if (relPath.startsWith('-')) {
    throw new Error(`PATH_ERROR: Option injection forbidden: ${relPath}`);
  }
  const normalized = path.normalize(relPath);
  if (normalized.startsWith('..') || path.isAbsolute(normalized)) {
    throw new Error(`PATH_ERROR: Path traversal forbidden: ${relPath}`);
  }
  return normalized;
}

export function validateGovernanceLock(lockObj, repoRoot = DEFAULT_REPO_ROOT) {
  if (!lockObj || typeof lockObj !== 'object' || Array.isArray(lockObj)) {
    return { valid: false, error: 'MALFORMED_LOCKFILE: Lockfile root must be a non-null object' };
  }

  if (lockObj.schema_version !== '1.0.0') {
    return { valid: false, error: `SCHEMA_VERSION_MISMATCH: Expected 1.0.0, got ${lockObj.schema_version}` };
  }
  if (lockObj.lockfile_kind !== 'GOVERNANCE_REQUIREMENTS_LOCK') {
    return { valid: false, error: `LOCKFILE_KIND_MISMATCH: Expected GOVERNANCE_REQUIREMENTS_LOCK, got ${lockObj.lockfile_kind}` };
  }
  if (typeof lockObj.locked_at_utc !== 'string' || isNaN(Date.parse(lockObj.locked_at_utc))) {
    return { valid: false, error: `INVALID_TIMESTAMP: locked_at_utc is not a valid ISO timestamp` };
  }
  if (!VALID_HEALTH_GATES.has(lockObj.root_governance_health_gate)) {
    return { valid: false, error: `INVALID_HEALTH_GATE: Invalid root_governance_health_gate: ${lockObj.root_governance_health_gate}` };
  }

  // Genesis anchor validation
  const anchor = lockObj.genesis_anchor;
  if (!anchor || typeof anchor !== 'object' || Array.isArray(anchor)) {
    return { valid: false, error: 'MISSING_GENESIS_ANCHOR: genesis_anchor must be an object' };
  }
  if (anchor.path !== '.synthesis/lineage/genesis.json') {
    return { valid: false, error: `INVALID_GENESIS_PATH: Expected .synthesis/lineage/genesis.json, got ${anchor.path}` };
  }
  if (typeof anchor.pinned_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(anchor.pinned_sha256)) {
    return { valid: false, error: `INVALID_GENESIS_HASH: Invalid pinned_sha256 format in genesis_anchor` };
  }

  if (repoRoot) {
    const genesisPath = path.resolve(repoRoot, anchor.path);
    if (!fs.existsSync(genesisPath)) {
      return { valid: false, error: `GENESIS_FILE_NOT_FOUND: Genesis anchor file not found: ${anchor.path}` };
    }
    const actualGenesisSha = computeFileSha256(genesisPath);
    if (!timingSafeHexCompare(actualGenesisSha, anchor.pinned_sha256)) {
      return { valid: false, error: `GENESIS_ANCHOR_DRIFT: Genesis hash mismatch: expected ${anchor.pinned_sha256}, actual ${actualGenesisSha}` };
    }
  }

  if (!Array.isArray(lockObj.pinned_items)) {
    return { valid: false, error: 'INVALID_PINNED_ITEMS: pinned_items must be an array' };
  }

  const seenPaths = new Set();

  for (let i = 0; i < lockObj.pinned_items.length; i++) {
    const item = lockObj.pinned_items[i];
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      return { valid: false, error: `MALFORMED_PINNED_ITEM: Item at index ${i} must be a non-null object` };
    }

    const { item_type, path: itemPath, sha256 } = item;

    if (!VALID_ITEM_TYPES.has(item_type)) {
      return { valid: false, error: `INVALID_ITEM_TYPE: Pinned item at index ${i} has invalid item_type: ${item_type}` };
    }

    try {
      validateSafeRelativePath(itemPath);
    } catch (e) {
      return { valid: false, error: `UNSAFE_PINNED_PATH: Pinned item at index ${i} has unsafe path: ${e.message}` };
    }

    if (seenPaths.has(itemPath)) {
      return { valid: false, error: `DUPLICATE_PINNED_PATH: Duplicate pinned path detected: ${itemPath}` };
    }
    seenPaths.add(itemPath);

    if (typeof sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(sha256)) {
      return { valid: false, error: `INVALID_PINNED_HASH: Pinned item ${itemPath} has invalid sha256 format` };
    }

    if (repoRoot) {
      const fullPath = path.resolve(repoRoot, itemPath);
      if (!fs.existsSync(fullPath)) {
        return { valid: false, error: `PINNED_FILE_MISSING: Pinned file does not exist on disk: ${itemPath}` };
      }
      const actualSha = computeFileSha256(fullPath);
      if (!timingSafeHexCompare(actualSha, sha256)) {
        return { valid: false, error: `PINNED_FILE_DRIFT: Pinned file ${itemPath} hash drift: expected ${sha256}, actual ${actualSha}` };
      }
    }
  }

  return { valid: true, pinnedCount: lockObj.pinned_items.length };
}

export function runSelfTest() {
  let positivePassed = 0;
  let negativePassed = 0;

  const validMock = {
    schema_version: '1.0.0',
    lockfile_kind: 'GOVERNANCE_REQUIREMENTS_LOCK',
    locked_at_utc: '2026-10-05T00:00:00.000Z',
    root_governance_health_gate: 'BOOTSTRAP_NOT_YET_ACTIVE',
    genesis_anchor: {
      path: '.synthesis/lineage/genesis.json',
      pinned_sha256: 'b3d47a6f732512a9f5b19668a07bb4d2c662adf316f5a1d33a6d52c57860ec60'
    },
    pinned_items: [
      {
        item_type: 'SCHEMA',
        path: '.synthesis/schemas/governance-lock.schema.json',
        sha256: '0'.repeat(64),
        identifier: 'SCHEMA-GOVERNANCE-LOCK'
      }
    ]
  };

  const res = validateGovernanceLock(validMock, null);
  if (res.valid) positivePassed++;

  const negativeCases = [
    { name: 'Null lockfile', generate: () => null, expected: 'MALFORMED_LOCKFILE' },
    { name: 'Array lockfile', generate: () => [], expected: 'MALFORMED_LOCKFILE' },
    { name: 'Bad schema_version', generate: m => { m.schema_version = '2.0'; return m; }, expected: 'SCHEMA_VERSION_MISMATCH' },
    { name: 'Bad lockfile_kind', generate: m => { m.lockfile_kind = 'UNKNOWN'; return m; }, expected: 'LOCKFILE_KIND_MISMATCH' },
    { name: 'Bad locked_at_utc', generate: m => { m.locked_at_utc = 'not-a-date'; return m; }, expected: 'INVALID_TIMESTAMP' },
    { name: 'Bad health gate', generate: m => { m.root_governance_health_gate = 'UNKNOWN'; return m; }, expected: 'INVALID_HEALTH_GATE' },
    { name: 'Missing genesis_anchor', generate: m => { delete m.genesis_anchor; return m; }, expected: 'MISSING_GENESIS_ANCHOR' },
    { name: 'Bad genesis path', generate: m => { m.genesis_anchor.path = 'wrong/path.json'; return m; }, expected: 'INVALID_GENESIS_PATH' },
    { name: 'Bad genesis sha', generate: m => { m.genesis_anchor.pinned_sha256 = 'abc'; return m; }, expected: 'INVALID_GENESIS_HASH' },
    { name: 'Pinned items not array', generate: m => { m.pinned_items = 'not-array'; return m; }, expected: 'INVALID_PINNED_ITEMS' },
    { name: 'Malformed pinned item', generate: m => { m.pinned_items = [null]; return m; }, expected: 'MALFORMED_PINNED_ITEM' },
    { name: 'Bad item type', generate: m => { m.pinned_items[0].item_type = 'UNKNOWN'; return m; }, expected: 'INVALID_ITEM_TYPE' },
    { name: 'Path traversal in pinned path', generate: m => { m.pinned_items[0].path = '../../secret'; return m; }, expected: 'UNSAFE_PINNED_PATH' },
    { name: 'Duplicate pinned path', generate: m => { m.pinned_items.push({ ...m.pinned_items[0] }); return m; }, expected: 'DUPLICATE_PINNED_PATH' },
    { name: 'Bad sha in pinned item', generate: m => { m.pinned_items[0].sha256 = 'short'; return m; }, expected: 'INVALID_PINNED_HASH' }
  ];

  for (const tc of negativeCases) {
    const clone = JSON.parse(JSON.stringify(validMock));
    const testObj = tc.generate(clone);
    const r = validateGovernanceLock(testObj, null);
    if (!r.valid && r.error && r.error.includes(tc.expected)) {
      negativePassed++;
    } else {
      throw new Error(`Self-test negative case '${tc.name}' failed. Expected ${tc.expected}, got: ${JSON.stringify(r)}`);
    }
  }

  const result = {
    positivePassed,
    negativePassed,
    totalTests: positivePassed + negativePassed
  };
  console.log(`GOVERNANCE_LOCK_SELFTEST: ${JSON.stringify(result)}`);
  return result;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.includes('--self-test')) {
    runSelfTest();
    process.exit(0);
  } else if (args.includes('--verify-all')) {
    const lockPath = path.resolve(DEFAULT_REPO_ROOT, '.synthesis/governance.lock.json');
    if (!fs.existsSync(lockPath)) {
      console.log('GOVERNANCE_LOCK_STATUS: BOOTSTRAP_PENDING_LOCK');
      process.exit(0);
    }
    const raw = fs.readFileSync(lockPath, 'utf8');
    const parsed = parseStrictIJson(raw);
    const res = validateGovernanceLock(parsed, DEFAULT_REPO_ROOT);
    if (!res.valid) {
      console.error(`GOVERNANCE_LOCK_VERIFICATION_FAILED: ${res.error}`);
      process.exit(1);
    }
    console.log(`GOVERNANCE_LOCK_VERIFIED: ${res.pinnedCount} pinned items match.`);
    process.exit(0);
  } else {
    console.log('Usage: node verify_governance_lock.mjs [--self-test|--verify-all]');
    process.exit(1);
  }
}
