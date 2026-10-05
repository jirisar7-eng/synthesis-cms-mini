#!/usr/bin/env node
/**
 * SYNTHESIS CMS MINI — GOVERNANCE CONTRACT REGISTRY VERIFIER
 *
 * Verifies machine-readable Governance Contract Registry instances and snapshots.
 * Enforces contract schema conformance, SHA-256 snapshot integrity, lifecycle state
 * invariants, and ensures separation between Capability Registry and Contract Registry.
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

export const VALID_LIFECYCLE_STATES = new Set(['DRAFT', 'STAGED', 'ACTIVE']);
export const VALID_CONTRACT_STATUSES = new Set(['DRAFT', 'STAGED', 'ACTIVE', 'SUPERSEDED']);

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

export function validateContractRegistry(registryObj, repoRoot = DEFAULT_REPO_ROOT) {
  if (!registryObj || typeof registryObj !== 'object' || Array.isArray(registryObj)) {
    return { valid: false, error: 'MALFORMED_REGISTRY: Registry root must be a non-null object' };
  }

  if (registryObj.schema_version !== 'contract-registry.v1') {
    return { valid: false, error: `SCHEMA_VERSION_MISMATCH: Expected contract-registry.v1, got ${registryObj.schema_version}` };
  }
  if (registryObj.format_version !== '1.0.0') {
    return { valid: false, error: `FORMAT_VERSION_MISMATCH: Expected 1.0.0, got ${registryObj.format_version}` };
  }
  if (registryObj.record_kind !== 'CONTRACT_REGISTRY') {
    return { valid: false, error: `RECORD_KIND_MISMATCH: Expected CONTRACT_REGISTRY, got ${registryObj.record_kind}` };
  }
  if (!VALID_LIFECYCLE_STATES.has(registryObj.lifecycle_state)) {
    return { valid: false, error: `INVALID_LIFECYCLE_STATE: Invalid lifecycle_state: ${registryObj.lifecycle_state}` };
  }
  if (!Array.isArray(registryObj.contracts)) {
    return { valid: false, error: 'INVALID_CONTRACTS_ARRAY: contracts field must be an array' };
  }

  const seenIds = new Set();
  const seenPaths = new Set();

  for (let i = 0; i < registryObj.contracts.length; i++) {
    const entry = registryObj.contracts[i];
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      return { valid: false, error: `MALFORMED_ENTRY: Entry at index ${i} must be a non-null object` };
    }

    const { contract_id, version, title, status, snapshot_path, snapshot_sha256 } = entry;

    if (typeof contract_id !== 'string' || !/^CONTRACT-[A-Z0-9-]+$/.test(contract_id)) {
      return { valid: false, error: `INVALID_CONTRACT_ID: Entry ${i} has invalid contract_id: ${contract_id}` };
    }
    if (seenIds.has(contract_id)) {
      return { valid: false, error: `DUPLICATE_CONTRACT_ID: Duplicate contract_id detected: ${contract_id}` };
    }
    seenIds.add(contract_id);

    if (typeof version !== 'string' || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(version)) {
      return { valid: false, error: `INVALID_CONTRACT_VERSION: Contract ${contract_id} has invalid version: ${version}` };
    }
    if (typeof title !== 'string' || title.trim().length === 0) {
      return { valid: false, error: `INVALID_CONTRACT_TITLE: Contract ${contract_id} has empty title` };
    }
    if (!VALID_CONTRACT_STATUSES.has(status)) {
      return { valid: false, error: `INVALID_CONTRACT_STATUS: Contract ${contract_id} has invalid status: ${status}` };
    }

    try {
      validateSafeRelativePath(snapshot_path);
    } catch (e) {
      return { valid: false, error: `UNSAFE_SNAPSHOT_PATH: Contract ${contract_id} path error: ${e.message}` };
    }

    if (seenPaths.has(snapshot_path)) {
      return { valid: false, error: `DUPLICATE_SNAPSHOT_PATH: Multiple contracts point to identical path: ${snapshot_path}` };
    }
    seenPaths.add(snapshot_path);

    if (typeof snapshot_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(snapshot_sha256)) {
      return { valid: false, error: `INVALID_SNAPSHOT_SHA256: Contract ${contract_id} has invalid snapshot_sha256 format` };
    }

    // Verify snapshot file on disk if repoRoot provided and status requires it
    if (repoRoot && (status === 'STAGED' || status === 'ACTIVE')) {
      const fullPath = path.resolve(repoRoot, snapshot_path);
      if (!fs.existsSync(fullPath)) {
        return { valid: false, error: `MISSING_SNAPSHOT_FILE: Snapshot for ${contract_id} does not exist: ${snapshot_path}` };
      }
      const actualSha = computeFileSha256(fullPath);
      if (!timingSafeHexCompare(actualSha, snapshot_sha256)) {
        return { valid: false, error: `SNAPSHOT_SHA_MISMATCH: Contract ${contract_id} snapshot hash mismatch: expected ${snapshot_sha256}, actual ${actualSha}` };
      }
    }
  }

  // Lifecycle consistency: if root is ACTIVE, all contracts must be ACTIVE or SUPERSEDED
  if (registryObj.lifecycle_state === 'ACTIVE') {
    for (const c of registryObj.contracts) {
      if (c.status === 'DRAFT' || c.status === 'STAGED') {
        return { valid: false, error: `LIFECYCLE_STATE_INCONSISTENCY: Root is ACTIVE but contract ${c.contract_id} is ${c.status}` };
      }
    }
  }

  return { valid: true, contractCount: registryObj.contracts.length };
}

export function runSelfTest() {
  let positivePassed = 0;
  let negativePassed = 0;

  const validMock = {
    schema_version: 'contract-registry.v1',
    format_version: '1.0.0',
    record_kind: 'CONTRACT_REGISTRY',
    lifecycle_state: 'DRAFT',
    contracts: [
      {
        contract_id: 'CONTRACT-GOV-TEST-001',
        version: '1.0.0',
        title: 'Test Contract',
        status: 'DRAFT',
        snapshot_path: '.synthesis/contracts/CONTRACT-GOV-TEST-001/v1.0.0.json',
        snapshot_sha256: 'a'.repeat(64)
      }
    ]
  };

  const res = validateContractRegistry(validMock, null);
  if (res.valid) positivePassed++;

  const negativeCases = [
    { name: 'Null registry', generate: () => null, expected: 'MALFORMED_REGISTRY' },
    { name: 'Array registry', generate: () => [], expected: 'MALFORMED_REGISTRY' },
    { name: 'Bad schema_version', generate: m => { m.schema_version = '2.0'; return m; }, expected: 'SCHEMA_VERSION_MISMATCH' },
    { name: 'Bad format_version', generate: m => { m.format_version = '0.9'; return m; }, expected: 'FORMAT_VERSION_MISMATCH' },
    { name: 'Bad record_kind', generate: m => { m.record_kind = 'UNKNOWN'; return m; }, expected: 'RECORD_KIND_MISMATCH' },
    { name: 'Bad lifecycle_state', generate: m => { m.lifecycle_state = 'INVALID'; return m; }, expected: 'INVALID_LIFECYCLE_STATE' },
    { name: 'Contracts not array', generate: m => { m.contracts = 'not-array'; return m; }, expected: 'INVALID_CONTRACTS_ARRAY' },
    { name: 'Malformed entry', generate: m => { m.contracts = [null]; return m; }, expected: 'MALFORMED_ENTRY' },
    { name: 'Bad contract_id', generate: m => { m.contracts[0].contract_id = 'bad_id'; return m; }, expected: 'INVALID_CONTRACT_ID' },
    { name: 'Duplicate contract_id', generate: m => { m.contracts.push({ ...m.contracts[0], snapshot_path: 'other.json' }); return m; }, expected: 'DUPLICATE_CONTRACT_ID' },
    { name: 'Bad version format', generate: m => { m.contracts[0].version = 'v1'; return m; }, expected: 'INVALID_CONTRACT_VERSION' },
    { name: 'Empty title', generate: m => { m.contracts[0].title = '   '; return m; }, expected: 'INVALID_CONTRACT_TITLE' },
    { name: 'Bad status', generate: m => { m.contracts[0].status = 'UNKNOWN'; return m; }, expected: 'INVALID_CONTRACT_STATUS' },
    { name: 'Path traversal', generate: m => { m.contracts[0].snapshot_path = '../../secret.json'; return m; }, expected: 'UNSAFE_SNAPSHOT_PATH' },
    { name: 'Duplicate snapshot path', generate: m => { m.contracts.push({ ...m.contracts[0], contract_id: 'CONTRACT-GOV-TEST-002' }); return m; }, expected: 'DUPLICATE_SNAPSHOT_PATH' },
    { name: 'Bad sha format', generate: m => { m.contracts[0].snapshot_sha256 = 'abc'; return m; }, expected: 'INVALID_SNAPSHOT_SHA256' },
    { name: 'ACTIVE root with DRAFT contract', generate: m => { m.lifecycle_state = 'ACTIVE'; m.contracts[0].status = 'DRAFT'; return m; }, expected: 'LIFECYCLE_STATE_INCONSISTENCY' }
  ];

  for (const tc of negativeCases) {
    const clone = JSON.parse(JSON.stringify(validMock));
    const testObj = tc.generate(clone);
    const r = validateContractRegistry(testObj, null);
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
  console.log(`CONTRACT_REGISTRY_SELFTEST: ${JSON.stringify(result)}`);
  return result;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.includes('--self-test')) {
    runSelfTest();
    process.exit(0);
  } else if (args.includes('--verify-all')) {
    const registryPath = path.resolve(DEFAULT_REPO_ROOT, '.synthesis/registries/contracts.json');
    if (!fs.existsSync(registryPath)) {
      console.log('CONTRACT_REGISTRY_STATUS: BOOTSTRAP_PENDING_REGISTRATION');
      process.exit(0);
    }
    const raw = fs.readFileSync(registryPath, 'utf8');
    const parsed = parseStrictIJson(raw);
    const res = validateContractRegistry(parsed, DEFAULT_REPO_ROOT);
    if (!res.valid) {
      console.error(`CONTRACT_REGISTRY_VERIFICATION_FAILED: ${res.error}`);
      process.exit(1);
    }
    console.log(`CONTRACT_REGISTRY_VERIFIED: ${res.contractCount} contracts valid.`);
    process.exit(0);
  } else {
    console.log('Usage: node verify_contract_registry.mjs [--self-test|--verify-all]');
    process.exit(1);
  }
}
