#!/usr/bin/env node
/**
 * SYNTHESIS CMS MINI — GOVERNANCE CONTRACT REGISTRY VERIFIER
 *
 * Verifies machine-readable Governance Contract Registry instances and snapshots.
 * Supports multi-version contracts (contract_id + version identity), effective_from_sha
 * git provenance & ancestry checks, RFC-8785 canonical JSON snapshot enforcement,
 * supersession consistency, SHA-256 integrity, and regular-file (no symlink) safety.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import child_process from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  parseStrictIJson,
  canonicalizeRfc8785,
  timingSafeHexCompare
} from './verify_capsule_seal.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_REPO_ROOT = path.resolve(__dirname, '..', '..');

export const VALID_LIFECYCLE_STATES = new Set(['DRAFT', 'STAGED', 'ACTIVE']);
export const VALID_CONTRACT_STATUSES = new Set(['DRAFT', 'STAGED', 'ACTIVE', 'SUPERSEDED']);

export function defaultGitExecutor(args, cwd = DEFAULT_REPO_ROOT) {
  try {
    return child_process.execFileSync('git', args, {
      cwd,
      shell: false,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe']
    });
  } catch (err) {
    throw new Error(`GIT_COMMAND_FAILED [git ${args.join(' ')}]: ${err.stderr || err.message}`);
  }
}

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

export function validateContractRegistry(registryObj, repoRoot = DEFAULT_REPO_ROOT, options = {}) {
  const gitExecutor = options.gitExecutor || defaultGitExecutor;

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

  const seenVersionKeys = new Set();
  const seenPaths = new Set();
  const activeContractsById = new Map();
  const allEntriesByKey = new Map();

  // First pass: structural, identity, and snapshot integrity
  for (let i = 0; i < registryObj.contracts.length; i++) {
    const entry = registryObj.contracts[i];
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      return { valid: false, error: `MALFORMED_ENTRY: Entry at index ${i} must be a non-null object` };
    }

    const {
      contract_id,
      version,
      title,
      status,
      snapshot_path,
      snapshot_sha256,
      effective_from_sha = null,
      supersedes = [],
      superseded_by = null
    } = entry;

    if (typeof contract_id !== 'string' || !/^CONTRACT-[A-Z0-9-]+$/.test(contract_id)) {
      return { valid: false, error: `INVALID_CONTRACT_ID: Entry ${i} has invalid contract_id: ${contract_id}` };
    }
    if (typeof version !== 'string' || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(version)) {
      return { valid: false, error: `INVALID_CONTRACT_VERSION: Contract ${contract_id} has invalid version: ${version}` };
    }

    const versionKey = `${contract_id}@${version}`;
    if (seenVersionKeys.has(versionKey)) {
      return { valid: false, error: `DUPLICATE_CONTRACT_VERSION: Duplicate (contract_id, version) detected: ${versionKey}` };
    }
    seenVersionKeys.add(versionKey);
    allEntriesByKey.set(versionKey, entry);

    if (typeof title !== 'string' || title.trim().length === 0) {
      return { valid: false, error: `INVALID_CONTRACT_TITLE: Contract ${versionKey} has empty title` };
    }
    if (!VALID_CONTRACT_STATUSES.has(status)) {
      return { valid: false, error: `INVALID_CONTRACT_STATUS: Contract ${versionKey} has invalid status: ${status}` };
    }

    // effective_from_sha validation
    if (status === 'STAGED' || status === 'ACTIVE') {
      if (typeof effective_from_sha !== 'string' || !/^[a-f0-9]{40}$/.test(effective_from_sha)) {
        return { valid: false, error: `MISSING_EFFECTIVE_FROM_SHA: Contract ${versionKey} with status ${status} requires a 40-char hex effective_from_sha` };
      }
    } else if (effective_from_sha !== null) {
      if (typeof effective_from_sha !== 'string' || !/^[a-f0-9]{40}$/.test(effective_from_sha)) {
        return { valid: false, error: `INVALID_EFFECTIVE_FROM_SHA_FORMAT: Contract ${versionKey} has invalid effective_from_sha format` };
      }
    }

    // Git ancestry check for effective_from_sha if provided
    if (repoRoot && gitExecutor && typeof effective_from_sha === 'string' && /^[a-f0-9]{40}$/.test(effective_from_sha)) {
      try {
        gitExecutor(['rev-parse', '--verify', `${effective_from_sha}^{commit}`], repoRoot);
      } catch (e) {
        return { valid: false, error: `EFFECTIVE_SHA_NONEXISTENT: effective_from_sha ${effective_from_sha} for ${versionKey} does not exist in repository` };
      }
      try {
        gitExecutor(['merge-base', '--is-ancestor', effective_from_sha, 'HEAD'], repoRoot);
      } catch (e) {
        return { valid: false, error: `EFFECTIVE_SHA_NON_ANCESTOR: effective_from_sha ${effective_from_sha} for ${versionKey} is not an ancestor of current HEAD` };
      }
    }

    try {
      validateSafeRelativePath(snapshot_path);
    } catch (e) {
      return { valid: false, error: `UNSAFE_SNAPSHOT_PATH: Contract ${versionKey} path error: ${e.message}` };
    }

    if (seenPaths.has(snapshot_path)) {
      return { valid: false, error: `DUPLICATE_SNAPSHOT_PATH: Multiple contracts point to identical path: ${snapshot_path}` };
    }
    seenPaths.add(snapshot_path);

    if (typeof snapshot_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(snapshot_sha256)) {
      return { valid: false, error: `INVALID_SNAPSHOT_SHA256: Contract ${versionKey} has invalid snapshot_sha256 format` };
    }

    // Verify snapshot file on disk if repoRoot provided and status requires it
    if (repoRoot && (status === 'STAGED' || status === 'ACTIVE' || status === 'SUPERSEDED')) {
      const fullPath = path.resolve(repoRoot, snapshot_path);
      if (!fs.existsSync(fullPath)) {
        return { valid: false, error: `MISSING_SNAPSHOT_FILE: Snapshot for ${versionKey} does not exist: ${snapshot_path}` };
      }
      try {
        const stat = fs.lstatSync(fullPath);
        if (!stat.isFile() || stat.isSymbolicLink()) {
          return { valid: false, error: `UNSAFE_FILE_TYPE: Snapshot ${snapshot_path} must be a regular file, not a symlink or directory` };
        }
      } catch (err) {
        return { valid: false, error: `SNAPSHOT_STAT_ERROR: Cannot stat snapshot ${snapshot_path}: ${err.message}` };
      }

      const rawBytes = fs.readFileSync(fullPath, 'utf8');
      let parsedSnapshot;
      try {
        parsedSnapshot = parseStrictIJson(rawBytes);
      } catch (err) {
        return { valid: false, error: `NON_CANONICAL_SNAPSHOT_PARSE_ERROR: Snapshot ${snapshot_path} parse failed: ${err.message}` };
      }

      const canonicalString = canonicalizeRfc8785(parsedSnapshot);
      if (rawBytes.trim() !== canonicalString) {
        return { valid: false, error: `NON_CANONICAL_SNAPSHOT_JSON: Snapshot ${snapshot_path} is not in RFC-8785 canonical JSON format` };
      }

      const actualSha = crypto.createHash('sha256').update(Buffer.from(rawBytes, 'utf8')).digest('hex');
      if (!timingSafeHexCompare(actualSha, snapshot_sha256)) {
        return { valid: false, error: `SNAPSHOT_SHA_MISMATCH: Contract ${versionKey} snapshot hash mismatch: expected ${snapshot_sha256}, actual ${actualSha}` };
      }
    }

    // Track active versions per contract_id
    if (status === 'ACTIVE') {
      if (activeContractsById.has(contract_id)) {
        return {
          valid: false,
          error: `MULTIPLE_ACTIVE_VERSIONS: Contract ${contract_id} has multiple ACTIVE versions: ${activeContractsById.get(contract_id)} and ${version}`
        };
      }
      activeContractsById.set(contract_id, version);
    }
  }

  // Second pass: Supersession consistency checks
  for (const [key, entry] of allEntriesByKey.entries()) {
    const { contract_id, version, status, supersedes = [], superseded_by } = entry;

    if (status === 'ACTIVE' && superseded_by !== null) {
      return { valid: false, error: `ACTIVE_CONTRACT_SUPERSEDED: ACTIVE contract ${key} cannot have superseded_by set` };
    }

    if (status === 'SUPERSEDED') {
      if (!superseded_by || typeof superseded_by !== 'string') {
        return { valid: false, error: `SUPERSEDED_WITHOUT_POINTER: SUPERSEDED contract ${key} must declare non-empty superseded_by` };
      }
      const targetKey = superseded_by.includes('@') ? superseded_by : `${contract_id}@${superseded_by}`;
      if (!allEntriesByKey.has(targetKey)) {
        return { valid: false, error: `INVALID_SUPERSEDED_BY_TARGET: Contract ${key} references non-existent superseded_by target ${targetKey}` };
      }
    }

    if (Array.isArray(supersedes) && supersedes.length > 0) {
      for (const s of supersedes) {
        const supersededKey = s.includes('@') ? s : `${contract_id}@${s}`;
        const targetEntry = allEntriesByKey.get(supersededKey);
        if (!targetEntry) {
          return { valid: false, error: `INVALID_SUPERSEDES_TARGET: Contract ${key} declares supersedes target that does not exist: ${supersededKey}` };
        }
        if (targetEntry.status !== 'SUPERSEDED') {
          return { valid: false, error: `SUPERSEDED_TARGET_NOT_SUPERSEDED: Contract ${key} supersedes ${supersededKey}, but target status is ${targetEntry.status}, not SUPERSEDED` };
        }
      }
    }
  }

  // Lifecycle consistency
  if (registryObj.lifecycle_state === 'ACTIVE') {
    for (const c of registryObj.contracts) {
      if (c.status === 'DRAFT' || c.status === 'STAGED') {
        return { valid: false, error: `LIFECYCLE_STATE_INCONSISTENCY: Root is ACTIVE but contract ${c.contract_id}@${c.version} is ${c.status}` };
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
        title: 'Test Contract v1',
        status: 'SUPERSEDED',
        snapshot_path: '.synthesis/contracts/CONTRACT-GOV-TEST-001/v1.0.0.json',
        snapshot_sha256: 'a'.repeat(64),
        effective_from_sha: '1'.repeat(40),
        supersedes: [],
        superseded_by: '1.1.0'
      },
      {
        contract_id: 'CONTRACT-GOV-TEST-001',
        version: '1.1.0',
        title: 'Test Contract v1.1',
        status: 'ACTIVE',
        snapshot_path: '.synthesis/contracts/CONTRACT-GOV-TEST-001/v1.1.0.json',
        snapshot_sha256: 'b'.repeat(64),
        effective_from_sha: '2'.repeat(40),
        supersedes: ['1.0.0'],
        superseded_by: null
      }
    ]
  };

  const res = validateContractRegistry(validMock, null, { gitExecutor: null });
  if (res.valid) positivePassed++;
  else throw new Error(`Initial valid mock failed: ${JSON.stringify(res)}`);

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
    { name: 'Duplicate contract version', generate: m => { m.contracts[1].version = '1.0.0'; return m; }, expected: 'DUPLICATE_CONTRACT_VERSION' },
    { name: 'Bad version format', generate: m => { m.contracts[0].version = 'v1'; return m; }, expected: 'INVALID_CONTRACT_VERSION' },
    { name: 'Empty title', generate: m => { m.contracts[0].title = '   '; return m; }, expected: 'INVALID_CONTRACT_TITLE' },
    { name: 'Bad status', generate: m => { m.contracts[0].status = 'UNKNOWN'; return m; }, expected: 'INVALID_CONTRACT_STATUS' },
    { name: 'Missing effective_from_sha on ACTIVE', generate: m => { m.contracts[1].effective_from_sha = null; return m; }, expected: 'MISSING_EFFECTIVE_FROM_SHA' },
    { name: 'Bad effective_from_sha format', generate: m => { m.contracts[1].effective_from_sha = 'short'; return m; }, expected: 'MISSING_EFFECTIVE_FROM_SHA' },
    { name: 'Path traversal', generate: m => { m.contracts[0].snapshot_path = '../../secret.json'; return m; }, expected: 'UNSAFE_SNAPSHOT_PATH' },
    { name: 'Duplicate snapshot path', generate: m => { m.contracts[1].snapshot_path = m.contracts[0].snapshot_path; return m; }, expected: 'DUPLICATE_SNAPSHOT_PATH' },
    { name: 'Bad sha format', generate: m => { m.contracts[0].snapshot_sha256 = 'abc'; return m; }, expected: 'INVALID_SNAPSHOT_SHA256' },
    { name: 'Multiple ACTIVE versions of same contract_id', generate: m => { m.contracts[0].status = 'ACTIVE'; m.contracts[0].superseded_by = null; return m; }, expected: 'MULTIPLE_ACTIVE_VERSIONS' },
    { name: 'ACTIVE contract with superseded_by set', generate: m => { m.contracts[1].superseded_by = '2.0.0'; return m; }, expected: 'ACTIVE_CONTRACT_SUPERSEDED' },
    { name: 'SUPERSEDED without superseded_by', generate: m => { m.contracts[0].superseded_by = null; return m; }, expected: 'SUPERSEDED_WITHOUT_POINTER' },
    { name: 'SUPERSEDED with invalid target', generate: m => { m.contracts[0].superseded_by = '9.9.9'; return m; }, expected: 'INVALID_SUPERSEDED_BY_TARGET' },
    { name: 'Invalid supersedes reference', generate: m => { m.contracts[1].supersedes = ['non-existent']; return m; }, expected: 'INVALID_SUPERSEDES_TARGET' },
    { name: 'Superseded target not marked SUPERSEDED', generate: m => { m.contracts[0].status = 'DRAFT'; return m; }, expected: 'SUPERSEDED_TARGET_NOT_SUPERSEDED' },
    { name: 'ACTIVE root with DRAFT contract', generate: m => { m.lifecycle_state = 'ACTIVE'; m.contracts = [{ contract_id: 'CONTRACT-GOV-TEST-002', version: '1.0.0', title: 'Single', status: 'DRAFT', snapshot_path: '.synthesis/contracts/CONTRACT-GOV-TEST-002/v1.0.0.json', snapshot_sha256: 'a'.repeat(64), effective_from_sha: null }]; return m; }, expected: 'LIFECYCLE_STATE_INCONSISTENCY' }
  ];

  for (const tc of negativeCases) {
    const clone = JSON.parse(JSON.stringify(validMock));
    const testObj = tc.generate(clone);
    const r = validateContractRegistry(testObj, null, { gitExecutor: null });
    if (!r.valid && r.error && r.error.includes(tc.expected)) {
      negativePassed++;
    } else {
      throw new Error(`Self-test negative case '${tc.name}' failed. Expected ${tc.expected}, got: ${JSON.stringify(r)}`);
    }
  }

  // Disk tests (canonical snapshot, symlink, effective SHA Git verification)
  const tempDir = fs.mkdtempSync(path.join('/tmp', 'contract-reg-test-'));
  try {
    const contractsDir = path.join(tempDir, '.synthesis', 'contracts', 'CONTRACT-GOV-TEST-001');
    fs.mkdirSync(contractsDir, { recursive: true });

    const canonicalContractObj = {
      authority_domain: 'GOVERNANCE',
      contract_id: 'CONTRACT-GOV-TEST-001',
      contract_version: '1.0.0',
      effective_from_step: '1',
      invariants: ['INV1'],
      lifecycle_state: 'ACTIVE',
      provisions: [{ enforcement: 'STRICT', rule_id: 'R1', statement: 'Rule 1' }],
      record_kind: 'GOVERNANCE_CONTRACT_SNAPSHOT',
      schema_version: '1.0.0',
      scope: 'TEST',
      title: 'Canonical Test'
    };
    const canonicalBytes = canonicalizeRfc8785(canonicalContractObj);
    const snapFile = path.join(contractsDir, 'v1.0.0.json');
    fs.writeFileSync(snapFile, canonicalBytes);
    const snapSha = crypto.createHash('sha256').update(Buffer.from(canonicalBytes, 'utf8')).digest('hex');

    const mockGit = (args) => {
      const cmd = args.join(' ');
      if (cmd.includes('rev-parse --verify') && cmd.includes('1'.repeat(40))) return '1'.repeat(40) + '\n';
      if (cmd.includes('merge-base --is-ancestor')) return '';
      throw new Error(`Unexpected mock cmd: ${cmd}`);
    };

    const validDiskMock = {
      schema_version: 'contract-registry.v1',
      format_version: '1.0.0',
      record_kind: 'CONTRACT_REGISTRY',
      lifecycle_state: 'DRAFT',
      contracts: [
        {
          contract_id: 'CONTRACT-GOV-TEST-001',
          version: '1.0.0',
          title: 'Test Contract',
          status: 'ACTIVE',
          snapshot_path: '.synthesis/contracts/CONTRACT-GOV-TEST-001/v1.0.0.json',
          snapshot_sha256: snapSha,
          effective_from_sha: '1'.repeat(40),
          supersedes: [],
          superseded_by: null
        }
      ]
    };

    const diskRes = validateContractRegistry(validDiskMock, tempDir, { gitExecutor: mockGit });
    if (diskRes.valid) {
      positivePassed++;
    } else {
      throw new Error(`Valid disk contract registry test failed: ${JSON.stringify(diskRes)}`);
    }

    // Negative Disk 1: Non-canonical JSON formatting (extra spaces)
    const nonCanonicalFile = path.join(contractsDir, 'v1.0.0.json');
    fs.writeFileSync(nonCanonicalFile, JSON.stringify(canonicalContractObj, null, 4));
    const nonCanonSha = crypto.createHash('sha256').update(fs.readFileSync(nonCanonicalFile)).digest('hex');
    const nonCanonMock = JSON.parse(JSON.stringify(validDiskMock));
    nonCanonMock.contracts[0].snapshot_sha256 = nonCanonSha;
    const resNonCanon = validateContractRegistry(nonCanonMock, tempDir, { gitExecutor: mockGit });
    if (!resNonCanon.valid && resNonCanon.error.includes('NON_CANONICAL_SNAPSHOT_JSON')) negativePassed++;
    else throw new Error(`Expected NON_CANONICAL_SNAPSHOT_JSON, got: ${JSON.stringify(resNonCanon)}`);

    // Restore canonical
    fs.writeFileSync(snapFile, canonicalBytes);

    // Negative Disk 2: Symlink snapshot
    const symlinkFile = path.join(contractsDir, 'sym.json');
    fs.symlinkSync(snapFile, symlinkFile);
    const symMock = JSON.parse(JSON.stringify(validDiskMock));
    symMock.contracts[0].snapshot_path = '.synthesis/contracts/CONTRACT-GOV-TEST-001/sym.json';
    const resSym = validateContractRegistry(symMock, tempDir, { gitExecutor: mockGit });
    if (!resSym.valid && resSym.error.includes('UNSAFE_FILE_TYPE')) negativePassed++;
    else throw new Error(`Expected UNSAFE_FILE_TYPE, got: ${JSON.stringify(resSym)}`);

    // Negative Disk 3: Non-ancestor effective_from_sha
    const nonAncestorGit = (args) => {
      const cmd = args.join(' ');
      if (cmd.includes('rev-parse --verify')) return '1'.repeat(40) + '\n';
      if (cmd.includes('merge-base --is-ancestor')) throw new Error('Not an ancestor');
      throw new Error(`Unexpected cmd: ${cmd}`);
    };
    const resNonAnc = validateContractRegistry(validDiskMock, tempDir, { gitExecutor: nonAncestorGit });
    if (!resNonAnc.valid && resNonAnc.error.includes('EFFECTIVE_SHA_NON_ANCESTOR')) negativePassed++;
    else throw new Error(`Expected EFFECTIVE_SHA_NON_ANCESTOR, got: ${JSON.stringify(resNonAnc)}`);

    // Negative Disk 4: Nonexistent effective_from_sha in Git
    const badCommitGit = () => { throw new Error('fatal: Not a valid object name'); };
    const resBadComm = validateContractRegistry(validDiskMock, tempDir, { gitExecutor: badCommitGit });
    if (!resBadComm.valid && resBadComm.error.includes('EFFECTIVE_SHA_NONEXISTENT')) negativePassed++;
    else throw new Error(`Expected EFFECTIVE_SHA_NONEXISTENT, got: ${JSON.stringify(resBadComm)}`);

  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
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
