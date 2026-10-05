#!/usr/bin/env node
/**
 * SYNTHESIS CMS MINI — GOVERNANCE LOCKFILE VERIFIER
 *
 * Verifies cryptographic pinning and integrity of governance files and required contracts
 * in governance.lock.json. Enforces BIDIRECTIONAL synchronization with Contract Registry,
 * effective_from_sha git ancestry, STAGED/ACTIVE required contract status,
 * and regular-file (no symlink) safety guarantees.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import child_process from 'node:child_process';
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
export const VALID_LOCK_CONTRACT_STATUSES = new Set(['STAGED', 'ACTIVE']);

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

export function validateGovernanceLock(lockObj, repoRoot = DEFAULT_REPO_ROOT, options = {}) {
  const gitExecutor = options.gitExecutor || defaultGitExecutor;

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
    try {
      const stat = fs.lstatSync(genesisPath);
      if (!stat.isFile() || stat.isSymbolicLink()) {
        return { valid: false, error: `UNSAFE_GENESIS_FILE: Genesis file must be a regular file, not a symlink` };
      }
    } catch (e) {
      return { valid: false, error: `GENESIS_STAT_ERROR: Cannot stat genesis anchor: ${e.message}` };
    }
    const actualGenesisSha = computeFileSha256(genesisPath);
    if (!timingSafeHexCompare(actualGenesisSha, anchor.pinned_sha256)) {
      return { valid: false, error: `GENESIS_ANCHOR_DRIFT: Genesis hash mismatch: expected ${anchor.pinned_sha256}, actual ${actualGenesisSha}` };
    }
  }

  // Pinned items validation
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
      try {
        const stat = fs.lstatSync(fullPath);
        if (!stat.isFile() || stat.isSymbolicLink()) {
          return { valid: false, error: `UNSAFE_PINNED_FILE: Pinned item ${itemPath} must be a regular file, not a symlink` };
        }
      } catch (e) {
        return { valid: false, error: `PINNED_FILE_STAT_ERROR: Cannot stat pinned file ${itemPath}: ${e.message}` };
      }
      const actualSha = computeFileSha256(fullPath);
      if (!timingSafeHexCompare(actualSha, sha256)) {
        return { valid: false, error: `PINNED_FILE_DRIFT: Pinned file ${itemPath} hash drift: expected ${sha256}, actual ${actualSha}` };
      }
    }
  }

  // Required contracts validation
  if (!Array.isArray(lockObj.required_contracts)) {
    return { valid: false, error: 'INVALID_REQUIRED_CONTRACTS: required_contracts must be an array' };
  }

  const seenReqContractKeys = new Set();
  const reqContractsMap = new Map();

  for (let i = 0; i < lockObj.required_contracts.length; i++) {
    const rc = lockObj.required_contracts[i];
    if (!rc || typeof rc !== 'object' || Array.isArray(rc)) {
      return { valid: false, error: `MALFORMED_REQUIRED_CONTRACT: Entry at index ${i} must be an object` };
    }

    const { contract_id, version, snapshot_path, sha256, effective_from_sha, status } = rc;

    if (typeof contract_id !== 'string' || !/^CONTRACT-[A-Z0-9-]+$/.test(contract_id)) {
      return { valid: false, error: `INVALID_REQUIRED_CONTRACT_ID: Entry ${i} has invalid contract_id: ${contract_id}` };
    }
    if (typeof version !== 'string' || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(version)) {
      return { valid: false, error: `INVALID_REQUIRED_CONTRACT_VERSION: Contract ${contract_id} has invalid version: ${version}` };
    }

    const key = `${contract_id}@${version}`;
    if (seenReqContractKeys.has(key)) {
      return { valid: false, error: `DUPLICATE_REQUIRED_CONTRACT: Duplicate (contract_id, version) in required_contracts: ${key}` };
    }
    seenReqContractKeys.add(key);
    reqContractsMap.set(key, rc);

    try {
      validateSafeRelativePath(snapshot_path);
    } catch (e) {
      return { valid: false, error: `UNSAFE_REQUIRED_CONTRACT_PATH: Contract ${key} path error: ${e.message}` };
    }

    if (typeof sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(sha256)) {
      return { valid: false, error: `INVALID_REQUIRED_CONTRACT_HASH: Contract ${key} has invalid sha256 format` };
    }
    if (typeof effective_from_sha !== 'string' || !/^[a-f0-9]{40}$/.test(effective_from_sha)) {
      return { valid: false, error: `INVALID_EFFECTIVE_FROM_SHA: Contract ${key} has invalid effective_from_sha: ${effective_from_sha}` };
    }

    // Required contracts in lock must ONLY be STAGED or ACTIVE
    if (!VALID_LOCK_CONTRACT_STATUSES.has(status)) {
      return { valid: false, error: `INVALID_LOCK_CONTRACT_STATUS: Contract ${key} in lock has status "${status}"; only STAGED or ACTIVE allowed in lockfile` };
    }

    // Git ancestry check for effective_from_sha
    if (repoRoot && gitExecutor && typeof effective_from_sha === 'string' && /^[a-f0-9]{40}$/.test(effective_from_sha)) {
      try {
        gitExecutor(['rev-parse', '--verify', `${effective_from_sha}^{commit}`], repoRoot);
      } catch (e) {
        return { valid: false, error: `LOCK_EFFECTIVE_SHA_NONEXISTENT: effective_from_sha ${effective_from_sha} for ${key} does not exist in repository` };
      }
      try {
        gitExecutor(['merge-base', '--is-ancestor', effective_from_sha, 'HEAD'], repoRoot);
      } catch (e) {
        return { valid: false, error: `LOCK_EFFECTIVE_SHA_NON_ANCESTOR: effective_from_sha ${effective_from_sha} for ${key} is not an ancestor of current HEAD` };
      }
    }

    if (repoRoot) {
      const fullPath = path.resolve(repoRoot, snapshot_path);
      if (!fs.existsSync(fullPath)) {
        return { valid: false, error: `REQUIRED_CONTRACT_SNAPSHOT_MISSING: Snapshot for ${key} missing: ${snapshot_path}` };
      }
      try {
        const stat = fs.lstatSync(fullPath);
        if (!stat.isFile() || stat.isSymbolicLink()) {
          return { valid: false, error: `UNSAFE_REQUIRED_CONTRACT_FILE: Snapshot for ${key} must be a regular file, not a symlink` };
        }
      } catch (e) {
        return { valid: false, error: `REQUIRED_CONTRACT_STAT_ERROR: Cannot stat snapshot for ${key}: ${e.message}` };
      }
      const actualSha = computeFileSha256(fullPath);
      if (!timingSafeHexCompare(actualSha, sha256)) {
        return { valid: false, error: `REQUIRED_CONTRACT_HASH_DRIFT: Contract ${key} snapshot hash drift: expected ${sha256}, actual ${actualSha}` };
      }
    }
  }

  // BIDIRECTIONAL Cross-check against Contract Registry
  if (repoRoot && options.checkContractRegistry !== false) {
    const regPath = path.resolve(repoRoot, '.synthesis/registries/contracts.json');
    if (fs.existsSync(regPath)) {
      try {
        const regRaw = fs.readFileSync(regPath, 'utf8');
        const regObj = parseStrictIJson(regRaw);
        if (!Array.isArray(regObj.contracts)) {
          return { valid: false, error: 'REGISTRY_CONTRACTS_NOT_ARRAY: contracts field in registry is not an array' };
        }

        const registryActiveOrStaged = new Map();

        // Check 1 (Registry -> Lock): every STAGED/ACTIVE in registry must match in lock
        for (const regEntry of regObj.contracts) {
          const regKey = `${regEntry.contract_id}@${regEntry.version}`;
          if (regEntry.status === 'ACTIVE' || regEntry.status === 'STAGED') {
            registryActiveOrStaged.set(regKey, regEntry);

            const lockedEntry = reqContractsMap.get(regKey);
            if (!lockedEntry) {
              return { valid: false, error: `ORPHAN_REGISTRY_REQUIRED_CONTRACT: ${regEntry.status} contract ${regKey} in registry is missing from lockfile required_contracts` };
            }
            if (lockedEntry.status !== regEntry.status) {
              return { valid: false, error: `STATUS_MISMATCH: Status mismatch for ${regKey}: lock has ${lockedEntry.status}, registry has ${regEntry.status}` };
            }
            if (lockedEntry.snapshot_path !== regEntry.snapshot_path) {
              return { valid: false, error: `SNAPSHOT_PATH_MISMATCH: Path mismatch for ${regKey}: lock has ${lockedEntry.snapshot_path}, registry has ${regEntry.snapshot_path}` };
            }
            if (!timingSafeHexCompare(lockedEntry.sha256, regEntry.snapshot_sha256)) {
              return { valid: false, error: `REGISTRY_LOCK_HASH_DRIFT: Hash mismatch between registry and lock for ${regKey}` };
            }
            if (lockedEntry.effective_from_sha !== regEntry.effective_from_sha) {
              return { valid: false, error: `EFFECTIVE_SHA_MISMATCH: effective_from_sha mismatch for ${regKey}: lock has ${lockedEntry.effective_from_sha}, registry has ${regEntry.effective_from_sha}` };
            }
          }
        }

        // Check 2 (Lock -> Registry): every entry in lock required_contracts must exist in registry and be STAGED/ACTIVE
        for (const [lockKey, lockedEntry] of reqContractsMap.entries()) {
          if (!registryActiveOrStaged.has(lockKey)) {
            return { valid: false, error: `ORPHAN_LOCK_REQUIRED_CONTRACT: Entry ${lockKey} in lockfile required_contracts is not present as STAGED or ACTIVE in contract registry` };
          }
        }

      } catch (err) {
        return { valid: false, error: `REGISTRY_CROSSCHECK_ERROR: ${err.message}` };
      }
    }
  }

  return {
    valid: true,
    pinnedCount: lockObj.pinned_items.length,
    requiredContractsCount: lockObj.required_contracts.length
  };
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
    ],
    required_contracts: [
      {
        contract_id: 'CONTRACT-GOV-TEST-001',
        version: '1.0.0',
        snapshot_path: '.synthesis/contracts/CONTRACT-GOV-TEST-001/v1.0.0.json',
        sha256: 'a'.repeat(64),
        effective_from_sha: '1'.repeat(40),
        status: 'ACTIVE'
      }
    ]
  };

  const res = validateGovernanceLock(validMock, null, { gitExecutor: null });
  if (res.valid) positivePassed++;
  else throw new Error(`Initial valid lock mock failed: ${JSON.stringify(res)}`);

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
    { name: 'Bad sha in pinned item', generate: m => { m.pinned_items[0].sha256 = 'short'; return m; }, expected: 'INVALID_PINNED_HASH' },
    { name: 'Required contracts not array', generate: m => { m.required_contracts = 'not-array'; return m; }, expected: 'INVALID_REQUIRED_CONTRACTS' },
    { name: 'Malformed required contract', generate: m => { m.required_contracts = [null]; return m; }, expected: 'MALFORMED_REQUIRED_CONTRACT' },
    { name: 'Bad required contract_id', generate: m => { m.required_contracts[0].contract_id = 'bad-id'; return m; }, expected: 'INVALID_REQUIRED_CONTRACT_ID' },
    { name: 'Duplicate required contract', generate: m => { m.required_contracts.push({ ...m.required_contracts[0] }); return m; }, expected: 'DUPLICATE_REQUIRED_CONTRACT' },
    { name: 'Unsafe required contract path', generate: m => { m.required_contracts[0].snapshot_path = '../../leak.json'; return m; }, expected: 'UNSAFE_REQUIRED_CONTRACT_PATH' },
    { name: 'Bad required contract sha', generate: m => { m.required_contracts[0].sha256 = 'xyz'; return m; }, expected: 'INVALID_REQUIRED_CONTRACT_HASH' },
    { name: 'Bad effective_from_sha', generate: m => { m.required_contracts[0].effective_from_sha = 'short'; return m; }, expected: 'INVALID_EFFECTIVE_FROM_SHA' },
    { name: 'DRAFT status forbidden in lock', generate: m => { m.required_contracts[0].status = 'DRAFT'; return m; }, expected: 'INVALID_LOCK_CONTRACT_STATUS' },
    { name: 'SUPERSEDED status forbidden in lock', generate: m => { m.required_contracts[0].status = 'SUPERSEDED'; return m; }, expected: 'INVALID_LOCK_CONTRACT_STATUS' }
  ];

  for (const tc of negativeCases) {
    const clone = JSON.parse(JSON.stringify(validMock));
    const testObj = tc.generate(clone);
    const r = validateGovernanceLock(testObj, null, { gitExecutor: null });
    if (!r.valid && r.error && r.error.includes(tc.expected)) {
      negativePassed++;
    } else {
      throw new Error(`Self-test negative case '${tc.name}' failed. Expected ${tc.expected}, got: ${JSON.stringify(r)}`);
    }
  }

  // Disk tests (symlink, bidirectional registry sync, git ancestry)
  const tempDir = fs.mkdtempSync(path.join('/tmp', 'gov-lock-test-'));
  try {
    fs.mkdirSync(path.join(tempDir, '.synthesis', 'lineage'), { recursive: true });
    fs.mkdirSync(path.join(tempDir, '.synthesis', 'contracts', 'CONTRACT-GOV-TEST-001'), { recursive: true });
    fs.mkdirSync(path.join(tempDir, '.synthesis', 'registries'), { recursive: true });

    const genesisFile = path.join(tempDir, '.synthesis', 'lineage', 'genesis.json');
    fs.writeFileSync(genesisFile, '{}');
    const genesisSha = computeFileSha256(genesisFile);

    const snapshotFile = path.join(tempDir, '.synthesis', 'contracts', 'CONTRACT-GOV-TEST-001', 'v1.0.0.json');
    fs.writeFileSync(snapshotFile, '{}');
    const snapshotSha = computeFileSha256(snapshotFile);

    const mockGit = (args) => {
      const cmd = args.join(' ');
      if (cmd.includes('rev-parse --verify') && cmd.includes('1'.repeat(40))) return '1'.repeat(40) + '\n';
      if (cmd.includes('merge-base --is-ancestor')) return '';
      throw new Error(`Unexpected mock cmd: ${cmd}`);
    };

    const lockValid = {
      schema_version: '1.0.0',
      lockfile_kind: 'GOVERNANCE_REQUIREMENTS_LOCK',
      locked_at_utc: '2026-10-05T00:00:00.000Z',
      root_governance_health_gate: 'BOOTSTRAP_NOT_YET_ACTIVE',
      genesis_anchor: {
        path: '.synthesis/lineage/genesis.json',
        pinned_sha256: genesisSha
      },
      pinned_items: [],
      required_contracts: [
        {
          contract_id: 'CONTRACT-GOV-TEST-001',
          version: '1.0.0',
          snapshot_path: '.synthesis/contracts/CONTRACT-GOV-TEST-001/v1.0.0.json',
          sha256: snapshotSha,
          effective_from_sha: '1'.repeat(40),
          status: 'ACTIVE'
        }
      ]
    };

    const matchingRegistry = {
      schema_version: 'contract-registry.v1',
      format_version: '1.0.0',
      record_kind: 'CONTRACT_REGISTRY',
      lifecycle_state: 'DRAFT',
      contracts: [
        {
          contract_id: 'CONTRACT-GOV-TEST-001',
          version: '1.0.0',
          title: 'Test',
          status: 'ACTIVE',
          snapshot_path: '.synthesis/contracts/CONTRACT-GOV-TEST-001/v1.0.0.json',
          snapshot_sha256: snapshotSha,
          effective_from_sha: '1'.repeat(40),
          supersedes: [],
          superseded_by: null
        }
      ]
    };
    fs.writeFileSync(path.join(tempDir, '.synthesis', 'registries', 'contracts.json'), JSON.stringify(matchingRegistry));

    const resBidirectionalValid = validateGovernanceLock(lockValid, tempDir, { gitExecutor: mockGit });
    if (resBidirectionalValid.valid) {
      positivePassed++;
    } else {
      throw new Error(`Valid bidirectional lock test failed: ${JSON.stringify(resBidirectionalValid)}`);
    }

    // Negative Disk 1: Orphan Lock Entry (entry in lock not in registry)
    const lockWithExtra = JSON.parse(JSON.stringify(lockValid));
    lockWithExtra.required_contracts.push({
      contract_id: 'CONTRACT-GOV-TEST-002',
      version: '1.0.0',
      snapshot_path: '.synthesis/contracts/CONTRACT-GOV-TEST-001/v1.0.0.json',
      sha256: snapshotSha,
      effective_from_sha: '1'.repeat(40),
      status: 'ACTIVE'
    });
    const resOrphanLock = validateGovernanceLock(lockWithExtra, tempDir, { gitExecutor: mockGit });
    if (!resOrphanLock.valid && resOrphanLock.error.includes('ORPHAN_LOCK_REQUIRED_CONTRACT')) negativePassed++;
    else throw new Error(`Expected ORPHAN_LOCK_REQUIRED_CONTRACT, got: ${JSON.stringify(resOrphanLock)}`);

    // Negative Disk 2: Orphan Registry Entry (ACTIVE in registry missing from lock)
    const regWithExtra = JSON.parse(JSON.stringify(matchingRegistry));
    regWithExtra.contracts.push({
      contract_id: 'CONTRACT-GOV-TEST-002',
      version: '1.0.0',
      title: 'Extra',
      status: 'ACTIVE',
      snapshot_path: '.synthesis/contracts/CONTRACT-GOV-TEST-001/v1.0.0.json',
      snapshot_sha256: snapshotSha,
      effective_from_sha: '1'.repeat(40),
      supersedes: [],
      superseded_by: null
    });
    fs.writeFileSync(path.join(tempDir, '.synthesis', 'registries', 'contracts.json'), JSON.stringify(regWithExtra));
    const resOrphanReg = validateGovernanceLock(lockValid, tempDir, { gitExecutor: mockGit });
    if (!resOrphanReg.valid && resOrphanReg.error.includes('ORPHAN_REGISTRY_REQUIRED_CONTRACT')) negativePassed++;
    else throw new Error(`Expected ORPHAN_REGISTRY_REQUIRED_CONTRACT, got: ${JSON.stringify(resOrphanReg)}`);

    // Restore matching registry
    fs.writeFileSync(path.join(tempDir, '.synthesis', 'registries', 'contracts.json'), JSON.stringify(matchingRegistry));

    // Negative Disk 3: Mismatch in effective_from_sha between lock and registry
    const regMismatchSha = JSON.parse(JSON.stringify(matchingRegistry));
    regMismatchSha.contracts[0].effective_from_sha = '2'.repeat(40);
    fs.writeFileSync(path.join(tempDir, '.synthesis', 'registries', 'contracts.json'), JSON.stringify(regMismatchSha));
    const resMismatchSha = validateGovernanceLock(lockValid, tempDir, { gitExecutor: mockGit });
    if (!resMismatchSha.valid && resMismatchSha.error.includes('EFFECTIVE_SHA_MISMATCH')) negativePassed++;
    else throw new Error(`Expected EFFECTIVE_SHA_MISMATCH, got: ${JSON.stringify(resMismatchSha)}`);

    // Restore matching registry
    fs.writeFileSync(path.join(tempDir, '.synthesis', 'registries', 'contracts.json'), JSON.stringify(matchingRegistry));

    // Negative Disk 4: Non-ancestor lock effective_from_sha
    const nonAncestorGit = (args) => {
      const cmd = args.join(' ');
      if (cmd.includes('rev-parse --verify')) return '1'.repeat(40) + '\n';
      if (cmd.includes('merge-base --is-ancestor')) throw new Error('Not an ancestor');
      throw new Error(`Unexpected mock cmd: ${cmd}`);
    };
    const resNonAnc = validateGovernanceLock(lockValid, tempDir, { gitExecutor: nonAncestorGit });
    if (!resNonAnc.valid && resNonAnc.error.includes('LOCK_EFFECTIVE_SHA_NON_ANCESTOR')) negativePassed++;
    else throw new Error(`Expected LOCK_EFFECTIVE_SHA_NON_ANCESTOR, got: ${JSON.stringify(resNonAnc)}`);

    // Negative Disk 5: Symlink lockfile snapshot
    const symlinkSnapshot = path.join(tempDir, '.synthesis', 'contracts', 'CONTRACT-GOV-TEST-001', 'sym.json');
    fs.symlinkSync(snapshotFile, symlinkSnapshot);
    const lockSym = JSON.parse(JSON.stringify(lockValid));
    lockSym.required_contracts[0].snapshot_path = '.synthesis/contracts/CONTRACT-GOV-TEST-001/sym.json';
    const resSym = validateGovernanceLock(lockSym, tempDir, { gitExecutor: mockGit });
    if (!resSym.valid && resSym.error.includes('UNSAFE_REQUIRED_CONTRACT_FILE')) negativePassed++;
    else throw new Error(`Expected UNSAFE_REQUIRED_CONTRACT_FILE, got: ${JSON.stringify(resSym)}`);

  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
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
    console.log(`GOVERNANCE_LOCK_VERIFIED: ${res.pinnedCount} pinned items and ${res.requiredContractsCount} required contracts match.`);
    process.exit(0);
  } else {
    console.log('Usage: node verify_governance_lock.mjs [--self-test|--verify-all]');
    process.exit(1);
  }
}
