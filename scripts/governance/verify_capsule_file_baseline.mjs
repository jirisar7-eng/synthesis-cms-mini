#!/usr/bin/env node

/**
 * Synthesis CMS mini — Detached Command Capsule Raw File Baseline Verifier
 * 
 * Verifies complete raw file bytes (SHA-256 & Git Blob SHA) of historical
 * Command Capsules against the detached observational baseline attestation.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import child_process from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Reuse existing governance production functions
import {
  loadSchema,
  validateCapsuleComplete,
  buildSampleProvisionalCapsule
} from './validate_command_capsule.mjs';

import {
  parseStrictIJson,
  verifyCapsuleSeal,
  computePayloadSha256,
  timingSafeHexCompare
} from './verify_capsule_seal.mjs';
import {
  verifyAttestationChain
} from './verify_capsule_attestation_chain.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ============================================================
// PINNED CONSTANTS FOR HISTORICAL BASELINE 20261002
// ============================================================

export const PINNED_MANIFEST_RELATIVE_PATH = '.synthesis/attestations/capsule-file-baseline-20261002.json';
export const PINNED_MANIFEST_GIT_BLOB = 'd0c91b768a14070c7b0b19ad56fb33a573278898';
export const PINNED_GENESIS_SHA256 = 'b3d47a6f732512a9f5b19668a07bb4d2c662adf316f5a1d33a6d52c57860ec60';
export const PINNED_SOURCE_MAIN_SHA = 'd362a6431bf0f5c7368df96b657c596eb093b6ff';
export const PINNED_SOURCE_TASK_SHA = '3db87689aee0ab72304efc3b46afc23a5a91890b';
export const EXPECTED_RECORD_COUNT = 2;

// ============================================================
// GIT BLOB SHA & RAW SHA CALCULATION
// ============================================================

export function computeGitBlobSha(rawBytes) {
  if (!Buffer.isBuffer(rawBytes)) {
    throw new Error('computeGitBlobSha requires a Buffer input');
  }
  const header = Buffer.from(`blob ${rawBytes.length}\0`, 'utf8');
  return crypto.createHash('sha1').update(Buffer.concat([header, rawBytes])).digest('hex');
}

export function computeRawFileSha256(rawBytes) {
  if (!Buffer.isBuffer(rawBytes)) {
    throw new Error('computeRawFileSha256 requires a Buffer input');
  }
  return crypto.createHash('sha256').update(rawBytes).digest('hex');
}

// ============================================================
// MANIFEST INTEGRITY VERIFICATION
// ============================================================

export function verifyManifestIntegrity(repoRoot, manifestRelPath = PINNED_MANIFEST_RELATIVE_PATH, expectedBlobSha = PINNED_MANIFEST_GIT_BLOB) {
  if (path.isAbsolute(manifestRelPath) || manifestRelPath.includes('..')) {
    return {
      valid: false,
      stage: 'MANIFEST_PATH_TRAVERSAL',
      error: `Illegal manifest path: "${manifestRelPath}"`
    };
  }

  const fullPath = path.join(repoRoot, manifestRelPath);
  if (!fs.existsSync(fullPath)) {
    return {
      valid: false,
      stage: 'MANIFEST_NOT_FOUND',
      error: `Manifest file does not exist: ${manifestRelPath}`
    };
  }

  const stat = fs.lstatSync(fullPath);
  if (stat.isSymbolicLink() || !stat.isFile()) {
    return {
      valid: false,
      stage: 'MANIFEST_UNSAFE_FILE',
      error: `Manifest must be a regular file, not a symlink or directory: ${manifestRelPath}`
    };
  }

  const rawBytes = fs.readFileSync(fullPath);
  const actualBlobSha = computeGitBlobSha(rawBytes);

  if (expectedBlobSha && actualBlobSha !== expectedBlobSha) {
    return {
      valid: false,
      stage: 'MANIFEST_BLOB_MISMATCH',
      error: `Manifest Git blob SHA mismatch! Computed: ${actualBlobSha}, Expected pinned: ${expectedBlobSha}`
    };
  }

  let manifest;
  try {
    manifest = parseStrictIJson(rawBytes.toString('utf8'));
  } catch (err) {
    return {
      valid: false,
      stage: 'MANIFEST_JSON_PARSE_ERROR',
      error: `Failed to parse manifest JSON: ${err.message}`
    };
  }

  // Verify manifest structural integrity
  if (manifest.format_version !== '1.0.0') {
    return {
      valid: false,
      stage: 'MANIFEST_SCHEMA_ERROR',
      error: `Unsupported format_version: "${manifest.format_version}", expected "1.0.0"`
    };
  }
  if (manifest.record_kind !== 'DETACHED_CAPSULE_RAW_FILE_BASELINE') {
    return {
      valid: false,
      stage: 'MANIFEST_SCHEMA_ERROR',
      error: `Unsupported record_kind: "${manifest.record_kind}"`
    };
  }
  if (manifest.status !== 'OBSERVED_UNANCHORED') {
    return {
      valid: false,
      stage: 'MANIFEST_SCHEMA_ERROR',
      error: `Unsupported status: "${manifest.status}"`
    };
  }
  if (manifest.source_repository !== 'jirisar7-eng/synthesis-cms-mini') {
    return {
      valid: false,
      stage: 'MANIFEST_SCHEMA_ERROR',
      error: `Invalid source_repository: "${manifest.source_repository}"`
    };
  }
  if (manifest.source_main_sha !== PINNED_SOURCE_MAIN_SHA) {
    return {
      valid: false,
      stage: 'MANIFEST_SCHEMA_ERROR',
      error: `Invalid source_main_sha: "${manifest.source_main_sha}", expected "${PINNED_SOURCE_MAIN_SHA}"`
    };
  }
  if (manifest.source_task_sha !== PINNED_SOURCE_TASK_SHA) {
    return {
      valid: false,
      stage: 'MANIFEST_SCHEMA_ERROR',
      error: `Invalid source_task_sha: "${manifest.source_task_sha}", expected "${PINNED_SOURCE_TASK_SHA}"`
    };
  }
  if (manifest.hash_scope !== 'SHA256_RAW_FILE_BYTES') {
    return {
      valid: false,
      stage: 'MANIFEST_SCHEMA_ERROR',
      error: `Unsupported hash_scope: "${manifest.hash_scope}"`
    };
  }
  if (manifest.genesis_sha256 !== PINNED_GENESIS_SHA256) {
    return {
      valid: false,
      stage: 'MANIFEST_SCHEMA_ERROR',
      error: `Genesis anchor SHA-256 mismatch in manifest: "${manifest.genesis_sha256}"`
    };
  }
  if (!manifest.observed_at_utc || typeof manifest.observed_at_utc !== 'string' || Number.isNaN(Date.parse(manifest.observed_at_utc))) {
    return {
      valid: false,
      stage: 'MANIFEST_SCHEMA_ERROR',
      error: `Invalid observed_at_utc timestamp in manifest: "${manifest.observed_at_utc}"`
    };
  }
  if (!Array.isArray(manifest.capsules) || manifest.capsules.length !== EXPECTED_RECORD_COUNT) {
    return {
      valid: false,
      stage: 'MANIFEST_SCHEMA_ERROR',
      error: `Manifest capsules must be an array of exactly ${EXPECTED_RECORD_COUNT} entries, got ${manifest.capsules ? manifest.capsules.length : 0}`
    };
  }

  const seenIds = new Set();
  const seenPaths = new Set();
  for (const c of manifest.capsules) {
    if (!c.capsule_id || seenIds.has(c.capsule_id)) {
      return {
        valid: false,
        stage: 'MANIFEST_DUPLICATE_ENTRY',
        error: `Duplicate or missing capsule_id in manifest: "${c.capsule_id}"`
      };
    }
    seenIds.add(c.capsule_id);

    if (!c.file_path || seenPaths.has(c.file_path)) {
      return {
        valid: false,
        stage: 'MANIFEST_DUPLICATE_ENTRY',
        error: `Duplicate or missing file_path in manifest: "${c.file_path}"`
      };
    }
    seenPaths.add(c.file_path);
  }

  return {
    valid: true,
    manifest,
    rawBytes,
    gitBlobSha: actualBlobSha
  };
}

// ============================================================
// CAPSULE RAW FILE & SEMANTIC VERIFICATION
// ============================================================

export function verifyManifestCapsuleRecord(repoRoot, record, schema) {
  if (!record || typeof record !== 'object') {
    return { valid: false, stage: 'RECORD_SCHEMA', error: 'Invalid capsule record object' };
  }

  // 1. Validate capsule ID syntax
  if (!/^CAP-SYN-MINI-[A-Z0-9_-]+$/.test(record.capsule_id)) {
    return { valid: false, stage: 'INVALID_CAPSULE_ID_SYNTAX', error: `Malformed capsule_id: "${record.capsule_id}"` };
  }

  // 2. Validate canonical relative file path
  if (!/^\.synthesis\/task-capsules\/CAP-[A-Za-z0-9_.-]+\.json$/.test(record.file_path)) {
    return { valid: false, stage: 'INVALID_FILE_PATH_SYNTAX', error: `Malformed relative file_path: "${record.file_path}"` };
  }

  // 3. Reject path traversal
  if (path.isAbsolute(record.file_path) || record.file_path.includes('..')) {
    return { valid: false, stage: 'PATH_TRAVERSAL_DETECTED', error: `Path traversal detected in file_path: "${record.file_path}"` };
  }

  // 4. Reject symlinks and nonregular files
  const fullPath = path.join(repoRoot, record.file_path);
  if (!fs.existsSync(fullPath)) {
    return { valid: false, stage: 'CAPSULE_FILE_MISSING', error: `Capsule file not found: ${record.file_path}` };
  }

  const stat = fs.lstatSync(fullPath);
  if (stat.isSymbolicLink() || !stat.isFile()) {
    return { valid: false, stage: 'UNSAFE_CAPSULE_FILE', error: `Capsule file must be a regular file, not a symlink: ${record.file_path}` };
  }

  // 5. Read actual file as raw bytes
  const rawBytes = fs.readFileSync(fullPath);

  // 6. Compare actual byte length with recorded size
  if (rawBytes.length !== record.file_size_bytes) {
    return {
      valid: false,
      stage: 'FILE_SIZE_MISMATCH',
      error: `File size mismatch for ${record.file_path}! Actual: ${rawBytes.length} bytes, Expected: ${record.file_size_bytes} bytes`
    };
  }

  // 7 & 8. Calculate full raw-file SHA-256 and compare
  const actualRawSha256 = computeRawFileSha256(rawBytes);
  if (!timingSafeHexCompare(actualRawSha256, record.raw_file_sha256)) {
    return {
      valid: false,
      stage: 'RAW_FILE_SHA256_MISMATCH',
      error: `Raw file SHA-256 mismatch for ${record.file_path}! Actual: ${actualRawSha256}, Expected: ${record.raw_file_sha256}`
    };
  }

  // 9 & 10. Calculate actual Git blob SHA and compare
  const actualGitBlob = computeGitBlobSha(rawBytes);
  if (actualGitBlob !== record.git_blob_sha) {
    return {
      valid: false,
      stage: 'GIT_BLOB_SHA_MISMATCH',
      error: `Git blob SHA mismatch for ${record.file_path}! Actual: ${actualGitBlob}, Expected: ${record.git_blob_sha}`
    };
  }

  // 11. Parse capsule using strict I-JSON parser
  let capsule;
  try {
    capsule = parseStrictIJson(rawBytes.toString('utf8'));
  } catch (err) {
    return {
      valid: false,
      stage: 'CAPSULE_I_JSON_ERROR',
      error: `Strict I-JSON parse failure on ${record.file_path}: ${err.message}`
    };
  }

  // 12. Verify actual capsule ID matches record (payload.capsule_id)
  if (capsule?.payload?.capsule_id !== record.capsule_id) {
    return {
      valid: false,
      stage: 'CAPSULE_ID_MISMATCH',
      error: `Capsule ID in file payload ("${capsule?.payload?.capsule_id}") does not match manifest record ("${record.capsule_id}")`
    };
  }

  // 13 & 14. Verify structural schema + cryptographic seal
  const sealRes = verifyCapsuleSeal(schema, capsule);
  if (!sealRes.valid) {
    return {
      valid: false,
      stage: sealRes.stage || 'CAPSULE_SEAL_INVALID',
      error: `Capsule verification failed for ${record.file_path}: ${sealRes.error}`
    };
  }
  if (!sealRes.isSealed || !sealRes.payloadHashMatch) {
    return {
      valid: false,
      stage: 'CAPSULE_NOT_SEALED',
      error: `Capsule ${record.file_path} is not a valid SEALED record with matching payload hash`
    };
  }

  // 15. Compare verified payload SHA-256 with manifest record
  if (!timingSafeHexCompare(sealRes.computedSha256, record.payload_sha256)) {
    return {
      valid: false,
      stage: 'RECORD_PAYLOAD_SHA256_MISMATCH',
      error: `Verified payload SHA-256 ("${sealRes.computedSha256}") does not match manifest record ("${record.payload_sha256}")`
    };
  }

  return {
    valid: true,
    capsuleId: record.capsule_id,
    filePath: record.file_path,
    rawFileSha256: actualRawSha256,
    gitBlobSha: actualGitBlob,
    payloadSha256: sealRes.computedSha256,
    fileSizeBytes: rawBytes.length
  };
}

// ============================================================
// DIRECTORY COVERAGE ENFORCEMENT (FAIL-CLOSED)
// ============================================================

export function verifyDirectoryCoverage(repoRoot, manifest) {
  const capsuleDir = path.join(repoRoot, '.synthesis', 'task-capsules');
  if (!fs.existsSync(capsuleDir)) {
    return { valid: false, stage: 'CAPSULE_DIR_MISSING', error: 'Directory .synthesis/task-capsules does not exist' };
  }

  // Hardened check B: verify the capsule directory itself is a nonsymlink directory
  const dirStat = fs.lstatSync(capsuleDir);
  if (dirStat.isSymbolicLink()) {
    return {
      valid: false,
      stage: 'CAPSULE_DIR_SYMLINK_REJECTED',
      error: 'Directory .synthesis/task-capsules is a symbolic link, which is not permitted.'
    };
  }
  if (!dirStat.isDirectory()) {
    return {
      valid: false,
      stage: 'CAPSULE_DIR_NOT_DIRECTORY',
      error: 'Path .synthesis/task-capsules is not a directory.'
    };
  }

  // Hardened check A: Inspect ALL filesystem entries without skipping dot-prefixed items
  const entries = fs.readdirSync(capsuleDir, { withFileTypes: true });
  const actualCapsulePaths = new Set();

  for (const entry of entries) {
    if (entry.isSymbolicLink()) {
      return {
        valid: false,
        stage: 'UNSAFE_SYMLINK_IN_DIR',
        error: `Unsafe symlink in capsule directory: ${entry.name}`
      };
    }
    if (!entry.isFile() || !entry.name.endsWith('.json')) {
      return {
        valid: false,
        stage: 'UNEXPECTED_ENTRY_IN_DIR',
        error: `Unexpected entry in capsule directory: ${entry.name}`
      };
    }
    const relPath = `.synthesis/task-capsules/${entry.name}`;
    actualCapsulePaths.add(relPath);
  }

  const manifestPaths = new Set(manifest.capsules.map(c => c.file_path));

  for (const actPath of actualCapsulePaths) {
    if (!manifestPaths.has(actPath)) {
      return {
        valid: false,
        stage: 'UNRECORDED_CAPSULE_DETECTED',
        error: `Found capsule in repository not covered by baseline manifest: ${actPath}`
      };
    }
  }

  for (const manPath of manifestPaths) {
    if (!actualCapsulePaths.has(manPath)) {
      return {
        valid: false,
        stage: 'RECORDED_CAPSULE_MISSING',
        error: `Manifest records capsule not found on filesystem: ${manPath}`
      };
    }
  }

  return { valid: true, count: actualCapsulePaths.size };
}

// ============================================================
// COMPREHENSIVE BASELINE VERIFIER
// ============================================================

export function verifyCapsuleFileBaseline(repoRoot) {
  // 1. Verify Manifest Integrity
  const manRes = verifyManifestIntegrity(repoRoot);
  if (!manRes.valid) {
    return {
      valid: false,
      stage: manRes.stage,
      error: manRes.error
    };
  }

  // 2. Load Schema
  let schema;
  try {
    schema = loadSchema(repoRoot);
  } catch (err) {
    return {
      valid: false,
      stage: 'SCHEMA_LOAD_FAILED',
      error: `Failed to load schema: ${err.message}`
    };
  }

  // 3. Verify each baseline-manifested capsule record
  for (const record of manRes.manifest.capsules) {
    const capRes = verifyManifestCapsuleRecord(repoRoot, record, schema);
    if (!capRes.valid) {
      return {
        valid: false,
        stage: capRes.stage,
        error: capRes.error
      };
    }
  }

  // 4. Delegate complete repository & DAG chain verification to authoritative chain verifier
  const chainRes = verifyAttestationChain(repoRoot);
  if (!chainRes.valid) {
    return {
      valid: false,
      stage: chainRes.stage,
      error: chainRes.error
    };
  }

  // 5. Adapt chain records explicitly to the legacy baseline record shape
  const adaptedRecords = chainRes.attestedRecords.map(r => ({
    valid: true,
    capsuleId: r.capsuleId,
    filePath: r.filePath,
    rawFileSha256: r.rawSha256,
    gitBlobSha: r.gitBlobSha,
    payloadSha256: r.payloadSha256,
    fileSizeBytes: r.fileSizeBytes
  }));

  return {
    valid: true,
    manifestGitBlob: manRes.gitBlobSha,
    verifiedCount: adaptedRecords.length,
    records: adaptedRecords,
    chainLength: chainRes.attestationChainLength,
    headAttestationId: chainRes.headAttestationId
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
        if (!expectedErrFragment || (res.error && res.error.includes(expectedErrFragment)) || (res.stage && res.stage.includes(expectedErrFragment))) {
          negativePassed++;
        } else {
          console.error(`FAIL: ${name} -> wrong error message. Expected fragment "${expectedErrFragment}", got stage="${res.stage}", error="${res.error}"`);
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
  // POSITIVE A: Unchanged manifest passes its pinned blob check
  assertPositive('POSITIVE A: Unchanged manifest passes pinned blob check', () => {
    return verifyManifestIntegrity(repoRoot);
  });

  // POSITIVE B: Original capsule 010 passes complete raw-file verification
  assertPositive('POSITIVE B: Original capsule 010 passes complete raw-file verification', () => {
    const manRes = verifyManifestIntegrity(repoRoot);
    if (!manRes.valid) return manRes;
    const rec010 = manRes.manifest.capsules.find(c => c.capsule_id.includes('-010'));
    return verifyManifestCapsuleRecord(repoRoot, rec010, schema);
  });

  // POSITIVE C: Original capsule 013 passes complete raw-file verification
  assertPositive('POSITIVE C: Original capsule 013 passes complete raw-file verification', () => {
    const manRes = verifyManifestIntegrity(repoRoot);
    if (!manRes.valid) return manRes;
    const rec013 = manRes.manifest.capsules.find(c => c.capsule_id.includes('-013'));
    return verifyManifestCapsuleRecord(repoRoot, rec013, schema);
  });

  // POSITIVE D: Full baseline verification passes on repository state
  assertPositive('POSITIVE D: Full baseline verification passes on repository state', () => {
    return verifyCapsuleFileBaseline(repoRoot);
  });

  // POSITIVE E: computeGitBlobSha produces exact Git blob SHA
  assertPositive('POSITIVE E: computeGitBlobSha produces standard Git blob SHA', () => {
    const buf = Buffer.from('hello world\n', 'utf8');
    const blobSha = computeGitBlobSha(buf);
    if (blobSha !== '3b18e512dba79e4c8300dd08aeb37f8e728b8dad') {
      return { valid: false, error: `Git blob SHA mismatch: got ${blobSha}` };
    }
    return { valid: true };
  });

  // POSITIVE F: Directory coverage confirms exactly 2 capsules in isolated fixture
  assertPositive('POSITIVE F: Directory coverage confirms exactly 2 capsules in isolated fixture', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'syn-mini-test-'));
    try {
      const cap010Rel = '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010.json';
      const cap013Rel = '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-013.json';
      const manRel = PINNED_MANIFEST_RELATIVE_PATH;

      const p010 = path.join(tmpDir, cap010Rel);
      const p013 = path.join(tmpDir, cap013Rel);
      const pMan = path.join(tmpDir, manRel);

      fs.mkdirSync(path.dirname(p010), { recursive: true });
      fs.mkdirSync(path.dirname(pMan), { recursive: true });

      fs.copyFileSync(path.join(repoRoot, cap010Rel), p010);
      fs.copyFileSync(path.join(repoRoot, cap013Rel), p013);
      fs.copyFileSync(path.join(repoRoot, manRel), pMan);

      const manRes = verifyManifestIntegrity(tmpDir);
      if (!manRes.valid) return manRes;
      const cov = verifyDirectoryCoverage(tmpDir, manRes.manifest);
      if (!cov.valid || cov.count !== 2) {
        return { valid: false, error: `Expected coverage count 2, got ${cov.count}` };
      }
      return { valid: true };
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  function setupMigrationTestEnv() {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'syn-mini-baseline-mig-'));
    fs.mkdirSync(path.join(tmpDir, '.synthesis', 'lineage'), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, '.synthesis', 'schemas'), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, '.synthesis', 'task-capsules'), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, '.synthesis', 'attestations'), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, 'scripts', 'governance'), { recursive: true });

    fs.copyFileSync(
      path.join(repoRoot, '.synthesis/lineage/genesis.json'),
      path.join(tmpDir, '.synthesis/lineage/genesis.json')
    );
    fs.copyFileSync(
      path.join(repoRoot, 'scripts/governance/verify_genesis.mjs'),
      path.join(tmpDir, 'scripts/governance/verify_genesis.mjs')
    );
    fs.copyFileSync(
      path.join(repoRoot, '.synthesis/schemas/command-capsule.schema.json'),
      path.join(tmpDir, '.synthesis/schemas/command-capsule.schema.json')
    );
    fs.copyFileSync(
      path.join(repoRoot, '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010.json'),
      path.join(tmpDir, '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010.json')
    );
    fs.copyFileSync(
      path.join(repoRoot, '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-013.json'),
      path.join(tmpDir, '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-013.json')
    );
    fs.copyFileSync(
      path.join(repoRoot, PINNED_MANIFEST_RELATIVE_PATH),
      path.join(tmpDir, PINNED_MANIFEST_RELATIVE_PATH)
    );
    return tmpDir;
  }

  function addSyntheticThirdCapsuleFixture(tmpDir) {
    const cap013Bytes = fs.readFileSync(path.join(tmpDir, '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-013.json'));
    const cap013 = JSON.parse(cap013Bytes.toString('utf8'));

    const cap014Payload = JSON.parse(JSON.stringify(cap013.payload));
    cap014Payload.capsule_id = 'CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-014';
    cap014Payload.command_id = 'CMD-SYN-MINI-GOV-CAPSULE-SCHEMA-001-014-SYNTHETIC';
    cap014Payload.lineage.parent_capsules = [
      {
        capsule_id: cap013.payload.capsule_id,
        command_id: cap013.payload.command_id,
        payload_sha256: cap013.seal.payload_sha256,
        relationship_type: 'LINEAR_PARENT'
      }
    ];

    const validPayloadSha = computePayloadSha256(cap014Payload).sha256Hex;

    const cap014 = {
      payload: cap014Payload,
      seal: {
        status: 'SEALED',
        hash_algorithm: 'SHA-256',
        canonicalization_algorithm: 'RFC-8785',
        payload_sha256: validPayloadSha,
        sealed_at: '2026-10-02T16:00:00Z',
        sealed_by: 'jirisar7-eng',
        seal_signature: null
      }
    };

    const cap014Bytes = Buffer.from(JSON.stringify(cap014, null, 2), 'utf8');
    const cap014RelPath = '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-014.json';
    fs.writeFileSync(path.join(tmpDir, cap014RelPath), cap014Bytes);

    const baselineBytes = fs.readFileSync(path.join(tmpDir, PINNED_MANIFEST_RELATIVE_PATH));
    const baselineRawSha = computeRawFileSha256(baselineBytes);

    const att001Id = 'ATT-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-001';
    const att001 = {
      format_version: '1.0.0',
      record_kind: 'LINKED_CAPSULE_FILE_ATTESTATION',
      attestation_id: att001Id,
      status: 'OBSERVED_UNANCHORED',
      observed_at_utc: '2026-10-02T16:05:00Z',
      source_repository: 'jirisar7-eng/synthesis-cms-mini',
      genesis_anchor_reference: {
        genesis_file: '.synthesis/lineage/genesis.json',
        pinned_sha256: PINNED_GENESIS_SHA256
      },
      parent_attestation: {
        attestation_id: 'DETACHED_CAPSULE_RAW_FILE_BASELINE_20261002',
        file_path: PINNED_MANIFEST_RELATIVE_PATH,
        raw_file_sha256: baselineRawSha
      },
      new_capsule: {
        capsule_id: cap014.payload.capsule_id,
        file_path: cap014RelPath,
        payload_sha256: validPayloadSha,
        raw_file_sha256: computeRawFileSha256(cap014Bytes),
        git_blob_sha: computeGitBlobSha(cap014Bytes),
        file_size_bytes: cap014Bytes.length
      }
    };

    const att001Bytes = Buffer.from(JSON.stringify(att001, null, 2), 'utf8');
    const att001RelPath = `.synthesis/attestations/${att001Id}.json`;
    fs.writeFileSync(path.join(tmpDir, att001RelPath), att001Bytes);

    return {
      capRelPath: cap014RelPath,
      attestationRelPath: att001RelPath,
      capBytes: cap014Bytes,
      attestationBytes: att001Bytes
    };
  }

  // POSITIVE G: Full baseline verification passes with valid synthetic 3rd capsule + linked attestation extension
  assertPositive('POSITIVE G: Full baseline verification passes with valid synthetic 3rd capsule extension', () => {
    const tmpDir = setupMigrationTestEnv();
    try {
      addSyntheticThirdCapsuleFixture(tmpDir);
      const res = verifyCapsuleFileBaseline(tmpDir);
      if (!res.valid) {
        return { valid: false, error: `Expected valid baseline verification, got ${res.stage}: ${res.error}` };
      }
      if (res.verifiedCount !== 3) {
        return { valid: false, error: `Expected 3 verified capsules, got ${res.verifiedCount}` };
      }
      if (!Array.isArray(res.records) || res.records.length !== 3) {
        return { valid: false, error: `Expected 3 records in result, got ${res.records?.length}` };
      }
      return { valid: true };
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // NEGATIVE TESTS (Isolated in-memory / temporary directory)
  // NEGATIVE A: Change seal.sealed_by in 010 (preserving file length) -> Raw file SHA mismatch
  assertNegative('NEGATIVE A: Altering sealed_by causes raw_file_sha256 mismatch', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'syn-mini-test-'));
    try {
      const capPath = path.join(repoRoot, '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010.json');
      const rawText = fs.readFileSync(capPath, 'utf8');
      const tampered = rawText.replace('"sealed_by": "jirisar7-eng"', '"sealed_by": "jirisar7-tam"');
      const tmpCapRel = '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010.json';
      const tmpCapFull = path.join(tmpDir, tmpCapRel);
      fs.mkdirSync(path.dirname(tmpCapFull), { recursive: true });
      fs.writeFileSync(tmpCapFull, tampered, 'utf8');

      const manRes = verifyManifestIntegrity(repoRoot);
      const rec = manRes.manifest.capsules.find(x => x.capsule_id.includes('-010'));
      return verifyManifestCapsuleRecord(tmpDir, rec, schema);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'RAW_FILE_SHA256_MISMATCH');

  // NEGATIVE B: Change seal.sealed_at in 013 (preserving file length) -> Raw file SHA mismatch
  assertNegative('NEGATIVE B: Altering sealed_at causes raw_file_sha256 mismatch', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'syn-mini-test-'));
    try {
      const capPath = path.join(repoRoot, '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-013.json');
      const rawText = fs.readFileSync(capPath, 'utf8');
      const tampered = rawText.replace('"sealed_at": "2026-10-02T15:00:00Z"', '"sealed_at": "2026-10-02T15:00:01Z"');
      const tmpCapRel = '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-013.json';
      const tmpCapFull = path.join(tmpDir, tmpCapRel);
      fs.mkdirSync(path.dirname(tmpCapFull), { recursive: true });
      fs.writeFileSync(tmpCapFull, tampered, 'utf8');

      const manRes = verifyManifestIntegrity(repoRoot);
      const rec = manRes.manifest.capsules.find(x => x.capsule_id.includes('-013'));
      return verifyManifestCapsuleRecord(tmpDir, rec, schema);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'RAW_FILE_SHA256_MISMATCH');

  // NEGATIVE C: Change seal.seal_signature in 010 -> Raw file SHA or Size mismatch
  assertNegative('NEGATIVE C: Altering seal_signature causes raw file integrity failure', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'syn-mini-test-'));
    try {
      const capPath = path.join(repoRoot, '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010.json');
      const rawText = fs.readFileSync(capPath, 'utf8');
      const tampered = rawText.replace('"seal_signature": null', '"seal_signature": "x" ');
      const tmpCapRel = '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010.json';
      const tmpCapFull = path.join(tmpDir, tmpCapRel);
      fs.mkdirSync(path.dirname(tmpCapFull), { recursive: true });
      fs.writeFileSync(tmpCapFull, tampered, 'utf8');

      const manRes = verifyManifestIntegrity(repoRoot);
      const rec = manRes.manifest.capsules.find(x => x.capsule_id.includes('-010'));
      return verifyManifestCapsuleRecord(tmpDir, rec, schema);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'RAW_FILE_SHA256_MISMATCH');

  // NEGATIVE D: Modify one byte of the manifest -> Manifest blob mismatch
  assertNegative('NEGATIVE D: Tampered manifest byte rejected by blob check', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'syn-mini-test-'));
    try {
      const manPath = path.join(repoRoot, PINNED_MANIFEST_RELATIVE_PATH);
      const raw = fs.readFileSync(manPath, 'utf8');
      const tampered = raw.replace('1.0.0', '1.0.1');
      const tmpMan = path.join(tmpDir, PINNED_MANIFEST_RELATIVE_PATH);
      fs.mkdirSync(path.dirname(tmpMan), { recursive: true });
      fs.writeFileSync(tmpMan, tampered, 'utf8');

      return verifyManifestIntegrity(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'MANIFEST_BLOB_MISMATCH');

  // NEGATIVE E: Changed expected raw_file_sha256 in manifest record -> Rejection
  assertNegative('NEGATIVE E: Tampered expected raw_file_sha256 rejected', () => {
    const manRes = verifyManifestIntegrity(repoRoot);
    const rec = JSON.parse(JSON.stringify(manRes.manifest.capsules[0]));
    rec.raw_file_sha256 = '0'.repeat(64);
    return verifyManifestCapsuleRecord(repoRoot, rec, schema);
  }, 'RAW_FILE_SHA256_MISMATCH');

  // NEGATIVE F: Changed expected git_blob_sha in manifest record -> Rejection
  assertNegative('NEGATIVE F: Tampered expected git_blob_sha rejected', () => {
    const manRes = verifyManifestIntegrity(repoRoot);
    const rec = JSON.parse(JSON.stringify(manRes.manifest.capsules[0]));
    rec.git_blob_sha = '0'.repeat(40);
    return verifyManifestCapsuleRecord(repoRoot, rec, schema);
  }, 'GIT_BLOB_SHA_MISMATCH');

  // NEGATIVE G: Changed expected file_size_bytes -> Rejection
  assertNegative('NEGATIVE G: Tampered expected file_size_bytes rejected', () => {
    const manRes = verifyManifestIntegrity(repoRoot);
    const rec = JSON.parse(JSON.stringify(manRes.manifest.capsules[0]));
    rec.file_size_bytes = 999999;
    return verifyManifestCapsuleRecord(repoRoot, rec, schema);
  }, 'FILE_SIZE_MISMATCH');

  // NEGATIVE H: Duplicate capsule entry in manifest -> Rejection
  assertNegative('NEGATIVE H: Duplicate capsule entry in manifest rejected', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'syn-mini-test-'));
    try {
      const manRes = verifyManifestIntegrity(repoRoot);
      const dupManifest = JSON.parse(JSON.stringify(manRes.manifest));
      dupManifest.capsules.push(dupManifest.capsules[0]);
      dupManifest.capsules = dupManifest.capsules.slice(0, 2);
      dupManifest.capsules[1] = JSON.parse(JSON.stringify(dupManifest.capsules[0]));
      const tmpMan = path.join(tmpDir, 'manifest.json');
      fs.writeFileSync(tmpMan, JSON.stringify(dupManifest), 'utf8');

      return verifyManifestIntegrity(tmpDir, 'manifest.json', null);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'MANIFEST_DUPLICATE_ENTRY');

  // NEGATIVE I: Traversal-shaped file path in record -> Rejection
  assertNegative('NEGATIVE I: Path traversal in capsule record rejected', () => {
    const manRes = verifyManifestIntegrity(repoRoot);
    const rec = JSON.parse(JSON.stringify(manRes.manifest.capsules[0]));
    rec.file_path = '../secret/capsule.json';
    return verifyManifestCapsuleRecord(repoRoot, rec, schema);
  }, 'INVALID_FILE_PATH_SYNTAX');

  // NEGATIVE J: Unrecorded capsule in directory -> Coverage rejection
  assertNegative('NEGATIVE J: Unrecorded extra capsule in directory rejected', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'syn-mini-test-'));
    try {
      const capDir = path.join(tmpDir, '.synthesis/task-capsules');
      fs.mkdirSync(capDir, { recursive: true });
      fs.writeFileSync(path.join(capDir, 'CAP-SYN-MINI-EXTRA.json'), '{}', 'utf8');

      const manRes = verifyManifestIntegrity(repoRoot);
      return verifyDirectoryCoverage(tmpDir, manRes.manifest);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'UNRECORDED_CAPSULE_DETECTED');

  // NEGATIVE K: Reject PROVISIONAL capsule even if raw bytes match synthetic manifest
  assertNegative('NEGATIVE K: Non-SEALED capsule rejected by semantic verification', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'syn-mini-test-'));
    try {
      const prov = buildSampleProvisionalCapsule();
      const provBytes = Buffer.from(JSON.stringify(prov, null, 2), 'utf8');
      const provPath = path.join(tmpDir, '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-001.json');
      fs.mkdirSync(path.dirname(provPath), { recursive: true });
      fs.writeFileSync(provPath, provBytes);

      const syntheticRec = {
        capsule_id: prov.payload.capsule_id,
        file_path: '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-001.json',
        payload_sha256: '0'.repeat(64),
        raw_file_sha256: computeRawFileSha256(provBytes),
        git_blob_sha: computeGitBlobSha(provBytes),
        file_size_bytes: provBytes.length
      };

      return verifyManifestCapsuleRecord(tmpDir, syntheticRec, schema);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'CAPSULE_NOT_SEALED');

  // NEGATIVE L: Place unexpected .hidden.json file in directory -> Coverage rejection
  assertNegative('NEGATIVE L: Hidden JSON file (.hidden.json) in capsule directory rejected', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'syn-mini-test-'));
    try {
      const capDir = path.join(tmpDir, '.synthesis/task-capsules');
      fs.mkdirSync(capDir, { recursive: true });
      fs.writeFileSync(path.join(capDir, '.hidden.json'), '{}', 'utf8');

      const manRes = verifyManifestIntegrity(repoRoot);
      return verifyDirectoryCoverage(tmpDir, manRes.manifest);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'UNRECORDED_CAPSULE_DETECTED');

  // NEGATIVE M: Place unexpected .hidden-note file in directory -> Unexpected entry rejection
  assertNegative('NEGATIVE M: Hidden non-JSON file (.hidden-note) in capsule directory rejected', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'syn-mini-test-'));
    try {
      const capDir = path.join(tmpDir, '.synthesis/task-capsules');
      fs.mkdirSync(capDir, { recursive: true });
      fs.writeFileSync(path.join(capDir, '.hidden-note'), 'secret note', 'utf8');

      const manRes = verifyManifestIntegrity(repoRoot);
      return verifyDirectoryCoverage(tmpDir, manRes.manifest);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'UNEXPECTED_ENTRY_IN_DIR');

  // NEGATIVE N: Place hidden symbolic link in directory -> Unsafe symlink rejection
  assertNegative('NEGATIVE N: Hidden symbolic link (.hidden-link) in capsule directory rejected', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'syn-mini-test-'));
    try {
      const capDir = path.join(tmpDir, '.synthesis/task-capsules');
      fs.mkdirSync(capDir, { recursive: true });
      const targetPath = path.join(tmpDir, 'target.txt');
      fs.writeFileSync(targetPath, 'target', 'utf8');
      fs.symlinkSync(targetPath, path.join(capDir, '.hidden-link'));

      const manRes = verifyManifestIntegrity(repoRoot);
      return verifyDirectoryCoverage(tmpDir, manRes.manifest);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'UNSAFE_SYMLINK_IN_DIR');

  // NEGATIVE O: Capsule directory itself is a symbolic link -> Directory symlink rejection
  assertNegative('NEGATIVE O: Capsule directory as a symbolic link rejected', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'syn-mini-test-'));
    try {
      const realDir = path.join(tmpDir, 'real-capsules');
      fs.mkdirSync(realDir, { recursive: true });
      const synDir = path.join(tmpDir, '.synthesis');
      fs.mkdirSync(synDir, { recursive: true });
      fs.symlinkSync(realDir, path.join(synDir, 'task-capsules'));

      const manRes = verifyManifestIntegrity(repoRoot);
      return verifyDirectoryCoverage(tmpDir, manRes.manifest);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'CAPSULE_DIR_SYMLINK_REJECTED');

  // NEGATIVE P: Capsule directory is a regular file -> Not a directory rejection
  assertNegative('NEGATIVE P: Capsule directory as a regular file rejected', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'syn-mini-test-'));
    try {
      const synDir = path.join(tmpDir, '.synthesis');
      fs.mkdirSync(synDir, { recursive: true });
      fs.writeFileSync(path.join(synDir, 'task-capsules'), 'not a directory', 'utf8');

      const manRes = verifyManifestIntegrity(repoRoot);
      return verifyDirectoryCoverage(tmpDir, manRes.manifest);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'CAPSULE_DIR_NOT_DIRECTORY');

  // NEGATIVE Q: Full baseline verification rejects 3rd capsule without linked attestation
  assertNegative('NEGATIVE Q: 3rd capsule without linked attestation rejected in full baseline verification', () => {
    const tmpDir = setupMigrationTestEnv();
    try {
      const third = addSyntheticThirdCapsuleFixture(tmpDir);
      fs.unlinkSync(path.join(tmpDir, third.attestationRelPath));
      return verifyCapsuleFileBaseline(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'UNRECORDED_CAPSULE_DETECTED');

  // NEGATIVE R: Full baseline verification rejects linked attestation with missing capsule file
  assertNegative('NEGATIVE R: Linked attestation with missing capsule file rejected in full baseline verification', () => {
    const tmpDir = setupMigrationTestEnv();
    try {
      const third = addSyntheticThirdCapsuleFixture(tmpDir);
      fs.unlinkSync(path.join(tmpDir, third.capRelPath));
      return verifyCapsuleFileBaseline(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'RECORDED_CAPSULE_FILE_MISSING');

  // NEGATIVE S: Full baseline verification rejects linked attestation with forged parent hash without fallback
  assertNegative('NEGATIVE S: Linked attestation with forged parent hash rejected without fallback', () => {
    const tmpDir = setupMigrationTestEnv();
    try {
      const third = addSyntheticThirdCapsuleFixture(tmpDir);
      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.parent_attestation.raw_file_sha256 = 'f'.repeat(64);
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');
      return verifyCapsuleFileBaseline(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'PARENT_RAW_SHA256_MISMATCH');

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
    console.log(`Synthesis CMS mini — Detached Command Capsule Raw File Baseline Verifier`);
    console.log(`Usage:`);
    console.log(`  node scripts/governance/verify_capsule_file_baseline.mjs --self-test`);
    console.log(`  node scripts/governance/verify_capsule_file_baseline.mjs --verify-all`);
    console.log(`  node scripts/governance/verify_capsule_file_baseline.mjs --help`);
    process.exit(args.length === 0 ? 1 : 0);
  }

  if (args[0] === '--self-test') {
    if (args.length !== 1) {
      console.error(`Error: Unexpected arguments after --self-test: ${args.slice(1).join(', ')}`);
      process.exit(1);
    }
    console.log(`Running Detached Capsule Raw File Baseline Verifier self-tests...`);
    const results = runSelfTests(repoRoot);
    console.log(`POSITIVE_TESTS_PASSED: ${results.positivePassed}`);
    console.log(`NEGATIVE_TESTS_PASSED: ${results.negativePassed}`);
    console.log(`FAILED_TESTS: ${results.failedTests}`);
    console.log(`BASELINE_VERIFICATION_STATUS: ${results.failedTests === 0 ? 'PASS' : 'FAIL'}`);

    if (results.failedTests > 0 || results.positivePassed < 7 || results.negativePassed < 19) {
      process.exit(1);
    }
    process.exit(0);
  }

  if (args[0] === '--verify-all') {
    if (args.length !== 1) {
      console.error(`Error: Unexpected arguments after --verify-all: ${args.slice(1).join(', ')}`);
      process.exit(1);
    }

    try {
      const res = verifyCapsuleFileBaseline(repoRoot);
      if (!res.valid) {
        console.error(`DETACHED BASELINE VERIFICATION FAILED [${res.stage}]: ${res.error}`);
        process.exit(1);
      }

      console.log(`MANIFEST_BLOB_VERIFICATION: PASS (${res.manifestGitBlob})`);
      console.log(`CAPSULES_VERIFIED_COUNT: ${res.verifiedCount}`);
      for (const rec of res.records) {
        console.log(`  - ${rec.capsuleId} (${rec.filePath}): RAW_SHA=${rec.rawFileSha256}, BLOB=${rec.gitBlobSha}, SIZE=${rec.fileSizeBytes}B`);
      }
      console.log(`DETACHED_BASELINE_VERIFICATION: PASS`);
      console.log(`WHOLE_FILE_INTEGRITY: PASS (FOR_MANIFESTED_RECORDS)`);
      console.log(`INDEPENDENT_TRUST_ANCHOR: NOT_ESTABLISHED`);
      console.log(`AUTHOR_SIGNATURE_VERIFICATION: NOT_IMPLEMENTED`);
      console.log(`APPEND_ONLY_LEDGER: NOT_IMPLEMENTED`);
      process.exit(0);
    } catch (err) {
      console.error(`DETACHED BASELINE VERIFICATION FAILED: ${err.message}`);
      process.exit(1);
    }
  }

  console.error(`Error: Unsupported argument "${args[0]}". See --help.`);
  process.exit(1);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  main();
}
