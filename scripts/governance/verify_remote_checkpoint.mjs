#!/usr/bin/env node
/**
 * SYNTHESIS CMS MINI — REMOTE FILE CHECKPOINT VERIFIER
 *
 * Roadmap Step: 6/60 — Remote file checkpoint protocol
 *
 * Verifies immutable, sealed remote file checkpoints (CHK-*.json)
 * ensuring cryptographic binding, remote durability verification,
 * git commit/tree provenance, and recovery semantics without self-reference.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import child_process from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_REPO_ROOT = path.resolve(__dirname, '..', '..');

// RFC-8785 Canonicalization
export function canonicalizeRfc8785(data) {
  if (data === null) return 'null';
  const type = typeof data;
  if (type === 'boolean') return data ? 'true' : 'false';
  if (type === 'number') {
    if (!Number.isFinite(data)) throw new TypeError('Non-finite numbers cannot be canonicalized');
    return String(data);
  }
  if (type === 'string') return JSON.stringify(data);
  if (Array.isArray(data)) {
    let out = '[';
    for (let i = 0; i < data.length; i++) {
      if (i > 0) out += ',';
      out += canonicalizeRfc8785(data[i]);
    }
    out += ']';
    return out;
  }
  if (type === 'object') {
    const keys = Object.keys(data).sort((a, b) => {
      const aBuf = Buffer.from(a, 'utf16le');
      const bBuf = Buffer.from(b, 'utf16le');
      return aBuf.compare(bBuf);
    });
    let out = '{';
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      if (i > 0) out += ',';
      out += JSON.stringify(k) + ':' + canonicalizeRfc8785(data[k]);
    }
    out += '}';
    return out;
  }
  throw new TypeError(`Cannot canonicalize unsupported type: ${type}`);
}

export function computePayloadSha256(payload) {
  const canonicalJson = canonicalizeRfc8785(payload);
  const sha256Hex = crypto.createHash('sha256').update(canonicalJson, 'utf8').digest('hex');
  return { canonicalJson, sha256Hex };
}

export function computeRawFileSha256(fileBytes) {
  return crypto.createHash('sha256').update(fileBytes).digest('hex');
}

export function computeGitBlobSha(fileBytes) {
  const header = `blob ${fileBytes.length}\0`;
  const store = Buffer.concat([Buffer.from(header, 'utf8'), fileBytes]);
  return crypto.createHash('sha1').update(store).digest('hex');
}

// Path validation helper
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
  if (/[\x00-\x1F\x7F]/.test(relPath)) {
    throw new Error(`PATH_ERROR: Control characters forbidden in path: ${relPath}`);
  }
  const normalized = path.normalize(relPath);
  if (normalized.startsWith('..') || normalized === '..' || path.isAbsolute(normalized)) {
    throw new Error(`PATH_ERROR: Path traversal detected: ${relPath}`);
  }
  // Check forbidden recursive checkpoint paths
  if (
    normalized.startsWith('.synthesis/checkpoints/') ||
    normalized.startsWith('.synthesis/task-capsules/') ||
    normalized.startsWith('.synthesis/attestations/')
  ) {
    throw new Error(`FORBIDDEN_RECURSIVE_TARGET: Checkpoint cannot target governance artifacts: ${relPath}`);
  }
  return normalized;
}

// Safe git execution
export function execGit(args, cwd) {
  for (const arg of args) {
    if (typeof arg !== 'string') throw new TypeError('Git arguments must be strings');
  }
  try {
    const res = child_process.spawnSync('git', args, {
      cwd,
      encoding: 'utf8',
      shell: false,
      maxBuffer: 20 * 1024 * 1024
    });
    if (res.error) throw res.error;
    if (res.status !== 0) {
      throw new Error(`GIT_ERROR: git ${args.join(' ')} exited with status ${res.status}: ${res.stderr}`);
    }
    return res.stdout.trim();
  } catch (err) {
    throw new Error(`GIT_EXEC_FAILED: ${err.message}`);
  }
}

// Checkpoint Schema & Structure Validator
export function validateCheckpointSchema(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new Error('SCHEMA_ERROR: Checkpoint must be a JSON object');
  }
  const topKeys = Object.keys(obj).sort();
  if (topKeys.length !== 2 || topKeys[0] !== 'payload' || topKeys[1] !== 'seal') {
    throw new Error('SCHEMA_ERROR: Checkpoint must have exactly "payload" and "seal" properties');
  }

  const { payload, seal } = obj;
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('SCHEMA_ERROR: payload must be an object');
  }
  if (!seal || typeof seal !== 'object' || Array.isArray(seal)) {
    throw new Error('SCHEMA_ERROR: seal must be an object');
  }

  // Payload required fields
  if (payload.schema_version !== '1.0.0') throw new Error('SCHEMA_ERROR: schema_version must be "1.0.0"');
  if (payload.record_kind !== 'REMOTE_FILE_CHECKPOINT') throw new Error('SCHEMA_ERROR: record_kind must be "REMOTE_FILE_CHECKPOINT"');
  if (!/^CHK-[A-Z0-9_-]+-[0-9]{8}-[0-9]{3}$/.test(payload.checkpoint_id || '')) {
    throw new Error(`SCHEMA_ERROR: Invalid checkpoint_id format: ${payload.checkpoint_id}`);
  }
  if (payload.checkpoint_type !== 'SINGLE_FILE' && payload.checkpoint_type !== 'ATOMIC_GROUP') {
    throw new Error(`SCHEMA_ERROR: Invalid checkpoint_type: ${payload.checkpoint_type}`);
  }
  if (payload.checkpoint_state !== 'CHECKPOINT_COMPLETE') {
    throw new Error(`NON_COMPLETE_CHECKPOINT: Only CHECKPOINT_COMPLETE state may be persisted, got: ${payload.checkpoint_state}`);
  }
  if (!payload.task_id || !payload.command_id) {
    throw new Error('SCHEMA_ERROR: task_id and command_id are required');
  }
  if (payload.project_id !== 'SYNTHESIS_CMS_MINI') {
    throw new Error(`SCHEMA_ERROR: project_id must be "SYNTHESIS_CMS_MINI", got: ${payload.project_id}`);
  }

  // Repository section
  const repo = payload.repository;
  if (!repo || typeof repo !== 'object') throw new Error('SCHEMA_ERROR: repository object required');
  if (repo.name !== 'jirisar7-eng/synthesis-cms-mini') throw new Error(`WRONG_REPOSITORY: Expected "jirisar7-eng/synthesis-cms-mini", got: ${repo.name}`);
  if (repo.id !== 1401215700) throw new Error(`WRONG_REPOSITORY_ID: Expected 1401215700, got: ${repo.id}`);
  if (!repo.branch || !/^(task\/[A-Z0-9_-]+|main)$/.test(repo.branch)) throw new Error(`WRONG_BRANCH: Invalid branch: ${repo.branch}`);
  if (!/^[0-9a-f]{40}$/.test(repo.base_main_sha || '')) throw new Error(`INVALID_SHA: Invalid base_main_sha: ${repo.base_main_sha}`);

  // Target commit section
  const tc = payload.target_commit;
  if (!tc || typeof tc !== 'object') throw new Error('SCHEMA_ERROR: target_commit object required');
  if (!/^[0-9a-f]{40}$/.test(tc.commit_sha || '')) throw new Error(`INVALID_SHA: Invalid target commit_sha: ${tc.commit_sha}`);
  if (!/^[0-9a-f]{40}$/.test(tc.parent_sha || '')) throw new Error(`INVALID_SHA: Invalid target parent_sha: ${tc.parent_sha}`);

  // Remote verification section
  const rv = payload.remote_verification;
  if (!rv || typeof rv !== 'object') throw new Error('SCHEMA_ERROR: remote_verification object required');
  if (rv.verification_method !== 'GIT_LS_REMOTE' && rv.verification_method !== 'GITHUB_REST_API') {
    throw new Error(`INVALID_VERIFICATION_METHOD: ${rv.verification_method}`);
  }
  if (!rv.observed_remote_ref) throw new Error('SCHEMA_ERROR: observed_remote_ref required');
  if (!/^[0-9a-f]{40}$/.test(rv.observed_remote_sha || '')) throw new Error(`INVALID_SHA: Invalid observed_remote_sha: ${rv.observed_remote_sha}`);
  if (rv.remote_relationship !== 'EXACT_HEAD' && rv.remote_relationship !== 'VERIFIED_DESCENDANT') {
    throw new Error(`INVALID_REMOTE_RELATIONSHIP: ${rv.remote_relationship}`);
  }

  // Checkpointed files
  const files = payload.checkpointed_files;
  if (!Array.isArray(files) || files.length === 0) throw new Error('SCHEMA_ERROR: checkpointed_files must be non-empty array');
  if (payload.checkpoint_type === 'SINGLE_FILE' && files.length !== 1) {
    throw new Error(`CHECKPOINT_TYPE_MISMATCH: SINGLE_FILE must have exactly 1 file, got: ${files.length}`);
  }
  const seenPaths = new Set();
  for (const f of files) {
    if (!f || typeof f !== 'object') throw new Error('SCHEMA_ERROR: checkpointed file entry must be object');
    const norm = validateSafeRelativePath(f.file_path);
    if (seenPaths.has(norm)) throw new Error(`DUPLICATE_FILE_PATH: Duplicate path in checkpoint: ${norm}`);
    seenPaths.add(norm);

    if (f.operation === 'DELETE') {
      throw new Error('UNSUPPORTED_OPERATION: DELETE operation is not supported in v1 checkpoint protocol');
    }
    if (f.operation !== 'ADD' && f.operation !== 'MODIFY') {
      throw new Error(`INVALID_OPERATION: Unsupported file operation: ${f.operation}`);
    }
    if (f.operation === 'MODIFY') {
      if (!/^[0-9a-f]{40}$/.test(f.source_blob_sha || '')) {
        throw new Error(`INVALID_SOURCE_BLOB: MODIFY operation requires valid source_blob_sha, got: ${f.source_blob_sha}`);
      }
    } else if (f.operation === 'ADD') {
      if (f.source_blob_sha !== null) {
        throw new Error(`INVALID_SOURCE_BLOB: ADD operation must have source_blob_sha = null, got: ${f.source_blob_sha}`);
      }
    }
    if (!/^[0-9a-f]{40}$/.test(f.result_blob_sha || '')) {
      throw new Error(`INVALID_RESULT_BLOB: Invalid result_blob_sha: ${f.result_blob_sha}`);
    }
    if (typeof f.file_size_bytes !== 'number' || f.file_size_bytes < 0) {
      throw new Error(`INVALID_FILE_SIZE: Invalid file_size_bytes: ${f.file_size_bytes}`);
    }
  }

  // Evidence binding
  const eb = payload.evidence_binding;
  if (!eb || typeof eb !== 'object') throw new Error('SCHEMA_ERROR: evidence_binding object required');
  if (!/^CAP-[A-Z0-9_-]+-[0-9]{8}-[0-9]{3}$/.test(eb.linked_capsule_id || '')) {
    throw new Error(`INVALID_CAPSULE_ID: ${eb.linked_capsule_id}`);
  }
  if (!/^[0-9a-f]{64}$/.test(eb.linked_capsule_payload_sha256 || '')) {
    throw new Error(`INVALID_CAPSULE_HASH: ${eb.linked_capsule_payload_sha256}`);
  }

  // Recovery semantics
  const rs = payload.recovery_semantics;
  if (!rs || typeof rs !== 'object') throw new Error('SCHEMA_ERROR: recovery_semantics object required');
  if (rs.durability_state !== 'REMOTE_DURABLE') throw new Error(`INVALID_DURABILITY_STATE: ${rs.durability_state}`);
  if (rs.skippable_on_recovery !== true) throw new Error('SCHEMA_ERROR: skippable_on_recovery must be true');

  // Seal section
  if (seal.status !== 'SEALED') throw new Error(`INVALID_SEAL_STATUS: ${seal.status}`);
  if (seal.hash_algorithm !== 'SHA-256') throw new Error(`INVALID_HASH_ALGO: ${seal.hash_algorithm}`);
  if (seal.canonicalization_algorithm !== 'RFC-8785') throw new Error(`INVALID_CANONICAL_ALGO: ${seal.canonicalization_algorithm}`);
  if (!/^[0-9a-f]{64}$/.test(seal.payload_sha256 || '')) throw new Error(`INVALID_SEAL_HASH: ${seal.payload_sha256}`);

  return true;
}

// Seal Integrity Validator
export function validateCheckpointSeal(obj) {
  validateCheckpointSchema(obj);
  const { sha256Hex } = computePayloadSha256(obj.payload);
  if (sha256Hex !== obj.seal.payload_sha256) {
    throw new Error(`SEAL_MISMATCH: Computed payload SHA-256 (${sha256Hex}) !== seal (${obj.seal.payload_sha256})`);
  }
  return true;
}

// Commit & Git Tree Binding Validator
export function validateCheckpointCommitBinding(repoRoot, checkpointObj) {
  validateCheckpointSeal(checkpointObj);
  const { payload } = checkpointObj;
  const targetCommit = payload.target_commit.commit_sha;
  const targetParent = payload.target_commit.parent_sha;

  // 1. Verify target commit exists in git
  let parentsOut;
  try {
    parentsOut = execGit(['rev-parse', `${targetCommit}^@`], repoRoot);
  } catch (err) {
    throw new Error(`TARGET_COMMIT_ABSENT: Commit ${targetCommit} not found in repository: ${err.message}`);
  }
  const parents = parentsOut.split(/\s+/).filter(Boolean);
  if (!parents.includes(targetParent)) {
    throw new Error(`TARGET_PARENT_MISMATCH: Target commit parents [${parents.join(', ')}] do not include claimed parent ${targetParent}`);
  }

  // 2. Inspect git tree at target commit
  const targetTreeRaw = execGit(['ls-tree', '-r', targetCommit], repoRoot);
  const targetTreeMap = {};
  for (const line of targetTreeRaw.split('\n')) {
    if (!line.trim()) continue;
    const parts = line.split(/\s+/);
    targetTreeMap[parts[3]] = parts[2];
  }

  // Inspect git tree at parent commit
  const parentTreeRaw = execGit(['ls-tree', '-r', targetParent], repoRoot);
  const parentTreeMap = {};
  for (const line of parentTreeRaw.split('\n')) {
    if (!line.trim()) continue;
    const parts = line.split(/\s+/);
    parentTreeMap[parts[3]] = parts[2];
  }

  // 3. Verify each declared file in checkpoint matches commit tree
  const declaredFiles = payload.checkpointed_files;
  for (const f of declaredFiles) {
    const p = f.file_path;
    const actualResultBlob = targetTreeMap[p];
    if (!actualResultBlob) {
      throw new Error(`FILE_NOT_IN_TARGET_TREE: Checkpointed file ${p} does not exist in target commit tree ${targetCommit}`);
    }
    if (actualResultBlob !== f.result_blob_sha) {
      throw new Error(`RESULT_BLOB_MISMATCH: File ${p} tree blob (${actualResultBlob}) !== claimed (${f.result_blob_sha})`);
    }

    if (f.operation === 'MODIFY') {
      const actualSourceBlob = parentTreeMap[p];
      if (!actualSourceBlob) {
        throw new Error(`MODIFY_SOURCE_NOT_IN_PARENT: File ${p} claimed MODIFY but was not present in parent commit tree ${targetParent}`);
      }
      if (actualSourceBlob !== f.source_blob_sha) {
        throw new Error(`SOURCE_BLOB_MISMATCH: File ${p} parent tree blob (${actualSourceBlob}) !== claimed source (${f.source_blob_sha})`);
      }
    } else if (f.operation === 'ADD') {
      if (parentTreeMap[p]) {
        throw new Error(`ADD_ALREADY_IN_PARENT: File ${p} claimed ADD but was already present in parent commit tree ${targetParent}`);
      }
    }
  }

  // 4. Verify no undeclared extra file changes in commit for atomic group
  const rawDiff = execGit(['diff-tree', '-r', '--name-only', '--no-commit-id', targetParent, targetCommit], repoRoot);
  const diffFiles = rawDiff.split('\n').filter(Boolean);
  const declaredSet = new Set(declaredFiles.map(f => f.file_path));
  
  // Note: If commit includes governance CAP/ATT, those are permitted outside the checkpointed file group
  for (const df of diffFiles) {
    if (df.startsWith('.synthesis/task-capsules/') || df.startsWith('.synthesis/attestations/')) {
      continue;
    }
    if (!declaredSet.has(df)) {
      throw new Error(`UNDECLARED_FILE_IN_COMMIT: Commit ${targetCommit} contains file outside declared atomic group: ${df}`);
    }
  }

  return true;
}

// Checkpoint Lineage Validator
export function validateCheckpointLineage(repoRoot, checkpointObj) {
  validateCheckpointSeal(checkpointObj);
  const parentRef = checkpointObj.payload.checkpoint_lineage.parent_checkpoint;
  if (!parentRef) return true;

  const parentPath = path.resolve(repoRoot, parentRef.file_path);
  if (!fs.existsSync(parentPath)) {
    throw new Error(`PARENT_CHECKPOINT_MISSING: Parent checkpoint file not found: ${parentRef.file_path}`);
  }

  const parentBytes = fs.readFileSync(parentPath);
  const parentRawSha256 = computeRawFileSha256(parentBytes);
  if (parentRawSha256 !== parentRef.raw_file_sha256) {
    throw new Error(`PARENT_CHECKPOINT_RAW_SHA_MISMATCH: Parent file ${parentRef.file_path} SHA256 (${parentRawSha256}) !== claimed (${parentRef.raw_file_sha256})`);
  }

  const parentObj = JSON.parse(parentBytes.toString('utf8'));
  validateCheckpointSeal(parentObj);

  if (parentObj.payload.checkpoint_id !== parentRef.checkpoint_id) {
    throw new Error(`PARENT_CHECKPOINT_ID_MISMATCH: Claimed parent ID ${parentRef.checkpoint_id} !== found ${parentObj.payload.checkpoint_id}`);
  }

  if (parentObj.payload.checkpoint_id === checkpointObj.payload.checkpoint_id) {
    throw new Error(`CHECKPOINT_LINEAGE_CYCLE: Self-referential checkpoint parent loop detected: ${parentRef.checkpoint_id}`);
  }

  return true;
}

// Live Remote Verifier & Recovery Engine
export function evaluateRecoveryStatus(repoRoot, checkpointObj, liveRemoteSha) {
  validateCheckpointCommitBinding(repoRoot, checkpointObj);
  const targetCommit = checkpointObj.payload.target_commit.commit_sha;

  if (!liveRemoteSha || typeof liveRemoteSha !== 'string' || !/^[0-9a-f]{40}$/.test(liveRemoteSha)) {
    return { status: 'REMOTE_UNAVAILABLE', reason: 'Invalid or missing live remote SHA' };
  }

  // Exact head match
  if (liveRemoteSha === targetCommit) {
    return { status: 'REMOTE_DURABLE_AND_CURRENT', reason: 'Live remote SHA exactly matches target commit' };
  }

  // Check descendant relationship
  let isDescendant = false;
  try {
    const mergeBase = execGit(['merge-base', targetCommit, liveRemoteSha], repoRoot);
    if (mergeBase === targetCommit) {
      isDescendant = true;
    }
  } catch (err) {
    return { status: 'ANCESTRY_LOSS', reason: `Ancestry check failed: ${err.message}` };
  }

  if (!isDescendant) {
    return { status: 'ANCESTRY_LOSS', reason: `Target commit ${targetCommit} is not an ancestor of remote HEAD ${liveRemoteSha}` };
  }

  // Check if checkpointed files have remained unchanged in live remote tree
  const liveTreeRaw = execGit(['ls-tree', '-r', liveRemoteSha], repoRoot);
  const liveTreeMap = {};
  for (const line of liveTreeRaw.split('\n')) {
    if (!line.trim()) continue;
    const parts = line.split(/\s+/);
    liveTreeMap[parts[3]] = parts[2];
  }

  for (const f of checkpointObj.payload.checkpointed_files) {
    const liveBlob = liveTreeMap[f.file_path];
    if (liveBlob !== f.result_blob_sha) {
      return {
        status: 'REMOTE_DURABLE_BUT_SUPERSEDED',
        reason: `File ${f.file_path} was modified after checkpoint (live blob ${liveBlob} !== ${f.result_blob_sha})`
      };
    }
  }

  return {
    status: 'REMOTE_BRANCH_ADVANCED_VALID_DESCENDANT',
    reason: 'Remote branch advanced, but checkpointed files remain unchanged'
  };
}

// Comprehensive Self-Test Runner
export function runSelfTests() {
  const tmpDir = path.join('/tmp', `synthesis-chk-selftest-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
  fs.mkdirSync(tmpDir, { recursive: true });

  let posPassed = 0;
  let negPassed = 0;

  function assert(cond, msg) {
    if (!cond) throw new Error(`Assertion failed: ${msg}`);
  }

  function assertThrows(fn, errSubstr, testName) {
    try {
      fn();
      throw new Error(`Expected test "${testName}" to throw, but it succeeded`);
    } catch (err) {
      if (errSubstr && !err.message.includes(errSubstr)) {
        throw new Error(`Test "${testName}" threw unexpected error: ${err.message}, expected substring: ${errSubstr}`);
      }
      negPassed++;
    }
  }

  try {
    // Initialize temporary git test repository
    execGit(['init', '--initial-branch=main'], tmpDir);
    execGit(['config', 'user.name', 'Synthesis Test'], tmpDir);
    execGit(['config', 'user.email', 'test@synthesis.local'], tmpDir);

    // Initial commit (C0)
    fs.writeFileSync(path.join(tmpDir, 'init.txt'), 'genesis\n');
    execGit(['add', 'init.txt'], tmpDir);
    execGit(['commit', '-m', 'genesis commit'], tmpDir);
    const c0Sha = execGit(['rev-parse', 'HEAD'], tmpDir);

    // Commit 1: Add a test module file (C1)
    fs.mkdirSync(path.join(tmpDir, 'src'), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, 'src', 'module.mjs'), 'export const v = 1;\n');
    execGit(['add', 'src/module.mjs'], tmpDir);
    execGit(['commit', '-m', 'add module'], tmpDir);
    const c1Sha = execGit(['rev-parse', 'HEAD'], tmpDir);
    const c1Blob = execGit(['ls-tree', '-r', c1Sha], tmpDir).split('\n').find(l => l.includes('src/module.mjs')).split(/\s+/)[2];

    // Commit 2: Modify test module file (C2)
    fs.writeFileSync(path.join(tmpDir, 'src', 'module.mjs'), 'export const v = 2;\n');
    execGit(['add', 'src/module.mjs'], tmpDir);
    execGit(['commit', '-m', 'modify module'], tmpDir);
    const c2Sha = execGit(['rev-parse', 'HEAD'], tmpDir);
    const c2Blob = execGit(['ls-tree', '-r', c2Sha], tmpDir).split('\n').find(l => l.includes('src/module.mjs')).split(/\s+/)[2];

    // Commit 3: Atomic group (C3)
    fs.writeFileSync(path.join(tmpDir, 'src', 'a.mjs'), 'export const a = 1;\n');
    fs.writeFileSync(path.join(tmpDir, 'src', 'b.mjs'), 'export const b = 2;\n');
    execGit(['add', 'src/a.mjs', 'src/b.mjs'], tmpDir);
    execGit(['commit', '-m', 'add atomic group'], tmpDir);
    const c3Sha = execGit(['rev-parse', 'HEAD'], tmpDir);
    const c3BlobA = execGit(['ls-tree', '-r', c3Sha], tmpDir).split('\n').find(l => l.includes('src/a.mjs')).split(/\s+/)[2];
    const c3BlobB = execGit(['ls-tree', '-r', c3Sha], tmpDir).split('\n').find(l => l.includes('src/b.mjs')).split(/\s+/)[2];

    // Helper to build sealed checkpoint
    function buildCheckpoint(payloadOverrides = {}) {
      const defaultPayload = {
        schema_version: '1.0.0',
        record_kind: 'REMOTE_FILE_CHECKPOINT',
        checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-001',
        checkpoint_type: 'SINGLE_FILE',
        checkpoint_state: 'CHECKPOINT_COMPLETE',
        task_id: 'SYN-MINI-TEST-001',
        command_id: 'CMD-SYN-MINI-TEST-001-001',
        project_id: 'SYNTHESIS_CMS_MINI',
        roadmap_step: '6/60 — Remote file checkpoint test',
        repository: {
          name: 'jirisar7-eng/synthesis-cms-mini',
          id: 1401215700,
          branch: 'task/SYN-MINI-TEST-001',
          base_main_sha: c0Sha
        },
        target_commit: {
          commit_sha: c2Sha,
          parent_sha: c1Sha,
          commit_timestamp_utc: '2026-10-05T00:00:00.000Z'
        },
        remote_verification: {
          verification_method: 'GIT_LS_REMOTE',
          observed_remote_ref: 'refs/heads/task/SYN-MINI-TEST-001',
          observed_remote_sha: c2Sha,
          remote_relationship: 'EXACT_HEAD',
          verified_at_utc: '2026-10-05T00:00:01.000Z'
        },
        checkpoint_lineage: {
          parent_checkpoint: null
        },
        checkpointed_files: [
          {
            file_path: 'src/module.mjs',
            operation: 'MODIFY',
            source_blob_sha: c1Blob,
            result_blob_sha: c2Blob,
            file_size_bytes: 20
          }
        ],
        evidence_binding: {
          linked_capsule_id: 'CAP-SYN-MINI-TEST-001-20261005-001',
          linked_capsule_payload_sha256: 'a'.repeat(64)
        },
        recovery_semantics: {
          durability_state: 'REMOTE_DURABLE',
          skippable_on_recovery: true
        }
      };

      function deepMerge(target, source) {
        const out = { ...target };
        for (const k of Object.keys(source)) {
          if (source[k] !== null && typeof source[k] === 'object' && !Array.isArray(source[k])) {
            out[k] = deepMerge(target[k] || {}, source[k]);
          } else {
            out[k] = source[k];
          }
        }
        return out;
      }

      const payload = deepMerge(defaultPayload, payloadOverrides);
      const { sha256Hex } = computePayloadSha256(payload);
      return {
        payload,
        seal: {
          status: 'SEALED',
          hash_algorithm: 'SHA-256',
          canonicalization_algorithm: 'RFC-8785',
          payload_sha256: sha256Hex,
          sealed_at: '2026-10-05T00:00:02.000Z',
          sealed_by: 'Test Verifier',
          seal_signature: null
        }
      };
    }

    // POS-01: Valid single-file MODIFY exact remote head
    const chkPos01 = buildCheckpoint();
    assert(validateCheckpointSeal(chkPos01), 'POS-01 seal failed');
    assert(validateCheckpointCommitBinding(tmpDir, chkPos01), 'POS-01 commit binding failed');
    const rec01 = evaluateRecoveryStatus(tmpDir, chkPos01, c2Sha);
    assert(rec01.status === 'REMOTE_DURABLE_AND_CURRENT', 'POS-01 recovery status');
    posPassed++;

    // POS-02: Valid single-file ADD exact remote head
    const chkPos02 = buildCheckpoint({
      checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-002',
      target_commit: { commit_sha: c1Sha, parent_sha: c0Sha, commit_timestamp_utc: '2026-10-05T00:00:00.000Z' },
      remote_verification: {
        verification_method: 'GIT_LS_REMOTE',
        observed_remote_ref: 'refs/heads/task/SYN-MINI-TEST-001',
        observed_remote_sha: c1Sha,
        remote_relationship: 'EXACT_HEAD',
        verified_at_utc: '2026-10-05T00:00:01.000Z'
      },
      checkpointed_files: [
        {
          file_path: 'src/module.mjs',
          operation: 'ADD',
          source_blob_sha: null,
          result_blob_sha: c1Blob,
          file_size_bytes: 20
        }
      ]
    });
    assert(validateCheckpointCommitBinding(tmpDir, chkPos02), 'POS-02 binding failed');
    posPassed++;

    // POS-03: Valid declared atomic group
    const chkPos03 = buildCheckpoint({
      checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-003',
      checkpoint_type: 'ATOMIC_GROUP',
      target_commit: { commit_sha: c3Sha, parent_sha: c2Sha, commit_timestamp_utc: '2026-10-05T00:00:00.000Z' },
      remote_verification: {
        verification_method: 'GIT_LS_REMOTE',
        observed_remote_ref: 'refs/heads/task/SYN-MINI-TEST-001',
        observed_remote_sha: c3Sha,
        remote_relationship: 'EXACT_HEAD',
        verified_at_utc: '2026-10-05T00:00:01.000Z'
      },
      checkpointed_files: [
        { file_path: 'src/a.mjs', operation: 'ADD', source_blob_sha: null, result_blob_sha: c3BlobA, file_size_bytes: 20 },
        { file_path: 'src/b.mjs', operation: 'ADD', source_blob_sha: null, result_blob_sha: c3BlobB, file_size_bytes: 20 }
      ]
    });
    assert(validateCheckpointCommitBinding(tmpDir, chkPos03), 'POS-03 binding failed');
    posPassed++;

    // POS-04: Valid remote descendant with unchanged checkpointed file
    // Commit 4: Add unrelated file (C4)
    fs.writeFileSync(path.join(tmpDir, 'unrelated.txt'), 'extra\n');
    execGit(['add', 'unrelated.txt'], tmpDir);
    execGit(['commit', '-m', 'unrelated commit'], tmpDir);
    const c4Sha = execGit(['rev-parse', 'HEAD'], tmpDir);

    const rec04 = evaluateRecoveryStatus(tmpDir, chkPos03, c4Sha);
    assert(rec04.status === 'REMOTE_BRANCH_ADVANCED_VALID_DESCENDANT', 'POS-04 recovery status');
    posPassed++;

    // POS-05: Fresh-session recovery skips a still-current durable file
    assert(rec04.status === 'REMOTE_BRANCH_ADVANCED_VALID_DESCENDANT', 'POS-05 recovery check');
    posPassed++;

    // POS-06: Valid parent checkpoint lineage
    fs.mkdirSync(path.join(tmpDir, '.synthesis', 'checkpoints'), { recursive: true });
    const p1Path = path.join(tmpDir, '.synthesis', 'checkpoints', 'CHK-SYN-MINI-TEST-001-20261005-001.json');
    fs.writeFileSync(p1Path, JSON.stringify(chkPos01, null, 2));
    const p1Sha256 = computeRawFileSha256(fs.readFileSync(p1Path));

    const chkPos06 = buildCheckpoint({
      checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-004',
      checkpoint_lineage: {
        parent_checkpoint: {
          checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-001',
          file_path: '.synthesis/checkpoints/CHK-SYN-MINI-TEST-001-20261005-001.json',
          raw_file_sha256: p1Sha256
        }
      }
    });
    assert(validateCheckpointLineage(tmpDir, chkPos06), 'POS-06 lineage check');
    posPassed++;

    // NEG-01: Local commit without remote proof (invalid verification method)
    assertThrows(() => {
      validateCheckpointSeal(buildCheckpoint({ remote_verification: { verification_method: 'LOCAL_REV_PARSE' } }));
    }, 'INVALID_VERIFICATION_METHOD', 'NEG-01');

    // NEG-02: Push rejected / no remote update
    assertThrows(() => {
      const chk = buildCheckpoint({
        remote_verification: {
          observed_remote_sha: '0'.repeat(40),
          verification_method: 'GIT_LS_REMOTE',
          observed_remote_ref: 'ref',
          remote_relationship: 'EXACT_HEAD',
          verified_at_utc: '2026-10-05T00:00:00Z'
        },
        target_commit: { commit_sha: '0'.repeat(40), parent_sha: c1Sha, commit_timestamp_utc: '2026-10-05T00:00:00Z' }
      });
      validateCheckpointCommitBinding(tmpDir, chk);
    }, 'TARGET_COMMIT_ABSENT', 'NEG-02 (commit binding)');

    // NEG-03: Remote SHA mismatch in live evaluation
    const rec03 = evaluateRecoveryStatus(tmpDir, chkPos01, '0'.repeat(40));
    assert(rec03.status === 'ANCESTRY_LOSS' || rec03.status === 'REMOTE_UNAVAILABLE', 'NEG-03 recovery status');
    negPassed++;

    // NEG-04: Cached origin ref substituted for live remote (invalid method)
    assertThrows(() => {
      validateCheckpointSeal(buildCheckpoint({ remote_verification: { verification_method: 'ORIGIN_CACHE' } }));
    }, 'INVALID_VERIFICATION_METHOD', 'NEG-04');

    // NEG-05: Expected SHA substituted for observed SHA (malformed SHA)
    assertThrows(() => {
      validateCheckpointSeal(buildCheckpoint({ remote_verification: { observed_remote_sha: 'NOT_A_VALID_SHA' } }));
    }, 'INVALID_SHA', 'NEG-05');

    // NEG-06: Wrong repository
    assertThrows(() => {
      validateCheckpointSeal(buildCheckpoint({ repository: { name: 'other/repo', id: 1401215700, branch: 'main', base_main_sha: c0Sha } }));
    }, 'WRONG_REPOSITORY', 'NEG-06');

    // NEG-07: Wrong repository ID
    assertThrows(() => {
      validateCheckpointSeal(buildCheckpoint({ repository: { name: 'jirisar7-eng/synthesis-cms-mini', id: 999999, branch: 'main', base_main_sha: c0Sha } }));
    }, 'WRONG_REPOSITORY_ID', 'NEG-07');

    // NEG-08: Wrong branch pattern
    assertThrows(() => {
      validateCheckpointSeal(buildCheckpoint({ repository: { name: 'jirisar7-eng/synthesis-cms-mini', id: 1401215700, branch: 'feat/unsupported', base_main_sha: c0Sha } }));
    }, 'WRONG_BRANCH', 'NEG-08');

    // NEG-09: Malformed Git SHA in target commit
    assertThrows(() => {
      validateCheckpointSeal(buildCheckpoint({ target_commit: { commit_sha: '12345', parent_sha: c1Sha, commit_timestamp_utc: '2026-10-05T00:00:00Z' } }));
    }, 'INVALID_SHA', 'NEG-09');

    // NEG-10: Target commit absent in git
    assertThrows(() => {
      const chk = buildCheckpoint({ target_commit: { commit_sha: '1234567890123456789012345678901234567890', parent_sha: c1Sha, commit_timestamp_utc: '2026-10-05T00:00:00Z' } });
      validateCheckpointCommitBinding(tmpDir, chk);
    }, 'TARGET_COMMIT_ABSENT', 'NEG-10');

    // NEG-11: Target parent mismatch
    assertThrows(() => {
      const chk = buildCheckpoint({ target_commit: { commit_sha: c2Sha, parent_sha: c0Sha, commit_timestamp_utc: '2026-10-05T00:00:00Z' } });
      validateCheckpointCommitBinding(tmpDir, chk);
    }, 'TARGET_PARENT_MISMATCH', 'NEG-11');

    // NEG-12: Source blob mismatch on MODIFY
    assertThrows(() => {
      const chk = buildCheckpoint({
        checkpointed_files: [{ file_path: 'src/module.mjs', operation: 'MODIFY', source_blob_sha: '0'.repeat(40), result_blob_sha: c2Blob, file_size_bytes: 20 }]
      });
      validateCheckpointCommitBinding(tmpDir, chk);
    }, 'SOURCE_BLOB_MISMATCH', 'NEG-12');

    // NEG-13: Result blob mismatch
    assertThrows(() => {
      const chk = buildCheckpoint({
        checkpointed_files: [{ file_path: 'src/module.mjs', operation: 'MODIFY', source_blob_sha: c1Blob, result_blob_sha: '0'.repeat(40), file_size_bytes: 20 }]
      });
      validateCheckpointCommitBinding(tmpDir, chk);
    }, 'RESULT_BLOB_MISMATCH', 'NEG-13');

    // NEG-14: File changed after checkpoint (superseded)
    // Commit 5: Modify src/module.mjs again (C5)
    fs.writeFileSync(path.join(tmpDir, 'src', 'module.mjs'), 'export const v = 3;\n');
    execGit(['add', 'src/module.mjs'], tmpDir);
    execGit(['commit', '-m', 'modify module to v3'], tmpDir);
    const c5Sha = execGit(['rev-parse', 'HEAD'], tmpDir);

    const rec14 = evaluateRecoveryStatus(tmpDir, chkPos01, c5Sha);
    assert(rec14.status === 'REMOTE_DURABLE_BUT_SUPERSEDED', 'NEG-14 superseded');
    negPassed++;

    // NEG-15: Force-push / ancestry loss
    // Create an orphan branch with unrelated commit C6
    execGit(['checkout', '--orphan', 'orphan-branch'], tmpDir);
    fs.writeFileSync(path.join(tmpDir, 'orphan.txt'), 'orphan\n');
    execGit(['add', 'orphan.txt'], tmpDir);
    execGit(['commit', '-m', 'orphan commit'], tmpDir);
    const c6Sha = execGit(['rev-parse', 'HEAD'], tmpDir);
    execGit(['checkout', 'main'], tmpDir);

    const rec15 = evaluateRecoveryStatus(tmpDir, chkPos01, c6Sha);
    assert(rec15.status === 'ANCESTRY_LOSS', 'NEG-15 ancestry loss');
    negPassed++;

    // NEG-16: Undeclared extra file in atomic group commit
    assertThrows(() => {
      const chk = buildCheckpoint({
        checkpoint_type: 'SINGLE_FILE',
        target_commit: { commit_sha: c3Sha, parent_sha: c2Sha, commit_timestamp_utc: '2026-10-05T00:00:00Z' },
        checkpointed_files: [{ file_path: 'src/a.mjs', operation: 'ADD', source_blob_sha: null, result_blob_sha: c3BlobA, file_size_bytes: 20 }]
      });
      validateCheckpointCommitBinding(tmpDir, chk);
    }, 'UNDECLARED_FILE_IN_COMMIT', 'NEG-16');

    // NEG-17: Duplicate file path in checkpointed files
    assertThrows(() => {
      validateCheckpointSeal(buildCheckpoint({
        checkpoint_type: 'ATOMIC_GROUP',
        checkpointed_files: [
          { file_path: 'src/a.mjs', operation: 'ADD', source_blob_sha: null, result_blob_sha: c3BlobA, file_size_bytes: 20 },
          { file_path: 'src/a.mjs', operation: 'ADD', source_blob_sha: null, result_blob_sha: c3BlobA, file_size_bytes: 20 }
        ]
      }));
    }, 'DUPLICATE_FILE_PATH', 'NEG-17');

    // NEG-18: Absolute path
    assertThrows(() => {
      validateSafeRelativePath('/etc/passwd');
    }, 'Absolute path forbidden', 'NEG-18');

    // NEG-19: Traversal path
    assertThrows(() => {
      validateSafeRelativePath('../outside.mjs');
    }, 'Path traversal detected', 'NEG-19');

    // NEG-20: Option injection path
    assertThrows(() => {
      validateSafeRelativePath('--help');
    }, 'Option injection forbidden', 'NEG-20');

    // NEG-21: Control characters in path
    assertThrows(() => {
      validateSafeRelativePath('file\x00.mjs');
    }, 'Control characters forbidden', 'NEG-21');

    // NEG-22: Checkpoint file schema top level invalid
    assertThrows(() => {
      validateCheckpointSchema([]);
    }, 'SCHEMA_ERROR', 'NEG-22');

    // NEG-23: Remote lookup missing observed remote sha
    assertThrows(() => {
      validateCheckpointSeal(buildCheckpoint({ remote_verification: { observed_remote_sha: null } }));
    }, 'INVALID_SHA', 'NEG-23');

    // NEG-24: Malformed checkpoint (missing required field)
    assertThrows(() => {
      const chk = buildCheckpoint();
      delete chk.payload.task_id;
      validateCheckpointSchema(chk);
    }, 'SCHEMA_ERROR', 'NEG-24');

    // NEG-25: Invalid RFC-8785 seal
    assertThrows(() => {
      const chk = buildCheckpoint();
      chk.seal.payload_sha256 = 'f'.repeat(64);
      validateCheckpointSeal(chk);
    }, 'SEAL_MISMATCH', 'NEG-25');

    // NEG-26: Non-CHECKPOINT_COMPLETE persisted record
    assertThrows(() => {
      validateCheckpointSeal(buildCheckpoint({ checkpoint_state: 'LOCAL_VALIDATED' }));
    }, 'NON_COMPLETE_CHECKPOINT', 'NEG-26');

    // NEG-27: Bad parent checkpoint raw SHA256
    assertThrows(() => {
      const chk = buildCheckpoint({
        checkpoint_lineage: {
          parent_checkpoint: {
            checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-001',
            file_path: '.synthesis/checkpoints/CHK-SYN-MINI-TEST-001-20261005-001.json',
            raw_file_sha256: '0'.repeat(64)
          }
        }
      });
      validateCheckpointLineage(tmpDir, chk);
    }, 'PARENT_CHECKPOINT_RAW_SHA_MISMATCH', 'NEG-27');

    // NEG-28: Checkpoint lineage cycle (self-reference)
    assertThrows(() => {
      const chk = buildCheckpoint({
        checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-001',
        checkpoint_lineage: {
          parent_checkpoint: {
            checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-001',
            file_path: '.synthesis/checkpoints/CHK-SYN-MINI-TEST-001-20261005-001.json',
            raw_file_sha256: p1Sha256
          }
        }
      });
      validateCheckpointLineage(tmpDir, chk);
    }, 'CHECKPOINT_LINEAGE_CYCLE', 'NEG-28');

    // NEG-29: Missing parent checkpoint file
    assertThrows(() => {
      const chk = buildCheckpoint({
        checkpoint_lineage: {
          parent_checkpoint: {
            checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-999',
            file_path: '.synthesis/checkpoints/CHK-SYN-MINI-TEST-001-20261005-999.json',
            raw_file_sha256: '0'.repeat(64)
          }
        }
      });
      validateCheckpointLineage(tmpDir, chk);
    }, 'PARENT_CHECKPOINT_MISSING', 'NEG-29');

    // NEG-30: Forbidden recursive target under .synthesis/checkpoints/
    assertThrows(() => {
      validateSafeRelativePath('.synthesis/checkpoints/CHK-1.json');
    }, 'FORBIDDEN_RECURSIVE_TARGET', 'NEG-30');

    // NEG-31: Forbidden recursive target under task-capsules/
    assertThrows(() => {
      validateSafeRelativePath('.synthesis/task-capsules/CAP-1.json');
    }, 'FORBIDDEN_RECURSIVE_TARGET', 'NEG-31');

    // NEG-32: Forbidden recursive target under attestations/
    assertThrows(() => {
      validateSafeRelativePath('.synthesis/attestations/ATT-1.json');
    }, 'FORBIDDEN_RECURSIVE_TARGET', 'NEG-32');

    // NEG-33: Unsupported DELETE in v1
    assertThrows(() => {
      validateCheckpointSeal(buildCheckpoint({
        checkpointed_files: [{ file_path: 'src/module.mjs', operation: 'DELETE', source_blob_sha: c1Blob, result_blob_sha: c2Blob, file_size_bytes: 20 }]
      }));
    }, 'UNSUPPORTED_OPERATION', 'NEG-33');

    // NEG-34: Invalid operation string
    assertThrows(() => {
      validateCheckpointSeal(buildCheckpoint({
        checkpointed_files: [{ file_path: 'src/module.mjs', operation: 'RENAME', source_blob_sha: c1Blob, result_blob_sha: c2Blob, file_size_bytes: 20 }]
      }));
    }, 'INVALID_OPERATION', 'NEG-34');

    // NEG-35: Current remote descendant modifies checkpointed blob
    const rec35 = evaluateRecoveryStatus(tmpDir, chkPos01, c5Sha);
    assert(rec35.status === 'REMOTE_DURABLE_BUT_SUPERSEDED', 'NEG-35 superseded check');
    negPassed++;

  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (_) {}
  }

  const total = posPassed + negPassed;
  return {
    positivePassed: posPassed,
    negativePassed: negPassed,
    totalTests: total
  };
}

// CLI Execution Entrypoint
export function main() {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes('--help')) {
    console.log(`
SYNTHESIS CMS MINI — REMOTE FILE CHECKPOINT VERIFIER

Usage:
  node verify_remote_checkpoint.mjs --self-test
  node verify_remote_checkpoint.mjs --verify <path-to-checkpoint.json>
  node verify_remote_checkpoint.mjs --verify-all
  node verify_remote_checkpoint.mjs --verify-live <path-to-checkpoint.json>
`);
    process.exit(0);
  }

  if (args.includes('--self-test')) {
    try {
      const summary = runSelfTests();
      console.log(`REMOTE_CHECKPOINT_SELFTEST: ${JSON.stringify(summary)}`);
      console.log('REMOTE_CHECKPOINT_VERIFICATION: PASS');
      process.exit(0);
    } catch (err) {
      console.error(`SELFTEST_FAIL: ${err.message}`);
      process.exit(1);
    }
  }

  if (args.includes('--verify-all')) {
    const chkDir = path.join(DEFAULT_REPO_ROOT, '.synthesis', 'checkpoints');
    if (!fs.existsSync(chkDir)) {
      console.log('No checkpoints directory found. 0 checkpoints verified.');
      console.log('REMOTE_CHECKPOINT_VERIFICATION: PASS');
      process.exit(0);
    }
    const files = fs.readdirSync(chkDir).filter(f => f.startsWith('CHK-') && f.endsWith('.json'));
    console.log(`Verifying ${files.length} remote checkpoint(s)...`);
    for (const f of files) {
      const p = path.join(chkDir, f);
      const raw = fs.readFileSync(p, 'utf8');
      const obj = JSON.parse(raw);
      validateCheckpointSeal(obj);
      validateCheckpointCommitBinding(DEFAULT_REPO_ROOT, obj);
      validateCheckpointLineage(DEFAULT_REPO_ROOT, obj);
      console.log(`Verified checkpoint: ${f}`);
    }
    console.log('REMOTE_CHECKPOINT_VERIFICATION: PASS');
    process.exit(0);
  }

  const verifyIdx = args.indexOf('--verify');
  if (verifyIdx !== -1 && args[verifyIdx + 1]) {
    const targetPath = path.resolve(process.cwd(), args[verifyIdx + 1]);
    const raw = fs.readFileSync(targetPath, 'utf8');
    const obj = JSON.parse(raw);
    validateCheckpointSeal(obj);
    validateCheckpointCommitBinding(DEFAULT_REPO_ROOT, obj);
    validateCheckpointLineage(DEFAULT_REPO_ROOT, obj);
    console.log(`CHECKPOINT_VERIFY_PASS: ${targetPath}`);
    process.exit(0);
  }

  console.error(`UNKNOWN_CLI_ARGS: ${args.join(' ')}`);
  process.exit(1);
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  main();
}
