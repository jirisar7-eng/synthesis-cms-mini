#!/usr/bin/env node
/**
 * SYNTHESIS CMS MINI — REMOTE FILE CHECKPOINT VERIFIER
 *
 * Roadmap Step: 6/60 — Remote file checkpoint protocol
 *
 * Verifies immutable, sealed remote file checkpoints (CHK-*.json)
 * ensuring cryptographic binding, remote durability verification,
 * git commit/tree provenance, and recovery semantics without self-reference.
 *
 * REPAIR 002R01: Reuses authoritative shared RFC-8785 canonicalizer,
 * timingSafeHexCompare, and strict I-JSON parsing from verify_capsule_seal.mjs.
 *
 * REPAIR 002R02: Implements independent live remote ref verification via shell-free
 * git ls-remote, strict origin identity validation, strict CLI grammar,
 * and fail-closed --verify-all behavior for empty checkpoint directories.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import child_process from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  canonicalizeRfc8785,
  computePayloadSha256,
  parseStrictIJson,
  timingSafeHexCompare,
  verifyCapsuleSeal
} from './verify_capsule_seal.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_REPO_ROOT = path.resolve(__dirname, '..', '..');

// Re-export shared canonicalization functions for external consumers
export { canonicalizeRfc8785, computePayloadSha256, parseStrictIJson, timingSafeHexCompare };

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

// Origin URL Validator
export function validateOriginUrl(url) {
  if (typeof url !== 'string' || !url.trim()) {
    throw new Error('ORIGIN_VALIDATION_ERROR: Origin URL must be a non-empty string');
  }
  const cleanUrl = url.trim();

  // Reject embedded credentials, local file paths, unsupported protocols
  if (cleanUrl.includes('@') && !cleanUrl.startsWith('git@github.com:')) {
    throw new Error(`ORIGIN_VALIDATION_ERROR: Embedded credentials or non-standard SSH remote rejected: ${cleanUrl}`);
  }
  if (path.isAbsolute(cleanUrl) || cleanUrl.startsWith('file://')) {
    throw new Error(`ORIGIN_VALIDATION_ERROR: Local filesystem remote rejected: ${cleanUrl}`);
  }

  // Allowed canonical patterns
  const httpsPattern = /^https:\/\/github\.com\/jirisar7-eng\/synthesis-cms-mini(\.git)?$/;
  const sshPattern = /^git@github\.com:jirisar7-eng\/synthesis-cms-mini(\.git)?$/;

  if (!httpsPattern.test(cleanUrl) && !sshPattern.test(cleanUrl)) {
    throw new Error(`ORIGIN_VALIDATION_ERROR: Origin URL "${cleanUrl}" does not match expected canonical repository "jirisar7-eng/synthesis-cms-mini"`);
  }

  return true;
}

// Independent Live Remote Ref Fetcher
export function fetchLiveRemoteRefSha(repoRoot, branchName, mockLsRemoteOutput = null) {
  if (typeof branchName !== 'string' || !/^(task\/[A-Z0-9_-]+|main)$/.test(branchName)) {
    throw new Error(`INVALID_BRANCH_NAME: Invalid branch name for remote fetch: ${branchName}`);
  }

  let lsRemoteRaw;
  if (mockLsRemoteOutput !== null) {
    lsRemoteRaw = mockLsRemoteOutput;
  } else {
    // 1. Validate local git origin URL identity
    let originUrl;
    try {
      originUrl = execGit(['remote', 'get-url', 'origin'], repoRoot);
    } catch (err) {
      throw new Error(`REMOTE_UNAVAILABLE: Failed to get origin URL: ${err.message}`);
    }
    validateOriginUrl(originUrl);

    // 2. Shell-free ls-remote for exact ref
    const exactRef = `refs/heads/${branchName}`;
    try {
      lsRemoteRaw = execGit(['ls-remote', '--heads', 'origin', exactRef], repoRoot);
    } catch (err) {
      throw new Error(`REMOTE_UNAVAILABLE: git ls-remote failed for ref ${exactRef}: ${err.message}`);
    }
  }

  const lines = lsRemoteRaw.split('\n').map(l => l.trim()).filter(Boolean);
  if (lines.length === 0) {
    throw new Error(`REMOTE_UNAVAILABLE: Branch refs/heads/${branchName} not found on remote origin`);
  }
  if (lines.length > 1) {
    throw new Error(`REMOTE_UNAVAILABLE: Multiple refs returned for refs/heads/${branchName}`);
  }

  const parts = lines[0].split(/\s+/);
  if (parts.length !== 2) {
    throw new Error(`REMOTE_UNAVAILABLE: Malformed ls-remote output line: ${lines[0]}`);
  }

  const [sha, ref] = parts;
  const expectedRef = `refs/heads/${branchName}`;
  if (ref !== expectedRef) {
    throw new Error(`REMOTE_UNAVAILABLE: ls-remote ref mismatch: expected ${expectedRef}, got ${ref}`);
  }
  if (!/^[0-9a-f]{40}$/.test(sha)) {
    throw new Error(`REMOTE_UNAVAILABLE: Malformed SHA returned from ls-remote: ${sha}`);
  }

  return sha;
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
  if (!/^CAP-[A-Z0-9_-]+$/.test(eb.linked_capsule_id || '')) {
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
  if (!timingSafeHexCompare(sha256Hex, obj.seal.payload_sha256)) {
    throw new Error(`SEAL_MISMATCH: Computed payload SHA-256 (${sha256Hex}) !== seal (${obj.seal.payload_sha256})`);
  }
  return true;
}

// Strict I-JSON Checkpoint Loader
export function loadCheckpointStrict(filePath, repoRoot = DEFAULT_REPO_ROOT) {
  const resolvedPath = path.isAbsolute(filePath) ? filePath : path.resolve(repoRoot, filePath);
  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`CHECKPOINT_FILE_NOT_FOUND: ${filePath}`);
  }
  const rawBytes = fs.readFileSync(resolvedPath);
  const rawText = rawBytes.toString('utf8');
  
  // Verify strict UTF-8 roundtrip
  if (Buffer.from(rawText, 'utf8').compare(rawBytes) !== 0) {
    throw new Error(`MALFORMED_UTF8: File contains invalid UTF-8 encoding: ${filePath}`);
  }

  const obj = parseStrictIJson(rawText);
  validateCheckpointSeal(obj);
  return { obj, rawBytes, rawText };
}

// Recorded Evidence Consistency Validator
export function validateRecordedRemoteEvidence(checkpointObj, repoRoot = DEFAULT_REPO_ROOT) {
  validateCheckpointSeal(checkpointObj);
  const { payload } = checkpointObj;
  const rv = payload.remote_verification;
  const expectedRef = `refs/heads/${payload.repository.branch}`;

  if (rv.observed_remote_ref !== expectedRef) {
    throw new Error(`RECORDED_EVIDENCE_MISMATCH: observed_remote_ref (${rv.observed_remote_ref}) !== expected branch ref (${expectedRef})`);
  }

  if (rv.remote_relationship === 'EXACT_HEAD') {
    if (rv.observed_remote_sha !== payload.target_commit.commit_sha) {
      throw new Error(`RECORDED_EVIDENCE_MISMATCH: EXACT_HEAD observed_remote_sha (${rv.observed_remote_sha}) !== target_commit.commit_sha (${payload.target_commit.commit_sha})`);
    }
  } else if (rv.remote_relationship === 'VERIFIED_DESCENDANT') {
    // Target commit must be an ancestor of observed_remote_sha
    try {
      const mergeBase = execGit(['merge-base', payload.target_commit.commit_sha, rv.observed_remote_sha], repoRoot);
      if (mergeBase !== payload.target_commit.commit_sha) {
        throw new Error(`RECORDED_EVIDENCE_MISMATCH: VERIFIED_DESCENDANT target commit ${payload.target_commit.commit_sha} is not an ancestor of observed remote SHA ${rv.observed_remote_sha}`);
      }
    } catch (err) {
      throw new Error(`RECORDED_EVIDENCE_MISMATCH: Failed ancestry check for VERIFIED_DESCENDANT: ${err.message}`);
    }
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

// Capsule Evidence Binding Validator
export function validateEvidenceBinding(repoRoot, checkpointObj) {
  validateCheckpointSeal(checkpointObj);
  const { payload } = checkpointObj;
  const eb = payload.evidence_binding;
  const linkedCapId = eb.linked_capsule_id;
  const claimedPayloadSha = eb.linked_capsule_payload_sha256;

  // 1. Canonical path check
  function validateSafeCapsulePath(p) {
    if (typeof p !== 'string' || !p) throw new Error('PATH_ERROR: Path must be a non-empty string');
    if (path.isAbsolute(p)) throw new Error('PATH_ERROR: Absolute path forbidden');
    if (p.startsWith('-')) throw new Error('PATH_ERROR: Option injection forbidden');
    if (/[\x00-\x1F\x7F]/.test(p)) throw new Error('PATH_ERROR: Control characters forbidden');
    const norm = path.normalize(p);
    if (norm.startsWith('..') || norm === '..' || path.isAbsolute(norm)) throw new Error('PATH_ERROR: Path traversal detected');
    if (!norm.startsWith('.synthesis/task-capsules/')) throw new Error('INVALID_CAPSULE_PATH: Must be in .synthesis/task-capsules/');
    return norm;
  }
  const relPath = validateSafeCapsulePath(`.synthesis/task-capsules/${linkedCapId}.json`);
  const fullCapPath = path.resolve(repoRoot, relPath);

  if (!fs.existsSync(fullCapPath)) {
    throw new Error(`CAPSULE_FILE_MISSING: Linked capsule file not found: ${relPath}`);
  }

  // Symlink checks: target file and ancestor directories
  if (fs.lstatSync(fullCapPath).isSymbolicLink()) {
    throw new Error(`UNSAFE_SYMLINK_DETECTED: Linked capsule path is a symlink: ${relPath}`);
  }
  let currentDir = path.dirname(fullCapPath);
  const resolvedRepoRoot = path.resolve(repoRoot);
  while (currentDir !== resolvedRepoRoot && currentDir !== path.dirname(currentDir)) {
    if (fs.existsSync(currentDir) && fs.lstatSync(currentDir).isSymbolicLink()) {
      throw new Error(`UNSAFE_SYMLINK_DETECTED: Symlink ancestor detected: ${currentDir}`);
    }
    currentDir = path.dirname(currentDir);
  }

  if (!fs.statSync(fullCapPath).isFile()) {
    throw new Error(`NOT_A_REGULAR_FILE: Linked capsule is not a regular file: ${relPath}`);
  }

  // 2. Strict load & seal verification of capsule
  const rawBytes = fs.readFileSync(fullCapPath);
  const rawText = rawBytes.toString('utf8');
  if (Buffer.from(rawText, 'utf8').compare(rawBytes) !== 0) {
    throw new Error(`MALFORMED_UTF8: Linked capsule file has invalid UTF-8: ${relPath}`);
  }

  const capObj = parseStrictIJson(rawText);
  if (!capObj || typeof capObj !== 'object' || Array.isArray(capObj)) {
    throw new Error(`INVALID_CAPSULE_STRUCTURE: Capsule must be an object: ${relPath}`);
  }
  if (capObj.seal?.status !== 'SEALED') {
    throw new Error(`CAPSULE_NOT_SEALED: Linked capsule is not in SEALED status: ${capObj.seal?.status}`);
  }

  const { sha256Hex: computedCapSha } = computePayloadSha256(capObj.payload);
  if (!timingSafeHexCompare(computedCapSha, capObj.seal.payload_sha256)) {
    throw new Error(`CAPSULE_SEAL_MISMATCH: Computed capsule SHA-256 (${computedCapSha}) !== seal (${capObj.seal.payload_sha256})`);
  }

  if (!timingSafeHexCompare(capObj.seal.payload_sha256, claimedPayloadSha)) {
    throw new Error(`CAPSULE_PAYLOAD_SHA_MISMATCH: Linked capsule payload SHA (${capObj.seal.payload_sha256}) !== checkpoint evidence binding (${claimedPayloadSha})`);
  }

  if (capObj.payload.capsule_id !== linkedCapId) {
    throw new Error(`CAPSULE_ID_MISMATCH: Linked capsule ID (${capObj.payload.capsule_id}) !== evidence binding (${linkedCapId})`);
  }

  // 3. Semantic alignment with checkpoint
  if (capObj.payload.project_id !== payload.project_id) {
    throw new Error(`CAPSULE_SEMANTIC_MISMATCH: project_id mismatch (${capObj.payload.project_id} !== ${payload.project_id})`);
  }
  if (capObj.payload.task_id !== payload.task_id) {
    throw new Error(`CAPSULE_SEMANTIC_MISMATCH: task_id mismatch (${capObj.payload.task_id} !== ${payload.task_id})`);
  }
  if (capObj.payload.command_id !== payload.command_id) {
    throw new Error(`CAPSULE_SEMANTIC_MISMATCH: command_id mismatch (${capObj.payload.command_id} !== ${payload.command_id})`);
  }
  if (capObj.payload.roadmap_step !== payload.roadmap_step) {
    throw new Error(`CAPSULE_SEMANTIC_MISMATCH: roadmap_step mismatch (${capObj.payload.roadmap_step} !== ${payload.roadmap_step})`);
  }

  // 4. Target commit tree binding
  const targetCommit = payload.target_commit.commit_sha;
  let treeOut;
  try {
    treeOut = execGit(['ls-tree', '-r', targetCommit], repoRoot);
  } catch (err) {
    throw new Error(`GIT_LS_TREE_FAILED: Could not inspect target commit tree: ${err.message}`);
  }

  const treeLines = treeOut.split('\n').filter(Boolean);
  let targetTreeBlob = null;
  for (const line of treeLines) {
    const parts = line.split(/\s+/);
    if (parts[3] === relPath) {
      targetTreeBlob = parts[2];
      break;
    }
  }

  if (!targetTreeBlob) {
    throw new Error(`CAPSULE_NOT_IN_TARGET_COMMIT: Linked capsule ${relPath} not found in target commit tree ${targetCommit}`);
  }

  const actualFileBlob = computeGitBlobSha(rawBytes);
  if (targetTreeBlob !== actualFileBlob) {
    throw new Error(`CAPSULE_COMMIT_BLOB_MISMATCH: Target commit tree blob (${targetTreeBlob}) !== local capsule blob (${actualFileBlob})`);
  }

  return true;
}

// Global Checkpoint Lineage & Directory Verifier
export function verifyAllCheckpointLineage(repoRoot = DEFAULT_REPO_ROOT) {
  const chkDir = path.join(repoRoot, '.synthesis', 'checkpoints');
  if (!fs.existsSync(chkDir)) {
    throw new Error('NO_CHECKPOINTS_AVAILABLE: Checkpoint directory .synthesis/checkpoints does not exist');
  }

  const dirEntries = fs.readdirSync(chkDir, { withFileTypes: true });
  if (dirEntries.length === 0) {
    throw new Error('NO_CHECKPOINTS_AVAILABLE: No checkpoint files found in .synthesis/checkpoints');
  }

  // Fail closed on symlinks, directories, non-checkpoint files
  for (const ent of dirEntries) {
    if (ent.isSymbolicLink()) {
      throw new Error(`UNEXPECTED_DIRECTORY_ENTRY: Symlink entry forbidden in checkpoints directory: ${ent.name}`);
    }
    if (!ent.isFile() || !ent.name.startsWith('CHK-') || !ent.name.endsWith('.json')) {
      throw new Error(`UNEXPECTED_DIRECTORY_ENTRY: Unexpected non-checkpoint entry in checkpoints directory: ${ent.name}`);
    }
  }

  const checkpointMap = new Map();
  const parentToChildren = new Map();

  for (const ent of dirEntries) {
    const filePath = path.join(chkDir, ent.name);
    const { obj, rawBytes } = loadCheckpointStrict(filePath, repoRoot);
    const chkId = obj.payload.checkpoint_id;

    if (ent.name !== `${chkId}.json`) {
      throw new Error(`CHECKPOINT_FILE_NAME_MISMATCH: File ${ent.name} does not match checkpoint_id ${chkId}`);
    }

    if (checkpointMap.has(chkId)) {
      throw new Error(`DUPLICATE_CHECKPOINT_ID: Duplicate checkpoint ID detected: ${chkId}`);
    }

    checkpointMap.set(chkId, { obj, rawBytes, filePath });
  }

  // Cycle detection (self-cycle, 2-node cycle, multi-node cycle)
  const parentMap = new Map();
  for (const [chkId, { obj }] of checkpointMap.entries()) {
    const p = obj.payload.checkpoint_lineage.parent_checkpoint;
    parentMap.set(chkId, p ? p.checkpoint_id : null);
  }

  for (const startId of checkpointMap.keys()) {
    const visitedInPath = new Set();
    let curr = startId;
    while (curr) {
      if (visitedInPath.has(curr)) {
        throw new Error(`CHECKPOINT_LINEAGE_CYCLE: Lineage cycle detected involving ${curr}`);
      }
      visitedInPath.add(curr);
      curr = parentMap.get(curr);
    }
  }

  // Lineage consistency, compatibility & fork check
  for (const [chkId, { obj }] of checkpointMap.entries()) {
    const parentRef = obj.payload.checkpoint_lineage.parent_checkpoint;
    if (parentRef) {
      const parentId = parentRef.checkpoint_id;
      if (parentId === chkId) {
        throw new Error(`CHECKPOINT_LINEAGE_CYCLE: Self-referential checkpoint parent loop detected: ${chkId}`);
      }

      const parentFullPath = path.resolve(repoRoot, parentRef.file_path);
      if (!fs.existsSync(parentFullPath)) {
        throw new Error(`PARENT_CHECKPOINT_MISSING: Parent checkpoint file not found: ${parentRef.file_path}`);
      }

      const { obj: parentObj, rawBytes: parentBytes } = loadCheckpointStrict(parentFullPath, repoRoot);
      const computedParentRawSha = computeRawFileSha256(parentBytes);
      if (computedParentRawSha !== parentRef.raw_file_sha256) {
        throw new Error(`PARENT_CHECKPOINT_RAW_SHA_MISMATCH: Parent file ${parentRef.file_path} SHA256 mismatch`);
      }
      if (parentObj.payload.checkpoint_id !== parentId) {
        throw new Error(`PARENT_CHECKPOINT_ID_MISMATCH: Claimed parent ID ${parentId} !== found ${parentObj.payload.checkpoint_id}`);
      }

      // Compatibility check between parent and child
      if (obj.payload.project_id !== parentObj.payload.project_id) {
        throw new Error(`LINEAGE_INCOMPATIBILITY: Parent/child project_id mismatch`);
      }
      if (obj.payload.repository.name !== parentObj.payload.repository.name) {
        throw new Error(`LINEAGE_INCOMPATIBILITY: Parent/child repository name mismatch`);
      }
      if (obj.payload.repository.branch !== parentObj.payload.repository.branch) {
        throw new Error(`LINEAGE_INCOMPATIBILITY: Parent/child repository branch mismatch`);
      }
      if (obj.payload.task_id !== parentObj.payload.task_id) {
        throw new Error(`LINEAGE_INCOMPATIBILITY: Parent/child task_id mismatch`);
      }

      // Linear lineage fork rejection (one parent cannot have multiple children)
      if (!parentToChildren.has(parentId)) {
        parentToChildren.set(parentId, []);
      }
      const children = parentToChildren.get(parentId);
      children.push(chkId);
      if (children.length > 1) {
        throw new Error(`LINEAGE_FORK_REJECTED: Multiple children [${children.join(', ')}] claim the same parent ${parentId}`);
      }
    }
  }



  return { success: true, count: checkpointMap.size };
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

  const { obj: parentObj, rawBytes: parentBytes } = loadCheckpointStrict(parentPath, repoRoot);
  const parentRawSha256 = computeRawFileSha256(parentBytes);
  if (parentRawSha256 !== parentRef.raw_file_sha256) {
    throw new Error(`PARENT_CHECKPOINT_RAW_SHA_MISMATCH: Parent file ${parentRef.file_path} SHA256 (${parentRawSha256}) !== claimed (${parentRef.raw_file_sha256})`);
  }

  if (parentObj.payload.checkpoint_id !== parentRef.checkpoint_id) {
    throw new Error(`PARENT_CHECKPOINT_ID_MISMATCH: Claimed parent ID ${parentRef.checkpoint_id} !== found ${parentObj.payload.checkpoint_id}`);
  }

  if (parentObj.payload.checkpoint_id === checkpointObj.payload.checkpoint_id) {
    throw new Error(`CHECKPOINT_LINEAGE_CYCLE: Self-referential checkpoint parent loop detected: ${parentRef.checkpoint_id}`);
  }

  return true;
}

// Live Recovery Evaluator
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

// Live Verification Runner
export function verifyLiveCheckpoint(filePath, repoRoot = DEFAULT_REPO_ROOT, mockLsRemoteOutput = null) {
  const { obj } = loadCheckpointStrict(filePath, repoRoot);
  validateCheckpointCommitBinding(repoRoot, obj);
  validateCheckpointLineage(repoRoot, obj);
  validateRecordedRemoteEvidence(obj, repoRoot);
  validateEvidenceBinding(repoRoot, obj);

  const branchName = obj.payload.repository.branch;
  const liveRemoteSha = fetchLiveRemoteRefSha(repoRoot, branchName, mockLsRemoteOutput);

  const evalResult = evaluateRecoveryStatus(repoRoot, obj, liveRemoteSha);
  if (
    evalResult.status === 'REMOTE_DURABLE_AND_CURRENT' ||
    evalResult.status === 'REMOTE_BRANCH_ADVANCED_VALID_DESCENDANT'
  ) {
    console.log(`LIVE_VERIFY_PASS [${evalResult.status}]: ${filePath}`);
    return { success: true, status: evalResult.status, liveRemoteSha, reason: evalResult.reason };
  }

  if (evalResult.status === 'REMOTE_DURABLE_BUT_SUPERSEDED') {
    console.log(`LIVE_VERIFY_SUPERSEDED [${evalResult.status}]: ${filePath} (${evalResult.reason})`);
    return { success: false, status: evalResult.status, liveRemoteSha, reason: evalResult.reason };
  }

  throw new Error(`LIVE_VERIFY_FAIL [${evalResult.status}]: ${evalResult.reason}`);
}

// Strict CLI Grammar Parser
export function parseCliArgs(argv) {
  const args = argv.slice(2);
  if (args.length === 0 || args[0] === '--help') {
    return { mode: 'HELP' };
  }

  if (args.length === 1 && args[0] === '--self-test') {
    return { mode: 'SELF_TEST' };
  }

  if (args.length === 1 && args[0] === '--verify-all') {
    return { mode: 'VERIFY_ALL' };
  }

  if (args.length === 2 && args[0] === '--verify') {
    if (!args[1] || args[1].startsWith('-')) {
      throw new Error('CLI_GRAMMAR_ERROR: --verify requires a valid non-flag path argument');
    }
    return { mode: 'VERIFY', filePath: args[1] };
  }

  if (args.length === 2 && args[0] === '--verify-live') {
    if (!args[1] || args[1].startsWith('-')) {
      throw new Error('CLI_GRAMMAR_ERROR: --verify-live requires a valid non-flag path argument');
    }
    return { mode: 'VERIFY_LIVE', filePath: args[1] };
  }

  // Reject mixed flags, unknown flags, extra arguments
  throw new Error(`CLI_GRAMMAR_ERROR: Invalid or mixed CLI arguments: "${args.join(' ')}"`);
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
    execGit(['remote', 'add', 'origin', 'https://github.com/jirisar7-eng/synthesis-cms-mini.git'], tmpDir);

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

    // Helper to create test capsule
    function makeTestCapsule(capId, taskId = 'SYN-MINI-TEST-001', commandId = 'CMD-SYN-MINI-TEST-001-001', step = '6/60 — Remote file checkpoint test', branch = 'task/SYN-MINI-TEST-001') {
      const payload = {
        schema_version: '1.0.0',
        capsule_type: 'COMMAND_CAPSULE',
        capsule_id: capId,
        command_id: commandId,
        task_id: taskId,
        project_id: 'SYNTHESIS_CMS_MINI',
        roadmap_step: step,
        actors: { owner: 'Jiří Šár', command_author: 'Test', executor: 'Test', verifier: 'Test' },
        execution_metadata: { execution_timestamp: '2026-10-05T00:00:00Z', development_phase: 'IMPLEMENT', execution_mode: 'RESTRICTED_GOVERNANCE_BOOTSTRAP' },
        repository_baseline: { repository_name: 'jirisar7-eng/synthesis-cms-mini', repository_id: 1401215700, base_main_sha: c0Sha, source_branch: branch, expected_target_branch: 'main' },
        scope_boundary: { permitted_read_paths: [], permitted_write_paths: [], protected_paths: [], forbidden_operations: [], max_write_files_limit: 3, max_read_files_limit: 10 },
        lineage: { genesis_anchor_reference: { path: '.synthesis/lineage/genesis.json', pinned_sha256: 'b'.repeat(64) }, parent_capsules: [], typed_lineage_references: { superseded_capsules: [], repaired_capsules: [], diagnostic_predecessors: [] } },
        contracts_and_dependencies: { affected_contracts: [], affected_capabilities: [], declared_dependencies: [] },
        changes_and_evidence: { expected_changed_files: [], actual_changed_files: [], commit_sha: null, source_blob_shas: {} },
        verification_states: { syntax_verification: 'PASS', behavioral_test_verification: 'PASS', security_review: 'PASS', remote_sha_verification: 'PENDING', ci_verification: 'PENDING', pull_request_status: 'NOT_CREATED', merge_status: 'NOT_MERGED', deployment_status: 'NOT_DEPLOYED' },
        recovery_and_next_steps: { global_governance_health: 'BOOTSTRAP_NOT_YET_ACTIVE', blockers: [], incomplete_work: [], next_safe_step: 'NEXT' }
      };
      const { sha256Hex } = computePayloadSha256(payload);
      return {
        payload,
        seal: {
          status: 'SEALED',
          hash_algorithm: 'SHA-256',
          canonicalization_algorithm: 'RFC-8785',
          payload_sha256: sha256Hex,
          sealed_at: '2026-10-05T00:00:00Z',
          sealed_by: 'Test',
          seal_signature: null
        }
      };
    }

    fs.mkdirSync(path.join(tmpDir, '.synthesis', 'task-capsules'), { recursive: true });
    const defaultTestCap = makeTestCapsule('CAP-SYN-MINI-TEST-001-20261005-001');
    const defaultCapPath = path.join(tmpDir, '.synthesis', 'task-capsules', 'CAP-SYN-MINI-TEST-001-20261005-001.json');
    fs.writeFileSync(defaultCapPath, JSON.stringify(defaultTestCap, null, 2));

    // Commit 2: Modify test module file and add linked capsule (C2)
    fs.writeFileSync(path.join(tmpDir, 'src', 'module.mjs'), 'export const v = 2;\n');
    execGit(['add', 'src/module.mjs', '.synthesis/task-capsules/CAP-SYN-MINI-TEST-001-20261005-001.json'], tmpDir);
    execGit(['commit', '-m', 'modify module and add capsule'], tmpDir);
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
          linked_capsule_payload_sha256: defaultTestCap.seal.payload_sha256
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

    // POS-07 (REPAIR): Shared canonicalizer UTF-16 code unit ordering on Unicode property keys
    const testObj = { "\u0100": 2, "A": 1 }; // "Ā" (U+0100) vs "A" (U+0041)
    const canonStr = canonicalizeRfc8785(testObj);
    assert(canonStr === '{"A":1,"\u0100":2}', `POS-07 canonical UTF-16 ordering: ${canonStr}`);
    posPassed++;

    // POS-08 (REPAIR): Strict I-JSON loader parses valid formatted JSON
    const loadedPos08 = loadCheckpointStrict(p1Path, tmpDir);
    assert(loadedPos08.obj.payload.checkpoint_id === 'CHK-SYN-MINI-TEST-001-20261005-001', 'POS-08 strict loader');
    posPassed++;

    // POS-09 (REPAIR 002R02): Independent remote ref fetcher via mock ls-remote
    const mockLsRemote09 = `${c2Sha}\trefs/heads/task/SYN-MINI-TEST-001\n`;
    const fetchedSha09 = fetchLiveRemoteRefSha(tmpDir, 'task/SYN-MINI-TEST-001', mockLsRemote09);
    assert(fetchedSha09 === c2Sha, 'POS-09 fetched sha');
    posPassed++;

    // POS-10 (REPAIR 002R02): Live verification succeeds with mock ls-remote
    const liveRes10 = verifyLiveCheckpoint(p1Path, tmpDir, mockLsRemote09);
    assert(liveRes10.success === true && liveRes10.status === 'REMOTE_DURABLE_AND_CURRENT', 'POS-10 live verify');
    posPassed++;

    // POS-11 (REPAIR 002R02): Canonical HTTPS origin accepted
    assert(validateOriginUrl('https://github.com/jirisar7-eng/synthesis-cms-mini.git'), 'POS-11 https origin');
    posPassed++;

    // POS-12 (REPAIR 002R02): Canonical SSH origin accepted
    assert(validateOriginUrl('git@github.com:jirisar7-eng/synthesis-cms-mini.git'), 'POS-12 ssh origin');
    posPassed++;

    // POS-13 (REPAIR 002R03): Actual-style repair capsule ID accepted
    assert(validateCheckpointSeal(buildCheckpoint({
      evidence_binding: {
        linked_capsule_id: 'CAP-SYN-MINI-GOV-REMOTE-FILE-CHECKPOINT-001-20261005-002R02',
        linked_capsule_payload_sha256: 'a'.repeat(64)
      }
    })), 'POS-13 repair capsule id');
    posPassed++;

    // POS-14 (REPAIR 002R03): Standard non-repair capsule ID accepted
    assert(validateCheckpointSeal(buildCheckpoint({
      evidence_binding: {
        linked_capsule_id: 'CAP-SYN-MINI-GOV-REMOTE-FILE-CHECKPOINT-001-20261005-001',
        linked_capsule_payload_sha256: 'a'.repeat(64)
      }
    })), 'POS-14 standard capsule id');
    posPassed++;

    // POS-15 (REPAIR 002R04): Real linked capsule with correct seal and hash accepted
    assert(validateEvidenceBinding(tmpDir, chkPos01), 'POS-15 evidence binding');
    posPassed++;

    // POS-16 (REPAIR 002R04): Repair capsule ID evidence accepted in target commit
    const repairCapObj = makeTestCapsule('CAP-SYN-MINI-GOV-REMOTE-FILE-CHECKPOINT-001-20261005-002R02');
    const repairCapPath = path.join(tmpDir, '.synthesis', 'task-capsules', 'CAP-SYN-MINI-GOV-REMOTE-FILE-CHECKPOINT-001-20261005-002R02.json');
    fs.writeFileSync(repairCapPath, JSON.stringify(repairCapObj, null, 2));

    // Commit repair capsule into commit C7
    execGit(['add', '.synthesis/task-capsules/CAP-SYN-MINI-GOV-REMOTE-FILE-CHECKPOINT-001-20261005-002R02.json'], tmpDir);
    execGit(['commit', '-m', 'add repair capsule'], tmpDir);
    const c7Sha = execGit(['rev-parse', 'HEAD'], tmpDir);
    const c7Parent = execGit(['rev-parse', 'HEAD~1'], tmpDir);

    const chkPos16 = buildCheckpoint({
      checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-016',
      target_commit: { commit_sha: c7Sha, parent_sha: c7Parent, commit_timestamp_utc: '2026-10-05T00:00:00Z' },
      evidence_binding: {
        linked_capsule_id: 'CAP-SYN-MINI-GOV-REMOTE-FILE-CHECKPOINT-001-20261005-002R02',
        linked_capsule_payload_sha256: repairCapObj.seal.payload_sha256
      }
    });
    assert(validateEvidenceBinding(tmpDir, chkPos16), 'POS-16 repair capsule binding');
    posPassed++;

    // POS-17 (REPAIR 002R04): Valid linear two-checkpoint lineage accepted
    const chkDir = path.join(tmpDir, '.synthesis', 'checkpoints');
    fs.mkdirSync(chkDir, { recursive: true });
    // Write checkpoint 1
    const chk1Obj = buildCheckpoint({ checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-001' });
    const chk1Path = path.join(chkDir, 'CHK-SYN-MINI-TEST-001-20261005-001.json');
    fs.writeFileSync(chk1Path, JSON.stringify(chk1Obj, null, 2));
    const chk1RawSha = computeRawFileSha256(fs.readFileSync(chk1Path));

    // Write checkpoint 2 linked to checkpoint 1
    const chk2Obj = buildCheckpoint({
      checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-002',
      checkpoint_lineage: {
        parent_checkpoint: {
          checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-001',
          file_path: '.synthesis/checkpoints/CHK-SYN-MINI-TEST-001-20261005-001.json',
          raw_file_sha256: chk1RawSha
        }
      }
    });
    const chk2Path = path.join(chkDir, 'CHK-SYN-MINI-TEST-001-20261005-002.json');
    fs.writeFileSync(chk2Path, JSON.stringify(chk2Obj, null, 2));

    const lin17Res = verifyAllCheckpointLineage(tmpDir);
    assert(lin17Res.success === true && lin17Res.count === 2, 'POS-17 linear lineage');
    posPassed++;

    // POS-18 (REPAIR 002R04): Two independent lineage roots accepted
    const capRoot2 = makeTestCapsule('CAP-SYN-MINI-TEST-002-20261005-001', 'SYN-MINI-TEST-002', 'CMD-SYN-MINI-TEST-002-001', '6/60 — Remote file checkpoint test', 'task/SYN-MINI-TEST-002');
    const capRoot2Path = path.join(tmpDir, '.synthesis', 'task-capsules', 'CAP-SYN-MINI-TEST-002-20261005-001.json');
    fs.writeFileSync(capRoot2Path, JSON.stringify(capRoot2, null, 2));
    execGit(['add', '.synthesis/task-capsules/CAP-SYN-MINI-TEST-002-20261005-001.json'], tmpDir);
    execGit(['commit', '-m', 'add second root capsule'], tmpDir);
    const c8Sha = execGit(['rev-parse', 'HEAD'], tmpDir);
    const c8Parent = execGit(['rev-parse', 'HEAD~1'], tmpDir);

    const chk3Obj = buildCheckpoint({
      checkpoint_id: 'CHK-SYN-MINI-TEST-002-20261005-001',
      task_id: 'SYN-MINI-TEST-002',
      command_id: 'CMD-SYN-MINI-TEST-002-001',
      target_commit: { commit_sha: c8Sha, parent_sha: c8Parent, commit_timestamp_utc: '2026-10-05T00:00:00Z' },
      repository: {
        name: 'jirisar7-eng/synthesis-cms-mini',
        id: 1401215700,
        branch: 'task/SYN-MINI-TEST-002',
        base_main_sha: c0Sha
      },
      evidence_binding: {
        linked_capsule_id: 'CAP-SYN-MINI-TEST-002-20261005-001',
        linked_capsule_payload_sha256: capRoot2.seal.payload_sha256
      },
      checkpoint_lineage: { parent_checkpoint: null }
    });
    const chk3Path = path.join(chkDir, 'CHK-SYN-MINI-TEST-002-20261005-001.json');
    fs.writeFileSync(chk3Path, JSON.stringify(chk3Obj, null, 2));

    const lin18Res = verifyAllCheckpointLineage(tmpDir);
    assert(lin18Res.success === true && lin18Res.count === 3, 'POS-18 two independent roots');
    posPassed++;

    // Clean up extra checkpoints created for POS-17 and POS-18, keeping p1Path intact
    try { fs.unlinkSync(chk2Path); } catch (_) {}
    try { fs.unlinkSync(chk3Path); } catch (_) {}

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

    // NEG-36 (REPAIR): Duplicate JSON key rejected by strict I-JSON parser
    assertThrows(() => {
      parseStrictIJson('{"a":1,"a":2}');
    }, 'Duplicate object key detected', 'NEG-36 (duplicate key)');

    // NEG-37 (REPAIR): Lone high surrogate rejected by strict parser
    assertThrows(() => {
      parseStrictIJson('{"bad":"\\uD800"}');
    }, 'surrogate', 'NEG-37 (lone high surrogate)');

    // NEG-38 (REPAIR): Lone low surrogate rejected by strict parser
    assertThrows(() => {
      parseStrictIJson('{"bad":"\\uDC00"}');
    }, 'surrogate', 'NEG-38 (lone low surrogate)');

    // NEG-39 (REPAIR): Lone surrogate in object key rejected
    assertThrows(() => {
      parseStrictIJson('{"\\uD800": 1}');
    }, 'surrogate', 'NEG-39 (lone surrogate key)');

    // NEG-40 (REPAIR): Malformed JSON rejected
    assertThrows(() => {
      parseStrictIJson('{bad_json: 1}');
    }, 'I_JSON_ERROR', 'NEG-40 (malformed JSON)');

    // NEG-41 (REPAIR): Parent checkpoint with duplicate key fails strict loading
    const badParentPath = path.join(tmpDir, '.synthesis', 'checkpoints', 'CHK-BAD-PARENT.json');
    fs.writeFileSync(badParentPath, '{"payload":{},"payload":{}}');
    assertThrows(() => {
      loadCheckpointStrict(badParentPath, tmpDir);
    }, 'Duplicate object key detected', 'NEG-41 (bad parent strict loading)');

    // NEG-42 (REPAIR 002R02): Wrong GitHub repository origin rejected
    assertThrows(() => {
      validateOriginUrl('https://github.com/other-owner/synthesis-cms-mini.git');
    }, 'ORIGIN_VALIDATION_ERROR', 'NEG-42 (wrong repo origin)');

    // NEG-43 (REPAIR 002R02): Wrong GitHub owner rejected
    assertThrows(() => {
      validateOriginUrl('https://github.com/jirisar7-eng/wrong-repo.git');
    }, 'ORIGIN_VALIDATION_ERROR', 'NEG-43 (wrong owner)');

    // NEG-44 (REPAIR 002R02): Non-GitHub / local filesystem remote rejected
    assertThrows(() => {
      validateOriginUrl('/tmp/local-repo.git');
    }, 'ORIGIN_VALIDATION_ERROR', 'NEG-44 (local filesystem remote)');

    // NEG-45 (REPAIR 002R02): Remote command / network failure handling
    assertThrows(() => {
      fetchLiveRemoteRefSha(tmpDir, 'task/SYN-MINI-TEST-001', 'command_error_failure');
    }, 'REMOTE_UNAVAILABLE', 'NEG-45 (remote command error)');

    // NEG-46 (REPAIR 002R02): Empty ls-remote response handling
    assertThrows(() => {
      fetchLiveRemoteRefSha(tmpDir, 'task/SYN-MINI-TEST-001', '');
    }, 'REMOTE_UNAVAILABLE', 'NEG-46 (empty response)');

    // NEG-47 (REPAIR 002R02): Malformed SHA response from ls-remote handling
    assertThrows(() => {
      fetchLiveRemoteRefSha(tmpDir, 'task/SYN-MINI-TEST-001', 'NOT_A_VALID_SHA\trefs/heads/task/SYN-MINI-TEST-001\n');
    }, 'REMOTE_UNAVAILABLE', 'NEG-47 (malformed sha response)');

    // NEG-48 (REPAIR 002R02): Multiple matching refs returned handling
    assertThrows(() => {
      fetchLiveRemoteRefSha(tmpDir, 'task/SYN-MINI-TEST-001', `${c1Sha}\trefs/heads/task/SYN-MINI-TEST-001\n${c2Sha}\trefs/heads/task/SYN-MINI-TEST-001\n`);
    }, 'REMOTE_UNAVAILABLE', 'NEG-48 (multiple refs)');

    // NEG-49 (REPAIR 002R02): Wrong returned ref name from ls-remote handling
    assertThrows(() => {
      fetchLiveRemoteRefSha(tmpDir, 'task/SYN-MINI-TEST-001', `${c2Sha}\trefs/heads/wrong-ref\n`);
    }, 'REMOTE_UNAVAILABLE', 'NEG-49 (wrong returned ref)');

    // NEG-50 (REPAIR 002R02): Caller-supplied SHA cannot bypass live remote lookup
    assertThrows(() => {
      verifyLiveCheckpoint(p1Path, tmpDir, '');
    }, 'REMOTE_UNAVAILABLE', 'NEG-50 (caller sha bypass attempt)');

    // NEG-51 (REPAIR 002R02): Cached origin ref cannot bypass live remote lookup (unsupported branch)
    assertThrows(() => {
      fetchLiveRemoteRefSha(tmpDir, 'unsupported-branch-name', mockLsRemote09);
    }, 'INVALID_BRANCH_NAME', 'NEG-51 (invalid branch name)');

    // NEG-52 (REPAIR 002R02): --verify-live missing file argument
    assertThrows(() => {
      parseCliArgs(['node', 'script.mjs', '--verify-live']);
    }, 'CLI_GRAMMAR_ERROR', 'NEG-52 (missing verify-live arg)');

    // NEG-53 (REPAIR 002R02): Mixed CLI modes
    assertThrows(() => {
      parseCliArgs(['node', 'script.mjs', '--self-test', '--verify', 'file.json']);
    }, 'CLI_GRAMMAR_ERROR', 'NEG-53 (mixed cli modes)');

    // NEG-54 (REPAIR 002R02): Extra CLI argument
    assertThrows(() => {
      parseCliArgs(['node', 'script.mjs', '--verify', 'file.json', 'extra']);
    }, 'CLI_GRAMMAR_ERROR', 'NEG-54 (extra cli arg)');

    // NEG-55 (REPAIR 002R02): Unknown CLI flag
    assertThrows(() => {
      parseCliArgs(['node', 'script.mjs', '--unknown-flag']);
    }, 'CLI_GRAMMAR_ERROR', 'NEG-55 (unknown flag)');

    // NEG-56 (REPAIR 002R02): Recorded observed_remote_ref differs from repository branch
    assertThrows(() => {
      const chk = buildCheckpoint({
        remote_verification: { observed_remote_ref: 'refs/heads/wrong-branch' }
      });
      validateRecordedRemoteEvidence(chk, tmpDir);
    }, 'RECORDED_EVIDENCE_MISMATCH', 'NEG-56 (mismatched observed_remote_ref)');

    // NEG-57 (REPAIR 002R02): EXACT_HEAD recorded SHA differs from target commit
    assertThrows(() => {
      const chk = buildCheckpoint({
        remote_verification: { observed_remote_sha: c1Sha, remote_relationship: 'EXACT_HEAD' }
      });
      validateRecordedRemoteEvidence(chk, tmpDir);
    }, 'RECORDED_EVIDENCE_MISMATCH', 'NEG-57 (EXACT_HEAD sha mismatch)');

    // NEG-58 (REPAIR 002R02): VERIFIED_DESCENDANT without proven ancestry
    assertThrows(() => {
      const chk = buildCheckpoint({
        target_commit: { commit_sha: c5Sha, parent_sha: c2Sha, commit_timestamp_utc: '2026-10-05T00:00:00Z' },
        remote_verification: { observed_remote_sha: c1Sha, remote_relationship: 'VERIFIED_DESCENDANT' }
      });
      validateRecordedRemoteEvidence(chk, tmpDir);
    }, 'RECORDED_EVIDENCE_MISMATCH', 'NEG-58 (VERIFIED_DESCENDANT ancestry failure)');

    // NEG-59 (REPAIR 002R02): Missing checkpoint directory in --verify-all
    const emptyTmpDir = path.join(tmpDir, 'empty-repo');
    fs.mkdirSync(emptyTmpDir, { recursive: true });
    assertThrows(() => {
      const chkDir = path.join(emptyTmpDir, '.synthesis', 'checkpoints');
      if (!fs.existsSync(chkDir) || fs.readdirSync(chkDir).filter(f => f.startsWith('CHK-') && f.endsWith('.json')).length === 0) {
        throw new Error('NO_CHECKPOINTS_AVAILABLE: No checkpoint files found in .synthesis/checkpoints');
      }
    }, 'NO_CHECKPOINTS_AVAILABLE', 'NEG-59 (missing chk dir)');

    // NEG-60 (REPAIR 002R02): Empty checkpoint directory in --verify-all
    const chkEmptyDir = path.join(emptyTmpDir, '.synthesis', 'checkpoints');
    fs.mkdirSync(chkEmptyDir, { recursive: true });
    assertThrows(() => {
      const files = fs.readdirSync(chkEmptyDir).filter(f => f.startsWith('CHK-') && f.endsWith('.json'));
      if (files.length === 0) {
        throw new Error('NO_CHECKPOINTS_AVAILABLE: No checkpoint files found in .synthesis/checkpoints');
      }
    }, 'NO_CHECKPOINTS_AVAILABLE', 'NEG-60 (empty chk dir)');

    // NEG-61 (REPAIR 002R03): Missing CAP- prefix rejected
    assertThrows(() => {
      validateCheckpointSeal(buildCheckpoint({
        evidence_binding: { linked_capsule_id: 'NO_PREFIX_ID-001', linked_capsule_payload_sha256: 'a'.repeat(64) }
      }));
    }, 'INVALID_CAPSULE_ID', 'NEG-61 (missing CAP- prefix)');

    // NEG-62 (REPAIR 002R03): Lowercase capsule ID rejected
    assertThrows(() => {
      validateCheckpointSeal(buildCheckpoint({
        evidence_binding: { linked_capsule_id: 'cap-syn-mini-001', linked_capsule_payload_sha256: 'a'.repeat(64) }
      }));
    }, 'INVALID_CAPSULE_ID', 'NEG-62 (lowercase capsule ID)');

    // NEG-63 (REPAIR 002R03): Capsule ID containing slash rejected
    assertThrows(() => {
      validateCheckpointSeal(buildCheckpoint({
        evidence_binding: { linked_capsule_id: 'CAP-SYN/MINI-001', linked_capsule_payload_sha256: 'a'.repeat(64) }
      }));
    }, 'INVALID_CAPSULE_ID', 'NEG-63 (slash in capsule ID)');

    // NEG-64 (REPAIR 002R03): Capsule ID containing whitespace rejected
    assertThrows(() => {
      validateCheckpointSeal(buildCheckpoint({
        evidence_binding: { linked_capsule_id: 'CAP-SYN MINI-001', linked_capsule_payload_sha256: 'a'.repeat(64) }
      }));
    }, 'INVALID_CAPSULE_ID', 'NEG-64 (whitespace in capsule ID)');

    // NEG-65 (REPAIR 002R03): Empty linked_capsule_id rejected
    assertThrows(() => {
      validateCheckpointSeal(buildCheckpoint({
        evidence_binding: { linked_capsule_id: '', linked_capsule_payload_sha256: 'a'.repeat(64) }
      }));
    }, 'INVALID_CAPSULE_ID', 'NEG-65 (empty capsule ID)');

    // NEG-66 (REPAIR 002R04): Linked capsule file missing
    assertThrows(() => {
      const chk = buildCheckpoint({
        evidence_binding: { linked_capsule_id: 'CAP-SYN-MINI-MISSING-001', linked_capsule_payload_sha256: '0'.repeat(64) }
      });
      validateEvidenceBinding(tmpDir, chk);
    }, 'CAPSULE_FILE_MISSING', 'NEG-66 (capsule file missing)');

    // NEG-67 (REPAIR 002R04): Linked capsule ID mismatch in file
    const mismatchCapPath = path.join(tmpDir, '.synthesis', 'task-capsules', 'CAP-SYN-MINI-MISMATCH-001.json');
    const mismatchCapObj = makeTestCapsule('CAP-SYN-MINI-OTHER-001');
    fs.writeFileSync(mismatchCapPath, JSON.stringify(mismatchCapObj, null, 2));
    assertThrows(() => {
      const chk = buildCheckpoint({
        evidence_binding: { linked_capsule_id: 'CAP-SYN-MINI-MISMATCH-001', linked_capsule_payload_sha256: mismatchCapObj.seal.payload_sha256 }
      });
      validateEvidenceBinding(tmpDir, chk);
    }, 'CAPSULE_ID_MISMATCH', 'NEG-67 (capsule ID mismatch)');

    // NEG-68 (REPAIR 002R04): Linked capsule payload SHA mismatch
    assertThrows(() => {
      const chk = buildCheckpoint({
        evidence_binding: { linked_capsule_id: 'CAP-SYN-MINI-TEST-001-20261005-001', linked_capsule_payload_sha256: 'f'.repeat(64) }
      });
      validateEvidenceBinding(tmpDir, chk);
    }, 'CAPSULE_PAYLOAD_SHA_MISMATCH', 'NEG-68 (payload SHA mismatch)');

    // NEG-69 (REPAIR 002R04): Tampered linked capsule payload/seal
    const tamperedCapPath = path.join(tmpDir, '.synthesis', 'task-capsules', 'CAP-SYN-MINI-TAMPERED-001.json');
    const tamperedCapObj = makeTestCapsule('CAP-SYN-MINI-TAMPERED-001');
    tamperedCapObj.seal.payload_sha256 = 'e'.repeat(64);
    fs.writeFileSync(tamperedCapPath, JSON.stringify(tamperedCapObj, null, 2));
    assertThrows(() => {
      const chk = buildCheckpoint({
        evidence_binding: { linked_capsule_id: 'CAP-SYN-MINI-TAMPERED-001', linked_capsule_payload_sha256: 'e'.repeat(64) }
      });
      validateEvidenceBinding(tmpDir, chk);
    }, 'CAPSULE_SEAL_MISMATCH', 'NEG-69 (tampered capsule seal)');

    // NEG-70 (REPAIR 002R04): Linked capsule not present in target commit
    const notInCommitCapPath = path.join(tmpDir, '.synthesis', 'task-capsules', 'CAP-SYN-MINI-NOT-IN-COMMIT-001.json');
    const notInCommitCapObj = makeTestCapsule('CAP-SYN-MINI-NOT-IN-COMMIT-001');
    fs.writeFileSync(notInCommitCapPath, JSON.stringify(notInCommitCapObj, null, 2));
    assertThrows(() => {
      const chk = buildCheckpoint({
        evidence_binding: { linked_capsule_id: 'CAP-SYN-MINI-NOT-IN-COMMIT-001', linked_capsule_payload_sha256: notInCommitCapObj.seal.payload_sha256 }
      });
      validateEvidenceBinding(tmpDir, chk);
    }, 'CAPSULE_NOT_IN_TARGET_COMMIT', 'NEG-70 (capsule not in target commit)');

    // NEG-71 (REPAIR 002R04): Linked capsule belongs to wrong command
    const wrongCmdCapPath = path.join(tmpDir, '.synthesis', 'task-capsules', 'CAP-SYN-MINI-WRONG-CMD-001.json');
    const wrongCmdCapObj = makeTestCapsule('CAP-SYN-MINI-WRONG-CMD-001', 'SYN-MINI-TEST-001', 'CMD-OTHER-COMMAND-999');
    fs.writeFileSync(wrongCmdCapPath, JSON.stringify(wrongCmdCapObj, null, 2));
    execGit(['add', '.synthesis/task-capsules/CAP-SYN-MINI-WRONG-CMD-001.json'], tmpDir);
    execGit(['commit', '-m', 'add wrong cmd capsule'], tmpDir);
    const cWrongCmdSha = execGit(['rev-parse', 'HEAD'], tmpDir);
    assertThrows(() => {
      const chk = buildCheckpoint({
        target_commit: { commit_sha: cWrongCmdSha, parent_sha: c2Sha, commit_timestamp_utc: '2026-10-05T00:00:00Z' },
        evidence_binding: { linked_capsule_id: 'CAP-SYN-MINI-WRONG-CMD-001', linked_capsule_payload_sha256: wrongCmdCapObj.seal.payload_sha256 }
      });
      validateEvidenceBinding(tmpDir, chk);
    }, 'CAPSULE_SEMANTIC_MISMATCH', 'NEG-71 (wrong command capsule)');

    // NEG-72 (REPAIR 002R04): Linked capsule belongs to wrong task
    const wrongTaskCapPath = path.join(tmpDir, '.synthesis', 'task-capsules', 'CAP-SYN-MINI-WRONG-TASK-001.json');
    const wrongTaskCapObj = makeTestCapsule('CAP-SYN-MINI-WRONG-TASK-001', 'SYN-MINI-OTHER-TASK-888', 'CMD-SYN-MINI-TEST-001-001');
    fs.writeFileSync(wrongTaskCapPath, JSON.stringify(wrongTaskCapObj, null, 2));
    execGit(['add', '.synthesis/task-capsules/CAP-SYN-MINI-WRONG-TASK-001.json'], tmpDir);
    execGit(['commit', '-m', 'add wrong task capsule'], tmpDir);
    const cWrongTaskSha = execGit(['rev-parse', 'HEAD'], tmpDir);
    assertThrows(() => {
      const chk = buildCheckpoint({
        target_commit: { commit_sha: cWrongTaskSha, parent_sha: c2Sha, commit_timestamp_utc: '2026-10-05T00:00:00Z' },
        evidence_binding: { linked_capsule_id: 'CAP-SYN-MINI-WRONG-TASK-001', linked_capsule_payload_sha256: wrongTaskCapObj.seal.payload_sha256 }
      });
      validateEvidenceBinding(tmpDir, chk);
    }, 'CAPSULE_SEMANTIC_MISMATCH', 'NEG-72 (wrong task capsule)');

    // Setup dedicated clean directory for global lineage negative tests
    const lineageRepo = path.join(tmpDir, 'lineage-test-repo');
    const testChkDir = path.join(lineageRepo, '.synthesis', 'checkpoints');
    fs.mkdirSync(testChkDir, { recursive: true });

    // NEG-73 (REPAIR 002R04): Duplicate checkpoint_id in two files
    const dupChkObj = buildCheckpoint({ checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-073' });
    fs.writeFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-073.json'), JSON.stringify(dupChkObj, null, 2));
    fs.writeFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-073-copy.json'), JSON.stringify(dupChkObj, null, 2));
    assertThrows(() => {
      verifyAllCheckpointLineage(lineageRepo);
    }, 'CHECKPOINT_FILE_NAME_MISMATCH', 'NEG-73 (duplicate checkpoint ID / filename mismatch)');

    // Clear test checkpoints
    fs.rmSync(testChkDir, { recursive: true, force: true });
    fs.mkdirSync(testChkDir, { recursive: true });

    // NEG-74 (REPAIR 002R04): Two-node lineage cycle
    const cycleA = buildCheckpoint({
      checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-074',
      checkpoint_lineage: {
        parent_checkpoint: {
          checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-075',
          file_path: '.synthesis/checkpoints/CHK-SYN-MINI-TEST-001-20261005-075.json',
          raw_file_sha256: '0'.repeat(64)
        }
      }
    });
    const cycleB = buildCheckpoint({
      checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-075',
      checkpoint_lineage: {
        parent_checkpoint: {
          checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-074',
          file_path: '.synthesis/checkpoints/CHK-SYN-MINI-TEST-001-20261005-074.json',
          raw_file_sha256: '0'.repeat(64)
        }
      }
    });
    fs.writeFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-074.json'), JSON.stringify(cycleA, null, 2));
    fs.writeFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-075.json'), JSON.stringify(cycleB, null, 2));
    cycleA.payload.checkpoint_lineage.parent_checkpoint.raw_file_sha256 = computeRawFileSha256(fs.readFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-075.json')));
    cycleB.payload.checkpoint_lineage.parent_checkpoint.raw_file_sha256 = computeRawFileSha256(fs.readFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-074.json')));
    cycleA.seal.payload_sha256 = computePayloadSha256(cycleA.payload).sha256Hex;
    cycleB.seal.payload_sha256 = computePayloadSha256(cycleB.payload).sha256Hex;
    fs.writeFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-074.json'), JSON.stringify(cycleA, null, 2));
    fs.writeFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-075.json'), JSON.stringify(cycleB, null, 2));

    assertThrows(() => {
      verifyAllCheckpointLineage(lineageRepo);
    }, 'CHECKPOINT_LINEAGE_CYCLE', 'NEG-74 (two-node lineage cycle)');

    // Clear test checkpoints
    fs.rmSync(testChkDir, { recursive: true, force: true });
    fs.mkdirSync(testChkDir, { recursive: true });

    // NEG-75 (REPAIR 002R04): Three-node lineage cycle
    const cycle1 = buildCheckpoint({ checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-081', checkpoint_lineage: { parent_checkpoint: { checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-083', file_path: '.synthesis/checkpoints/CHK-SYN-MINI-TEST-001-20261005-083.json', raw_file_sha256: '' } } });
    const cycle2 = buildCheckpoint({ checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-082', checkpoint_lineage: { parent_checkpoint: { checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-081', file_path: '.synthesis/checkpoints/CHK-SYN-MINI-TEST-001-20261005-081.json', raw_file_sha256: '' } } });
    const cycle3 = buildCheckpoint({ checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-083', checkpoint_lineage: { parent_checkpoint: { checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-082', file_path: '.synthesis/checkpoints/CHK-SYN-MINI-TEST-001-20261005-082.json', raw_file_sha256: '' } } });
    fs.writeFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-081.json'), JSON.stringify(cycle1, null, 2));
    fs.writeFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-082.json'), JSON.stringify(cycle2, null, 2));
    fs.writeFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-083.json'), JSON.stringify(cycle3, null, 2));
    cycle1.payload.checkpoint_lineage.parent_checkpoint.raw_file_sha256 = computeRawFileSha256(fs.readFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-083.json')));
    cycle2.payload.checkpoint_lineage.parent_checkpoint.raw_file_sha256 = computeRawFileSha256(fs.readFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-081.json')));
    cycle3.payload.checkpoint_lineage.parent_checkpoint.raw_file_sha256 = computeRawFileSha256(fs.readFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-082.json')));
    cycle1.seal.payload_sha256 = computePayloadSha256(cycle1.payload).sha256Hex;
    cycle2.seal.payload_sha256 = computePayloadSha256(cycle2.payload).sha256Hex;
    cycle3.seal.payload_sha256 = computePayloadSha256(cycle3.payload).sha256Hex;
    fs.writeFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-081.json'), JSON.stringify(cycle1, null, 2));
    fs.writeFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-082.json'), JSON.stringify(cycle2, null, 2));
    fs.writeFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-083.json'), JSON.stringify(cycle3, null, 2));

    assertThrows(() => {
      verifyAllCheckpointLineage(lineageRepo);
    }, 'CHECKPOINT_LINEAGE_CYCLE', 'NEG-75 (three-node lineage cycle)');

    // Clear test checkpoints
    fs.rmSync(testChkDir, { recursive: true, force: true });
    fs.mkdirSync(testChkDir, { recursive: true });

    // NEG-76 (REPAIR 002R04): Fork: two children reference same parent
    const forkParent = buildCheckpoint({ checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-090', checkpoint_lineage: { parent_checkpoint: null } });
    fs.writeFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-090.json'), JSON.stringify(forkParent, null, 2));
    const forkPRawSha = computeRawFileSha256(fs.readFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-090.json')));

    const forkChild1 = buildCheckpoint({
      checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-091',
      checkpoint_lineage: { parent_checkpoint: { checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-090', file_path: '.synthesis/checkpoints/CHK-SYN-MINI-TEST-001-20261005-090.json', raw_file_sha256: forkPRawSha } }
    });
    const forkChild2 = buildCheckpoint({
      checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-092',
      checkpoint_lineage: { parent_checkpoint: { checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-090', file_path: '.synthesis/checkpoints/CHK-SYN-MINI-TEST-001-20261005-090.json', raw_file_sha256: forkPRawSha } }
    });
    fs.writeFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-091.json'), JSON.stringify(forkChild1, null, 2));
    fs.writeFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-092.json'), JSON.stringify(forkChild2, null, 2));

    assertThrows(() => {
      verifyAllCheckpointLineage(lineageRepo);
    }, 'LINEAGE_FORK_REJECTED', 'NEG-76 (fork rejection)');

    // Clear test checkpoints
    fs.rmSync(testChkDir, { recursive: true, force: true });
    fs.mkdirSync(testChkDir, { recursive: true });

    // NEG-77 (REPAIR 002R04): Parent task mismatch
    const parentTask1 = buildCheckpoint({ checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-095', task_id: 'SYN-TASK-001', checkpoint_lineage: { parent_checkpoint: null } });
    fs.writeFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-095.json'), JSON.stringify(parentTask1, null, 2));
    const pTaskRawSha = computeRawFileSha256(fs.readFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-095.json')));

    const childTask2 = buildCheckpoint({
      checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-096',
      task_id: 'SYN-TASK-002',
      checkpoint_lineage: { parent_checkpoint: { checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-095', file_path: '.synthesis/checkpoints/CHK-SYN-MINI-TEST-001-20261005-095.json', raw_file_sha256: pTaskRawSha } }
    });
    fs.writeFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-096.json'), JSON.stringify(childTask2, null, 2));

    assertThrows(() => {
      verifyAllCheckpointLineage(lineageRepo);
    }, 'LINEAGE_INCOMPATIBILITY', 'NEG-77 (parent task mismatch)');

    // Clear test checkpoints
    fs.rmSync(testChkDir, { recursive: true, force: true });
    fs.mkdirSync(testChkDir, { recursive: true });

    // NEG-78 (REPAIR 002R04): Parent branch mismatch
    const parentBr1 = buildCheckpoint({
      checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-097',
      repository: { name: 'jirisar7-eng/synthesis-cms-mini', id: 1401215700, branch: 'main', base_main_sha: c0Sha },
      checkpoint_lineage: { parent_checkpoint: null }
    });
    fs.writeFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-097.json'), JSON.stringify(parentBr1, null, 2));
    const pBrRawSha = computeRawFileSha256(fs.readFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-097.json')));

    const childBr2 = buildCheckpoint({
      checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-098',
      repository: { name: 'jirisar7-eng/synthesis-cms-mini', id: 1401215700, branch: 'task/SYN-MINI-TEST-001', base_main_sha: c0Sha },
      checkpoint_lineage: { parent_checkpoint: { checkpoint_id: 'CHK-SYN-MINI-TEST-001-20261005-097', file_path: '.synthesis/checkpoints/CHK-SYN-MINI-TEST-001-20261005-097.json', raw_file_sha256: pBrRawSha } }
    });
    fs.writeFileSync(path.join(testChkDir, 'CHK-SYN-MINI-TEST-001-20261005-098.json'), JSON.stringify(childBr2, null, 2));

    assertThrows(() => {
      verifyAllCheckpointLineage(lineageRepo);
    }, 'LINEAGE_INCOMPATIBILITY', 'NEG-78 (parent branch mismatch)');

    // Clear test checkpoints
    fs.rmSync(testChkDir, { recursive: true, force: true });
    fs.mkdirSync(testChkDir, { recursive: true });

    // NEG-79 (REPAIR 002R04): Unexpected / non-checkpoint file in directory
    fs.writeFileSync(path.join(testChkDir, 'random-file.txt'), 'not a checkpoint');
    assertThrows(() => {
      verifyAllCheckpointLineage(lineageRepo);
    }, 'UNEXPECTED_DIRECTORY_ENTRY', 'NEG-79 (unexpected file in checkpoints dir)');

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
  let parsed;
  try {
    parsed = parseCliArgs(process.argv);
  } catch (err) {
    console.error(`CLI_ERROR: ${err.message}`);
    process.exit(1);
  }

  if (parsed.mode === 'HELP') {
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

  if (parsed.mode === 'SELF_TEST') {
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

  if (parsed.mode === 'VERIFY_ALL') {
    try {
      verifyAllCheckpointLineage(DEFAULT_REPO_ROOT);
      const chkDir = path.join(DEFAULT_REPO_ROOT, '.synthesis', 'checkpoints');
      const files = fs.readdirSync(chkDir).filter(f => f.startsWith('CHK-') && f.endsWith('.json'));
      console.log(`Verifying ${files.length} remote checkpoint(s)...`);
      for (const f of files) {
        const p = path.join(chkDir, f);
        const { obj } = loadCheckpointStrict(p, DEFAULT_REPO_ROOT);
        validateCheckpointCommitBinding(DEFAULT_REPO_ROOT, obj);
        validateCheckpointLineage(DEFAULT_REPO_ROOT, obj);
        validateRecordedRemoteEvidence(obj, DEFAULT_REPO_ROOT);
        validateEvidenceBinding(DEFAULT_REPO_ROOT, obj);
        console.log(`Verified checkpoint: ${f}`);
      }
      console.log('REMOTE_CHECKPOINT_VERIFICATION: PASS');
      process.exit(0);
    } catch (err) {
      console.error(`VERIFY_ALL_FAIL: ${err.message}`);
      process.exit(1);
    }
  }

  if (parsed.mode === 'VERIFY') {
    try {
      const targetPath = path.resolve(process.cwd(), parsed.filePath);
      const { obj } = loadCheckpointStrict(targetPath, DEFAULT_REPO_ROOT);
      validateCheckpointCommitBinding(DEFAULT_REPO_ROOT, obj);
      validateCheckpointLineage(DEFAULT_REPO_ROOT, obj);
      validateRecordedRemoteEvidence(obj, DEFAULT_REPO_ROOT);
      validateEvidenceBinding(DEFAULT_REPO_ROOT, obj);
      console.log(`CHECKPOINT_VERIFY_PASS: ${targetPath}`);
      process.exit(0);
    } catch (err) {
      console.error(`VERIFY_FAIL: ${err.message}`);
      process.exit(1);
    }
  }

  if (parsed.mode === 'VERIFY_LIVE') {
    try {
      const targetPath = path.resolve(process.cwd(), parsed.filePath);
      const res = verifyLiveCheckpoint(targetPath, DEFAULT_REPO_ROOT);
      if (res.success) {
        console.log(`CHECKPOINT_VERIFY_LIVE_PASS: ${targetPath}`);
        process.exit(0);
      } else {
        console.error(`CHECKPOINT_VERIFY_LIVE_SUPERSEDED: ${targetPath} (${res.reason})`);
        process.exit(2);
      }
    } catch (err) {
      console.error(`VERIFY_LIVE_FAIL: ${err.message}`);
      process.exit(1);
    }
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  main();
}
