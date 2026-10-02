#!/usr/bin/env node

/**
 * Synthesis CMS mini — Command Capsule Linked Attestation Chain Verifier
 * 
 * Verifies full-file integrity and append-only DAG/chain lineage of Command Capsules
 * against linked attestations rooted in the pinned baseline manifest.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

// Reuse existing governance production modules (strictly acyclic)
import {
  loadSchema
} from './validate_command_capsule.mjs';

import {
  parseStrictIJson,
  verifyCapsuleSeal,
  computePayloadSha256,
  timingSafeHexCompare
} from './verify_capsule_seal.mjs';

import {
  loadAndVerifyCapsule,
  verifyGenesisAnchor
} from './verify_capsule_lineage.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ============================================================
// PINNED CONSTANTS FOR ROOT BASELINE ATTESTATION
// ============================================================

export const PINNED_BASELINE_PATH = '.synthesis/attestations/capsule-file-baseline-20261002.json';
export const PINNED_BASELINE_LOGICAL_ID = 'DETACHED_CAPSULE_RAW_FILE_BASELINE_20261002';
export const PINNED_BASELINE_RAW_SHA256 = '1c5f8c125f5a1c8bbc730d9b4b7d9c82b76aff452ee9b82023633f5921764168';
export const PINNED_BASELINE_GIT_BLOB = 'd0c91b768a14070c7b0b19ad56fb33a573278898';
export const PINNED_GENESIS_SHA256 = 'b3d47a6f732512a9f5b19668a07bb4d2c662adf316f5a1d33a6d52c57860ec60';
export const PINNED_SOURCE_MAIN_SHA = 'd362a6431bf0f5c7368df96b657c596eb093b6ff';
export const PINNED_SOURCE_TASK_SHA = '3db87689aee0ab72304efc3b46afc23a5a91890b';

export const MAX_JSON_FILE_BYTES = 512 * 1024; // 512 KiB limit
export const MAX_CAPSULE_RECORDS = 1000;

// Helper: compute Git blob SHA-1
export function computeGitBlobSha(rawBytes) {
  if (!Buffer.isBuffer(rawBytes)) {
    throw new Error('computeGitBlobSha requires a Buffer input');
  }
  const header = Buffer.from(`blob ${rawBytes.length}\0`, 'utf8');
  return crypto.createHash('sha1').update(Buffer.concat([header, rawBytes])).digest('hex');
}

// Helper: compute raw-file SHA-256
export function computeRawFileSha256(rawBytes) {
  if (!Buffer.isBuffer(rawBytes)) {
    throw new Error('computeRawFileSha256 requires a Buffer input');
  }
  return crypto.createHash('sha256').update(rawBytes).digest('hex');
}

// ============================================================
// ATTESTATION CHAIN DISCOVERY & GRAPH CONSTRUCTION
// ============================================================

export function loadAttestationChain(repoRoot) {
  const attestationsDir = path.join(repoRoot, '.synthesis', 'attestations');
  if (!fs.existsSync(attestationsDir)) {
    return { valid: false, stage: 'ATTESTATIONS_DIR_MISSING', error: 'Directory .synthesis/attestations does not exist' };
  }

  const dirStat = fs.lstatSync(attestationsDir);
  if (dirStat.isSymbolicLink()) {
    return { valid: false, stage: 'ATTESTATIONS_DIR_SYMLINK_REJECTED', error: 'Directory .synthesis/attestations is a symlink' };
  }
  if (!dirStat.isDirectory()) {
    return { valid: false, stage: 'ATTESTATIONS_DIR_NOT_DIRECTORY', error: 'Path .synthesis/attestations is not a directory' };
  }

  // Inspect all entries in .synthesis/attestations
  const entries = fs.readdirSync(attestationsDir, { withFileTypes: true });
  const attestationFiles = [];

  for (const entry of entries) {
    if (entry.isSymbolicLink()) {
      return { valid: false, stage: 'UNSAFE_SYMLINK_IN_ATTESTATIONS_DIR', error: `Unsafe symlink in attestations directory: ${entry.name}` };
    }
    if (!entry.isFile() || entry.name.startsWith('.') || !entry.name.endsWith('.json')) {
      return { valid: false, stage: 'UNEXPECTED_ENTRY_IN_ATTESTATIONS_DIR', error: `Unexpected entry in attestations directory: ${entry.name}` };
    }
    attestationFiles.push(entry.name);
  }

  // Verify Root Baseline exists and is among files
  const baselineFileName = path.basename(PINNED_BASELINE_PATH);
  if (!attestationFiles.includes(baselineFileName)) {
    return { valid: false, stage: 'BASELINE_MANIFEST_MISSING', error: `Root baseline manifest missing: ${PINNED_BASELINE_PATH}` };
  }

  // Load and verify Root Baseline Manifest raw bytes
  const rootFullPath = path.join(repoRoot, PINNED_BASELINE_PATH);
  const rootStat = fs.lstatSync(rootFullPath);
  if (rootStat.isSymbolicLink() || !rootStat.isFile()) {
    return { valid: false, stage: 'BASELINE_MANIFEST_UNSAFE', error: 'Root baseline manifest is not a regular file' };
  }
  if (rootStat.size > MAX_JSON_FILE_BYTES) {
    return { valid: false, stage: 'FILE_SIZE_LIMIT_EXCEEDED', error: `Baseline manifest exceeds size limit (${rootStat.size} bytes)` };
  }

  const rootRawBytes = fs.readFileSync(rootFullPath);
  const rootRawSha = computeRawFileSha256(rootRawBytes);
  if (!timingSafeHexCompare(rootRawSha, PINNED_BASELINE_RAW_SHA256)) {
    return {
      valid: false,
      stage: 'BASELINE_RAW_SHA256_MISMATCH',
      error: `Root baseline raw SHA-256 mismatch! Got: ${rootRawSha}, expected: ${PINNED_BASELINE_RAW_SHA256}`
    };
  }

  const rootBlobSha = computeGitBlobSha(rootRawBytes);
  if (rootBlobSha !== PINNED_BASELINE_GIT_BLOB) {
    return {
      valid: false,
      stage: 'BASELINE_GIT_BLOB_MISMATCH',
      error: `Root baseline Git blob mismatch! Got: ${rootBlobSha}, expected: ${PINNED_BASELINE_GIT_BLOB}`
    };
  }

  let rootManifest;
  try {
    rootManifest = parseStrictIJson(rootRawBytes.toString('utf8'));
  } catch (err) {
    return { valid: false, stage: 'BASELINE_JSON_PARSE_ERROR', error: `Failed to parse root manifest JSON: ${err.message}` };
  }

  // Validate structural baseline attributes
  if (rootManifest.format_version !== '1.0.0' || rootManifest.record_kind !== 'DETACHED_CAPSULE_RAW_FILE_BASELINE' || rootManifest.status !== 'OBSERVED_UNANCHORED') {
    return { valid: false, stage: 'BASELINE_SCHEMA_ERROR', error: 'Root baseline manifest schema attributes invalid' };
  }
  if (rootManifest.source_repository !== 'jirisar7-eng/synthesis-cms-mini') {
    return { valid: false, stage: 'BASELINE_SCHEMA_ERROR', error: `Invalid source_repository: "${rootManifest.source_repository}"` };
  }
  if (rootManifest.genesis_sha256 !== PINNED_GENESIS_SHA256) {
    return { valid: false, stage: 'BASELINE_GENESIS_MISMATCH', error: `Genesis mismatch in baseline: ${rootManifest.genesis_sha256}` };
  }
  if (!Array.isArray(rootManifest.capsules) || rootManifest.capsules.length !== 2) {
    return { valid: false, stage: 'BASELINE_RECORD_COUNT_INVALID', error: `Root baseline must contain exactly 2 capsule records, got ${rootManifest.capsules?.length}` };
  }

  // Map of all loaded attestations: id -> object
  const attestationsMap = new Map();
  const fileToIdMap = new Map();

  // Insert Root Node
  const rootNode = {
    id: PINNED_BASELINE_LOGICAL_ID,
    filePath: PINNED_BASELINE_PATH,
    rawSha256: rootRawSha,
    gitBlobSha: rootBlobSha,
    isRoot: true,
    parentId: null,
    parentPath: null,
    parentRawSha: null,
    capsules: rootManifest.capsules, // array of 2 records
    parsed: rootManifest
  };
  attestationsMap.set(rootNode.id, rootNode);
  fileToIdMap.set(PINNED_BASELINE_PATH, rootNode.id);

  // Load remaining linked attestations
  for (const fileName of attestationFiles) {
    if (fileName === baselineFileName) continue;

    const relPath = `.synthesis/attestations/${fileName}`;
    const fullPath = path.join(repoRoot, relPath);
    const stat = fs.lstatSync(fullPath);
    if (stat.isSymbolicLink() || !stat.isFile()) {
      return { valid: false, stage: 'LINKED_ATTESTATION_UNSAFE', error: `Attestation ${relPath} is not a regular file` };
    }
    if (stat.size > MAX_JSON_FILE_BYTES) {
      return { valid: false, stage: 'FILE_SIZE_LIMIT_EXCEEDED', error: `Attestation ${relPath} exceeds size limit` };
    }

    const rawBytes = fs.readFileSync(fullPath);
    const rawSha256 = computeRawFileSha256(rawBytes);
    const gitBlobSha = computeGitBlobSha(rawBytes);

    let parsed;
    try {
      parsed = parseStrictIJson(rawBytes.toString('utf8'));
    } catch (err) {
      return { valid: false, stage: 'LINKED_ATTESTATION_PARSE_ERROR', error: `Failed to parse ${relPath}: ${err.message}` };
    }

    // Strict schema check on linked record
    if (parsed.format_version !== '1.0.0') {
      return { valid: false, stage: 'LINKED_ATTESTATION_SCHEMA_ERROR', error: `Invalid format_version in ${relPath}` };
    }
    if (parsed.record_kind !== 'LINKED_CAPSULE_FILE_ATTESTATION') {
      return { valid: false, stage: 'LINKED_ATTESTATION_SCHEMA_ERROR', error: `Invalid record_kind in ${relPath}: "${parsed.record_kind}"` };
    }
    if (!parsed.attestation_id || typeof parsed.attestation_id !== 'string' || !/^ATT-SYN-MINI-[A-Z0-9_-]+$/.test(parsed.attestation_id)) {
      return { valid: false, stage: 'INVALID_ATTESTATION_ID_SYNTAX', error: `Malformed attestation_id in ${relPath}: "${parsed.attestation_id}"` };
    }
    if (fileName !== `${parsed.attestation_id}.json`) {
      return { valid: false, stage: 'ATTESTATION_FILENAME_MISMATCH', error: `File name "${fileName}" does not match attestation_id "${parsed.attestation_id}.json"` };
    }
    if (parsed.status !== 'OBSERVED_UNANCHORED') {
      return { valid: false, stage: 'LINKED_ATTESTATION_SCHEMA_ERROR', error: `Invalid status in ${relPath}: "${parsed.status}"` };
    }
    if (!parsed.observed_at_utc || typeof parsed.observed_at_utc !== 'string' || Number.isNaN(Date.parse(parsed.observed_at_utc))) {
      return { valid: false, stage: 'LINKED_ATTESTATION_SCHEMA_ERROR', error: `Invalid observed_at_utc timestamp in ${relPath}` };
    }
    if (parsed.source_repository !== 'jirisar7-eng/synthesis-cms-mini') {
      return { valid: false, stage: 'LINKED_ATTESTATION_SCHEMA_ERROR', error: `Invalid source_repository in ${relPath}: "${parsed.source_repository}"` };
    }

    // Genesis anchor reference
    if (!parsed.genesis_anchor_reference || typeof parsed.genesis_anchor_reference !== 'object') {
      return { valid: false, stage: 'LINKED_ATTESTATION_SCHEMA_ERROR', error: `Missing genesis_anchor_reference in ${relPath}` };
    }
    if (parsed.genesis_anchor_reference.genesis_file !== '.synthesis/lineage/genesis.json' || parsed.genesis_anchor_reference.pinned_sha256 !== PINNED_GENESIS_SHA256) {
      return { valid: false, stage: 'LINKED_ATTESTATION_GENESIS_MISMATCH', error: `Genesis mismatch in ${relPath}` };
    }

    // Parent attestation reference
    if (!parsed.parent_attestation || typeof parsed.parent_attestation !== 'object') {
      return { valid: false, stage: 'LINKED_ATTESTATION_SCHEMA_ERROR', error: `Missing parent_attestation in ${relPath}` };
    }
    const p = parsed.parent_attestation;
    if (!p.attestation_id || typeof p.attestation_id !== 'string' || !p.file_path || typeof p.file_path !== 'string' || !p.raw_file_sha256 || !/^[a-f0-9]{64}$/.test(p.raw_file_sha256)) {
      return { valid: false, stage: 'INVALID_PARENT_ATTESTATION_REF', error: `Malformed parent_attestation fields in ${relPath}` };
    }
    if (path.isAbsolute(p.file_path) || p.file_path.includes('..') || !p.file_path.startsWith('.synthesis/attestations/')) {
      return { valid: false, stage: 'PATH_TRAVERSAL_IN_PARENT_REF', error: `Illegal parent file_path in ${relPath}: "${p.file_path}"` };
    }

    // New capsule payload
    if (!parsed.new_capsule || typeof parsed.new_capsule !== 'object') {
      return { valid: false, stage: 'LINKED_ATTESTATION_SCHEMA_ERROR', error: `Missing new_capsule in ${relPath}` };
    }
    const c = parsed.new_capsule;
    if (!c.capsule_id || !/^CAP-SYN-MINI-[A-Z0-9_-]+$/.test(c.capsule_id)) {
      return { valid: false, stage: 'INVALID_CAPSULE_ID_SYNTAX', error: `Malformed capsule_id in ${relPath}: "${c.capsule_id}"` };
    }
    if (!c.file_path || !/^\.synthesis\/task-capsules\/CAP-[A-Za-z0-9_.-]+\.json$/.test(c.file_path) || c.file_path.includes('..')) {
      return { valid: false, stage: 'INVALID_CAPSULE_FILE_PATH', error: `Malformed capsule file_path in ${relPath}: "${c.file_path}"` };
    }
    if (!c.payload_sha256 || !/^[a-f0-9]{64}$/.test(c.payload_sha256)) {
      return { valid: false, stage: 'INVALID_PAYLOAD_SHA256', error: `Malformed payload_sha256 in ${relPath}` };
    }
    if (!c.raw_file_sha256 || !/^[a-f0-9]{64}$/.test(c.raw_file_sha256)) {
      return { valid: false, stage: 'INVALID_RAW_FILE_SHA256', error: `Malformed raw_file_sha256 in ${relPath}` };
    }
    if (!c.git_blob_sha || !/^[a-f0-9]{40}$/.test(c.git_blob_sha)) {
      return { valid: false, stage: 'INVALID_GIT_BLOB_SHA', error: `Malformed git_blob_sha in ${relPath}` };
    }
    if (typeof c.file_size_bytes !== 'number' || !Number.isInteger(c.file_size_bytes) || c.file_size_bytes <= 0) {
      return { valid: false, stage: 'INVALID_FILE_SIZE_BYTES', error: `Malformed file_size_bytes in ${relPath}` };
    }

    if (attestationsMap.has(parsed.attestation_id)) {
      return { valid: false, stage: 'DUPLICATE_ATTESTATION_ID', error: `Duplicate attestation_id detected: "${parsed.attestation_id}"` };
    }

    const node = {
      id: parsed.attestation_id,
      filePath: relPath,
      rawSha256,
      gitBlobSha,
      isRoot: false,
      parentId: p.attestation_id,
      parentPath: p.file_path,
      parentRawSha: p.raw_file_sha256,
      capsules: [c], // exactly 1 new capsule
      parsed
    };

    attestationsMap.set(node.id, node);
    fileToIdMap.set(relPath, node.id);
  }

  // Verify Graph Lineage: single connected linear chain from root to unique HEAD
  const childrenMap = new Map();
  for (const [id, node] of attestationsMap) {
    if (!node.isRoot) {
      const parent = attestationsMap.get(node.parentId);
      if (!parent) {
        return { valid: false, stage: 'ORPHAN_ATTESTATION_DETECTED', error: `Attestation ${node.id} references non-existent parent "${node.parentId}"` };
      }
      if (node.parentPath !== parent.filePath) {
        return { valid: false, stage: 'PARENT_PATH_MISMATCH', error: `Attestation ${node.id} parentPath "${node.parentPath}" does not match parent file "${parent.filePath}"` };
      }
      if (!timingSafeHexCompare(node.parentRawSha, parent.rawSha256)) {
        return { valid: false, stage: 'PARENT_RAW_SHA256_MISMATCH', error: `Attestation ${node.id} parent raw SHA mismatch! Recorded: ${node.parentRawSha}, Actual parent: ${parent.rawSha256}` };
      }

      if (!childrenMap.has(node.parentId)) {
        childrenMap.set(node.parentId, []);
      }
      childrenMap.get(node.parentId).push(node.id);
    }
  }

  // Detect forks (any node having > 1 children)
  for (const [parentId, childIds] of childrenMap) {
    if (childIds.length > 1) {
      return { valid: false, stage: 'ATTESTATION_CHAIN_FORK_DETECTED', error: `Fork detected at parent "${parentId}": multiple children [${childIds.join(', ')}]` };
    }
  }

  // Traverse linear chain from root to find head and detect cycles
  const orderedChain = [];
  let currentId = PINNED_BASELINE_LOGICAL_ID;
  const visited = new Set();

  while (currentId) {
    if (visited.has(currentId)) {
      return { valid: false, stage: 'ATTESTATION_CHAIN_CYCLE_DETECTED', error: `Cycle detected in attestation chain at "${currentId}"` };
    }
    visited.add(currentId);
    const currentNode = attestationsMap.get(currentId);
    orderedChain.push(currentNode);

    const children = childrenMap.get(currentId) || [];
    if (children.length === 0) {
      break;
    }
    currentId = children[0];
  }

  // Ensure ALL loaded attestations are in the linear chain (no disconnected subgraphs/orphans)
  if (visited.size !== attestationsMap.size) {
    return { valid: false, stage: 'DISCONNECTED_OR_ORPHAN_ATTESTATIONS', error: `Disconnected attestation graph: visited ${visited.size} of ${attestationsMap.size} files` };
  }

  const headNode = orderedChain[orderedChain.length - 1];

  return {
    valid: true,
    orderedChain,
    headNode,
    attestationCount: orderedChain.length
  };
}

// ============================================================
// FULL CHAIN & CAPSULE REPOSITORY VERIFICATION
// ============================================================

export function verifyAttestationChain(repoRoot, options = {}) {
  // 1. Verify Genesis anchor in repository
  try {
    verifyGenesisAnchor(repoRoot);
  } catch (err) {
    return { valid: false, stage: 'GENESIS_ANCHOR_INVALID', error: err.message };
  }

  // 2. Load schema
  let schema;
  try {
    schema = loadSchema(repoRoot);
  } catch (err) {
    return { valid: false, stage: 'SCHEMA_LOAD_FAILED', error: `Failed to load schema: ${err.message}` };
  }

  // 3. Load attestation chain
  const chainRes = loadAttestationChain(repoRoot);
  if (!chainRes.valid) {
    return chainRes;
  }

  // 4. Verify capsules against chain records
  const seenCapsuleIds = new Set();
  const seenCapsulePaths = new Set();
  const allAttestedRecords = [];

  for (const node of chainRes.orderedChain) {
    for (const record of node.capsules) {
      if (seenCapsuleIds.has(record.capsule_id)) {
        return { valid: false, stage: 'DUPLICATE_CAPSULE_ID_IN_CHAIN', error: `Duplicate capsule_id in chain: "${record.capsule_id}"` };
      }
      seenCapsuleIds.add(record.capsule_id);

      if (seenCapsulePaths.has(record.file_path)) {
        return { valid: false, stage: 'DUPLICATE_CAPSULE_PATH_IN_CHAIN', error: `Duplicate capsule file_path in chain: "${record.file_path}"` };
      }
      seenCapsulePaths.add(record.file_path);

      // Verify physical capsule file
      const fullCapPath = path.join(repoRoot, record.file_path);
      if (!fs.existsSync(fullCapPath)) {
        return { valid: false, stage: 'RECORDED_CAPSULE_FILE_MISSING', error: `Recorded capsule file does not exist: ${record.file_path}` };
      }

      const stat = fs.lstatSync(fullCapPath);
      if (stat.isSymbolicLink() || !stat.isFile()) {
        return { valid: false, stage: 'UNSAFE_CAPSULE_FILE', error: `Capsule ${record.file_path} is not a regular file` };
      }
      if (stat.size !== record.file_size_bytes) {
        return { valid: false, stage: 'FILE_SIZE_MISMATCH', error: `Size mismatch on ${record.file_path}: actual ${stat.size}B, recorded ${record.file_size_bytes}B` };
      }

      const rawBytes = fs.readFileSync(fullCapPath);
      const rawSha = computeRawFileSha256(rawBytes);
      if (!timingSafeHexCompare(rawSha, record.raw_file_sha256)) {
        return { valid: false, stage: 'RAW_FILE_SHA256_MISMATCH', error: `Raw SHA-256 mismatch on ${record.file_path}! Got: ${rawSha}, recorded: ${record.raw_file_sha256}` };
      }

      const blobSha = computeGitBlobSha(rawBytes);
      if (blobSha !== record.git_blob_sha) {
        return { valid: false, stage: 'GIT_BLOB_SHA_MISMATCH', error: `Git blob mismatch on ${record.file_path}! Got: ${blobSha}, recorded: ${record.git_blob_sha}` };
      }

      let capsule;
      try {
        capsule = parseStrictIJson(rawBytes.toString('utf8'));
      } catch (err) {
        return { valid: false, stage: 'CAPSULE_JSON_PARSE_ERROR', error: `Failed to parse capsule ${record.file_path}: ${err.message}` };
      }

      // Verify capsule seal & payload
      const sealRes = verifyCapsuleSeal(schema, capsule);
      if (!sealRes.valid || !sealRes.isSealed || !sealRes.payloadHashMatch) {
        return { valid: false, stage: sealRes.stage || 'CAPSULE_SEAL_INVALID', error: `Seal validation failed on ${record.file_path}: ${sealRes.error}` };
      }
      if (!timingSafeHexCompare(sealRes.computedSha256, record.payload_sha256)) {
        return { valid: false, stage: 'PAYLOAD_SHA256_MISMATCH', error: `Payload SHA-256 mismatch on ${record.file_path}` };
      }

      // Semantic integrity: check repository and genesis binding in payload
      const repoName = capsule?.payload?.repository_baseline?.repository_name;
      if (repoName !== 'jirisar7-eng/synthesis-cms-mini') {
        return { valid: false, stage: 'CAPSULE_REPO_MISMATCH', error: `Capsule ${record.file_path} bound to invalid repo: "${repoName}"` };
      }
      const genRef = capsule?.payload?.lineage?.genesis_anchor_reference?.pinned_sha256;
      if (genRef !== PINNED_GENESIS_SHA256) {
        return { valid: false, stage: 'CAPSULE_GENESIS_MISMATCH', error: `Capsule ${record.file_path} bound to invalid Genesis anchor: "${genRef}"` };
      }

      allAttestedRecords.push({
        capsuleId: record.capsule_id,
        filePath: record.file_path,
        rawSha256: rawSha,
        gitBlobSha: blobSha,
        payloadSha256: sealRes.computedSha256,
        fileSizeBytes: stat.size
      });
    }
  }

  if (allAttestedRecords.length > MAX_CAPSULE_RECORDS) {
    return { valid: false, stage: 'MAX_CAPSULE_LIMIT_EXCEEDED', error: `Attested capsules exceed maximum count (${allAttestedRecords.length})` };
  }

  // 5. Verify Complete Directory Coverage (Fail-Closed)
  const capsuleDir = path.join(repoRoot, '.synthesis', 'task-capsules');
  if (!fs.existsSync(capsuleDir)) {
    return { valid: false, stage: 'CAPSULE_DIR_MISSING', error: 'Directory .synthesis/task-capsules does not exist' };
  }

  const dirStat = fs.lstatSync(capsuleDir);
  if (dirStat.isSymbolicLink()) {
    return { valid: false, stage: 'CAPSULE_DIR_SYMLINK_REJECTED', error: 'Directory .synthesis/task-capsules is a symlink' };
  }
  if (!dirStat.isDirectory()) {
    return { valid: false, stage: 'CAPSULE_DIR_NOT_DIRECTORY', error: 'Path .synthesis/task-capsules is not a directory' };
  }

  const entries = fs.readdirSync(capsuleDir, { withFileTypes: true });
  const actualCapsulePaths = new Set();

  for (const entry of entries) {
    if (entry.isSymbolicLink()) {
      return { valid: false, stage: 'UNSAFE_SYMLINK_IN_CAPSULE_DIR', error: `Unsafe symlink in capsule directory: ${entry.name}` };
    }
    if (!entry.isFile() || entry.name.startsWith('.') || !entry.name.endsWith('.json')) {
      return { valid: false, stage: 'UNEXPECTED_ENTRY_IN_CAPSULE_DIR', error: `Unexpected non-JSON entry in capsule directory: ${entry.name}` };
    }
    actualCapsulePaths.add(`.synthesis/task-capsules/${entry.name}`);
  }

  for (const actPath of actualCapsulePaths) {
    if (!seenCapsulePaths.has(actPath)) {
      return { valid: false, stage: 'UNRECORDED_CAPSULE_DETECTED', error: `Found capsule file in repository not covered by attestation chain: ${actPath}` };
    }
  }

  for (const attPath of seenCapsulePaths) {
    if (!actualCapsulePaths.has(attPath)) {
      return { valid: false, stage: 'RECORDED_CAPSULE_MISSING', error: `Attestation chain records capsule missing from filesystem: ${attPath}` };
    }
  }

  // 6. Checkpoint Verification
  const trustedPrior = options.trustedPriorCheckpoint;
  let checkpointStatus = {
    priorCheckpointProvided: false,
    priorCheckpointMembership: 'NOT_APPLICABLE',
    externalAuthenticity: 'NOT_APPLICABLE',
    historyContinuity: 'NOT_VERIFIED'
  };

  if (options.requireTrustedPrior && !trustedPrior) {
    return { valid: false, stage: 'REQUIRED_TRUSTED_PRIOR_MISSING', error: 'Option requireTrustedPrior was specified but no trusted checkpoint was provided' };
  }

  if (trustedPrior) {
    if (!trustedPrior.filePath || !trustedPrior.rawFileSha256) {
      return { valid: false, stage: 'MALFORMED_TRUSTED_PRIOR_CHECKPOINT', error: 'trustedPriorCheckpoint must specify both filePath and rawFileSha256' };
    }

    // Checkpoint must match one node in the verified linear chain
    const matchedNode = chainRes.orderedChain.find(n => n.filePath === trustedPrior.filePath);
    if (!matchedNode) {
      return {
        valid: false,
        stage: 'HISTORY_CHECKPOINT_MISMATCH',
        error: `Trusted prior checkpoint file "${trustedPrior.filePath}" is not present in the current attestation chain (possible history rollback/truncation)`
      };
    }

    if (!timingSafeHexCompare(matchedNode.rawSha256, trustedPrior.rawFileSha256)) {
      return {
        valid: false,
        stage: 'HISTORY_CHECKPOINT_MISMATCH',
        error: `Trusted prior checkpoint raw SHA mismatch for "${trustedPrior.filePath}"! Expected: ${trustedPrior.rawFileSha256}, Actual: ${matchedNode.rawSha256}`
      };
    }

    checkpointStatus = {
      priorCheckpointProvided: true,
      priorCheckpointMembership: 'PASS',
      externalAuthenticity: 'ASSUMED_FROM_CALLER',
      historyContinuity: 'CHECKPOINT_VERIFIED'
    };
  }

  return {
    valid: true,
    attestationChainLength: chainRes.attestationCount,
    headAttestationId: chainRes.headNode.id,
    headAttestationPath: chainRes.headNode.filePath,
    headAttestationRawSha: chainRes.headNode.rawSha256,
    capsulesCount: allAttestedRecords.length,
    attestedRecords: allAttestedRecords,
    checkpointStatus
  };
}

// ============================================================
// SELF-TEST SUITE WITH ISOLATED FIXTURES IN OS.TMPDIR()
// ============================================================

export function runSelfTests(repoRoot) {
  let positivePassed = 0;
  let negativePassed = 0;
  let failedTests = 0;

  function assertPositive(name, fn) {
    try {
      const res = fn();
      if (res && res.valid) {
        positivePassed++;
      } else {
        console.error(`FAIL [${name}]: expected valid, got: ${res ? res.error || res.stage : 'falsy result'}`);
        failedTests++;
      }
    } catch (err) {
      console.error(`FAIL (exception) [${name}]: ${err.message}`);
      failedTests++;
    }
  }

  function assertNegative(name, fn, expectedStage) {
    try {
      const res = fn();
      if (res && !res.valid) {
        if (!expectedStage || res.stage === expectedStage || (res.error && res.error.includes(expectedStage))) {
          negativePassed++;
        } else {
          console.error(`FAIL [${name}]: wrong error stage. Expected "${expectedStage}", got stage="${res.stage}", error="${res.error}"`);
          failedTests++;
        }
      } else {
        console.error(`FAIL [${name}]: expected invalid stage "${expectedStage}", but was accepted as valid!`);
        failedTests++;
      }
    } catch (err) {
      if (expectedStage && err.message.includes(expectedStage)) {
        negativePassed++;
      } else {
        console.error(`FAIL (unexpected exception) [${name}]: ${err.message}`);
        failedTests++;
      }
    }
  }

  // Helper: setup isolated test environment in os.tmpdir()
  function setupTestEnv() {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'syn-mini-chain-test-'));
    
    // Copy genesis file and validator script
    const genesisSrc = path.join(repoRoot, '.synthesis/lineage/genesis.json');
    const genesisDst = path.join(tmpDir, '.synthesis/lineage/genesis.json');
    fs.mkdirSync(path.dirname(genesisDst), { recursive: true });
    fs.copyFileSync(genesisSrc, genesisDst);

    const genesisValidatorSrc = path.join(repoRoot, 'scripts/governance/verify_genesis.mjs');
    const genesisValidatorDst = path.join(tmpDir, 'scripts/governance/verify_genesis.mjs');
    fs.mkdirSync(path.dirname(genesisValidatorDst), { recursive: true });
    fs.copyFileSync(genesisValidatorSrc, genesisValidatorDst);

    const schemaSrc = path.join(repoRoot, '.synthesis/schemas/command-capsule.schema.json');
    const schemaDst = path.join(tmpDir, '.synthesis/schemas/command-capsule.schema.json');
    fs.mkdirSync(path.dirname(schemaDst), { recursive: true });
    fs.copyFileSync(schemaSrc, schemaDst);

    const baselineSrc = path.join(repoRoot, PINNED_BASELINE_PATH);
    const baselineDst = path.join(tmpDir, PINNED_BASELINE_PATH);
    fs.mkdirSync(path.dirname(baselineDst), { recursive: true });
    fs.copyFileSync(baselineSrc, baselineDst);

    const cap010Src = path.join(repoRoot, '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010.json');
    const cap010Dst = path.join(tmpDir, '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010.json');
    fs.mkdirSync(path.dirname(cap010Dst), { recursive: true });
    fs.copyFileSync(cap010Src, cap010Dst);

    const cap013Src = path.join(repoRoot, '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-013.json');
    const cap013Dst = path.join(tmpDir, '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-013.json');
    fs.mkdirSync(path.dirname(cap013Dst), { recursive: true });
    fs.copyFileSync(cap013Src, cap013Dst);

    return tmpDir;
  }

  // Helper: create synthetic valid 3rd capsule & attestation in tmpDir
  function addSyntheticThirdCapsule(tmpDir) {
    const cap013Text = fs.readFileSync(path.join(tmpDir, '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-013.json'), 'utf8');
    const cap013 = JSON.parse(cap013Text);

    const cap014Payload = JSON.parse(JSON.stringify(cap013.payload));
    cap014Payload.capsule_id = 'CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-014';
    cap014Payload.command_id = 'CMD-SYN-MINI-GOV-CAPSULE-SCHEMA-001-014-SYNTHETIC';
    cap014Payload.lineage.parent_capsules = [
      {
        capsule_id: 'CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-013',
        command_id: cap013.payload.command_id,
        payload_sha256: cap013.seal.payload_sha256,
        relationship_type: 'LINEAR_PARENT'
      }
    ];

    // Compute canonical RFC-8785 SHA-256 for payload
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

    const cap014RawSha = computeRawFileSha256(cap014Bytes);
    const cap014BlobSha = computeGitBlobSha(cap014Bytes);

    // Create companion linked attestation
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
        attestation_id: PINNED_BASELINE_LOGICAL_ID,
        file_path: PINNED_BASELINE_PATH,
        raw_file_sha256: PINNED_BASELINE_RAW_SHA256
      },
      new_capsule: {
        capsule_id: cap014.payload.capsule_id,
        file_path: cap014RelPath,
        payload_sha256: validPayloadSha,
        raw_file_sha256: cap014RawSha,
        git_blob_sha: cap014BlobSha,
        file_size_bytes: cap014Bytes.length
      }
    };

    const att001Bytes = Buffer.from(JSON.stringify(att001, null, 2), 'utf8');
    const att001RelPath = `.synthesis/attestations/${att001Id}.json`;
    fs.writeFileSync(path.join(tmpDir, att001RelPath), att001Bytes);

    return {
      capsuleRelPath: cap014RelPath,
      capsuleRawSha: cap014RawSha,
      attestationId: att001Id,
      attestationRelPath: att001RelPath,
      attestationRawSha: computeRawFileSha256(att001Bytes)
    };
  }

  // --- POSITIVE TESTS ---
  // POSITIVE 1: Baseline 2-capsule root-only repo passes
  assertPositive('POSITIVE 1: Baseline 2-capsule root-only passes', () => {
    const tmpDir = setupTestEnv();
    try {
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // POSITIVE 2: Valid 3rd capsule + linked attestation passes
  assertPositive('POSITIVE 2: Valid 3rd capsule + linked attestation passes', () => {
    const tmpDir = setupTestEnv();
    try {
      addSyntheticThirdCapsule(tmpDir);
      const res = verifyAttestationChain(tmpDir);
      if (!res.valid || res.capsulesCount !== 3 || res.attestationChainLength !== 2) {
        return { valid: false, error: `Expected 3 capsules and 2 attestations, got ${res?.capsulesCount}/${res?.attestationChainLength}` };
      }
      return { valid: true };
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // POSITIVE 3: Valid 4th capsule retaining trusted 3rd attestation as checkpoint passes
  assertPositive('POSITIVE 3: Checkpoint match on ancestor node passes', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);

      // Add 4th capsule
      const cap014Bytes = fs.readFileSync(path.join(tmpDir, third.capsuleRelPath));
      const cap014 = JSON.parse(cap014Bytes.toString('utf8'));
      const cap015Payload = JSON.parse(JSON.stringify(cap014.payload));
      cap015Payload.capsule_id = 'CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-015';
      cap015Payload.command_id = 'CMD-SYN-MINI-GOV-CAPSULE-SCHEMA-001-015-SYNTHETIC';
      cap015Payload.lineage.parent_capsules = [
        {
          capsule_id: cap014.payload.capsule_id,
          command_id: cap014.payload.command_id,
          payload_sha256: cap014.seal.payload_sha256,
          relationship_type: 'LINEAR_PARENT'
        }
      ];
      const validPayloadSha = computePayloadSha256(cap015Payload).sha256Hex;
      const cap015 = {
        payload: cap015Payload,
        seal: {
          status: 'SEALED',
          hash_algorithm: 'SHA-256',
          canonicalization_algorithm: 'RFC-8785',
          payload_sha256: validPayloadSha,
          sealed_at: '2026-10-02T17:00:00Z',
          sealed_by: 'jirisar7-eng',
          seal_signature: null
        }
      };
      const cap015Bytes = Buffer.from(JSON.stringify(cap015, null, 2), 'utf8');
      const cap015RelPath = '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-015.json';
      fs.writeFileSync(path.join(tmpDir, cap015RelPath), cap015Bytes);

      const att002Id = 'ATT-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-002';
      const att002 = {
        format_version: '1.0.0',
        record_kind: 'LINKED_CAPSULE_FILE_ATTESTATION',
        attestation_id: att002Id,
        status: 'OBSERVED_UNANCHORED',
        observed_at_utc: '2026-10-02T17:05:00Z',
        source_repository: 'jirisar7-eng/synthesis-cms-mini',
        genesis_anchor_reference: { genesis_file: '.synthesis/lineage/genesis.json', pinned_sha256: PINNED_GENESIS_SHA256 },
        parent_attestation: { attestation_id: third.attestationId, file_path: third.attestationRelPath, raw_file_sha256: third.attestationRawSha },
        new_capsule: { capsule_id: cap015.payload.capsule_id, file_path: cap015RelPath, payload_sha256: validPayloadSha, raw_file_sha256: computeRawFileSha256(cap015Bytes), git_blob_sha: computeGitBlobSha(cap015Bytes), file_size_bytes: cap015Bytes.length }
      };
      fs.writeFileSync(path.join(tmpDir, `.synthesis/attestations/${att002Id}.json`), Buffer.from(JSON.stringify(att002, null, 2), 'utf8'));

      // Checkpoint points to 3rd attestation (ancestor)
      const res = verifyAttestationChain(tmpDir, {
        trustedPriorCheckpoint: { filePath: third.attestationRelPath, rawFileSha256: third.attestationRawSha }
      });
      if (!res.valid || res.checkpointStatus.priorCheckpointMembership !== 'PASS') {
        return { valid: false, error: 'Ancestor checkpoint match failed' };
      }
      return { valid: true };
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // POSITIVE 4: Checkpoint matching current head passes
  assertPositive('POSITIVE 4: Checkpoint matching current head passes', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      return verifyAttestationChain(tmpDir, {
        trustedPriorCheckpoint: { filePath: third.attestationRelPath, rawFileSha256: third.attestationRawSha }
      });
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // --- NEGATIVE TESTS ---
  // NEGATIVE 1: Capsule-only (3rd capsule added without attestation) -> UNRECORDED_CAPSULE_DETECTED
  assertNegative('NEGATIVE 1: Unrecorded 3rd capsule rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const capPath = path.join(tmpDir, '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-014.json');
      fs.writeFileSync(capPath, '{}', 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'UNRECORDED_CAPSULE_DETECTED');

  // NEGATIVE 2: Attestation-only (attestation added without capsule file) -> RECORDED_CAPSULE_FILE_MISSING
  assertNegative('NEGATIVE 2: Attestation missing capsule file rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      fs.unlinkSync(path.join(tmpDir, third.capsuleRelPath)); // delete capsule
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'RECORDED_CAPSULE_FILE_MISSING');

  // NEGATIVE 3: Tampered historical baseline manifest -> BASELINE_RAW_SHA256_MISMATCH
  assertNegative('NEGATIVE 3: Tampered baseline manifest rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const p = path.join(tmpDir, PINNED_BASELINE_PATH);
      const text = fs.readFileSync(p, 'utf8');
      fs.writeFileSync(p, text.replace('"1.0.0"', '"1.0.1"'), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'BASELINE_RAW_SHA256_MISMATCH');

  // NEGATIVE 4: Tampered capsule 010 bytes -> RAW_FILE_SHA256_MISMATCH
  assertNegative('NEGATIVE 4: Tampered capsule 010 raw bytes rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const p = path.join(tmpDir, '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010.json');
      const text = fs.readFileSync(p, 'utf8');
      fs.writeFileSync(p, text.replace('"sealed_by": "jirisar7-eng"', '"sealed_by": "jirisar7-tam"'), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'RAW_FILE_SHA256_MISMATCH');

  // NEGATIVE 5: Tampered seal metadata in 3rd capsule -> RAW_FILE_SHA256_MISMATCH
  assertNegative('NEGATIVE 5: Tampered seal metadata in 3rd capsule rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.capsuleRelPath);
      const text = fs.readFileSync(p, 'utf8');
      fs.writeFileSync(p, text.replace('"jirisar7-eng"', '"jirisar7-tam"'), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'RAW_FILE_SHA256_MISMATCH');

  // NEGATIVE 6: Altered payload with recomputed seal (capsule raw hash mismatch against attestation)
  assertNegative('NEGATIVE 6: Altered payload with recomputed seal rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.capsuleRelPath);
      const text = fs.readFileSync(p, 'utf8');
      const cap = JSON.parse(text);
      cap.payload.project_id = 'SYNTHESIS_CMS_MINI_ALT';
      cap.seal.payload_sha256 = computePayloadSha256(cap.payload).sha256Hex;
      fs.writeFileSync(p, JSON.stringify(cap, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'FILE_SIZE_MISMATCH');

  // NEGATIVE 7: Stale/forged parent raw SHA in attestation -> PARENT_RAW_SHA256_MISMATCH
  assertNegative('NEGATIVE 7: Forged parent hash in attestation rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(p, 'utf8'));
      att.parent_attestation.raw_file_sha256 = '0'.repeat(64);
      fs.writeFileSync(p, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'PARENT_RAW_SHA256_MISMATCH');

  // NEGATIVE 8: Duplicate attestation ID -> ATTESTATION_FILENAME_MISMATCH
  assertNegative('NEGATIVE 8: Duplicate attestation ID rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const dupPath = path.join(tmpDir, '.synthesis/attestations/dup.json');
      fs.copyFileSync(path.join(tmpDir, third.attestationRelPath), dupPath);
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'ATTESTATION_FILENAME_MISMATCH');

  // NEGATIVE 9: Malformed JSON syntax in attestation -> LINKED_ATTESTATION_PARSE_ERROR
  assertNegative('NEGATIVE 9: Malformed JSON syntax in attestation rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      fs.writeFileSync(path.join(tmpDir, third.attestationRelPath), '{ "invalid": json }', 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'LINKED_ATTESTATION_PARSE_ERROR');

  // NEGATIVE 10: Unsafe hidden file (.hidden.json) in attestations dir -> UNEXPECTED_ENTRY_IN_ATTESTATIONS_DIR
  assertNegative('NEGATIVE 10: Hidden file in attestations directory rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      fs.writeFileSync(path.join(tmpDir, '.synthesis/attestations/.hidden.json'), '{}', 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'UNEXPECTED_ENTRY_IN_ATTESTATIONS_DIR');

  // NEGATIVE 11: Orphan / Disconnected attestation -> ORPHAN_ATTESTATION_DETECTED
  assertNegative('NEGATIVE 11: Orphan attestation rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(p, 'utf8'));
      att.parent_attestation.attestation_id = 'ATT-NON-EXISTENT';
      fs.writeFileSync(p, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'ORPHAN_ATTESTATION_DETECTED');

  // NEGATIVE 12: Fork in attestation chain (two attestations sharing same parent) -> ATTESTATION_CHAIN_FORK_DETECTED
  assertNegative('NEGATIVE 12: Fork in attestation chain rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const forkId = 'ATT-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-FORK';
      const fork = JSON.parse(fs.readFileSync(path.join(tmpDir, third.attestationRelPath), 'utf8'));
      fork.attestation_id = forkId;
      fork.new_capsule.capsule_id = 'CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-FORK';
      fork.new_capsule.file_path = '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-FORK.json';
      fs.writeFileSync(path.join(tmpDir, `.synthesis/attestations/${forkId}.json`), JSON.stringify(fork, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'ATTESTATION_CHAIN_FORK_DETECTED');

  // NEGATIVE 13: Required trusted prior checkpoint missing -> REQUIRED_TRUSTED_PRIOR_MISSING
  assertNegative('NEGATIVE 13: Missing required trusted prior checkpoint rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      return verifyAttestationChain(tmpDir, { requireTrustedPrior: true });
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'REQUIRED_TRUSTED_PRIOR_MISSING');

  // NEGATIVE 14: Deleted checkpointed suffix (truncation attack with checkpoint) -> HISTORY_CHECKPOINT_MISMATCH
  assertNegative('NEGATIVE 14: Checkpoint mismatch on truncated history rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      fs.unlinkSync(path.join(tmpDir, third.capsuleRelPath));
      fs.unlinkSync(path.join(tmpDir, third.attestationRelPath));

      return verifyAttestationChain(tmpDir, {
        trustedPriorCheckpoint: { filePath: third.attestationRelPath, rawFileSha256: third.attestationRawSha }
      });
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'HISTORY_CHECKPOINT_MISMATCH');

  // DEMONSTRATION: Uncheckpointed suffix deletion passes internal consistency with NOT_VERIFIED continuity
  assertPositive('POSITIVE 5 (DEMO): Uncheckpointed truncation passes internally but reports unverified continuity', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      fs.unlinkSync(path.join(tmpDir, third.capsuleRelPath));
      fs.unlinkSync(path.join(tmpDir, third.attestationRelPath));

      const res = verifyAttestationChain(tmpDir);
      if (res.valid && res.checkpointStatus.historyContinuity === 'NOT_VERIFIED') {
        return { valid: true };
      }
      return { valid: false, error: 'Expected valid result with NOT_VERIFIED continuity' };
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

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

  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    if (args.length > 1 && (args[0] === '--help' || args[0] === '-h')) {
      console.error(`Error: Unsupported surplus arguments after ${args[0]}`);
      process.exit(1);
    }
    console.log(`Synthesis CMS mini — Command Capsule Attestation Chain Verifier`);
    console.log(`Usage:`);
    console.log(`  node scripts/governance/verify_capsule_attestation_chain.mjs --self-test`);
    console.log(`  node scripts/governance/verify_capsule_attestation_chain.mjs --verify-all`);
    console.log(`  node scripts/governance/verify_capsule_attestation_chain.mjs --verify-all --trusted-prior-path <PATH> --trusted-prior-sha256 <SHA>`);
    console.log(`  node scripts/governance/verify_capsule_attestation_chain.mjs --verify-all --require-trusted-prior --trusted-prior-path <PATH> --trusted-prior-sha256 <SHA>`);
    console.log(`  node scripts/governance/verify_capsule_attestation_chain.mjs --help`);
    process.exit(args.length === 0 ? 1 : 0);
  }

  if (args[0] === '--self-test') {
    if (args.length !== 1) {
      console.error(`Error: Unexpected arguments after --self-test: ${args.slice(1).join(', ')}`);
      process.exit(1);
    }
    console.log(`Running Command Capsule Attestation Chain Verifier self-tests...`);
    const results = runSelfTests(repoRoot);
    console.log(`POSITIVE_TESTS_PASSED: ${results.positivePassed}`);
    console.log(`NEGATIVE_TESTS_PASSED: ${results.negativePassed}`);
    console.log(`FAILED_TESTS: ${results.failedTests}`);
    console.log(`CHAIN_VERIFICATION_STATUS: ${results.failedTests === 0 ? 'PASS' : 'FAIL'}`);

    if (results.failedTests > 0 || results.positivePassed < 5 || results.negativePassed < 14) {
      process.exit(1);
    }
    process.exit(0);
  }

  if (args[0] === '--verify-all') {
    let trustedPriorPath = null;
    let trustedPriorSha = null;
    let requireTrustedPrior = false;

    for (let i = 1; i < args.length; i++) {
      if (args[i] === '--require-trusted-prior') {
        requireTrustedPrior = true;
      } else if (args[i] === '--trusted-prior-path') {
        if (i + 1 >= args.length) {
          console.error('Error: Missing value for --trusted-prior-path');
          process.exit(1);
        }
        trustedPriorPath = args[++i];
      } else if (args[i] === '--trusted-prior-sha256') {
        if (i + 1 >= args.length) {
          console.error('Error: Missing value for --trusted-prior-sha256');
          process.exit(1);
        }
        trustedPriorSha = args[++i];
      } else {
        console.error(`Error: Unknown argument "${args[i]}"`);
        process.exit(1);
      }
    }

    if ((trustedPriorPath && !trustedPriorSha) || (!trustedPriorPath && trustedPriorSha)) {
      console.error('Error: Both --trusted-prior-path and --trusted-prior-sha256 must be provided together.');
      process.exit(1);
    }

    const options = {
      requireTrustedPrior
    };
    if (trustedPriorPath && trustedPriorSha) {
      options.trustedPriorCheckpoint = {
        filePath: trustedPriorPath,
        rawFileSha256: trustedPriorSha
      };
    }

    try {
      const res = verifyAttestationChain(repoRoot, options);
      if (!res.valid) {
        console.error(`ATTESTATION CHAIN VERIFICATION FAILED [${res.stage}]: ${res.error}`);
        process.exit(1);
      }

      console.log(`ATTESTATION_CHAIN_VERIFICATION: PASS`);
      console.log(`ATTESTATION_CHAIN_LENGTH: ${res.attestationChainLength}`);
      console.log(`HEAD_ATTESTATION_ID: ${res.headAttestationId}`);
      console.log(`HEAD_ATTESTATION_PATH: ${res.headAttestationPath}`);
      console.log(`HEAD_ATTESTATION_RAW_SHA256: ${res.headAttestationRawSha}`);
      console.log(`CAPSULES_VERIFIED_COUNT: ${res.capsulesCount}`);
      for (const rec of res.attestedRecords) {
        console.log(`  - ${rec.capsuleId} (${rec.filePath}): RAW_SHA=${rec.rawSha256}, BLOB=${rec.gitBlobSha}, SIZE=${rec.fileSizeBytes}B`);
      }
      console.log(`PRIOR_CHECKPOINT_MEMBERSHIP: ${res.checkpointStatus.priorCheckpointMembership}`);
      console.log(`EXTERNAL_CHECKPOINT_AUTHENTICITY: ${res.checkpointStatus.externalAuthenticity}`);
      console.log(`HISTORY_CONTINUITY: ${res.checkpointStatus.historyContinuity}`);
      console.log(`INDEPENDENT_TRUST_ANCHOR: NOT_ESTABLISHED`);
      console.log(`AUTHOR_SIGNATURE_VERIFICATION: NOT_IMPLEMENTED`);
      console.log(`APPEND_ONLY_LEDGER: NOT_IMPLEMENTED`);
      console.log(`GLOBAL_GOVERNANCE_HEALTH: BOOTSTRAP_NOT_YET_ACTIVE`);
      process.exit(0);
    } catch (err) {
      console.error(`ATTESTATION CHAIN VERIFICATION EXCEPTION: ${err.message}`);
      process.exit(1);
    }
  }

  console.error(`Error: Unsupported argument "${args[0]}". See --help.`);
  process.exit(1);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  main();
}
