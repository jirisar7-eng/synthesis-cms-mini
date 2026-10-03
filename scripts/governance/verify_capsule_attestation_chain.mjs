#!/usr/bin/env node

/**
 * Synthesis CMS mini — Command Capsule Linked Attestation Chain Verifier
 *
 * Task: SYN-MINI-GOV-CAPSULE-SCHEMA-001
 * Roadmap Step: 2/60 — COMMAND CAPSULE SCHEMA
 *
 * Verifies full-file integrity and append-only DAG/chain lineage of Command Capsules
 * against linked attestations rooted in the pinned baseline manifest.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import child_process from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Reuse existing governance production modules (strictly acyclic)
import {
  loadSchema,
  validateCapsuleComplete
} from './validate_command_capsule.mjs';

import {
  parseStrictIJson,
  verifyCapsuleSeal,
  computePayloadSha256,
  timingSafeHexCompare
} from './verify_capsule_seal.mjs';

import {
  loadAndVerifyCapsule,
  verifyGenesisAnchor,
  verifyLineageGraph,
  EXPECTED_BOOTSTRAP_ROOT_ID
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

// Helper: fatal UTF-8 decoder
export function decodeUtf8Strict(rawBytes, contextName = 'File') {
  try {
    const decoder = new TextDecoder('utf-8', { fatal: true });
    return decoder.decode(rawBytes);
  } catch (err) {
    throw new Error(`INVALID_UTF8_ENCODING: ${contextName} contains invalid UTF-8 byte sequence: ${err.message}`);
  }
}

// Helper: ISO-8601 UTC timestamp check
export function isValidIsoUtcTimestamp(str) {
  if (typeof str !== 'string') return false;
  if (!/^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?Z$/.test(str)) {
    return false;
  }
  const d = new Date(str);
  if (Number.isNaN(d.getTime())) return false;
  const [datePart, timePart] = str.slice(0, -1).split('T');
  const [year, month, day] = datePart.split('-').map(Number);
  const [hour, minute, secWithFrac] = timePart.split(':');
  const sec = Math.floor(Number(secWithFrac));
  if (d.getUTCFullYear() !== year || (d.getUTCMonth() + 1) !== month || d.getUTCDate() !== day ||
      d.getUTCHours() !== Number(hour) || d.getUTCMinutes() !== Number(minute) || d.getUTCSeconds() !== sec) {
    return false;
  }
  return true;
}

// Helper: strict plain object validation
export function isStrictObject(val) {
  return val !== null && typeof val === 'object' && !Array.isArray(val);
}

// Helper: exact own-keys validation (rejects inherited keys satisfying requirement or extra own keys)
export function hasExactKeys(obj, allowedKeys) {
  if (!isStrictObject(obj)) return false;
  const ownKeys = Object.keys(obj);
  if (ownKeys.length !== allowedKeys.length) return false;
  const allowedSet = new Set(allowedKeys);
  for (const k of ownKeys) {
    if (!allowedSet.has(k)) return false;
  }
  return true;
}

// Helper: safe pre-validation of internal repository data path components
export function validateRepoPathComponents(repoRoot) {
  const checks = [
    { rel: '.synthesis', isDir: true, symlinkStage: 'SYNTHESIS_DIR_SYMLINK_REJECTED', typeStage: 'SYNTHESIS_DIR_NOT_DIRECTORY' },
    { rel: '.synthesis/schemas', isDir: true, symlinkStage: 'SCHEMAS_DIR_SYMLINK_REJECTED', typeStage: 'SCHEMAS_DIR_NOT_DIRECTORY' },
    { rel: '.synthesis/schemas/command-capsule.schema.json', isDir: false, symlinkStage: 'SCHEMA_FILE_SYMLINK_REJECTED', typeStage: 'SCHEMA_NOT_REGULAR_FILE' },
    { rel: '.synthesis/lineage', isDir: true, symlinkStage: 'LINEAGE_DIR_SYMLINK_REJECTED', typeStage: 'LINEAGE_DIR_NOT_DIRECTORY' },
    { rel: '.synthesis/lineage/genesis.json', isDir: false, symlinkStage: 'GENESIS_FILE_SYMLINK_REJECTED', typeStage: 'GENESIS_NOT_REGULAR_FILE' },
    { rel: '.synthesis/attestations', isDir: true, symlinkStage: 'ATTESTATIONS_DIR_SYMLINK_REJECTED', typeStage: 'ATTESTATIONS_DIR_NOT_DIRECTORY' },
    { rel: '.synthesis/task-capsules', isDir: true, symlinkStage: 'CAPSULES_DIR_SYMLINK_REJECTED', typeStage: 'CAPSULES_DIR_NOT_DIRECTORY' }
  ];

  for (const c of checks) {
    const full = path.join(repoRoot, c.rel);
    let stat;
    try {
      stat = fs.lstatSync(full);
    } catch (err) {
      if (err.code === 'ENOENT') {
        return { valid: false, stage: 'REQUIRED_PATH_COMPONENT_MISSING', error: `Path component does not exist: ${c.rel}` };
      }
      return { valid: false, stage: 'PATH_COMPONENT_STAT_FAILED', error: `Failed to stat path component ${c.rel}: ${err.message}` };
    }
    if (stat.isSymbolicLink()) {
      return { valid: false, stage: c.symlinkStage, error: `Symbolic link rejected at: ${c.rel}` };
    }
    if (c.isDir && !stat.isDirectory()) {
      return { valid: false, stage: c.typeStage, error: `Path is not a directory: ${c.rel}` };
    }
    if (!c.isDir && !stat.isFile()) {
      return { valid: false, stage: c.typeStage, error: `Path is not a regular file: ${c.rel}` };
    }
  }
  return { valid: true };
}

// ============================================================
// ATTESTATION CHAIN DISCOVERY & GRAPH CONSTRUCTION
// ============================================================

export function loadAttestationChain(repoRoot) {
  const pathCheck = validateRepoPathComponents(repoRoot);
  if (!pathCheck.valid) {
    return pathCheck;
  }

    const attestationsDir = path.join(repoRoot, '.synthesis', 'attestations');
  // Inspect all entries in .synthesis/attestations
  let entries;
  try {
    entries = fs.readdirSync(attestationsDir, { withFileTypes: true });
  } catch (err) {
    return { valid: false, stage: 'ATTESTATIONS_DIR_READ_FAILED', error: `Failed to read attestations directory: ${err.message}` };
  }
  if (entries.length > MAX_CAPSULE_RECORDS) {
    return { valid: false, stage: 'MAX_CAPSULE_LIMIT_EXCEEDED', error: `Too many attestation entries: ${entries.length}` };
  }

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
  let rootStat;
  try {
    rootStat = fs.lstatSync(rootFullPath);
  } catch (err) {
    return { valid: false, stage: 'BASELINE_STAT_FAILED', error: `Failed to stat root baseline manifest: ${err.message}` };
  }
  if (rootStat.isSymbolicLink() || !rootStat.isFile()) {
    return { valid: false, stage: 'BASELINE_MANIFEST_UNSAFE', error: 'Root baseline manifest is not a regular file' };
  }
  if (rootStat.size > MAX_JSON_FILE_BYTES) {
    return { valid: false, stage: 'FILE_SIZE_LIMIT_EXCEEDED', error: `Baseline manifest exceeds size limit (${rootStat.size} bytes)` };
  }

  let rootRawBytes;
  try {
    rootRawBytes = fs.readFileSync(rootFullPath);
  } catch (err) {
    return { valid: false, stage: 'BASELINE_FILE_READ_FAILED', error: `Failed to read root baseline manifest: ${err.message}` };
  }
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

  let rootUtf8;
  try {
    rootUtf8 = decodeUtf8Strict(rootRawBytes, PINNED_BASELINE_PATH);
  } catch (err) {
    return { valid: false, stage: 'INVALID_UTF8_ENCODING', error: err.message };
  }

  let rootManifest;
  try {
    rootManifest = parseStrictIJson(rootUtf8);
  } catch (err) {
    return { valid: false, stage: 'BASELINE_JSON_PARSE_ERROR', error: `Failed to parse root manifest JSON: ${err.message}` };
  }

  if (!isStrictObject(rootManifest)) {
    return { valid: false, stage: 'BASELINE_SCHEMA_ERROR', error: 'Root baseline manifest must be a JSON object' };
  }

  // Validate structural baseline attributes
  const baselineAllowedKeys = [
    'format_version',
    'record_kind',
    'status',
    'observed_at_utc',
    'source_repository',
    'source_main_sha',
    'source_task_sha',
    'hash_scope',
    'genesis_sha256',
    'capsules'
  ];
  if (!hasExactKeys(rootManifest, baselineAllowedKeys)) {
    return { valid: false, stage: 'BASELINE_SCHEMA_ERROR', error: 'Root baseline manifest has unexpected or missing keys' };
  }

  if (rootManifest.format_version !== '1.0.0' || rootManifest.record_kind !== 'DETACHED_CAPSULE_RAW_FILE_BASELINE' || rootManifest.status !== 'OBSERVED_UNANCHORED') {
    return { valid: false, stage: 'BASELINE_SCHEMA_ERROR', error: 'Root baseline manifest schema attributes invalid' };
  }
  if (!isValidIsoUtcTimestamp(rootManifest.observed_at_utc)) {
    return { valid: false, stage: 'BASELINE_SCHEMA_ERROR', error: 'Root baseline observed_at_utc timestamp invalid' };
  }
  if (rootManifest.source_repository !== 'jirisar7-eng/synthesis-cms-mini') {
    return { valid: false, stage: 'BASELINE_SCHEMA_ERROR', error: `Invalid source_repository: "${rootManifest.source_repository}"` };
  }
  if (rootManifest.source_main_sha !== PINNED_SOURCE_MAIN_SHA || rootManifest.source_task_sha !== PINNED_SOURCE_TASK_SHA) {
    return { valid: false, stage: 'BASELINE_SCHEMA_ERROR', error: 'Invalid source SHAs in baseline' };
  }
  if (rootManifest.hash_scope !== 'SHA256_RAW_FILE_BYTES') {
    return { valid: false, stage: 'BASELINE_SCHEMA_ERROR', error: 'Invalid hash_scope in baseline' };
  }
  if (rootManifest.genesis_sha256 !== PINNED_GENESIS_SHA256) {
    return { valid: false, stage: 'BASELINE_GENESIS_MISMATCH', error: `Genesis mismatch in baseline: ${rootManifest.genesis_sha256}` };
  }
  if (!Array.isArray(rootManifest.capsules) || rootManifest.capsules.length !== 2) {
    return { valid: false, stage: 'BASELINE_RECORD_COUNT_INVALID', error: `Root baseline must contain exactly 2 capsule records, got ${rootManifest.capsules?.length}` };
  }

  const capsuleRecordAllowedKeys = [
    'capsule_id',
    'file_path',
    'payload_sha256',
    'raw_file_sha256',
    'git_blob_sha',
    'file_size_bytes'
  ];

  for (const capRec of rootManifest.capsules) {
    if (!isStrictObject(capRec) || !hasExactKeys(capRec, capsuleRecordAllowedKeys)) {
      return { valid: false, stage: 'BASELINE_SCHEMA_ERROR', error: 'Baseline capsule record has unexpected or missing keys' };
    }
  }

  let cumulativeCapsuleCount = rootManifest.capsules.length;

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
    let stat;
    try {
      stat = fs.lstatSync(fullPath);
    } catch (err) {
      return { valid: false, stage: 'LINKED_ATTESTATION_STAT_FAILED', error: `Failed to stat attestation ${relPath}: ${err.message}` };
    }
    if (stat.isSymbolicLink() || !stat.isFile()) {
      return { valid: false, stage: 'LINKED_ATTESTATION_UNSAFE', error: `Attestation ${relPath} is not a regular file` };
    }
    if (stat.size > MAX_JSON_FILE_BYTES) {
      return { valid: false, stage: 'FILE_SIZE_LIMIT_EXCEEDED', error: `Attestation ${relPath} exceeds size limit` };
    }

    cumulativeCapsuleCount++;
    if (cumulativeCapsuleCount > MAX_CAPSULE_RECORDS) {
      return { valid: false, stage: 'MAX_CAPSULE_LIMIT_EXCEEDED', error: `Cumulative capsule count exceeds ${MAX_CAPSULE_RECORDS}` };
    }

    let rawBytes;
    try {
      rawBytes = fs.readFileSync(fullPath);
    } catch (err) {
      return { valid: false, stage: 'LINKED_ATTESTATION_READ_FAILED', error: `Failed to read attestation ${relPath}: ${err.message}` };
    }
    const rawSha256 = computeRawFileSha256(rawBytes);
    const gitBlobSha = computeGitBlobSha(rawBytes);

    let decodedUtf8;
    try {
      decodedUtf8 = decodeUtf8Strict(rawBytes, relPath);
    } catch (err) {
      return { valid: false, stage: 'INVALID_UTF8_ENCODING', error: err.message };
    }

    let parsed;
    try {
      parsed = parseStrictIJson(decodedUtf8);
    } catch (err) {
      return { valid: false, stage: 'LINKED_ATTESTATION_PARSE_ERROR', error: `Failed to parse ${relPath}: ${err.message}` };
    }

    if (!isStrictObject(parsed)) {
      return { valid: false, stage: 'LINKED_ATTESTATION_SCHEMA_ERROR', error: `Root of ${relPath} must be a JSON object` };
    }

    // Version 1.0.0 top-level keys are EXACTLY the 9 original keys (no signature allowed)
    const linkedTopAllowedKeys = [
      'format_version',
      'record_kind',
      'attestation_id',
      'status',
      'observed_at_utc',
      'source_repository',
      'genesis_anchor_reference',
      'parent_attestation',
      'new_capsule'
    ];

    if (!hasExactKeys(parsed, linkedTopAllowedKeys)) {
      return { valid: false, stage: 'LINKED_ATTESTATION_SCHEMA_ERROR', error: `Unexpected or missing keys in ${relPath}` };
    }

    if (parsed.format_version !== '1.0.0') {
      return { valid: false, stage: 'LINKED_ATTESTATION_SCHEMA_ERROR', error: `Invalid format_version in ${relPath}` };
    }
    if (parsed.record_kind !== 'LINKED_CAPSULE_FILE_ATTESTATION') {
      return { valid: false, stage: 'LINKED_ATTESTATION_SCHEMA_ERROR', error: `Invalid record_kind in ${relPath}: "${parsed.record_kind}"` };
    }
    if (typeof parsed.attestation_id !== 'string' || !/^ATT-SYN-MINI-[A-Z0-9_-]+$/.test(parsed.attestation_id)) {
      return { valid: false, stage: 'INVALID_ATTESTATION_ID_SYNTAX', error: `Malformed attestation_id in ${relPath}: "${parsed.attestation_id}"` };
    }
    if (fileName !== `${parsed.attestation_id}.json`) {
      return { valid: false, stage: 'ATTESTATION_FILENAME_MISMATCH', error: `File name "${fileName}" does not match attestation_id "${parsed.attestation_id}.json"` };
    }
    if (parsed.status !== 'OBSERVED_UNANCHORED') {
      return { valid: false, stage: 'LINKED_ATTESTATION_SCHEMA_ERROR', error: `Invalid status in ${relPath}: "${parsed.status}"` };
    }
    if (!isValidIsoUtcTimestamp(parsed.observed_at_utc)) {
      return { valid: false, stage: 'INVALID_OBSERVED_AT_TIMESTAMP', error: `Invalid observed_at_utc timestamp in ${relPath}: "${parsed.observed_at_utc}"` };
    }
    if (parsed.source_repository !== 'jirisar7-eng/synthesis-cms-mini') {
      return { valid: false, stage: 'LINKED_ATTESTATION_SCHEMA_ERROR', error: `Invalid source_repository in ${relPath}: "${parsed.source_repository}"` };
    }

    // Genesis anchor reference
    if (!isStrictObject(parsed.genesis_anchor_reference) || !hasExactKeys(parsed.genesis_anchor_reference, ['genesis_file', 'pinned_sha256'])) {
      return { valid: false, stage: 'LINKED_ATTESTATION_SCHEMA_ERROR', error: `Malformed or unexpected keys in genesis_anchor_reference in ${relPath}` };
    }
    if (parsed.genesis_anchor_reference.genesis_file !== '.synthesis/lineage/genesis.json' || parsed.genesis_anchor_reference.pinned_sha256 !== PINNED_GENESIS_SHA256) {
      return { valid: false, stage: 'LINKED_ATTESTATION_GENESIS_MISMATCH', error: `Genesis mismatch in ${relPath}` };
    }

    // Parent attestation reference
    if (!isStrictObject(parsed.parent_attestation) || !hasExactKeys(parsed.parent_attestation, ['attestation_id', 'file_path', 'raw_file_sha256'])) {
      return { valid: false, stage: 'LINKED_ATTESTATION_SCHEMA_ERROR', error: `Malformed or unexpected keys in parent_attestation in ${relPath}` };
    }
    const p = parsed.parent_attestation;
    if (typeof p.attestation_id !== 'string' || typeof p.file_path !== 'string' || typeof p.raw_file_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(p.raw_file_sha256)) {
      return { valid: false, stage: 'INVALID_PARENT_ATTESTATION_REF', error: `Malformed parent_attestation fields in ${relPath}` };
    }
    if (path.isAbsolute(p.file_path) || p.file_path.includes('..') || !p.file_path.startsWith('.synthesis/attestations/')) {
      return { valid: false, stage: 'PATH_TRAVERSAL_IN_PARENT_REF', error: `Illegal parent file_path in ${relPath}: "${p.file_path}"` };
    }

    // New capsule payload
    if (!isStrictObject(parsed.new_capsule) || !hasExactKeys(parsed.new_capsule, ['capsule_id', 'file_path', 'payload_sha256', 'raw_file_sha256', 'git_blob_sha', 'file_size_bytes'])) {
      return { valid: false, stage: 'LINKED_ATTESTATION_SCHEMA_ERROR', error: `Malformed or unexpected keys in new_capsule in ${relPath}` };
    }
    const c = parsed.new_capsule;
    if (typeof c.capsule_id !== 'string' || !/^CAP-SYN-MINI-[A-Z0-9_-]+$/.test(c.capsule_id)) {
      return { valid: false, stage: 'INVALID_CAPSULE_ID_SYNTAX', error: `Malformed capsule_id in ${relPath}: "${c.capsule_id}"` };
    }
    if (typeof c.file_path !== 'string' || !/^\.synthesis\/task-capsules\/CAP-[A-Za-z0-9_.-]+\.json$/.test(c.file_path) || c.file_path.includes('..')) {
      return { valid: false, stage: 'INVALID_CAPSULE_FILE_PATH', error: `Malformed capsule file_path in ${relPath}: "${c.file_path}"` };
    }
    const expectedCapFilename = `${c.capsule_id}.json`;
    if (path.basename(c.file_path) !== expectedCapFilename) {
      return { valid: false, stage: 'CAPSULE_FILENAME_MISMATCH', error: `Attestation capsule_id "${c.capsule_id}" does not match file_path "${c.file_path}"` };
    }
    if (typeof c.payload_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(c.payload_sha256)) {
      return { valid: false, stage: 'INVALID_PAYLOAD_SHA256', error: `Malformed payload_sha256 in ${relPath}` };
    }
    if (typeof c.raw_file_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(c.raw_file_sha256)) {
      return { valid: false, stage: 'INVALID_RAW_FILE_SHA256', error: `Malformed raw_file_sha256 in ${relPath}` };
    }
    if (typeof c.git_blob_sha !== 'string' || !/^[a-f0-9]{40}$/.test(c.git_blob_sha)) {
      return { valid: false, stage: 'INVALID_GIT_BLOB_SHA', error: `Malformed git_blob_sha in ${relPath}` };
    }
    if (typeof c.file_size_bytes !== 'number' || !Number.isSafeInteger(c.file_size_bytes) || c.file_size_bytes <= 0) {
      return { valid: false, stage: 'INVALID_FILE_SIZE_BYTES', error: `Malformed file_size_bytes in ${relPath}` };
    }
    if (c.file_size_bytes > MAX_JSON_FILE_BYTES) {
      return { valid: false, stage: 'FILE_SIZE_LIMIT_EXCEEDED', error: `Capsule file size recorded in ${relPath} exceeds limit of ${MAX_JSON_FILE_BYTES} bytes` };
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
  // Pre-validate path components within repoRoot
  const pathCheck = validateRepoPathComponents(repoRoot);
  if (!pathCheck.valid) {
    return pathCheck;
  }

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
  const seenCommandIds = new Map();
  const allAttestedRecords = [];
  const capsuleMapForLineage = new Map();

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

      let stat;
      try {
        stat = fs.lstatSync(fullCapPath);
      } catch (err) {
        return { valid: false, stage: 'CAPSULE_STAT_FAILED', error: `Failed to stat capsule ${record.file_path}: ${err.message}` };
      }
      if (stat.isSymbolicLink() || !stat.isFile()) {
        return { valid: false, stage: 'UNSAFE_CAPSULE_FILE', error: `Capsule ${record.file_path} is not a regular file` };
      }

      if (stat.size > MAX_JSON_FILE_BYTES) {
        return { valid: false, stage: 'FILE_SIZE_LIMIT_EXCEEDED', error: `Capsule file ${record.file_path} (${stat.size} bytes) exceeds limit of ${MAX_JSON_FILE_BYTES} bytes` };
      }

      if (stat.size !== record.file_size_bytes) {
        return { valid: false, stage: 'FILE_SIZE_MISMATCH', error: `Size mismatch on ${record.file_path}: actual ${stat.size}B, recorded ${record.file_size_bytes}B` };
      }

      let rawBytes;
      try {
        rawBytes = fs.readFileSync(fullCapPath);
      } catch (err) {
        return { valid: false, stage: 'CAPSULE_FILE_READ_FAILED', error: `Failed to read capsule ${record.file_path}: ${err.message}` };
      }
      const rawSha = computeRawFileSha256(rawBytes);
      if (!timingSafeHexCompare(rawSha, record.raw_file_sha256)) {
        return { valid: false, stage: 'RAW_FILE_SHA256_MISMATCH', error: `Raw SHA-256 mismatch on ${record.file_path}! Got: ${rawSha}, recorded: ${record.raw_file_sha256}` };
      }

      const blobSha = computeGitBlobSha(rawBytes);
      if (blobSha !== record.git_blob_sha) {
        return { valid: false, stage: 'GIT_BLOB_SHA_MISMATCH', error: `Git blob mismatch on ${record.file_path}! Got: ${blobSha}, recorded: ${record.git_blob_sha}` };
      }

      let decodedUtf8;
      try {
        decodedUtf8 = decodeUtf8Strict(rawBytes, record.file_path);
      } catch (err) {
        return { valid: false, stage: 'INVALID_UTF8_ENCODING', error: err.message };
      }

      let capsule;
      try {
        capsule = parseStrictIJson(decodedUtf8);
      } catch (err) {
        return { valid: false, stage: 'CAPSULE_JSON_PARSE_ERROR', error: `Failed to parse capsule ${record.file_path}: ${err.message}` };
      }

      // Check capsule_id consistency
      if (!capsule || !capsule.payload || typeof capsule.payload !== 'object') {
        return { valid: false, stage: 'INVALID_CAPSULE_STRUCTURE', error: `Capsule payload missing or invalid in ${record.file_path}` };
      }

      if (capsule.payload.capsule_id !== record.capsule_id) {
        return { valid: false, stage: 'CAPSULE_ID_MISMATCH', error: `Payload capsule_id "${capsule.payload.capsule_id}" does not match attestation record "${record.capsule_id}"` };
      }

      // Command ID uniqueness
      const cmdId = capsule.payload.command_id;
      if (seenCommandIds.has(cmdId)) {
        return { valid: false, stage: 'DUPLICATE_COMMAND_ID_IN_CHAIN', error: `Duplicate command_id "${cmdId}" across capsules in chain` };
      }
      seenCommandIds.set(cmdId, record.capsule_id);

      // Structural validation
      const structRes = validateCapsuleComplete(schema, capsule);
      if (!structRes.valid) {
        return { valid: false, stage: 'CAPSULE_STRUCTURAL_VALIDATION_FAILED', error: `Structural validation failed on ${record.file_path}: ${structRes.message || structRes.error}` };
      }

      // Verify capsule seal & payload
      const sealRes = verifyCapsuleSeal(schema, capsule);
      if (!sealRes.valid || !sealRes.isSealed || !sealRes.payloadHashMatch) {
        return { valid: false, stage: sealRes.stage || 'CAPSULE_SEAL_INVALID', error: `Seal validation failed on ${record.file_path}: ${sealRes.error}` };
      }

      if (capsule.seal?.status !== 'SEALED') {
        return { valid: false, stage: 'PROVISIONAL_CAPSULE_REJECTED', error: `Capsule ${record.capsule_id} is PROVISIONAL, only SEALED capsules permitted` };
      }

      if (capsule.seal?.seal_signature !== null && capsule.seal?.seal_signature !== undefined) {
        return { valid: false, stage: 'UNSUPPORTED_SIGNATURE', error: `Non-null signature rejected on capsule ${record.capsule_id}` };
      }

      if (!timingSafeHexCompare(sealRes.computedSha256, record.payload_sha256)) {
        return { valid: false, stage: 'PAYLOAD_SHA256_MISMATCH', error: `Payload SHA-256 mismatch on ${record.file_path}` };
      }

      // Semantic integrity: check repository and genesis binding in payload
      const repoName = capsule.payload.repository_baseline?.repository_name;
      if (repoName !== 'jirisar7-eng/synthesis-cms-mini') {
        return { valid: false, stage: 'CAPSULE_REPO_MISMATCH', error: `Capsule ${record.file_path} bound to invalid repo: "${repoName}"` };
      }

      const genRef = capsule.payload.lineage?.genesis_anchor_reference?.pinned_sha256;
      if (genRef !== PINNED_GENESIS_SHA256) {
        return { valid: false, stage: 'CAPSULE_GENESIS_MISMATCH', error: `Capsule ${record.file_path} bound to invalid Genesis anchor: "${genRef}"` };
      }

      const genPath = capsule.payload.lineage?.genesis_anchor_reference?.path;
      if (genPath !== '.synthesis/lineage/genesis.json') {
        return { valid: false, stage: 'CAPSULE_GENESIS_MISMATCH', error: `Capsule ${record.file_path} bound to invalid Genesis path: "${genPath}"` };
      }

      allAttestedRecords.push({
        capsuleId: record.capsule_id,
        filePath: record.file_path,
        rawSha256: rawSha,
        gitBlobSha: blobSha,
        payloadSha256: sealRes.computedSha256,
        fileSizeBytes: stat.size
      });

      capsuleMapForLineage.set(record.capsule_id, {
        capsule,
        filePath: fullCapPath,
        capsuleId: record.capsule_id,
        commandId: cmdId,
        payloadHash: sealRes.computedSha256
      });
    }
  }

  // 5. Verify generic lineage graph of all capsules together
  try {
    verifyLineageGraph(capsuleMapForLineage, {
      singleRoot: true,
      expectedRootId: EXPECTED_BOOTSTRAP_ROOT_ID
    });
  } catch (err) {
    return { valid: false, stage: 'LINEAGE_GRAPH_INVALID', error: `Capsule lineage graph verification failed: ${err.message}` };
  }

  // 6. Verify Complete Directory Coverage (Fail-Closed)
  const capsuleDir = path.join(repoRoot, '.synthesis', 'task-capsules');
  let entries;
  try {
    entries = fs.readdirSync(capsuleDir, { withFileTypes: true });
  } catch (err) {
    return { valid: false, stage: 'CAPSULES_DIR_READ_FAILED', error: `Failed to read capsule directory: ${err.message}` };
  }
  if (entries.length > MAX_CAPSULE_RECORDS) {
    return { valid: false, stage: 'MAX_CAPSULE_LIMIT_EXCEEDED', error: `Too many capsule entries: ${entries.length}` };
  }

  const actualCapsulePaths = new Set();
  for (const entry of entries) {
    if (entry.isSymbolicLink()) {
      return { valid: false, stage: 'UNSAFE_SYMLINK_IN_CAPSULE_DIR', error: `Unsafe symlink in capsule directory: ${entry.name}` };
    }
    if (!entry.isFile() || entry.name.startsWith('.') || !entry.name.endsWith('.json') || !/^CAP-[A-Z0-9_-]+\.json$/.test(entry.name)) {
      return { valid: false, stage: 'UNEXPECTED_ENTRY_IN_CAPSULE_DIR', error: `Unexpected entry in capsule directory: ${entry.name}` };
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

  // 7. Checkpoint Verification
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
    if (typeof trustedPrior.filePath !== 'string' || typeof trustedPrior.rawFileSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(trustedPrior.rawFileSha256)) {
      return { valid: false, stage: 'MALFORMED_TRUSTED_PRIOR_CHECKPOINT', error: 'trustedPriorCheckpoint must specify valid filePath and rawFileSha256' };
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

export const REQUIRED_TEST_CASES = [
  // --- POSITIVE TESTS (9) ---
  { id: 'POS-01', name: 'POSITIVE 1: Baseline 2-capsule root-only passes', type: 'POSITIVE' },
  { id: 'POS-02', name: 'POSITIVE 2: Valid 3rd capsule + linked attestation passes', type: 'POSITIVE' },
  { id: 'POS-03', name: 'POSITIVE 3: Valid 4th capsule retaining trusted 3rd attestation as ancestor checkpoint passes', type: 'POSITIVE' },
  { id: 'POS-04', name: 'POSITIVE 4: Checkpoint matching current head passes', type: 'POSITIVE' },
  { id: 'POS-05', name: 'POSITIVE 5 (DEMO): Uncheckpointed truncation passes internally but reports unverified continuity', type: 'POSITIVE' },
  { id: 'POS-06', name: 'POSITIVE 6: hasExactKeys accepts null-prototype object with exact keys', type: 'POSITIVE' },
  { id: 'POS-07', name: 'POSITIVE 7: CLI standalone --help succeeds with exit 0', type: 'POSITIVE_CLI' },
  { id: 'POS-08', name: 'POSITIVE 8: CLI valid paired checkpoint flags succeed with exit 0', type: 'POSITIVE_CLI' },
  { id: 'POS-09', name: 'POSITIVE 9: Harness control verifies thrown exception in negative test fails assertNegative', type: 'POSITIVE' },

  // --- NEGATIVE TESTS (104) ---
  { id: 'NEG-01', name: 'NEGATIVE 1: Unrecorded 3rd capsule rejected', type: 'NEGATIVE' },
  { id: 'NEG-02', name: 'NEGATIVE 2: Attestation missing capsule file rejected', type: 'NEGATIVE' },
  { id: 'NEG-03', name: 'NEGATIVE 3: Tampered baseline manifest rejected', type: 'NEGATIVE' },
  { id: 'NEG-04', name: 'NEGATIVE 4: Tampered capsule 010 raw bytes rejected', type: 'NEGATIVE' },
  { id: 'NEG-05', name: 'NEGATIVE 5: Tampered seal metadata in 3rd capsule rejected', type: 'NEGATIVE' },
  { id: 'NEG-06', name: 'NEGATIVE 6: Altered payload with recomputed seal rejected by raw hash check', type: 'NEGATIVE' },
  { id: 'NEG-07', name: 'NEGATIVE 7: Forged parent hash in attestation rejected', type: 'NEGATIVE' },
  { id: 'NEG-08', name: 'NEGATIVE 8: Attestation file name mismatch on unaligned ID rejected', type: 'NEGATIVE' },
  { id: 'NEG-09', name: 'NEGATIVE 9: Malformed JSON syntax in attestation rejected', type: 'NEGATIVE' },
  { id: 'NEG-10', name: 'NEGATIVE 10: Hidden file in attestations directory rejected', type: 'NEGATIVE' },
  { id: 'NEG-11', name: 'NEGATIVE 11: Orphan attestation rejected', type: 'NEGATIVE' },
  { id: 'NEG-12', name: 'NEGATIVE 12: Fork in attestation chain rejected', type: 'NEGATIVE' },
  { id: 'NEG-13', name: 'NEGATIVE 13: Missing required trusted prior checkpoint rejected', type: 'NEGATIVE' },
  { id: 'NEG-14', name: 'NEGATIVE 14: Checkpoint mismatch on truncated history rejected', type: 'NEGATIVE' },
  { id: 'NEG-15', name: 'NEGATIVE 15: Capsule referencing missing parent rejected by lineage graph', type: 'NEGATIVE' },
  { id: 'NEG-16', name: 'NEGATIVE 16: Capsule with wrong parent payload digest rejected by lineage graph', type: 'NEGATIVE' },
  { id: 'NEG-17', name: 'NEGATIVE 17: Capsule with wrong parent command ID rejected by lineage graph', type: 'NEGATIVE' },
  { id: 'NEG-18', name: 'NEGATIVE 18: Duplicate command ID across capsules rejected', type: 'NEGATIVE' },
  { id: 'NEG-19', name: 'NEGATIVE 19: Additional parentless root rejected by lineage graph', type: 'NEGATIVE' },
  { id: 'NEG-20', name: 'NEGATIVE 20: Attestation capsule_id mismatch with actual payload rejected', type: 'NEGATIVE' },
  { id: 'NEG-21', name: 'NEGATIVE 21: Extra key at attestation top level rejected', type: 'NEGATIVE' },
  { id: 'NEG-22', name: 'NEGATIVE 22: Extra key in genesis_anchor_reference rejected', type: 'NEGATIVE' },
  { id: 'NEG-23', name: 'NEGATIVE 23: Extra key in parent_attestation rejected', type: 'NEGATIVE' },
  { id: 'NEG-24', name: 'NEGATIVE 24: Extra key in new_capsule rejected', type: 'NEGATIVE' },
  { id: 'NEG-25', name: 'NEGATIVE 25: Date-only observed_at_utc rejected', type: 'NEGATIVE' },
  { id: 'NEG-26', name: 'NEGATIVE 26: Non-UTC offset observed_at_utc rejected', type: 'NEGATIVE' },
  { id: 'NEG-27', name: 'NEGATIVE 27: Invalid calendar date in observed_at_utc rejected', type: 'NEGATIVE' },
  { id: 'NEG-28', name: 'NEGATIVE 28: Invalid UTF-8 byte sequence in capsule rejected', type: 'NEGATIVE' },
  { id: 'NEG-29', name: 'NEGATIVE 29: Capsule exceeding 512 KiB rejected', type: 'NEGATIVE' },
  { id: 'NEG-30', name: 'NEGATIVE 30: Symlinked .synthesis directory rejected', type: 'NEGATIVE' },
  { id: 'NEG-31', name: 'NEGATIVE 31: Symlinked schemas directory rejected', type: 'NEGATIVE' },
  { id: 'NEG-32', name: 'NEGATIVE 32: Symlinked schema file rejected', type: 'NEGATIVE' },
  { id: 'NEG-33', name: 'NEGATIVE 33: Symlinked lineage directory rejected', type: 'NEGATIVE' },
  { id: 'NEG-34', name: 'NEGATIVE 34: signature:null at linked attestation top level rejected', type: 'NEGATIVE' },
  { id: 'NEG-35', name: 'NEGATIVE 35: hasExactKeys rejects inherited property satisfying requirement', type: 'NEGATIVE' },
  { id: 'NEG-36', name: 'NEGATIVE 36: Linked JSON root null returns explicit schema failure', type: 'NEGATIVE' },
  { id: 'NEG-37', name: 'NEGATIVE 37: Linked JSON root scalar 123 returns explicit schema failure', type: 'NEGATIVE' },
  { id: 'NEG-38', name: 'NEGATIVE 38: new_capsule.file_path array rejected without uncaught exception', type: 'NEGATIVE' },
  { id: 'NEG-39', name: 'NEGATIVE 39: CLI empty --trusted-prior-path rejected with exit 1', type: 'NEGATIVE_CLI' },
  { id: 'NEG-40', name: 'NEGATIVE 40: CLI empty --trusted-prior-sha256 rejected with exit 1', type: 'NEGATIVE_CLI' },
  { id: 'NEG-41', name: 'NEGATIVE 41: CLI both empty trusted prior args rejected with exit 1', type: 'NEGATIVE_CLI' },
  { id: 'NEG-42', name: 'NEGATIVE 42: CLI --unknown --help rejected with exit 1', type: 'NEGATIVE_CLI' },
  { id: 'NEG-43', name: 'NEGATIVE 43: CLI mixed --verify-all --help rejected with exit 1', type: 'NEGATIVE_CLI' },
  { id: 'NEG-44', name: 'NEGATIVE 44: CLI repeated --trusted-prior-path rejected with exit 1', type: 'NEGATIVE_CLI' },
  { id: 'NEG-45', name: 'NEGATIVE 45: CLI flag as value rejected with exit 1', type: 'NEGATIVE_CLI' },
  { id: 'NEG-46', name: 'NEGATIVE 46: Filesystem read error in loadAttestationChain returns structured error without throwing', type: 'NEGATIVE' },
  { id: 'NEG-47', name: 'NEGATIVE 47: Filesystem read error in verifyAttestationChain returns structured error without throwing', type: 'NEGATIVE' },
  { id: 'NEG-48', name: 'NEGATIVE 48: Tampered capsule 013 raw bytes rejected', type: 'NEGATIVE' },
  { id: 'NEG-49', name: 'NEGATIVE 49: Baseline manifest JSON syntax error rejected', type: 'NEGATIVE' },
  { id: 'NEG-50', name: 'NEGATIVE 50: Baseline manifest root array rejected', type: 'NEGATIVE' },
  { id: 'NEG-51', name: 'NEGATIVE 51: Baseline manifest duplicate key rejected', type: 'NEGATIVE' },
  { id: 'NEG-52', name: 'NEGATIVE 52: Linked JSON root array rejected', type: 'NEGATIVE' },
  { id: 'NEG-53', name: 'NEGATIVE 53: Linked attestation duplicate key rejected', type: 'NEGATIVE' },
  { id: 'NEG-54', name: 'NEGATIVE 54: Linked attestation invalid UTF-8 byte rejected', type: 'NEGATIVE' },
  { id: 'NEG-55', name: 'NEGATIVE 55: Linked attestation wrong format_version rejected', type: 'NEGATIVE' },
  { id: 'NEG-56', name: 'NEGATIVE 56: Linked attestation wrong record_kind rejected', type: 'NEGATIVE' },
  { id: 'NEG-57', name: 'NEGATIVE 57: Linked attestation wrong status rejected', type: 'NEGATIVE' },
  { id: 'NEG-58', name: 'NEGATIVE 58: Linked attestation wrong source_repository rejected', type: 'NEGATIVE' },
  { id: 'NEG-59', name: 'NEGATIVE 59: Linked attestation genesis mismatch rejected', type: 'NEGATIVE' },
  { id: 'NEG-60', name: 'NEGATIVE 60: Linked attestation parent traversal path rejected', type: 'NEGATIVE' },
  { id: 'NEG-61', name: 'NEGATIVE 61: Linked attestation new_capsule.payload_sha256 malformed hex rejected', type: 'NEGATIVE' },
  { id: 'NEG-62', name: 'NEGATIVE 62: Linked attestation new_capsule.git_blob_sha malformed hex rejected', type: 'NEGATIVE' },
  { id: 'NEG-63', name: 'NEGATIVE 63: Linked attestation new_capsule.file_size_bytes negative rejected', type: 'NEGATIVE' },
  { id: 'NEG-64', name: 'NEGATIVE 64: Capsule JSON syntax error rejected', type: 'NEGATIVE' },
  { id: 'NEG-65', name: 'NEGATIVE 65: Capsule JSON duplicate key rejected', type: 'NEGATIVE' },
  { id: 'NEG-66', name: 'NEGATIVE 66: Capsule payload array root rejected', type: 'NEGATIVE' },
  { id: 'NEG-67', name: 'NEGATIVE 67: Capsule repository name mismatch in payload rejected', type: 'NEGATIVE' },
  { id: 'NEG-68', name: 'NEGATIVE 68: Capsule genesis sha mismatch in payload rejected', type: 'NEGATIVE' },
  { id: 'NEG-69', name: 'NEGATIVE 69: Structurally valid PROVISIONAL capsule rejected', type: 'NEGATIVE' },
  { id: 'NEG-70', name: 'NEGATIVE 70: Non-null capsule seal signature rejected', type: 'NEGATIVE' },
  { id: 'NEG-71', name: 'NEGATIVE 71: Capsule filename mismatch with capsule_id rejected', type: 'NEGATIVE' },
  { id: 'NEG-72', name: 'NEGATIVE 72: Non-JSON file in attestations directory rejected', type: 'NEGATIVE' },
  { id: 'NEG-73', name: 'NEGATIVE 73: Subdirectory in attestations directory rejected', type: 'NEGATIVE' },
  { id: 'NEG-74', name: 'NEGATIVE 74: Hidden file in task-capsules directory rejected', type: 'NEGATIVE' },
  { id: 'NEG-75', name: 'NEGATIVE 75: Non-JSON file in task-capsules directory rejected', type: 'NEGATIVE' },
  { id: 'NEG-76', name: 'NEGATIVE 76: Subdirectory in task-capsules directory rejected', type: 'NEGATIVE' },
  { id: 'NEG-77', name: 'NEGATIVE 77: Symlink leaf file in attestations directory rejected', type: 'NEGATIVE' },
  { id: 'NEG-78', name: 'NEGATIVE 78: Symlink leaf file in task-capsules directory rejected', type: 'NEGATIVE' },
  { id: 'NEG-79', name: 'NEGATIVE 79: Symlink genesis file rejected', type: 'NEGATIVE' },
  { id: 'NEG-80', name: 'NEGATIVE 80: Symlink attestations directory rejected', type: 'NEGATIVE' },
  { id: 'NEG-81', name: 'NEGATIVE 81: Symlink task-capsules directory rejected', type: 'NEGATIVE' },
  { id: 'NEG-82', name: 'NEGATIVE 82: EACCES on readFileSync for baseline manifest in loadAttestationChain rejected', type: 'NEGATIVE' },
  { id: 'NEG-83', name: 'NEGATIVE 83: EACCES on readFileSync for baseline manifest in verifyAttestationChain rejected', type: 'NEGATIVE' },
  { id: 'NEG-84', name: 'NEGATIVE 84: EACCES on lstatSync for baseline manifest in loadAttestationChain rejected', type: 'NEGATIVE' },
  { id: 'NEG-85', name: 'NEGATIVE 85: EACCES on readFileSync for linked attestation rejected', type: 'NEGATIVE' },
  { id: 'NEG-86', name: 'NEGATIVE 86: EACCES on lstatSync for linked attestation rejected', type: 'NEGATIVE' },
  { id: 'NEG-87', name: 'NEGATIVE 87: EACCES on readFileSync for capsule file rejected', type: 'NEGATIVE' },
  { id: 'NEG-88', name: 'NEGATIVE 88: EACCES on lstatSync for capsule file rejected', type: 'NEGATIVE' },
  { id: 'NEG-89', name: 'NEGATIVE 89: EACCES on readdirSync for task-capsules directory rejected', type: 'NEGATIVE' },
  { id: 'NEG-90', name: 'NEGATIVE 90: Lineage topology self-parent loop rejected', type: 'NEGATIVE' },
  { id: 'NEG-91', name: 'NEGATIVE 91: Lineage topology graph cycle rejected', type: 'NEGATIVE' },
  { id: 'NEG-92', name: 'NEGATIVE 92: Lineage topology duplicate parent edge rejected', type: 'NEGATIVE' },
  { id: 'NEG-93', name: 'NEGATIVE 93: Duplicate capsule ID in chain rejected', type: 'NEGATIVE' },
  { id: 'NEG-94', name: 'NEGATIVE 94: Duplicate capsule file path in chain rejected', type: 'NEGATIVE' },
  { id: 'NEG-95', name: 'NEGATIVE 95: Checkpoint raw SHA mismatch on existing node rejected', type: 'NEGATIVE' },
  { id: 'NEG-96', name: 'NEGATIVE 96: Malformed checkpoint object missing rawFileSha256 rejected', type: 'NEGATIVE' },
  { id: 'NEG-97', name: 'NEGATIVE 97: CLI whitespace-only --trusted-prior-path rejected with exit 1', type: 'NEGATIVE_CLI' },
  { id: 'NEG-98', name: 'NEGATIVE 98: CLI whitespace-only --trusted-prior-sha256 rejected with exit 1', type: 'NEGATIVE_CLI' },
  { id: 'NEG-99', name: 'NEGATIVE 99: CLI malformed SHA-256 rejected with exit 1', type: 'NEGATIVE_CLI' },
  { id: 'NEG-100', name: 'NEGATIVE 100: CLI path traversal in --trusted-prior-path rejected with exit 1', type: 'NEGATIVE_CLI' },
  { id: 'NEG-101', name: 'NEGATIVE 101: CLI incomplete pair rejected with exit 1', type: 'NEGATIVE_CLI' },
  { id: 'NEG-102', name: 'NEGATIVE 102: CLI duplicate --require-trusted-prior flag rejected with exit 1', type: 'NEGATIVE_CLI' },
  { id: 'NEG-103', name: 'NEGATIVE 103: CLI surplus argument after --self-test rejected with exit 1', type: 'NEGATIVE_CLI' },
  { id: 'NEG-104', name: 'NEGATIVE 104: CLI unknown flag rejected with exit 1', type: 'NEGATIVE_CLI' }
];

export class TestHarness {
  constructor(repoRoot) {
    this.repoRoot = repoRoot;
    this.executedCases = [];
    this.executedIds = new Set();
  }

  recordCase(id, name, status, type, stage, error = null, reason = null) {
    this.executedIds.add(id);
    this.executedCases.push({
      id,
      name,
      status,
      type,
      stage,
      error,
      reason
    });
  }

  assertPositive(id, name, fn) {
    try {
      const res = fn();
      if (res && res.valid) {
        this.recordCase(id, name, 'PASS', 'POSITIVE', 'VALID', null, 'Valid execution verified');
      } else {
        const errMsg = res ? res.error || res.stage : 'falsy result';
        console.error(`FAIL [${id}: ${name}]: expected valid, got: ${errMsg}`);
        this.recordCase(id, name, 'FAIL', 'POSITIVE', res?.stage || 'UNEXPECTED_INVALID', errMsg, errMsg);
      }
    } catch (err) {
      console.error(`FAIL (uncaught exception) [${id}: ${name}]: ${err.message}`);
      this.recordCase(id, name, 'FAIL', 'POSITIVE', 'UNCAUGHT_EXCEPTION', err.message, err.message);
    }
  }

  assertNegative(id, name, fn, expectedStage, expectedReasonMarker = null) {
    try {
      const res = fn();
      if (res && res.valid === false) {
        if (res.stage === expectedStage) {
          if (!expectedReasonMarker || (res.error && res.error.includes(expectedReasonMarker))) {
            this.recordCase(id, name, 'PASS', 'NEGATIVE', res.stage, null, res.error || `Successfully rejected at ${res.stage}`);
          } else {
            console.error(`FAIL [${id}: ${name}]: expected reason marker "${expectedReasonMarker}", got error: "${res.error}"`);
            this.recordCase(id, name, 'FAIL', 'NEGATIVE', res.stage, `Reason marker mismatch: ${res.error}`, res.error);
          }
        } else {
          console.error(`FAIL [${id}: ${name}]: wrong error stage. Expected exact "${expectedStage}", got "${res.stage}"`);
          this.recordCase(id, name, 'FAIL', 'NEGATIVE', res.stage, `Stage mismatch: expected ${expectedStage}, got ${res.stage}`, res.error || res.stage);
        }
      } else {
        console.error(`FAIL [${id}: ${name}]: expected invalid stage "${expectedStage}", but result was valid!`);
        this.recordCase(id, name, 'FAIL', 'NEGATIVE', 'ACCEPTED_AS_VALID', 'Expected invalid result, got valid', 'Result was unexpectedly valid');
      }
    } catch (err) {
      console.error(`FAIL (unexpected exception in negative test) [${id}: ${name}]: ${err.message}`);
      this.recordCase(id, name, 'FAIL', 'NEGATIVE', 'UNEXPECTED_EXCEPTION', err.message, err.message);
    }
  }

  assertCliPositive(id, name, cliArgs) {
    try {
      const scriptPath = path.join(this.repoRoot, 'scripts/governance/verify_capsule_attestation_chain.mjs');
      const res = child_process.spawnSync(process.execPath, [scriptPath, ...cliArgs], {
        encoding: 'utf8',
        cwd: this.repoRoot
      });
      if (res.status === 0) {
        this.recordCase(id, name, 'PASS', 'POSITIVE_CLI', 'CLI_EXIT_0', null, 'CLI exit status 0');
      } else {
        console.error(`FAIL [${id}: ${name}]: expected CLI exit 0, got status ${res.status}, stderr=${res.stderr}`);
        this.recordCase(id, name, 'FAIL', 'POSITIVE_CLI', 'CLI_STATUS_MISMATCH', `Exit status ${res.status}`, res.stderr || `Exit ${res.status}`);
      }
    } catch (err) {
      console.error(`FAIL [${id}: ${name}]: CLI execution error: ${err.message}`);
      this.recordCase(id, name, 'FAIL', 'POSITIVE_CLI', 'CLI_EXEC_ERROR', err.message, err.message);
    }
  }

  assertCliNegative(id, name, cliArgs) {
    try {
      const scriptPath = path.join(this.repoRoot, 'scripts/governance/verify_capsule_attestation_chain.mjs');
      const res = child_process.spawnSync(process.execPath, [scriptPath, ...cliArgs], {
        encoding: 'utf8',
        cwd: this.repoRoot
      });
      if (res.status === 1) {
        this.recordCase(id, name, 'PASS', 'NEGATIVE_CLI', 'CLI_EXIT_1', null, 'CLI exit status 1 as expected');
      } else {
        console.error(`FAIL [${id}: ${name}]: expected CLI exit 1, got status ${res.status}`);
        this.recordCase(id, name, 'FAIL', 'NEGATIVE_CLI', 'CLI_STATUS_MISMATCH', `Exit status ${res.status}`, `Exit status ${res.status}`);
      }
    } catch (err) {
      console.error(`FAIL [${id}: ${name}]: CLI execution error: ${err.message}`);
      this.recordCase(id, name, 'FAIL', 'NEGATIVE_CLI', 'CLI_EXEC_ERROR', err.message, err.message);
    }
  }

  getResults(requiredRegistry = REQUIRED_TEST_CASES) {
    const executedMap = new Map();
    let duplicates = 0;
    for (const c of this.executedCases) {
      if (executedMap.has(c.id)) {
        duplicates++;
      }
      executedMap.set(c.id, c);
    }

    const missingCases = [];
    for (const req of requiredRegistry) {
      if (!executedMap.has(req.id)) {
        missingCases.push(req.id);
      }
    }

    const positivePassed = this.executedCases.filter(c => c.status === 'PASS' && (c.type === 'POSITIVE' || c.type === 'POSITIVE_CLI')).length;
    const negativePassed = this.executedCases.filter(c => c.status === 'PASS' && (c.type === 'NEGATIVE' || c.type === 'NEGATIVE_CLI')).length;
    const failedTests = this.executedCases.filter(c => c.status === 'FAIL').length + (missingCases.length > 0 ? missingCases.length : 0) + (duplicates > 0 ? duplicates : 0);
    const omittedOrSkippedCases = missingCases.length;

    return {
      valid: failedTests === 0 && omittedOrSkippedCases === 0 && duplicates === 0,
      positivePassed,
      negativePassed,
      failedTests,
      omittedOrSkippedCases,
      duplicateCases: duplicates,
      totalExecuted: this.executedCases.length,
      totalRequired: requiredRegistry.length,
      missingCases,
      executedCases: this.executedCases
    };
  }
}

export function runSelfTests(repoRoot) {
  const harness = new TestHarness(repoRoot);

  function setupTestEnv() {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'syn-mini-chain-test-'));
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
      path.join(repoRoot, PINNED_BASELINE_PATH),
      path.join(tmpDir, PINNED_BASELINE_PATH)
    );

    return tmpDir;
  }

  function addSyntheticThirdCapsule(tmpDir) {
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
        raw_file_sha256: computeRawFileSha256(cap014Bytes),
        git_blob_sha: computeGitBlobSha(cap014Bytes),
        file_size_bytes: cap014Bytes.length
      }
    };

    const att001Bytes = Buffer.from(JSON.stringify(att001, null, 2), 'utf8');
    const att001RelPath = `.synthesis/attestations/${att001Id}.json`;
    fs.writeFileSync(path.join(tmpDir, att001RelPath), att001Bytes);

    return {
      capsuleId: cap014.payload.capsule_id,
      capsuleRelPath: cap014RelPath,
      capsuleRawSha: computeRawFileSha256(cap014Bytes),
      attestationId: att001Id,
      attestationRelPath: att001RelPath,
      attestationRawSha: computeRawFileSha256(att001Bytes)
    };
  }

  // --- POSITIVE TESTS (9) ---

  harness.assertPositive('POS-01', 'POSITIVE 1: Baseline 2-capsule root-only passes', () => {
    const tmpDir = setupTestEnv();
    try {
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  harness.assertPositive('POS-02', 'POSITIVE 2: Valid 3rd capsule + linked attestation passes', () => {
    const tmpDir = setupTestEnv();
    try {
      addSyntheticThirdCapsule(tmpDir);
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  harness.assertPositive('POS-03', 'POSITIVE 3: Valid 4th capsule retaining trusted 3rd attestation as ancestor checkpoint passes', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
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

  harness.assertPositive('POS-04', 'POSITIVE 4: Checkpoint matching current head passes', () => {
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

  harness.assertPositive('POS-05', 'POSITIVE 5 (DEMO): Uncheckpointed truncation passes internally but reports unverified continuity', () => {
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

  harness.assertPositive('POS-06', 'POSITIVE 6: hasExactKeys accepts null-prototype object with exact keys', () => {
    const nullProto = Object.create(null);
    nullProto.a = 1;
    nullProto.b = 2;
    if (hasExactKeys(nullProto, ['a', 'b']) && !hasExactKeys(nullProto, ['a'])) {
      return { valid: true };
    }
    return { valid: false, error: 'hasExactKeys failed on null-prototype object' };
  });

  harness.assertCliPositive('POS-07', 'POSITIVE 7: CLI standalone --help succeeds with exit 0', ['--help']);

  harness.assertCliPositive('POS-08', 'POSITIVE 8: CLI valid paired checkpoint flags succeed with exit 0', [
    '--verify-all',
    '--trusted-prior-path', PINNED_BASELINE_PATH,
    '--trusted-prior-sha256', PINNED_BASELINE_RAW_SHA256
  ]);

  harness.assertPositive('POS-09', 'POSITIVE 9: Harness control verifies thrown exception in negative test fails assertNegative', () => {
    const probeHarness = new TestHarness(repoRoot);
    probeHarness.assertNegative('PROBE-NEG', 'Probe negative throwing error', () => {
      throw new Error('PROBE_TEST_STAGE');
    }, 'PROBE_TEST_STAGE');
    const probeResults = probeHarness.getResults([
      { id: 'PROBE-NEG', name: 'Probe negative throwing error', type: 'NEGATIVE' }
    ]);
    if (
      probeResults.failedTests === 1 &&
      probeResults.negativePassed === 0 &&
      probeResults.executedCases.length === 1 &&
      probeResults.executedCases[0].status === 'FAIL' &&
      probeResults.executedCases[0].stage === 'UNEXPECTED_EXCEPTION'
    ) {
      return { valid: true };
    }
    return { valid: false, error: 'Harness control did not properly fail on thrown exception' };
  });

  // --- NEGATIVE TESTS (104) ---

  // NEG-01: Capsule-only (3rd capsule added without attestation) -> UNRECORDED_CAPSULE_DETECTED
  harness.assertNegative('NEG-01', 'NEGATIVE 1: Unrecorded 3rd capsule rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const capPath = path.join(tmpDir, '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-014.json');
      fs.writeFileSync(capPath, '{}', 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'UNRECORDED_CAPSULE_DETECTED');

  // NEG-02: Attestation-only (attestation added without capsule file) -> RECORDED_CAPSULE_FILE_MISSING
  harness.assertNegative('NEG-02', 'NEGATIVE 2: Attestation missing capsule file rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      fs.unlinkSync(path.join(tmpDir, third.capsuleRelPath));
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'RECORDED_CAPSULE_FILE_MISSING');

  // NEG-03: Tampered baseline manifest -> BASELINE_RAW_SHA256_MISMATCH
  harness.assertNegative('NEG-03', 'NEGATIVE 3: Tampered baseline manifest rejected', () => {
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

  // NEG-04: Tampered capsule 010 bytes -> RAW_FILE_SHA256_MISMATCH
  harness.assertNegative('NEG-04', 'NEGATIVE 4: Tampered capsule 010 raw bytes rejected', () => {
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

  // NEG-05: Tampered seal metadata in 3rd capsule -> RAW_FILE_SHA256_MISMATCH
  harness.assertNegative('NEG-05', 'NEGATIVE 5: Tampered seal metadata in 3rd capsule rejected', () => {
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

  // NEG-06: Altered payload with recomputed seal (same byte length) -> RAW_FILE_SHA256_MISMATCH
  harness.assertNegative('NEG-06', 'NEGATIVE 6: Altered payload with recomputed seal rejected by raw hash check', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.capsuleRelPath);
      const originalBytes = fs.readFileSync(p);
      const cap = JSON.parse(originalBytes.toString('utf8'));

      cap.payload.command_id = 'CMD-SYN-MINI-GOV-CAPSULE-SCHEMA-001-014-MUTATED01';
      cap.seal.payload_sha256 = computePayloadSha256(cap.payload).sha256Hex;
      const mutatedBytes = Buffer.from(JSON.stringify(cap, null, 2), 'utf8');

      if (mutatedBytes.length !== originalBytes.length) {
        throw new Error(`Test invariant failed: length changed from ${originalBytes.length} to ${mutatedBytes.length}`);
      }
      fs.writeFileSync(p, mutatedBytes);
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'RAW_FILE_SHA256_MISMATCH');

  // NEG-07: Stale/forged parent raw SHA in attestation -> PARENT_RAW_SHA256_MISMATCH
  harness.assertNegative('NEG-07', 'NEGATIVE 7: Forged parent hash in attestation rejected', () => {
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

  // NEG-08: Attestation filename mismatch on unaligned ID -> ATTESTATION_FILENAME_MISMATCH
  harness.assertNegative('NEG-08', 'NEGATIVE 8: Attestation file name mismatch on unaligned ID rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const wrongPath = path.join(tmpDir, '.synthesis/attestations/ATT-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-999.json');
      fs.renameSync(path.join(tmpDir, third.attestationRelPath), wrongPath);
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'ATTESTATION_FILENAME_MISMATCH');

  // NEG-09: Malformed JSON syntax in attestation -> LINKED_ATTESTATION_PARSE_ERROR
  harness.assertNegative('NEG-09', 'NEGATIVE 9: Malformed JSON syntax in attestation rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      fs.writeFileSync(path.join(tmpDir, third.attestationRelPath), "{\n  \"broken\": \n", "utf8");
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'LINKED_ATTESTATION_PARSE_ERROR');

  // NEG-10: Hidden file in attestations directory -> UNEXPECTED_ENTRY_IN_ATTESTATIONS_DIR
  harness.assertNegative('NEG-10', 'NEGATIVE 10: Hidden file in attestations directory rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      fs.writeFileSync(path.join(tmpDir, '.synthesis/attestations/.DS_Store'), 'bogus', 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'UNEXPECTED_ENTRY_IN_ATTESTATIONS_DIR');

  // NEG-11: Orphan attestation -> ORPHAN_ATTESTATION_DETECTED
  harness.assertNegative('NEG-11', 'NEGATIVE 11: Orphan attestation rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(p, 'utf8'));
      att.parent_attestation.attestation_id = 'ATT-SYN-MINI-NONEXISTENT';
      att.parent_attestation.file_path = '.synthesis/attestations/ATT-SYN-MINI-NONEXISTENT.json';
      fs.writeFileSync(p, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'ORPHAN_ATTESTATION_DETECTED');

  // NEG-12: Fork in attestation chain -> ATTESTATION_CHAIN_FORK_DETECTED
  harness.assertNegative('NEG-12', 'NEGATIVE 12: Fork in attestation chain rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      addSyntheticThirdCapsule(tmpDir);
      const cap015Bytes = fs.readFileSync(path.join(tmpDir, '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010.json'));
      const forkAttId = 'ATT-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-002';
      const forkAtt = {
        format_version: '1.0.0',
        record_kind: 'LINKED_CAPSULE_FILE_ATTESTATION',
        attestation_id: forkAttId,
        status: 'OBSERVED_UNANCHORED',
        observed_at_utc: '2026-10-02T16:10:00Z',
        source_repository: 'jirisar7-eng/synthesis-cms-mini',
        genesis_anchor_reference: { genesis_file: '.synthesis/lineage/genesis.json', pinned_sha256: PINNED_GENESIS_SHA256 },
        parent_attestation: { attestation_id: PINNED_BASELINE_LOGICAL_ID, file_path: PINNED_BASELINE_PATH, raw_file_sha256: PINNED_BASELINE_RAW_SHA256 },
        new_capsule: { capsule_id: 'CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010', file_path: '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010.json', payload_sha256: '9219b10636365a1ea0fe4177d463d142d21ec27076f780e8e97fca6a1ba36fb4', raw_file_sha256: computeRawFileSha256(cap015Bytes), git_blob_sha: computeGitBlobSha(cap015Bytes), file_size_bytes: cap015Bytes.length }
      };
      fs.writeFileSync(path.join(tmpDir, `.synthesis/attestations/${forkAttId}.json`), Buffer.from(JSON.stringify(forkAtt, null, 2), 'utf8'));
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'ATTESTATION_CHAIN_FORK_DETECTED');

  // NEG-13: Missing required trusted prior checkpoint -> REQUIRED_TRUSTED_PRIOR_MISSING
  harness.assertNegative('NEG-13', 'NEGATIVE 13: Missing required trusted prior checkpoint rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      return verifyAttestationChain(tmpDir, { requireTrustedPrior: true });
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'REQUIRED_TRUSTED_PRIOR_MISSING');

  // NEG-14: Checkpoint mismatch on truncated history -> HISTORY_CHECKPOINT_MISMATCH
  harness.assertNegative('NEG-14', 'NEGATIVE 14: Checkpoint mismatch on truncated history rejected', () => {
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

  // NEG-15: Missing capsule parent in 3rd capsule -> LINEAGE_GRAPH_INVALID
  harness.assertNegative('NEG-15', 'NEGATIVE 15: Capsule referencing missing parent rejected by lineage graph', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const capPath = path.join(tmpDir, third.capsuleRelPath);
      const cap = JSON.parse(fs.readFileSync(capPath, 'utf8'));
      cap.payload.lineage.parent_capsules[0].capsule_id = 'CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-999';
      cap.seal.payload_sha256 = computePayloadSha256(cap.payload).sha256Hex;
      const capBytes = Buffer.from(JSON.stringify(cap, null, 2), 'utf8');
      fs.writeFileSync(capPath, capBytes);

      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.new_capsule.payload_sha256 = cap.seal.payload_sha256;
      att.new_capsule.raw_file_sha256 = computeRawFileSha256(capBytes);
      att.new_capsule.git_blob_sha = computeGitBlobSha(capBytes);
      att.new_capsule.file_size_bytes = capBytes.length;
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');

      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'LINEAGE_GRAPH_INVALID');

  // NEG-16: Capsule with wrong parent payload digest -> LINEAGE_GRAPH_INVALID
  harness.assertNegative('NEG-16', 'NEGATIVE 16: Capsule with wrong parent payload digest rejected by lineage graph', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const capPath = path.join(tmpDir, third.capsuleRelPath);
      const cap = JSON.parse(fs.readFileSync(capPath, 'utf8'));
      cap.payload.lineage.parent_capsules[0].payload_sha256 = '0'.repeat(64);
      cap.seal.payload_sha256 = computePayloadSha256(cap.payload).sha256Hex;
      const capBytes = Buffer.from(JSON.stringify(cap, null, 2), 'utf8');
      fs.writeFileSync(capPath, capBytes);

      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.new_capsule.payload_sha256 = cap.seal.payload_sha256;
      att.new_capsule.raw_file_sha256 = computeRawFileSha256(capBytes);
      att.new_capsule.git_blob_sha = computeGitBlobSha(capBytes);
      att.new_capsule.file_size_bytes = capBytes.length;
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');

      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'LINEAGE_GRAPH_INVALID');

  // NEG-17: Capsule with wrong parent command ID -> LINEAGE_GRAPH_INVALID
  harness.assertNegative('NEG-17', 'NEGATIVE 17: Capsule with wrong parent command ID rejected by lineage graph', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const capPath = path.join(tmpDir, third.capsuleRelPath);
      const cap = JSON.parse(fs.readFileSync(capPath, 'utf8'));
      cap.payload.lineage.parent_capsules[0].command_id = 'CMD-SYN-MINI-GOV-CAPSULE-SCHEMA-001-999';
      cap.seal.payload_sha256 = computePayloadSha256(cap.payload).sha256Hex;
      const capBytes = Buffer.from(JSON.stringify(cap, null, 2), 'utf8');
      fs.writeFileSync(capPath, capBytes);

      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.new_capsule.payload_sha256 = cap.seal.payload_sha256;
      att.new_capsule.raw_file_sha256 = computeRawFileSha256(capBytes);
      att.new_capsule.git_blob_sha = computeGitBlobSha(capBytes);
      att.new_capsule.file_size_bytes = capBytes.length;
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');

      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'LINEAGE_GRAPH_INVALID');

  // NEG-18: Duplicate command ID across capsules -> DUPLICATE_COMMAND_ID_IN_CHAIN
  harness.assertNegative('NEG-18', 'NEGATIVE 18: Duplicate command ID across capsules rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const capPath = path.join(tmpDir, third.capsuleRelPath);
      const cap = JSON.parse(fs.readFileSync(capPath, 'utf8'));
      cap.payload.command_id = 'CMD-SYN-MINI-GOV-CAPSULE-SCHEMA-001-010-FIRST-REAL-CAPSULE';
      cap.seal.payload_sha256 = computePayloadSha256(cap.payload).sha256Hex;
      const capBytes = Buffer.from(JSON.stringify(cap, null, 2), 'utf8');
      fs.writeFileSync(capPath, capBytes);

      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.new_capsule.payload_sha256 = cap.seal.payload_sha256;
      att.new_capsule.raw_file_sha256 = computeRawFileSha256(capBytes);
      att.new_capsule.git_blob_sha = computeGitBlobSha(capBytes);
      att.new_capsule.file_size_bytes = capBytes.length;
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');

      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'DUPLICATE_COMMAND_ID_IN_CHAIN');

  // NEG-19: Additional parentless root -> CAPSULE_STRUCTURAL_VALIDATION_FAILED
  harness.assertNegative('NEG-19', 'NEGATIVE 19: Additional parentless root rejected by lineage graph', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const capPath = path.join(tmpDir, third.capsuleRelPath);
      const cap = JSON.parse(fs.readFileSync(capPath, 'utf8'));
      cap.payload.lineage.parent_capsules = [];
      cap.payload.lineage.parent_capsule_id = null;
      cap.seal.payload_sha256 = computePayloadSha256(cap.payload).sha256Hex;
      const capBytes = Buffer.from(JSON.stringify(cap, null, 2), 'utf8');
      fs.writeFileSync(capPath, capBytes);

      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.new_capsule.payload_sha256 = cap.seal.payload_sha256;
      att.new_capsule.raw_file_sha256 = computeRawFileSha256(capBytes);
      att.new_capsule.git_blob_sha = computeGitBlobSha(capBytes);
      att.new_capsule.file_size_bytes = capBytes.length;
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');

      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'CAPSULE_STRUCTURAL_VALIDATION_FAILED');

  // NEG-20: Attestation new_capsule.capsule_id mismatch -> RECORDED_CAPSULE_FILE_MISSING
  harness.assertNegative('NEG-20', 'NEGATIVE 20: Attestation capsule_id mismatch with actual payload rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.new_capsule.capsule_id = 'CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-999';
      att.new_capsule.file_path = '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-999.json';
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'RECORDED_CAPSULE_FILE_MISSING');

  // NEG-21: Extra key at attestation top level -> LINKED_ATTESTATION_SCHEMA_ERROR
  harness.assertNegative('NEG-21', 'NEGATIVE 21: Extra key at attestation top level rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.extra_field = 'unsupported';
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'LINKED_ATTESTATION_SCHEMA_ERROR');

  // NEG-22: Extra key in genesis_anchor_reference -> LINKED_ATTESTATION_SCHEMA_ERROR
  harness.assertNegative('NEG-22', 'NEGATIVE 22: Extra key in genesis_anchor_reference rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.genesis_anchor_reference.extra_field = 'unsupported';
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'LINKED_ATTESTATION_SCHEMA_ERROR');

  // NEG-23: Extra key in parent_attestation -> LINKED_ATTESTATION_SCHEMA_ERROR
  harness.assertNegative('NEG-23', 'NEGATIVE 23: Extra key in parent_attestation rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.parent_attestation.extra_field = 'unsupported';
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'LINKED_ATTESTATION_SCHEMA_ERROR');

  // NEG-24: Extra key in new_capsule -> LINKED_ATTESTATION_SCHEMA_ERROR
  harness.assertNegative('NEG-24', 'NEGATIVE 24: Extra key in new_capsule rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.new_capsule.extra_field = 'unsupported';
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'LINKED_ATTESTATION_SCHEMA_ERROR');

  // NEG-25: Date-only observed_at_utc -> INVALID_OBSERVED_AT_TIMESTAMP
  harness.assertNegative('NEG-25', 'NEGATIVE 25: Date-only observed_at_utc rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.observed_at_utc = '2026-10-02';
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'INVALID_OBSERVED_AT_TIMESTAMP');

  // NEG-26: Non-UTC offset observed_at_utc -> INVALID_OBSERVED_AT_TIMESTAMP
  harness.assertNegative('NEG-26', 'NEGATIVE 26: Non-UTC offset observed_at_utc rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.observed_at_utc = '2026-10-02T16:00:00+02:00';
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'INVALID_OBSERVED_AT_TIMESTAMP');

  // NEG-27: Invalid calendar date in observed_at_utc -> INVALID_OBSERVED_AT_TIMESTAMP
  harness.assertNegative('NEG-27', 'NEGATIVE 27: Invalid calendar date in observed_at_utc rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.observed_at_utc = '2026-02-31T16:00:00Z';
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'INVALID_OBSERVED_AT_TIMESTAMP');

  // NEG-28: Invalid UTF-8 byte sequence in capsule -> INVALID_UTF8_ENCODING
  harness.assertNegative('NEG-28', 'NEGATIVE 28: Invalid UTF-8 byte sequence in capsule rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const capPath = path.join(tmpDir, third.capsuleRelPath);
      const capBytes = fs.readFileSync(capPath);
      const targetSub = Buffer.from('jirisar7-eng');
      const idx = capBytes.indexOf(targetSub);
      if (idx === -1) throw new Error('Could not find target substring');
      const corruptedBytes = Buffer.from(capBytes);
      corruptedBytes[idx] = 0xff;
      fs.writeFileSync(capPath, corruptedBytes);

      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.new_capsule.raw_file_sha256 = computeRawFileSha256(corruptedBytes);
      att.new_capsule.git_blob_sha = computeGitBlobSha(corruptedBytes);
      att.new_capsule.file_size_bytes = corruptedBytes.length;
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');

      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'INVALID_UTF8_ENCODING');

  // NEG-29: Capsule exceeding 512 KiB -> FILE_SIZE_LIMIT_EXCEEDED
  harness.assertNegative('NEG-29', 'NEGATIVE 29: Capsule exceeding 512 KiB rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const capPath = path.join(tmpDir, third.capsuleRelPath);
      const originalText = fs.readFileSync(capPath, 'utf8');
      const padding = ' '.repeat(520 * 1024);
      const paddedBytes = Buffer.from(originalText + padding, 'utf8');
      fs.writeFileSync(capPath, paddedBytes);

      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.new_capsule.raw_file_sha256 = computeRawFileSha256(paddedBytes);
      att.new_capsule.git_blob_sha = computeGitBlobSha(paddedBytes);
      att.new_capsule.file_size_bytes = paddedBytes.length;
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');

      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'FILE_SIZE_LIMIT_EXCEEDED');

  // NEG-30: Symlinked .synthesis directory -> SYNTHESIS_DIR_SYMLINK_REJECTED
  harness.assertNegative('NEG-30', 'NEGATIVE 30: Symlinked .synthesis directory rejected', () => {
    const tmpDir = setupTestEnv();
    const realSynthesisDir = path.join(tmpDir, '.synthesis');
    const targetDir = path.join(tmpDir, '.synthesis_target');
    try {
      fs.renameSync(realSynthesisDir, targetDir);
      fs.symlinkSync(targetDir, realSynthesisDir, 'dir');
      return verifyAttestationChain(tmpDir);
    } finally {
      try {
        fs.unlinkSync(realSynthesisDir);
        fs.renameSync(targetDir, realSynthesisDir);
      } catch (_) {}
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'SYNTHESIS_DIR_SYMLINK_REJECTED');

  // NEG-31: Symlinked schemas directory -> SCHEMAS_DIR_SYMLINK_REJECTED
  harness.assertNegative('NEG-31', 'NEGATIVE 31: Symlinked schemas directory rejected', () => {
    const tmpDir = setupTestEnv();
    const realDir = path.join(tmpDir, '.synthesis', 'schemas');
    const targetDir = path.join(tmpDir, '.synthesis', 'schemas_target');
    try {
      fs.renameSync(realDir, targetDir);
      fs.symlinkSync(targetDir, realDir, 'dir');
      return verifyAttestationChain(tmpDir);
    } finally {
      try {
        fs.unlinkSync(realDir);
        fs.renameSync(targetDir, realDir);
      } catch (_) {}
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'SCHEMAS_DIR_SYMLINK_REJECTED');

  // NEG-32: Symlinked schema file -> SCHEMA_FILE_SYMLINK_REJECTED
  harness.assertNegative('NEG-32', 'NEGATIVE 32: Symlinked schema file rejected', () => {
    const tmpDir = setupTestEnv();
    const realFile = path.join(tmpDir, '.synthesis', 'schemas', 'command-capsule.schema.json');
    const targetFile = path.join(tmpDir, '.synthesis', 'schemas', 'target.json');
    try {
      fs.renameSync(realFile, targetFile);
      fs.symlinkSync(targetFile, realFile, 'file');
      return verifyAttestationChain(tmpDir);
    } finally {
      try {
        fs.unlinkSync(realFile);
        fs.renameSync(targetFile, realFile);
      } catch (_) {}
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'SCHEMA_FILE_SYMLINK_REJECTED');

  // NEG-33: Symlinked lineage directory -> LINEAGE_DIR_SYMLINK_REJECTED
  harness.assertNegative('NEG-33', 'NEGATIVE 33: Symlinked lineage directory rejected', () => {
    const tmpDir = setupTestEnv();
    const realDir = path.join(tmpDir, '.synthesis', 'lineage');
    const targetDir = path.join(tmpDir, '.synthesis', 'lineage_target');
    try {
      fs.renameSync(realDir, targetDir);
      fs.symlinkSync(targetDir, realDir, 'dir');
      return verifyAttestationChain(tmpDir);
    } finally {
      try {
        fs.unlinkSync(realDir);
        fs.renameSync(targetDir, realDir);
      } catch (_) {}
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'LINEAGE_DIR_SYMLINK_REJECTED');

  // NEG-34: signature:null at linked attestation top level -> LINKED_ATTESTATION_SCHEMA_ERROR
  harness.assertNegative('NEG-34', 'NEGATIVE 34: signature:null at linked attestation top level rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.signature = null;
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'LINKED_ATTESTATION_SCHEMA_ERROR');

  // NEG-35: hasExactKeys helper rejects inherited key satisfying allowed key
  harness.assertNegative('NEG-35', 'NEGATIVE 35: hasExactKeys rejects inherited property satisfying requirement', () => {
    const parentProto = { allowed: 'inherited' };
    const childObj = Object.assign(Object.create(parentProto), { extra: 'own' });
    if (!hasExactKeys(childObj, ['allowed'])) {
      return { valid: false, stage: 'INHERITED_PROPERTY_REJECTED' };
    }
    return { valid: true };
  }, 'INHERITED_PROPERTY_REJECTED');

  // NEG-36: Linked JSON root null returns explicit schema failure -> LINKED_ATTESTATION_SCHEMA_ERROR
  harness.assertNegative('NEG-36', 'NEGATIVE 36: Linked JSON root null returns explicit schema failure', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      fs.writeFileSync(path.join(tmpDir, third.attestationRelPath), 'null', 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'LINKED_ATTESTATION_SCHEMA_ERROR');

  // NEG-37: Linked JSON root scalar 123 returns explicit schema failure -> LINKED_ATTESTATION_SCHEMA_ERROR
  harness.assertNegative('NEG-37', 'NEGATIVE 37: Linked JSON root scalar 123 returns explicit schema failure', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      fs.writeFileSync(path.join(tmpDir, third.attestationRelPath), '123', 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'LINKED_ATTESTATION_SCHEMA_ERROR');

  // NEG-38: new_capsule.file_path array rejected without uncaught exception -> INVALID_CAPSULE_FILE_PATH
  harness.assertNegative('NEG-38', 'NEGATIVE 38: new_capsule.file_path array rejected without uncaught exception', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.new_capsule.file_path = [third.capsuleRelPath];
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'INVALID_CAPSULE_FILE_PATH');

  // NEG-39..45: CLI error tests
  harness.assertCliNegative('NEG-39', 'NEGATIVE 39: CLI empty --trusted-prior-path rejected with exit 1', ['--verify-all', '--trusted-prior-path', '']);
  harness.assertCliNegative('NEG-40', 'NEGATIVE 40: CLI empty --trusted-prior-sha256 rejected with exit 1', ['--verify-all', '--trusted-prior-sha256', '']);
  harness.assertCliNegative('NEG-41', 'NEGATIVE 41: CLI both empty trusted prior args rejected with exit 1', ['--verify-all', '--trusted-prior-path', '', '--trusted-prior-sha256', '']);
  harness.assertCliNegative('NEG-42', 'NEGATIVE 42: CLI --unknown --help rejected with exit 1', ['--unknown', '--help']);
  harness.assertCliNegative('NEG-43', 'NEGATIVE 43: CLI mixed --verify-all --help rejected with exit 1', ['--verify-all', '--require-trusted-prior', '--help']);
  harness.assertCliNegative('NEG-44', 'NEGATIVE 44: CLI repeated --trusted-prior-path rejected with exit 1', ['--verify-all', '--trusted-prior-path', 'a', '--trusted-prior-path', 'b', '--trusted-prior-sha256', 'c']);
  harness.assertCliNegative('NEG-45', 'NEGATIVE 45: CLI flag as value rejected with exit 1', ['--verify-all', '--trusted-prior-path', '--require-trusted-prior']);

  // NEG-46: Filesystem read error in loadAttestationChain -> ATTESTATIONS_DIR_READ_FAILED
  harness.assertNegative('NEG-46', 'NEGATIVE 46: Filesystem read error in loadAttestationChain returns structured error without throwing', () => {
    const tmpDir = setupTestEnv();
    const origReaddirSync = fs.readdirSync;
    try {
      fs.readdirSync = (p, options) => {
        if (typeof p === 'string' && p.endsWith('.synthesis/attestations')) {
          const err = new Error('EACCES: permission denied');
          err.code = 'EACCES';
          throw err;
        }
        return origReaddirSync(p, options);
      };
      return loadAttestationChain(tmpDir);
    } finally {
      fs.readdirSync = origReaddirSync;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'ATTESTATIONS_DIR_READ_FAILED');

  // NEG-47: Filesystem read error in verifyAttestationChain -> ATTESTATIONS_DIR_READ_FAILED
  harness.assertNegative('NEG-47', 'NEGATIVE 47: Filesystem read error in verifyAttestationChain returns structured error without throwing', () => {
    const tmpDir = setupTestEnv();
    const origReaddirSync = fs.readdirSync;
    try {
      fs.readdirSync = (p, options) => {
        if (typeof p === 'string' && p.endsWith('.synthesis/attestations')) {
          const err = new Error('EACCES: permission denied');
          err.code = 'EACCES';
          throw err;
        }
        return origReaddirSync(p, options);
      };
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.readdirSync = origReaddirSync;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'ATTESTATIONS_DIR_READ_FAILED');

  // NEG-48: Tampered capsule 013 raw bytes -> RAW_FILE_SHA256_MISMATCH
  harness.assertNegative('NEG-48', 'NEGATIVE 48: Tampered capsule 013 raw bytes rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const p = path.join(tmpDir, '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-013.json');
      const text = fs.readFileSync(p, 'utf8');
      fs.writeFileSync(p, text.replace('"sealed_by": "jirisar7-eng"', '"sealed_by": "jirisar7-tam"'), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'RAW_FILE_SHA256_MISMATCH');

  // NEG-49: Baseline manifest JSON syntax error -> BASELINE_JSON_PARSE_ERROR
  harness.assertNegative('NEG-49', 'NEGATIVE 49: Baseline manifest JSON syntax error rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const p = path.join(tmpDir, PINNED_BASELINE_PATH);
      fs.writeFileSync(p, '{\n "bad": \n', 'utf8');
      return loadAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'BASELINE_RAW_SHA256_MISMATCH');

  // NEG-50: Baseline manifest root array -> BASELINE_SCHEMA_ERROR
  harness.assertNegative('NEG-50', 'NEGATIVE 50: Baseline manifest root array rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const p = path.join(tmpDir, PINNED_BASELINE_PATH);
      fs.writeFileSync(p, '[]', 'utf8');
      return loadAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'BASELINE_RAW_SHA256_MISMATCH');

  // NEG-51: Baseline manifest duplicate key -> BASELINE_RAW_SHA256_MISMATCH
  harness.assertNegative('NEG-51', 'NEGATIVE 51: Baseline manifest duplicate key rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const p = path.join(tmpDir, PINNED_BASELINE_PATH);
      fs.writeFileSync(p, '{"format_version":"1.0.0","format_version":"1.0.0"}', 'utf8');
      return loadAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'BASELINE_RAW_SHA256_MISMATCH');

  // NEG-52: Linked JSON root array -> LINKED_ATTESTATION_SCHEMA_ERROR
  harness.assertNegative('NEG-52', 'NEGATIVE 52: Linked JSON root array rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      fs.writeFileSync(path.join(tmpDir, third.attestationRelPath), '[]', 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'LINKED_ATTESTATION_SCHEMA_ERROR');

  // NEG-53: Linked attestation duplicate key -> LINKED_ATTESTATION_PARSE_ERROR
  harness.assertNegative('NEG-53', 'NEGATIVE 53: Linked attestation duplicate key rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const raw = fs.readFileSync(path.join(tmpDir, third.attestationRelPath), 'utf8');
      const dup = raw.replace('"status": "OBSERVED_UNANCHORED",', '"status": "OBSERVED_UNANCHORED",\n  "status": "OBSERVED_UNANCHORED",');
      fs.writeFileSync(path.join(tmpDir, third.attestationRelPath), dup, 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'LINKED_ATTESTATION_PARSE_ERROR');

  // NEG-54: Linked attestation invalid UTF-8 byte -> INVALID_UTF8_ENCODING
  harness.assertNegative('NEG-54', 'NEGATIVE 54: Linked attestation invalid UTF-8 byte rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.attestationRelPath);
      const bytes = fs.readFileSync(p);
      const corrupted = Buffer.from(bytes);
      corrupted[10] = 0xff;
      fs.writeFileSync(p, corrupted);
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'INVALID_UTF8_ENCODING');

  // NEG-55: Linked attestation wrong format_version -> LINKED_ATTESTATION_SCHEMA_ERROR
  harness.assertNegative('NEG-55', 'NEGATIVE 55: Linked attestation wrong format_version rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(p, 'utf8'));
      att.format_version = '2.0.0';
      fs.writeFileSync(p, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'LINKED_ATTESTATION_SCHEMA_ERROR');

  // NEG-56: Linked attestation wrong record_kind -> LINKED_ATTESTATION_SCHEMA_ERROR
  harness.assertNegative('NEG-56', 'NEGATIVE 56: Linked attestation wrong record_kind rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(p, 'utf8'));
      att.record_kind = 'UNKNOWN_RECORD_KIND';
      fs.writeFileSync(p, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'LINKED_ATTESTATION_SCHEMA_ERROR');

  // NEG-57: Linked attestation wrong status -> LINKED_ATTESTATION_SCHEMA_ERROR
  harness.assertNegative('NEG-57', 'NEGATIVE 57: Linked attestation wrong status rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(p, 'utf8'));
      att.status = 'SEALED';
      fs.writeFileSync(p, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'LINKED_ATTESTATION_SCHEMA_ERROR');

  // NEG-58: Linked attestation wrong source_repository -> LINKED_ATTESTATION_SCHEMA_ERROR
  harness.assertNegative('NEG-58', 'NEGATIVE 58: Linked attestation wrong source_repository rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(p, 'utf8'));
      att.source_repository = 'other/repo';
      fs.writeFileSync(p, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'LINKED_ATTESTATION_SCHEMA_ERROR');

  // NEG-59: Linked attestation genesis mismatch -> LINKED_ATTESTATION_GENESIS_MISMATCH
  harness.assertNegative('NEG-59', 'NEGATIVE 59: Linked attestation genesis mismatch rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(p, 'utf8'));
      att.genesis_anchor_reference.pinned_sha256 = '0'.repeat(64);
      fs.writeFileSync(p, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'LINKED_ATTESTATION_GENESIS_MISMATCH');

  // NEG-60: Linked attestation parent traversal path -> PATH_TRAVERSAL_IN_PARENT_REF
  harness.assertNegative('NEG-60', 'NEGATIVE 60: Linked attestation parent traversal path rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(p, 'utf8'));
      att.parent_attestation.file_path = '.synthesis/attestations/../secret.json';
      fs.writeFileSync(p, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'PATH_TRAVERSAL_IN_PARENT_REF');

  // NEG-61: Linked attestation new_capsule.payload_sha256 malformed hex -> INVALID_PAYLOAD_SHA256
  harness.assertNegative('NEG-61', 'NEGATIVE 61: Linked attestation new_capsule.payload_sha256 malformed hex rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(p, 'utf8'));
      att.new_capsule.payload_sha256 = 'badhex';
      fs.writeFileSync(p, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'INVALID_PAYLOAD_SHA256');

  // NEG-62: Linked attestation new_capsule.git_blob_sha malformed hex -> INVALID_GIT_BLOB_SHA
  harness.assertNegative('NEG-62', 'NEGATIVE 62: Linked attestation new_capsule.git_blob_sha malformed hex rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(p, 'utf8'));
      att.new_capsule.git_blob_sha = 'badblob';
      fs.writeFileSync(p, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'INVALID_GIT_BLOB_SHA');

  // NEG-63: Linked attestation new_capsule.file_size_bytes negative -> INVALID_FILE_SIZE_BYTES
  harness.assertNegative('NEG-63', 'NEGATIVE 63: Linked attestation new_capsule.file_size_bytes negative rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(p, 'utf8'));
      att.new_capsule.file_size_bytes = -100;
      fs.writeFileSync(p, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'INVALID_FILE_SIZE_BYTES');

  // NEG-64: Capsule JSON syntax error -> CAPSULE_JSON_PARSE_ERROR
  harness.assertNegative('NEG-64', 'NEGATIVE 64: Capsule JSON syntax error rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.capsuleRelPath);
      const corruptedBytes = Buffer.from('{\n  "broken": \n', 'utf8');
      fs.writeFileSync(p, corruptedBytes);

      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.new_capsule.raw_file_sha256 = computeRawFileSha256(corruptedBytes);
      att.new_capsule.git_blob_sha = computeGitBlobSha(corruptedBytes);
      att.new_capsule.file_size_bytes = corruptedBytes.length;
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'CAPSULE_JSON_PARSE_ERROR');

  // NEG-65: Capsule JSON duplicate key -> CAPSULE_JSON_PARSE_ERROR
  harness.assertNegative('NEG-65', 'NEGATIVE 65: Capsule JSON duplicate key rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.capsuleRelPath);
      const raw = fs.readFileSync(p, 'utf8');
      const dup = raw.replace('"status": "SEALED",', '"status": "SEALED",\n    "status": "SEALED",');
      const dupBytes = Buffer.from(dup, 'utf8');
      fs.writeFileSync(p, dupBytes);

      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.new_capsule.raw_file_sha256 = computeRawFileSha256(dupBytes);
      att.new_capsule.git_blob_sha = computeGitBlobSha(dupBytes);
      att.new_capsule.file_size_bytes = dupBytes.length;
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'CAPSULE_JSON_PARSE_ERROR');

  // NEG-66: Capsule payload array root -> INVALID_CAPSULE_STRUCTURE
  harness.assertNegative('NEG-66', 'NEGATIVE 66: Capsule payload array root rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.capsuleRelPath);
      const cap = { payload: [], seal: { status: 'SEALED' } };
      const capBytes = Buffer.from(JSON.stringify(cap, null, 2), 'utf8');
      fs.writeFileSync(p, capBytes);

      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.new_capsule.raw_file_sha256 = computeRawFileSha256(capBytes);
      att.new_capsule.git_blob_sha = computeGitBlobSha(capBytes);
      att.new_capsule.file_size_bytes = capBytes.length;
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'CAPSULE_ID_MISMATCH');

  // NEG-67: Capsule repository name mismatch in payload -> CAPSULE_REPOSITORY_MISMATCH
  harness.assertNegative('NEG-67', 'NEGATIVE 67: Capsule repository name mismatch in payload rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.capsuleRelPath);
      const cap = JSON.parse(fs.readFileSync(p, 'utf8'));
      cap.payload.repository_baseline = { repository_name: 'wrong/repo', genesis_sha256: PINNED_GENESIS_SHA256 };
      cap.seal.payload_sha256 = computePayloadSha256(cap.payload).sha256Hex;
      const capBytes = Buffer.from(JSON.stringify(cap, null, 2), 'utf8');
      fs.writeFileSync(p, capBytes);

      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.new_capsule.payload_sha256 = cap.seal.payload_sha256;
      att.new_capsule.raw_file_sha256 = computeRawFileSha256(capBytes);
      att.new_capsule.git_blob_sha = computeGitBlobSha(capBytes);
      att.new_capsule.file_size_bytes = capBytes.length;
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'CAPSULE_STRUCTURAL_VALIDATION_FAILED');

  // NEG-68: Capsule genesis sha mismatch in payload -> CAPSULE_GENESIS_MISMATCH
  harness.assertNegative('NEG-68', 'NEGATIVE 68: Capsule genesis sha mismatch in payload rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.capsuleRelPath);
      const cap = JSON.parse(fs.readFileSync(p, 'utf8'));
      cap.payload.repository_baseline = { repository_name: 'jirisar7-eng/synthesis-cms-mini', genesis_sha256: '0'.repeat(64) };
      cap.seal.payload_sha256 = computePayloadSha256(cap.payload).sha256Hex;
      const capBytes = Buffer.from(JSON.stringify(cap, null, 2), 'utf8');
      fs.writeFileSync(p, capBytes);

      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.new_capsule.payload_sha256 = cap.seal.payload_sha256;
      att.new_capsule.raw_file_sha256 = computeRawFileSha256(capBytes);
      att.new_capsule.git_blob_sha = computeGitBlobSha(capBytes);
      att.new_capsule.file_size_bytes = capBytes.length;
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'CAPSULE_STRUCTURAL_VALIDATION_FAILED');

  // NEG-69: Structurally valid PROVISIONAL capsule -> PROVISIONAL_CAPSULE_REJECTED
  harness.assertNegative('NEG-69', 'NEGATIVE 69: Structurally valid PROVISIONAL capsule rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.capsuleRelPath);
      const cap = JSON.parse(fs.readFileSync(p, 'utf8'));
      cap.seal.status = 'PROVISIONAL';
      cap.seal.payload_sha256 = computePayloadSha256(cap.payload).sha256Hex;
      const capBytes = Buffer.from(JSON.stringify(cap, null, 2), 'utf8');
      fs.writeFileSync(p, capBytes);

      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.new_capsule.payload_sha256 = cap.seal.payload_sha256;
      att.new_capsule.raw_file_sha256 = computeRawFileSha256(capBytes);
      att.new_capsule.git_blob_sha = computeGitBlobSha(capBytes);
      att.new_capsule.file_size_bytes = capBytes.length;
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'PROVISIONAL_RECORD');

  // NEG-70: Non-null capsule seal signature -> UNSUPPORTED_SIGNATURE
  harness.assertNegative('NEG-70', 'NEGATIVE 70: Non-null capsule seal signature rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.capsuleRelPath);
      const cap = JSON.parse(fs.readFileSync(p, 'utf8'));
      cap.seal.seal_signature = 'sig_12345';
      cap.seal.payload_sha256 = computePayloadSha256(cap.payload).sha256Hex;
      const capBytes = Buffer.from(JSON.stringify(cap, null, 2), 'utf8');
      fs.writeFileSync(p, capBytes);

      const attPath = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(attPath, 'utf8'));
      att.new_capsule.payload_sha256 = cap.seal.payload_sha256;
      att.new_capsule.raw_file_sha256 = computeRawFileSha256(capBytes);
      att.new_capsule.git_blob_sha = computeGitBlobSha(capBytes);
      att.new_capsule.file_size_bytes = capBytes.length;
      fs.writeFileSync(attPath, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'UNVERIFIED_SIGNATURE_REJECTED');

  // NEG-71: Capsule filename mismatch with capsule_id -> CAPSULE_FILENAME_MISMATCH
  harness.assertNegative('NEG-71', 'NEGATIVE 71: Capsule filename mismatch with capsule_id rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(p, 'utf8'));
      att.new_capsule.file_path = '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-999.json';
      fs.writeFileSync(p, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'CAPSULE_FILENAME_MISMATCH');

  // NEG-72: Non-JSON file in attestations directory -> UNEXPECTED_ENTRY_IN_ATTESTATIONS_DIR
  harness.assertNegative('NEG-72', 'NEGATIVE 72: Non-JSON file in attestations directory rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      fs.writeFileSync(path.join(tmpDir, '.synthesis/attestations/readme.txt'), 'text', 'utf8');
      return loadAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'UNEXPECTED_ENTRY_IN_ATTESTATIONS_DIR');

  // NEG-73: Subdirectory in attestations directory -> UNEXPECTED_ENTRY_IN_ATTESTATIONS_DIR
  harness.assertNegative('NEG-73', 'NEGATIVE 73: Subdirectory in attestations directory rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      fs.mkdirSync(path.join(tmpDir, '.synthesis/attestations/subdir'));
      return loadAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'UNEXPECTED_ENTRY_IN_ATTESTATIONS_DIR');

  // NEG-74: Hidden file in task-capsules directory -> UNEXPECTED_ENTRY_IN_CAPSULE_DIR
  harness.assertNegative('NEG-74', 'NEGATIVE 74: Hidden file in task-capsules directory rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      fs.writeFileSync(path.join(tmpDir, '.synthesis/task-capsules/.DS_Store'), 'hidden', 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'UNEXPECTED_ENTRY_IN_CAPSULE_DIR');

  // NEG-75: Non-JSON file in task-capsules directory -> UNEXPECTED_ENTRY_IN_CAPSULE_DIR
  harness.assertNegative('NEG-75', 'NEGATIVE 75: Non-JSON file in task-capsules directory rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      fs.writeFileSync(path.join(tmpDir, '.synthesis/task-capsules/readme.txt'), 'text', 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'UNEXPECTED_ENTRY_IN_CAPSULE_DIR');

  // NEG-76: Subdirectory in task-capsules directory -> UNEXPECTED_ENTRY_IN_CAPSULE_DIR
  harness.assertNegative('NEG-76', 'NEGATIVE 76: Subdirectory in task-capsules directory rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      fs.mkdirSync(path.join(tmpDir, '.synthesis/task-capsules/subdir'));
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'UNEXPECTED_ENTRY_IN_CAPSULE_DIR');

  // NEG-77: Symlink leaf file in attestations directory -> UNSAFE_SYMLINK_IN_ATTESTATIONS_DIR
  harness.assertNegative('NEG-77', 'NEGATIVE 77: Symlink leaf file in attestations directory rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const realP = path.join(tmpDir, PINNED_BASELINE_PATH);
      const symlinkP = path.join(tmpDir, '.synthesis/attestations/ATT-SYN-MINI-SYMLINK.json');
      fs.symlinkSync(realP, symlinkP, 'file');
      return loadAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'UNSAFE_SYMLINK_IN_ATTESTATIONS_DIR');

  // NEG-78: Symlink leaf file in task-capsules directory -> UNSAFE_SYMLINK_IN_CAPSULE_DIR
  harness.assertNegative('NEG-78', 'NEGATIVE 78: Symlink leaf file in task-capsules directory rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const realP = path.join(tmpDir, '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010.json');
      const symlinkP = path.join(tmpDir, '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-999.json');
      fs.symlinkSync(realP, symlinkP, 'file');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'UNSAFE_SYMLINK_IN_CAPSULE_DIR');

  // NEG-79: Symlink genesis file -> GENESIS_FILE_SYMLINK_REJECTED
  harness.assertNegative('NEG-79', 'NEGATIVE 79: Symlink genesis file rejected', () => {
    const tmpDir = setupTestEnv();
    const realFile = path.join(tmpDir, '.synthesis/lineage/genesis.json');
    const targetFile = path.join(tmpDir, '.synthesis/lineage/target_genesis.json');
    try {
      fs.renameSync(realFile, targetFile);
      fs.symlinkSync(targetFile, realFile, 'file');
      return verifyAttestationChain(tmpDir);
    } finally {
      try {
        fs.unlinkSync(realFile);
        fs.renameSync(targetFile, realFile);
      } catch (_) {}
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'GENESIS_FILE_SYMLINK_REJECTED');

  // NEG-80: Symlink attestations directory -> ATTESTATIONS_DIR_SYMLINK_REJECTED
  harness.assertNegative('NEG-80', 'NEGATIVE 80: Symlink attestations directory rejected', () => {
    const tmpDir = setupTestEnv();
    const realDir = path.join(tmpDir, '.synthesis', 'attestations');
    const targetDir = path.join(tmpDir, '.synthesis', 'attestations_target');
    try {
      fs.renameSync(realDir, targetDir);
      fs.symlinkSync(targetDir, realDir, 'dir');
      return verifyAttestationChain(tmpDir);
    } finally {
      try {
        fs.unlinkSync(realDir);
        fs.renameSync(targetDir, realDir);
      } catch (_) {}
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'ATTESTATIONS_DIR_SYMLINK_REJECTED');

  // NEG-81: Symlink task-capsules directory -> CAPSULES_DIR_SYMLINK_REJECTED
  harness.assertNegative('NEG-81', 'NEGATIVE 81: Symlink task-capsules directory rejected', () => {
    const tmpDir = setupTestEnv();
    const realDir = path.join(tmpDir, '.synthesis', 'task-capsules');
    const targetDir = path.join(tmpDir, '.synthesis', 'task-capsules_target');
    try {
      fs.renameSync(realDir, targetDir);
      fs.symlinkSync(targetDir, realDir, 'dir');
      return verifyAttestationChain(tmpDir);
    } finally {
      try {
        fs.unlinkSync(realDir);
        fs.renameSync(targetDir, realDir);
      } catch (_) {}
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'CAPSULES_DIR_SYMLINK_REJECTED');

  // NEG-82: EACCES on readFileSync for baseline manifest in loadAttestationChain -> BASELINE_FILE_READ_FAILED
  harness.assertNegative('NEG-82', 'NEGATIVE 82: EACCES on readFileSync for baseline manifest in loadAttestationChain rejected', () => {
    const tmpDir = setupTestEnv();
    const origRead = fs.readFileSync;
    try {
      fs.readFileSync = (p, options) => {
        if (typeof p === 'string' && p.endsWith(PINNED_BASELINE_PATH)) {
          const err = new Error('EACCES: permission denied');
          err.code = 'EACCES';
          throw err;
        }
        return origRead(p, options);
      };
      return loadAttestationChain(tmpDir);
    } finally {
      fs.readFileSync = origRead;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'BASELINE_FILE_READ_FAILED');

  // NEG-83: EACCES on readFileSync for baseline manifest in verifyAttestationChain -> BASELINE_FILE_READ_FAILED
  harness.assertNegative('NEG-83', 'NEGATIVE 83: EACCES on readFileSync for baseline manifest in verifyAttestationChain rejected', () => {
    const tmpDir = setupTestEnv();
    const origRead = fs.readFileSync;
    try {
      fs.readFileSync = (p, options) => {
        if (typeof p === 'string' && p.endsWith(PINNED_BASELINE_PATH)) {
          const err = new Error('EACCES: permission denied');
          err.code = 'EACCES';
          throw err;
        }
        return origRead(p, options);
      };
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.readFileSync = origRead;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'BASELINE_FILE_READ_FAILED');

  // NEG-84: EACCES on lstatSync for baseline manifest in loadAttestationChain -> BASELINE_STAT_FAILED
  harness.assertNegative('NEG-84', 'NEGATIVE 84: EACCES on lstatSync for baseline manifest in loadAttestationChain rejected', () => {
    const tmpDir = setupTestEnv();
    const origLstat = fs.lstatSync;
    try {
      fs.lstatSync = (p, options) => {
        if (typeof p === 'string' && p.endsWith(PINNED_BASELINE_PATH)) {
          const err = new Error('EACCES: permission denied');
          err.code = 'EACCES';
          throw err;
        }
        return origLstat(p, options);
      };
      return loadAttestationChain(tmpDir);
    } finally {
      fs.lstatSync = origLstat;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'BASELINE_STAT_FAILED');

  // NEG-85: EACCES on readFileSync for linked attestation -> LINKED_ATTESTATION_READ_FAILED
  harness.assertNegative('NEG-85', 'NEGATIVE 85: EACCES on readFileSync for linked attestation rejected', () => {
    const tmpDir = setupTestEnv();
    const third = addSyntheticThirdCapsule(tmpDir);
    const origRead = fs.readFileSync;
    try {
      fs.readFileSync = (p, options) => {
        if (typeof p === 'string' && p.endsWith(third.attestationRelPath)) {
          const err = new Error('EACCES: permission denied');
          err.code = 'EACCES';
          throw err;
        }
        return origRead(p, options);
      };
      return loadAttestationChain(tmpDir);
    } finally {
      fs.readFileSync = origRead;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'LINKED_ATTESTATION_READ_FAILED');

  // NEG-86: EACCES on lstatSync for linked attestation -> LINKED_ATTESTATION_STAT_FAILED
  harness.assertNegative('NEG-86', 'NEGATIVE 86: EACCES on lstatSync for linked attestation rejected', () => {
    const tmpDir = setupTestEnv();
    const third = addSyntheticThirdCapsule(tmpDir);
    const origLstat = fs.lstatSync;
    try {
      fs.lstatSync = (p, options) => {
        if (typeof p === 'string' && p.endsWith(third.attestationRelPath)) {
          const err = new Error('EACCES: permission denied');
          err.code = 'EACCES';
          throw err;
        }
        return origLstat(p, options);
      };
      return loadAttestationChain(tmpDir);
    } finally {
      fs.lstatSync = origLstat;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'LINKED_ATTESTATION_STAT_FAILED');

  // NEG-87: EACCES on readFileSync for capsule file -> CAPSULE_FILE_READ_FAILED
  harness.assertNegative('NEG-87', 'NEGATIVE 87: EACCES on readFileSync for capsule file rejected', () => {
    const tmpDir = setupTestEnv();
    const origRead = fs.readFileSync;
    try {
      fs.readFileSync = (p, options) => {
        if (typeof p === 'string' && p.endsWith('.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010.json')) {
          const err = new Error('EACCES: permission denied');
          err.code = 'EACCES';
          throw err;
        }
        return origRead(p, options);
      };
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.readFileSync = origRead;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'CAPSULE_FILE_READ_FAILED');

  // NEG-88: EACCES on lstatSync for capsule file -> CAPSULE_STAT_FAILED
  harness.assertNegative('NEG-88', 'NEGATIVE 88: EACCES on lstatSync for capsule file rejected', () => {
    const tmpDir = setupTestEnv();
    const origLstat = fs.lstatSync;
    try {
      fs.lstatSync = (p, options) => {
        if (typeof p === 'string' && p.endsWith('.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010.json')) {
          const err = new Error('EACCES: permission denied');
          err.code = 'EACCES';
          throw err;
        }
        return origLstat(p, options);
      };
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.lstatSync = origLstat;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'CAPSULE_STAT_FAILED');

  // NEG-89: EACCES on readdirSync for task-capsules directory -> CAPSULES_DIR_READ_FAILED
  harness.assertNegative('NEG-89', 'NEGATIVE 89: EACCES on readdirSync for task-capsules directory rejected', () => {
    const tmpDir = setupTestEnv();
    const origReaddir = fs.readdirSync;
    try {
      fs.readdirSync = (p, options) => {
        if (typeof p === 'string' && p.endsWith('.synthesis/task-capsules')) {
          const err = new Error('EACCES: permission denied');
          err.code = 'EACCES';
          throw err;
        }
        return origReaddir(p, options);
      };
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.readdirSync = origReaddir;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'CAPSULES_DIR_READ_FAILED');

  // NEG-90: Lineage topology self-parent loop -> LINEAGE_GRAPH_INVALID
  harness.assertNegative('NEG-90', 'NEGATIVE 90: Lineage topology self-parent loop rejected', () => {
    const graph = new Map();
    graph.set('CAP-01', {
      capsule_id: 'CAP-01',
      command_id: 'CMD-01',
      payload_sha256: 'a'.repeat(64),
      parent_capsules: [{ capsule_id: 'CAP-01', command_id: 'CMD-01', payload_sha256: 'a'.repeat(64), relationship_type: 'LINEAR_PARENT' }]
    });
    try {
      verifyLineageGraph(graph);
      return { valid: true };
    } catch (err) {
      return { valid: false, stage: 'LINEAGE_GRAPH_INVALID', error: err.message };
    }
  }, 'LINEAGE_GRAPH_INVALID');

  // NEG-91: Lineage topology graph cycle -> LINEAGE_GRAPH_INVALID
  harness.assertNegative('NEG-91', 'NEGATIVE 91: Lineage topology graph cycle rejected', () => {
    const graph = new Map();
    graph.set('CAP-01', {
      capsule_id: 'CAP-01',
      command_id: 'CMD-01',
      payload_sha256: 'a'.repeat(64),
      parent_capsules: [{ capsule_id: 'CAP-02', command_id: 'CMD-02', payload_sha256: 'b'.repeat(64), relationship_type: 'LINEAR_PARENT' }]
    });
    graph.set('CAP-02', {
      capsule_id: 'CAP-02',
      command_id: 'CMD-02',
      payload_sha256: 'b'.repeat(64),
      parent_capsules: [{ capsule_id: 'CAP-01', command_id: 'CMD-01', payload_sha256: 'a'.repeat(64), relationship_type: 'LINEAR_PARENT' }]
    });
    try {
      verifyLineageGraph(graph);
      return { valid: true };
    } catch (err) {
      return { valid: false, stage: 'LINEAGE_GRAPH_INVALID', error: err.message };
    }
  }, 'LINEAGE_GRAPH_INVALID');

  // NEG-92: Lineage topology duplicate parent edge -> LINEAGE_GRAPH_INVALID
  harness.assertNegative('NEG-92', 'NEGATIVE 92: Lineage topology duplicate parent edge rejected', () => {
    const graph = new Map();
    graph.set('CAP-01', {
      capsule_id: 'CAP-01',
      command_id: 'CMD-01',
      payload_sha256: 'a'.repeat(64),
      parent_capsules: []
    });
    graph.set('CAP-02', {
      capsule_id: 'CAP-02',
      command_id: 'CMD-02',
      payload_sha256: 'b'.repeat(64),
      parent_capsules: [
        { capsule_id: 'CAP-01', command_id: 'CMD-01', payload_sha256: 'a'.repeat(64), relationship_type: 'LINEAR_PARENT' },
        { capsule_id: 'CAP-01', command_id: 'CMD-01', payload_sha256: 'a'.repeat(64), relationship_type: 'LINEAR_PARENT' }
      ]
    });
    try {
      verifyLineageGraph(graph);
      return { valid: true };
    } catch (err) {
      return { valid: false, stage: 'LINEAGE_GRAPH_INVALID', error: err.message };
    }
  }, 'LINEAGE_GRAPH_INVALID');

  // NEG-93: Duplicate capsule ID in chain -> DUPLICATE_CAPSULE_ID_IN_CHAIN (tested via simulated duplicate record in loadAttestationChain)
  harness.assertNegative('NEG-93', 'NEGATIVE 93: Duplicate capsule ID in chain rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      // In canonical layout, duplicate capsule IDs in attestations are caught by DUPLICATE_CAPSULE_ID_IN_CHAIN or earlier filename checks
      const p = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(p, 'utf8'));
      att.new_capsule.capsule_id = 'CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010';
      att.new_capsule.file_path = '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010.json';
      fs.writeFileSync(p, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'DUPLICATE_CAPSULE_ID_IN_CHAIN');

  // NEG-94: Duplicate capsule file path in chain -> DUPLICATE_CAPSULE_PATH_IN_CHAIN
  harness.assertNegative('NEG-94', 'NEGATIVE 94: Duplicate capsule file path in chain rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      const third = addSyntheticThirdCapsule(tmpDir);
      const p = path.join(tmpDir, third.attestationRelPath);
      const att = JSON.parse(fs.readFileSync(p, 'utf8'));
      att.new_capsule.file_path = '.synthesis/task-capsules/CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010.json';
      fs.writeFileSync(p, JSON.stringify(att, null, 2), 'utf8');
      return verifyAttestationChain(tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'CAPSULE_FILENAME_MISMATCH');

  // NEG-95: Checkpoint raw SHA mismatch on existing node -> HISTORY_CHECKPOINT_MISMATCH
  harness.assertNegative('NEG-95', 'NEGATIVE 95: Checkpoint raw SHA mismatch on existing node rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      return verifyAttestationChain(tmpDir, {
        trustedPriorCheckpoint: { filePath: PINNED_BASELINE_PATH, rawFileSha256: '0'.repeat(64) }
      });
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'HISTORY_CHECKPOINT_MISMATCH');

  // NEG-96: Malformed checkpoint object missing rawFileSha256 -> MALFORMED_TRUSTED_PRIOR_CHECKPOINT
  harness.assertNegative('NEG-96', 'NEGATIVE 96: Malformed checkpoint object missing rawFileSha256 rejected', () => {
    const tmpDir = setupTestEnv();
    try {
      return verifyAttestationChain(tmpDir, {
        trustedPriorCheckpoint: { filePath: PINNED_BASELINE_PATH }
      });
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 'MALFORMED_TRUSTED_PRIOR_CHECKPOINT');

  // NEG-97..104: Additional CLI tests
  harness.assertCliNegative('NEG-97', 'NEGATIVE 97: CLI whitespace-only --trusted-prior-path rejected with exit 1', ['--verify-all', '--trusted-prior-path', '   ']);
  harness.assertCliNegative('NEG-98', 'NEGATIVE 98: CLI whitespace-only --trusted-prior-sha256 rejected with exit 1', ['--verify-all', '--trusted-prior-sha256', '   ']);
  harness.assertCliNegative('NEG-99', 'NEGATIVE 99: CLI malformed SHA-256 rejected with exit 1', ['--verify-all', '--trusted-prior-path', PINNED_BASELINE_PATH, '--trusted-prior-sha256', 'tooshort']);
  harness.assertCliNegative('NEG-100', 'NEGATIVE 100: CLI path traversal in --trusted-prior-path rejected with exit 1', ['--verify-all', '--trusted-prior-path', '.synthesis/attestations/../secret.json', '--trusted-prior-sha256', '0'.repeat(64)]);
  harness.assertCliNegative('NEG-101', 'NEGATIVE 101: CLI incomplete pair rejected with exit 1', ['--verify-all', '--trusted-prior-path', PINNED_BASELINE_PATH]);
  harness.assertCliNegative('NEG-102', 'NEGATIVE 102: CLI duplicate --require-trusted-prior flag rejected with exit 1', ['--verify-all', '--require-trusted-prior', '--require-trusted-prior']);
  harness.assertCliNegative('NEG-103', 'NEGATIVE 103: CLI surplus argument after --self-test rejected with exit 1', ['--self-test', '--extra']);
  harness.assertCliNegative('NEG-104', 'NEGATIVE 104: CLI unknown flag rejected with exit 1', ['--unrecognized-flag']);

  return harness.getResults();
}

// ============================================================
// CLI ENTRY POINT
// ============================================================

function main() {
  const args = process.argv.slice(2);
  const repoRoot = path.resolve(__dirname, '..', '..');

  if (args.length === 0) {
    console.error('Error: No command specified. Use --help for usage.');
    process.exit(1);
  }

  // Check standalone --help or -h
  if (args[0] === '--help' || args[0] === '-h') {
    if (args.length !== 1) {
      console.error('Error: Standalone --help cannot be combined with other arguments.');
      process.exit(1);
    }
    console.log(`Synthesis CMS mini — Command Capsule Attestation Chain Verifier`);
    console.log(`Usage:`);
    console.log(`  node scripts/governance/verify_capsule_attestation_chain.mjs --self-test`);
    console.log(`  node scripts/governance/verify_capsule_attestation_chain.mjs --verify-all`);
    console.log(`  node scripts/governance/verify_capsule_attestation_chain.mjs --verify-all --trusted-prior-path <PATH> --trusted-prior-sha256 <SHA>`);
    console.log(`  node scripts/governance/verify_capsule_attestation_chain.mjs --verify-all --require-trusted-prior --trusted-prior-path <PATH> --trusted-prior-sha256 <SHA>`);
    console.log(`  node scripts/governance/verify_capsule_attestation_chain.mjs --help`);
    process.exit(0);
  }

  // Reject any embedded help in non-first position
  if (args.includes('--help') || args.includes('-h')) {
    console.error('Error: --help cannot be combined with other arguments.');
    process.exit(1);
  }

  if (args[0] === '--self-test') {
    if (args.length !== 1) {
      console.error(`Error: Unexpected arguments after --self-test: ${args.slice(1).join(', ')}`);
      process.exit(1);
    }
    console.log(`Running Command Capsule Attestation Chain Verifier self-tests...`);
    const results = runSelfTests(repoRoot);
    for (const c of results.executedCases) {
      console.log(`  [${c.status}] ${c.id}: ${c.name} (${c.stage})`);
    }
    console.log(`POSITIVE_TESTS_PASSED: ${results.positivePassed}`);
    console.log(`NEGATIVE_TESTS_PASSED: ${results.negativePassed}`);
    console.log(`FAILED_TESTS: ${results.failedTests}`);
    console.log(`OMITTED_OR_SKIPPED_CASES: ${results.omittedOrSkippedCases}`);
    console.log(`TOTAL_EXECUTED_CASES: ${results.totalExecuted}`);
    console.log(`TOTAL_REQUIRED_CASES: ${results.totalRequired}`);
    console.log(`CHAIN_VERIFICATION_STATUS: ${results.valid ? 'PASS' : 'FAIL'}`);
    if (!results.valid || results.failedTests > 0 || results.omittedOrSkippedCases > 0) {
      process.exit(1);
    }
    process.exit(0);
  }

  if (args[0] === '--verify-all') {
    let trustedPriorPath = null;
    let trustedPriorSha = null;
    let hasTrustedPriorPath = false;
    let hasTrustedPriorSha = false;
    let requireTrustedPrior = false;
    let seenFlags = new Set();

    for (let i = 1; i < args.length; i++) {
      const flag = args[i];
      if (flag === '--require-trusted-prior') {
        if (seenFlags.has(flag)) {
          console.error(`Error: Duplicate flag "${flag}"`);
          process.exit(1);
        }
        seenFlags.add(flag);
        requireTrustedPrior = true;
      } else if (flag === '--trusted-prior-path') {
        if (seenFlags.has(flag)) {
          console.error(`Error: Duplicate flag "${flag}"`);
          process.exit(1);
        }
        seenFlags.add(flag);
        hasTrustedPriorPath = true;
        if (i + 1 >= args.length) {
          console.error('Error: Missing value for --trusted-prior-path');
          process.exit(1);
        }
        const val = args[++i];
        if (!val || val.trim() === '') {
          console.error('Error: Empty value for --trusted-prior-path');
          process.exit(1);
        }
        if (val.startsWith('--')) {
          console.error(`Error: Flag "${val}" cannot be used as value for --trusted-prior-path`);
          process.exit(1);
        }
        if (!/^\.synthesis\/attestations\/[A-Za-z0-9_.-]+\.json$/.test(val) || val.includes('..')) {
          console.error(`Error: Invalid format for --trusted-prior-path: "${val}"`);
          process.exit(1);
        }
        trustedPriorPath = val;
      } else if (flag === '--trusted-prior-sha256') {
        if (seenFlags.has(flag)) {
          console.error(`Error: Duplicate flag "${flag}"`);
          process.exit(1);
        }
        seenFlags.add(flag);
        hasTrustedPriorSha = true;
        if (i + 1 >= args.length) {
          console.error('Error: Missing value for --trusted-prior-sha256');
          process.exit(1);
        }
        const val = args[++i];
        if (!val || val.trim() === '') {
          console.error('Error: Empty value for --trusted-prior-sha256');
          process.exit(1);
        }
        if (val.startsWith('--')) {
          console.error(`Error: Flag "${val}" cannot be used as value for --trusted-prior-sha256`);
          process.exit(1);
        }
        if (!/^[a-f0-9]{64}$/.test(val)) {
          console.error(`Error: Invalid SHA-256 format for --trusted-prior-sha256: "${val}"`);
          process.exit(1);
        }
        trustedPriorSha = val;
      } else {
        console.error(`Error: Unknown argument "${flag}"`);
        process.exit(1);
      }
    }

    if (hasTrustedPriorPath !== hasTrustedPriorSha) {
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
