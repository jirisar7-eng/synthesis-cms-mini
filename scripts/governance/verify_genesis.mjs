#!/usr/bin/env node

/**
 * Synthesis CMS mini — Genesis Anchor Integrity Validator
 * 
 * Task: SYN-MINI-GOV-GENESIS-001
 * Command: CMD-SYN-MINI-GOV-GENESIS-001-004-HARDEN-SELFTEST
 * Roadmap Step: 1/60
 * 
 * Standalone Node.js ESM script with zero external dependencies.
 * Validates the cryptographic and structural invariants of .synthesis/lineage/genesis.json.
 */

import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { readFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import process from 'node:process';

export const PINNED_GENESIS_SHA256 = 'b3d47a6f732512a9f5b19668a07bb4d2c662adf316f5a1d33a6d52c57860ec60';

export const EXPECTED_INVARIANTS = Object.freeze({
  record_type: 'GENESIS_ANCHOR',
  project_id: 'SYNTHESIS_CMS_MINI',
  repository_full_name: 'jirisar7-eng/synthesis-cms-mini',
  repository_id: 1401215700,
  initial_repository_commit: 'a727bd6ac1979586833145f8503ac88fd2ce8623',
  verified_initial_license_blob_sha: '0ad25db4bd1d86c452db3f9602ccdbe172438f52',
  capsule_id: 'CAP-SYN-MINI-GOV-GENESIS-001-20261002-001',
  command_id: 'CMD-SYN-MINI-GOV-GENESIS-001-002-BOOTSTRAP-GENESIS',
  capsule_schema_version: '1.0.0',
  hash_algorithm: 'SHA-256',
  immutable_history_policy: 'APPEND_ONLY_STRICT',
  append_only_correction_policy: 'SUPERSEDE_WITH_NEW_CAPSULE',
  one_command_one_capsule_policy: 'ENFORCED',
  initial_governance_state: 'GENESIS_BOOTSTRAP',
  main_protection_ruleset_id: 24351135,
  main_protection_ruleset_name: 'SYN-MINI-MAIN-PROTECTION',
  main_protection_ruleset_enforcement: 'active'
});

export function computeSha256(bufferOrString) {
  return createHash('sha256').update(bufferOrString).digest('hex');
}

export function validateLineEndings(rawContent) {
  const str = typeof rawContent === 'string' ? rawContent : rawContent.toString('utf-8');
  if (str.includes('\r')) {
    throw new Error('LINE_ENDING_ERROR: Carriage return (\\r) detected. Genesis must use LF (\\n) line endings exclusively.');
  }
  return true;
}

export function validateGenesisHash(rawBuffer) {
  const actualHash = computeSha256(rawBuffer);
  if (actualHash !== PINNED_GENESIS_SHA256) {
    throw new Error(`HASH_MISMATCH: Genesis SHA-256 mismatch. Expected ${PINNED_GENESIS_SHA256}, got ${actualHash}`);
  }
  return actualHash;
}

export function parseGenesisJson(rawBytes) {
  const str = typeof rawBytes === 'string' ? rawBytes : rawBytes.toString('utf-8');
  try {
    return JSON.parse(str);
  } catch (err) {
    throw new Error(`JSON_PARSE_ERROR: Failed to parse genesis.json: ${err.message}`);
  }
}

export function validateGenesisStructure(genesis) {
  if (typeof genesis !== 'object' || genesis === null || Array.isArray(genesis)) {
    throw new Error('STRUCTURAL_ERROR: Genesis content must be a JSON object.');
  }

  for (const field of [
    'record_type',
    'project_id',
    'repository_full_name',
    'repository_id',
    'initial_repository_commit',
    'verified_initial_license_blob_sha',
    'capsule_id',
    'command_id',
    'capsule_schema_version',
    'hash_algorithm',
    'immutable_history_policy',
    'append_only_correction_policy',
    'one_command_one_capsule_policy',
    'initial_governance_state'
  ]) {
    if (genesis[field] !== EXPECTED_INVARIANTS[field]) {
      throw new Error(`INVARIANT_VIOLATION: Field "${field}" expected "${EXPECTED_INVARIANTS[field]}", got "${genesis[field]}"`);
    }
  }

  if (!Array.isArray(genesis.parent_capsules) || genesis.parent_capsules.length !== 0) {
    throw new Error('INVARIANT_VIOLATION: Genesis parent_capsules must be strictly empty array ([]).');
  }

  if (!genesis.owner_identity || typeof genesis.owner_identity !== 'object') {
    throw new Error('INVARIANT_VIOLATION: owner_identity must be an object.');
  }
  if (genesis.owner_identity.login !== 'jirisar7-eng' || genesis.owner_identity.id !== 263165555 || genesis.owner_identity.role !== 'OWNER_AUTHORITY') {
    throw new Error('INVARIANT_VIOLATION: owner_identity does not match authoritative owner record.');
  }

  if (!Array.isArray(genesis.initial_actor_registry) || genesis.initial_actor_registry.length === 0) {
    throw new Error('INVARIANT_VIOLATION: initial_actor_registry must be a non-empty array.');
  }
  for (const actor of genesis.initial_actor_registry) {
    if (!actor.actor_id || !actor.role) {
      throw new Error('INVARIANT_VIOLATION: Each actor in initial_actor_registry must have actor_id and role.');
    }
  }

  if (!genesis.previous_diagnostic_command_reference || typeof genesis.previous_diagnostic_command_reference !== 'object') {
    throw new Error('INVARIANT_VIOLATION: previous_diagnostic_command_reference must be an object.');
  }
  if (genesis.previous_diagnostic_command_reference.command_id !== 'CMD-SYN-MINI-GOV-GENESIS-001-001-DISCOVER-VERIFY' ||
      genesis.previous_diagnostic_command_reference.sealed_capsule !== false) {
    throw new Error('INVARIANT_VIOLATION: previous_diagnostic_command_reference invalid.');
  }

  const state = genesis.initial_verified_project_state;
  if (!state || typeof state !== 'object') {
    throw new Error('INVARIANT_VIOLATION: initial_verified_project_state must be an object.');
  }
  if (state.base_main_sha !== EXPECTED_INVARIANTS.initial_repository_commit ||
      state.license !== 'AGPL-3.0' ||
      state.license_blob_sha !== EXPECTED_INVARIANTS.verified_initial_license_blob_sha ||
      state.main_protection_ruleset_id !== EXPECTED_INVARIANTS.main_protection_ruleset_id ||
      state.main_protection_ruleset_name !== EXPECTED_INVARIANTS.main_protection_ruleset_name ||
      state.main_protection_ruleset_enforcement !== EXPECTED_INVARIANTS.main_protection_ruleset_enforcement) {
    throw new Error('INVARIANT_VIOLATION: initial_verified_project_state fields do not match verified constants.');
  }
  if (!Array.isArray(state.root_files) || !state.root_files.includes('LICENSE')) {
    throw new Error('INVARIANT_VIOLATION: initial_verified_project_state.root_files must include "LICENSE".');
  }

  const pending = genesis.explicitly_pending_future_validators_and_ci;
  if (!pending || typeof pending !== 'object') {
    throw new Error('INVARIANT_VIOLATION: explicitly_pending_future_validators_and_ci must be an object.');
  }
  for (const k of ['capsule_validator', 'contract_registry', 'governance_ci', 'technical_ci']) {
    if (pending[k] !== 'PENDING') {
      throw new Error(`INVARIANT_VIOLATION: Pending declaration "${k}" must be "PENDING".`);
    }
  }

  return true;
}

export function locateRepositoryRoot() {
  const currentFile = fileURLToPath(import.meta.url);
  let dir = dirname(currentFile);
  while (dir && dir !== dirname(dir)) {
    const candidate = join(dir, '.synthesis', 'lineage', 'genesis.json');
    if (existsSync(candidate)) {
      return dir;
    }
    dir = dirname(dir);
  }
  throw new Error('REPOSITORY_ROOT_NOT_FOUND: Could not locate .synthesis/lineage/genesis.json in directory tree.');
}

export function verifyGenesisFile(filePath) {
  if (!existsSync(filePath)) {
    throw new Error(`GENESIS_NOT_FOUND: Genesis file does not exist at ${filePath}`);
  }
  const rawBytes = readFileSync(filePath);
  validateLineEndings(rawBytes);
  const hash = validateGenesisHash(rawBytes);
  const parsed = parseGenesisJson(rawBytes);
  validateGenesisStructure(parsed);
  return { hash, parsed };
}

export function runSelfTests() {
  console.log('[SELF-TEST] Initiating Genesis Validator Behavioral Self-Tests...');
  const repoRoot = locateRepositoryRoot();
  const genesisPath = join(repoRoot, '.synthesis', 'lineage', 'genesis.json');
  const validBytes = readFileSync(genesisPath);
  const validJson = parseGenesisJson(validBytes);

  let passed = 0;
  let failed = 0;

  function runCase(name, fn) {
    try {
      fn();
      passed++;
      console.log(`  ✓ PASS: ${name}`);
    } catch (err) {
      failed++;
      console.error(`  ✗ FAIL: ${name} -> ${err.message}`);
    }
  }

  // 1. Original Genesis: PASS (exercises complete production verifyGenesisFile)
  runCase('1. Original Genesis: PASS', () => {
    verifyGenesisFile(genesisPath);
  });

  // 2. Single-byte content mutation: REJECT
  runCase('2. Single-byte content mutation: REJECT', () => {
    const mutated = Buffer.from(validBytes);
    mutated[10] = mutated[10] === 32 ? 33 : 32;
    let threw = false;
    try {
      validateGenesisHash(mutated);
    } catch (e) {
      threw = true;
      if (!e.message.includes('HASH_MISMATCH')) throw e;
    }
    if (!threw) throw new Error('Expected single-byte mutation to throw HASH_MISMATCH');
  });

  // 3. Wrong project identity: REJECT
  runCase('3. Wrong project identity: REJECT', () => {
    const invalidObj = { ...validJson, project_id: 'WRONG_PROJECT' };
    let threw = false;
    try {
      validateGenesisStructure(invalidObj);
    } catch (e) {
      threw = true;
      if (!e.message.includes('project_id')) throw e;
    }
    if (!threw) throw new Error('Expected wrong project identity to throw INVARIANT_VIOLATION');
  });

  // 4. Wrong repository identity: REJECT
  runCase('4. Wrong repository identity: REJECT', () => {
    const invalidObj = { ...validJson, repository_full_name: 'wrong/repo' };
    let threw = false;
    try {
      validateGenesisStructure(invalidObj);
    } catch (e) {
      threw = true;
      if (!e.message.includes('repository_full_name')) throw e;
    }
    if (!threw) throw new Error('Expected wrong repository identity to throw INVARIANT_VIOLATION');
  });

  // 5. Nonempty Genesis parent array: REJECT
  runCase('5. Nonempty Genesis parent array: REJECT', () => {
    const invalidObj = { ...validJson, parent_capsules: ['CAP-FAKE-PARENT-001'] };
    let threw = false;
    try {
      validateGenesisStructure(invalidObj);
    } catch (e) {
      threw = true;
      if (!e.message.includes('parent_capsules')) throw e;
    }
    if (!threw) throw new Error('Expected nonempty parent_capsules to throw INVARIANT_VIOLATION');
  });

  // 6. Malformed JSON: REJECT (exercises production parseGenesisJson error boundary)
  runCase('6. Malformed JSON: REJECT', () => {
    const badJsonBytes = Buffer.from('{"record_type": "GENESIS_ANCHOR", unclosed...', 'utf-8');
    let threw = false;
    try {
      parseGenesisJson(badJsonBytes);
    } catch (e) {
      threw = true;
      if (!e.message.includes('JSON_PARSE_ERROR')) throw e;
    }
    if (!threw) throw new Error('Expected malformed JSON to throw JSON_PARSE_ERROR');
  });

  // 7. Invalid initial commit identity: REJECT
  runCase('7. Invalid initial commit identity: REJECT', () => {
    const invalidObj = { ...validJson, initial_repository_commit: '0000000000000000000000000000000000000000' };
    let threw = false;
    try {
      validateGenesisStructure(invalidObj);
    } catch (e) {
      threw = true;
      if (!e.message.includes('initial_repository_commit')) throw e;
    }
    if (!threw) throw new Error('Expected invalid initial commit to throw INVARIANT_VIOLATION');
  });

  // 8. Wrong line-ending format (CRLF): REJECT
  runCase('8. Wrong line-ending format (CRLF): REJECT', () => {
    const crlfContent = validBytes.toString('utf-8').replace(/\n/g, '\r\n');
    let threw = false;
    try {
      validateLineEndings(crlfContent);
    } catch (e) {
      threw = true;
      if (!e.message.includes('LINE_ENDING_ERROR')) throw e;
    }
    if (!threw) throw new Error('Expected CRLF content to throw LINE_ENDING_ERROR');
  });

  console.log(`[SELF-TEST] Summary: ${passed} passed, ${failed} failed.`);
  if (failed > 0) {
    process.exit(1);
  }
}

const args = process.argv.slice(2);
if (args.length === 0) {
  try {
    const root = locateRepositoryRoot();
    const targetFile = join(root, '.synthesis', 'lineage', 'genesis.json');
    const result = verifyGenesisFile(targetFile);
    console.log('[GENESIS-VERIFY] PASS: Genesis anchor verified successfully.');
    console.log(`[GENESIS-VERIFY] File: ${targetFile}`);
    console.log(`[GENESIS-VERIFY] SHA-256: ${result.hash}`);
    console.log(`[GENESIS-VERIFY] Record Type: ${result.parsed.record_type}`);
    console.log(`[GENESIS-VERIFY] Capsule ID: ${result.parsed.capsule_id}`);
    process.exit(0);
  } catch (err) {
    console.error(`[GENESIS-VERIFY] FAIL: ${err.message}`);
    process.exit(1);
  }
} else if (args.length === 1 && args[0] === '--self-test') {
  runSelfTests();
  process.exit(0);
} else {
  console.error(`[GENESIS-VERIFY] FAIL: Unknown argument(s): ${args.join(' ')}. Unknown arguments are strictly forbidden.`);
  process.exit(1);
}
