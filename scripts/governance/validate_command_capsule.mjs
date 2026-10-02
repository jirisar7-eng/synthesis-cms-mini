#!/usr/bin/env node

/**
 * Synthesis CMS mini — Command Capsule Instance Validator
 * 
 * Standalone schema-driven validator and behavioral test suite
 * for Command Capsule Draft 2020-12 instances.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import child_process from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const PINNED_SCHEMA_BLOB_SHA = 'a224fea7cafb49afd6579e504e7f31cf10ebbe2a';
export const EXPECTED_SCHEMA_RELATIVE_PATH = path.join('.synthesis', 'schemas', 'command-capsule.schema.json');

const KNOWN_KEYWORDS = new Set([
  '$schema',
  '$id',
  'title',
  'description',
  'type',
  'properties',
  'required',
  'additionalProperties',
  'const',
  'enum',
  'pattern',
  'format',
  'minimum',
  'items',
  'allOf',
  'if',
  'then',
  'minLength'
]);

export function calculateGitBlobSha(buffer) {
  const header = Buffer.from(`blob ${buffer.length}\0`);
  return crypto.createHash('sha1').update(Buffer.concat([header, buffer])).digest('hex');
}

export function loadSchema(repoRoot) {
  const schemaPath = path.resolve(repoRoot, EXPECTED_SCHEMA_RELATIVE_PATH);
  if (!fs.existsSync(schemaPath)) {
    throw new Error(`Schema file not found at expected location: ${schemaPath}`);
  }
  const content = fs.readFileSync(schemaPath);
  const actualBlobSha = calculateGitBlobSha(content);
  if (actualBlobSha !== PINNED_SCHEMA_BLOB_SHA) {
    throw new Error(`Schema blob SHA mismatch! Expected ${PINNED_SCHEMA_BLOB_SHA}, got ${actualBlobSha}`);
  }
  return JSON.parse(content.toString('utf-8'));
}

export function parseCapsuleJson(rawContent) {
  try {
    return { ok: true, data: JSON.parse(rawContent) };
  } catch (err) {
    return { ok: false, error: `JSON_PARSE_ERROR: ${err.message}` };
  }
}

export function validateSchemaKeywords(schema, jsonPath = '$') {
  if (typeof schema !== 'object' || schema === null) return;
  for (const key of Object.keys(schema)) {
    if (!KNOWN_KEYWORDS.has(key)) {
      throw new Error(`Unsupported schema assertion keyword "${key}" at ${jsonPath}`);
    }
    if (key === 'properties') {
      for (const [propName, propSchema] of Object.entries(schema.properties)) {
        validateSchemaKeywords(propSchema, `${jsonPath}.properties.${propName}`);
      }
    } else if (key === 'additionalProperties' && typeof schema.additionalProperties === 'object' && schema.additionalProperties !== null) {
      validateSchemaKeywords(schema.additionalProperties, `${jsonPath}.additionalProperties`);
    } else if (key === 'items') {
      validateSchemaKeywords(schema.items, `${jsonPath}.items`);
    } else if (key === 'allOf') {
      schema.allOf.forEach((sub, idx) => validateSchemaKeywords(sub, `${jsonPath}.allOf[${idx}]`));
    } else if (key === 'if') {
      validateSchemaKeywords(schema.if, `${jsonPath}.if`);
    } else if (key === 'then') {
      validateSchemaKeywords(schema.then, `${jsonPath}.then`);
    }
  }
}

export function isValidIsoDateTime(str) {
  if (typeof str !== 'string') return false;
  const m = str.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|([+-])(\d{2}):(\d{2}))$/);
  if (!m) return false;
  const year = parseInt(m[1], 10);
  const month = parseInt(m[2], 10);
  const day = parseInt(m[3], 10);
  const hour = parseInt(m[4], 10);
  const min = parseInt(m[5], 10);
  const sec = parseInt(m[6], 10);
  if (month < 1 || month > 12) return false;
  if (hour > 23 || min > 59 || sec > 59) return false;
  const isLeap = (year % 4 === 0 && year % 100 !== 0) || (year % 400 === 0);
  const daysInMonth = [0, 31, isLeap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (day < 1 || day > daysInMonth[month]) return false;
  if (m[8] && m[8] !== 'Z') {
    const tzHour = parseInt(m[10], 10);
    const tzMin = parseInt(m[11], 10);
    if (tzHour > 23 || tzMin > 59) return false;
  }
  return true;
}

export function validateInstance(schema, instance, jsonPath = '$', depth = 0) {
  if (depth > 50) {
    return { valid: false, error: `Recursion depth limit exceeded at ${jsonPath}` };
  }

  // Check all schema keywords
  validateSchemaKeywords(schema, jsonPath);

  // 1. type
  if (schema.type) {
    const allowedTypes = Array.isArray(schema.type) ? schema.type : [schema.type];
    const actualType = getJsonType(instance);
    if (!allowedTypes.includes(actualType)) {
      return {
        valid: false,
        error: `Type mismatch at ${jsonPath}: expected one of [${allowedTypes.join(', ')}], got ${actualType}`
      };
    }
  }

  // 2. const
  if (Object.hasOwn(schema, 'const')) {
    if (instance !== schema.const) {
      return {
        valid: false,
        error: `Const value mismatch at ${jsonPath}: expected "${schema.const}", got "${instance}"`
      };
    }
  }

  // 3. enum
  if (schema.enum) {
    if (!schema.enum.includes(instance)) {
      return {
        valid: false,
        error: `Enum mismatch at ${jsonPath}: value "${instance}" is not in allowed enum [${schema.enum.join(', ')}]`
      };
    }
  }

  // 4. minLength
  if (typeof schema.minLength === 'number' && typeof instance === 'string') {
    if (instance.length < schema.minLength) {
      return {
        valid: false,
        error: `String length too short at ${jsonPath}: expected at least ${schema.minLength}, got ${instance.length}`
      };
    }
  }

  // 5. pattern
  if (schema.pattern && typeof instance === 'string') {
    const regex = new RegExp(schema.pattern);
    if (!regex.test(instance)) {
      return {
        valid: false,
        error: `Pattern mismatch at ${jsonPath}: "${instance}" does not match pattern /${schema.pattern}/`
      };
    }
  }

  // 6. format
  if (schema.format && typeof instance === 'string') {
    if (schema.format === 'date-time') {
      if (!isValidIsoDateTime(instance)) {
        return {
          valid: false,
          error: `Format mismatch at ${jsonPath}: "${instance}" is not a valid ISO-8601 calendar date-time`
        };
      }
    }
  }

  // 7. minimum
  if (typeof schema.minimum === 'number' && typeof instance === 'number') {
    if (instance < schema.minimum) {
      return {
        valid: false,
        error: `Minimum limit violation at ${jsonPath}: ${instance} < ${schema.minimum}`
      };
    }
  }

  // 8. Object validation: required, properties, additionalProperties (Strict own-property semantics)
  if (typeof instance === 'object' && instance !== null && !Array.isArray(instance)) {
    if (schema.required) {
      for (const reqProp of schema.required) {
        if (!Object.hasOwn(instance, reqProp) || instance[reqProp] === undefined) {
          return {
            valid: false,
            error: `Missing required property "${reqProp}" at ${jsonPath}`
          };
        }
      }
    }

    for (const key of Object.keys(instance)) {
      if (schema.properties && Object.hasOwn(schema.properties, key)) {
        const subRes = validateInstance(schema.properties[key], instance[key], `${jsonPath}.${key}`, depth + 1);
        if (!subRes.valid) return subRes;
      } else if (schema.additionalProperties === false) {
        return {
          valid: false,
          error: `Unexpected additional property "${key}" at ${jsonPath} (additionalProperties: false)`
        };
      } else if (typeof schema.additionalProperties === 'object' && schema.additionalProperties !== null) {
        const subRes = validateInstance(schema.additionalProperties, instance[key], `${jsonPath}.${key}`, depth + 1);
        if (!subRes.valid) return subRes;
      }
    }
  }

  // 9. Array validation: items
  if (Array.isArray(instance) && schema.items) {
    for (let i = 0; i < instance.length; i++) {
      const itemRes = validateInstance(schema.items, instance[i], `${jsonPath}[${i}]`, depth + 1);
      if (!itemRes.valid) return itemRes;
    }
  }

  // 10. Conditional validation: allOf, if, then
  if (schema.allOf) {
    for (let i = 0; i < schema.allOf.length; i++) {
      const sub = schema.allOf[i];
      if (sub.if && sub.then) {
        const ifRes = validateInstance(sub.if, instance, `${jsonPath}.if`, depth + 1);
        if (ifRes.valid) {
          const thenRes = validateInstance(sub.then, instance, `${jsonPath}.then`, depth + 1);
          if (!thenRes.valid) return thenRes;
        }
      } else {
        const allRes = validateInstance(sub, instance, `${jsonPath}.allOf[${i}]`, depth + 1);
        if (!allRes.valid) return allRes;
      }
    }
  }

  return { valid: true };
}

function getJsonType(val) {
  if (val === null) return 'null';
  if (Array.isArray(val)) return 'array';
  if (typeof val === 'number') {
    return Number.isInteger(val) ? 'integer' : 'number';
  }
  return typeof val;
}

export function validateSemanticConsistency(capsule) {
  if (!capsule || !capsule.payload) {
    return { valid: false, error: 'Cannot check semantic consistency on missing payload' };
  }
  const payload = capsule.payload;

  // 1. Changed files count vs max_write_files_limit
  const maxWrite = payload.scope_boundary?.max_write_files_limit;
  const actualChanged = payload.changes_and_evidence?.actual_changed_files;
  if (typeof maxWrite === 'number' && Array.isArray(actualChanged)) {
    if (actualChanged.length > maxWrite) {
      return {
        valid: false,
        error: `Changed-file count (${actualChanged.length}) exceeds declared write-file limit (${maxWrite})`
      };
    }
  }

  // 2. Self-referential parent check
  const capsuleId = payload.capsule_id;
  const parents = payload.lineage?.parent_capsules;
  if (capsuleId && Array.isArray(parents)) {
    for (const p of parents) {
      if (p.capsule_id === capsuleId) {
        return {
          valid: false,
          error: `Capsule cannot reference itself as parent: ${capsuleId}`
        };
      }
    }
  }

  return { valid: true };
}

export function validateCapsuleComplete(schema, capsule) {
  // 1. Structural schema validation
  const structRes = validateInstance(schema, capsule);
  if (!structRes.valid) {
    return {
      valid: false,
      stage: 'STRUCTURAL_SCHEMA',
      error: structRes.error,
      cryptoVerified: false
    };
  }

  // 2. Semantic consistency validation
  const semRes = validateSemanticConsistency(capsule);
  if (!semRes.valid) {
    return {
      valid: false,
      stage: 'SEMANTIC_CONSISTENCY',
      error: semRes.error,
      cryptoVerified: false
    };
  }

  const isSealed = capsule.seal?.status === 'SEALED';
  return {
    valid: true,
    status: isSealed ? 'SEALED_STRUCTURE_VALID' : 'PROVISIONAL_STRUCTURE_VALID',
    cryptoVerified: false, // Honesty: actual payload hash equality & signatures require subsequent tooling
    message: isSealed
      ? 'SEALED_STRUCTURE_VALID / CRYPTOGRAPHIC_SEAL_NOT_VERIFIED'
      : 'PROVISIONAL_STRUCTURE_VALID / BOOTSTRAP_RECORD'
  };
}

// ============================================================
// SELF-TEST SUITE
// ============================================================

export function buildSampleProvisionalCapsule() {
  return {
    payload: {
      schema_version: '1.0.0',
      capsule_type: 'COMMAND_CAPSULE',
      capsule_id: 'CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-004',
      command_id: 'CMD-SYN-MINI-GOV-CAPSULE-SCHEMA-001-004-HARDEN-INSTANCE-VALIDATOR',
      task_id: 'SYN-MINI-GOV-CAPSULE-SCHEMA-001',
      project_id: 'SYNTHESIS_CMS_MINI',
      roadmap_step: '2/60 — COMMAND CAPSULE SCHEMA',
      actors: {
        owner: 'jirisar7-eng',
        command_author: 'jirisar7-eng',
        executor: 'AI Studio Engineer',
        verifier: 'jirisar7-eng'
      },
      execution_metadata: {
        execution_timestamp: '2026-10-02T02:00:00Z',
        development_phase: 'IMPLEMENT',
        execution_mode: 'RESTRICTED_GOVERNANCE_BOOTSTRAP'
      },
      repository_baseline: {
        repository_name: 'jirisar7-eng/synthesis-cms-mini',
        repository_id: 1401215700,
        base_main_sha: 'd362a6431bf0f5c7368df96b657c596eb093b6ff',
        source_branch: 'task/SYN-MINI-GOV-CAPSULE-SCHEMA-001',
        expected_target_branch: 'main'
      },
      scope_boundary: {
        permitted_read_paths: ['.synthesis/schemas/command-capsule.schema.json'],
        permitted_write_paths: ['scripts/governance/validate_command_capsule.mjs'],
        protected_paths: ['.synthesis/schemas/command-capsule.schema.json', 'LICENSE'],
        forbidden_operations: ['npm install', 'git push origin main'],
        max_write_files_limit: 1,
        max_read_files_limit: 10
      },
      lineage: {
        genesis_anchor_reference: {
          path: '.synthesis/lineage/genesis.json',
          pinned_sha256: 'b3d47a6f732512a9f5b19668a07bb4d2c662adf316f5a1d33a6d52c57860ec60'
        },
        parent_capsules: [
          {
            capsule_id: 'CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-003',
            command_id: 'CMD-SYN-MINI-GOV-CAPSULE-SCHEMA-001-003-VALIDATE-INSTANCES',
            payload_sha256: null,
            relationship_type: 'LINEAR_PARENT'
          }
        ],
        typed_lineage_references: {
          superseded_capsules: [],
          repaired_capsules: [],
          diagnostic_predecessors: []
        }
      },
      contracts_and_dependencies: {
        affected_contracts: ['command-capsule.v1'],
        affected_capabilities: ['CAPSULE_VALIDATOR'],
        declared_dependencies: []
      },
      changes_and_evidence: {
        expected_changed_files: ['scripts/governance/validate_command_capsule.mjs'],
        actual_changed_files: ['scripts/governance/validate_command_capsule.mjs'],
        commit_sha: null,
        source_blob_shas: {
          'scripts/governance/validate_command_capsule.mjs': '1171fbab2c694617821ddf92006a876ed08086ea'
        }
      },
      verification_states: {
        syntax_verification: 'PASS',
        behavioral_test_verification: 'PASS',
        security_review: 'PASS',
        remote_sha_verification: 'PENDING',
        ci_verification: 'PENDING',
        pull_request_status: 'NOT_CREATED',
        merge_status: 'NOT_MERGED',
        deployment_status: 'NOT_DEPLOYED'
      },
      recovery_and_next_steps: {
        global_governance_health: 'BOOTSTRAP_NOT_YET_ACTIVE',
        blockers: [],
        incomplete_work: [],
        next_safe_step: 'Verify task branch remote checkpoint',
        stateless_recovery_context: {
          verified_task_head: '20b8c26f88c4479d4a5028988152bce5314640db',
          expected_clean_worktree: true,
          last_authoritative_remote_sync: '2026-10-02T02:00:00Z'
        }
      }
    },
    seal: {
      status: 'PROVISIONAL',
      hash_algorithm: 'SHA-256',
      canonicalization_algorithm: 'RFC-8785',
      payload_sha256: null,
      sealed_at: null,
      sealed_by: null,
      seal_signature: null
    }
  };
}

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
        console.error(`FAIL: ${name} -> ${res.error}`);
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
        if (!expectedErrFragment || res.error.includes(expectedErrFragment)) {
          negativePassed++;
        } else {
          console.error(`FAIL: ${name} -> wrong error message. Expected fragment "${expectedErrFragment}", got "${res.error}"`);
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

  // 1. POSITIVE TESTS
  assertPositive('POSITIVE A: Structurally valid PROVISIONAL Command Capsule', () => {
    const c = buildSampleProvisionalCapsule();
    return validateCapsuleComplete(schema, c);
  });

  assertPositive('POSITIVE B: Valid read-only capsule with zero changed files', () => {
    const c = buildSampleProvisionalCapsule();
    c.payload.scope_boundary.max_write_files_limit = 0;
    c.payload.changes_and_evidence.expected_changed_files = [];
    c.payload.changes_and_evidence.actual_changed_files = [];
    return validateCapsuleComplete(schema, c);
  });

  assertPositive('POSITIVE C: Structurally valid SEALED capsule with non-null SHA-256 parent', () => {
    const c = buildSampleProvisionalCapsule();
    c.seal.status = 'SEALED';
    c.seal.payload_sha256 = 'b3d47a6f732512a9f5b19668a07bb4d2c662adf316f5a1d33a6d52c57860ec60';
    c.seal.sealed_at = '2026-10-02T02:00:00Z';
    c.seal.sealed_by = 'jirisar7-eng';
    c.payload.lineage.parent_capsules[0].payload_sha256 = 'a'.repeat(64);
    return validateCapsuleComplete(schema, c);
  });

  assertPositive('POSITIVE D: Valid source_blob_shas additionalProperties matching lowercase 40-hex SHA', () => {
    const c = buildSampleProvisionalCapsule();
    c.payload.changes_and_evidence.source_blob_shas = {
      'file1.txt': '1171fbab2c694617821ddf92006a876ed08086ea',
      'path/to/file2.json': 'a'.repeat(40)
    };
    return validateCapsuleComplete(schema, c);
  });

  assertPositive('POSITIVE E: Valid leap-day and timezone-offset date-times', () => {
    const c = buildSampleProvisionalCapsule();
    c.payload.execution_metadata.execution_timestamp = '2024-02-29T12:00:00Z';
    const res1 = validateCapsuleComplete(schema, c);
    if (!res1.valid) return res1;
    c.payload.execution_metadata.execution_timestamp = '2026-10-02T10:00:00+02:00';
    return validateCapsuleComplete(schema, c);
  });

  // POSITIVE F (POSITIVE B): additionalProperties schema map may legitimately have keys named constructor, toString, __proto__, proto with valid schema values
  assertPositive('POSITIVE F: additionalProperties map with special keys (constructor, toString, __proto__, proto) having valid values', () => {
    const c = buildSampleProvisionalCapsule();
    const shas = c.payload.changes_and_evidence.source_blob_shas;
    shas['constructor'] = 'a'.repeat(40);
    shas['toString'] = 'b'.repeat(40);
    shas['proto'] = 'c'.repeat(40);
    Object.defineProperty(shas, '__proto__', {
      value: 'd'.repeat(40),
      enumerable: true,
      configurable: true,
      writable: true
    });
    return validateCapsuleComplete(schema, c);
  });

  // 2. NEGATIVE TESTS
  assertNegative('1. Missing payload', () => {
    const c = buildSampleProvisionalCapsule();
    delete c.payload;
    return validateCapsuleComplete(schema, c);
  }, 'Missing required property "payload"');

  assertNegative('2. Missing seal', () => {
    const c = buildSampleProvisionalCapsule();
    delete c.seal;
    return validateCapsuleComplete(schema, c);
  }, 'Missing required property "seal"');

  assertNegative('3. Unexpected top-level schema_version', () => {
    const c = buildSampleProvisionalCapsule();
    c.schema_version = '1.0.0';
    return validateCapsuleComplete(schema, c);
  }, 'Unexpected additional property "schema_version"');

  assertNegative('4. Invalid payload.schema_version', () => {
    const c = buildSampleProvisionalCapsule();
    c.payload.schema_version = '2.0.0';
    return validateCapsuleComplete(schema, c);
  }, 'Const value mismatch');

  assertNegative('5. Invalid payload.capsule_type', () => {
    const c = buildSampleProvisionalCapsule();
    c.payload.capsule_type = 'UNSUPPORTED_TYPE';
    return validateCapsuleComplete(schema, c);
  }, 'Enum mismatch');

  assertNegative('6. Wrong Genesis anchor SHA-256', () => {
    const c = buildSampleProvisionalCapsule();
    c.payload.lineage.genesis_anchor_reference.pinned_sha256 = '0'.repeat(64);
    return validateCapsuleComplete(schema, c);
  }, 'Const value mismatch');

  assertNegative('7. SEALED capsule with null parent payload hash', () => {
    const c = buildSampleProvisionalCapsule();
    c.seal.status = 'SEALED';
    c.seal.payload_sha256 = 'a'.repeat(64);
    c.seal.sealed_at = '2026-10-02T02:00:00Z';
    c.seal.sealed_by = 'jirisar7-eng';
    c.payload.lineage.parent_capsules[0].payload_sha256 = null;
    return validateCapsuleComplete(schema, c);
  }, 'Type mismatch');

  assertNegative('8. SEALED capsule with malformed parent SHA-256', () => {
    const c = buildSampleProvisionalCapsule();
    c.seal.status = 'SEALED';
    c.seal.payload_sha256 = 'a'.repeat(64);
    c.seal.sealed_at = '2026-10-02T02:00:00Z';
    c.seal.sealed_by = 'jirisar7-eng';
    c.payload.lineage.parent_capsules[0].payload_sha256 = 'invalid-hex';
    return validateCapsuleComplete(schema, c);
  }, 'Pattern mismatch');

  assertNegative('9. Missing nested required identity (task_id)', () => {
    const c = buildSampleProvisionalCapsule();
    delete c.payload.task_id;
    return validateCapsuleComplete(schema, c);
  }, 'Missing required property "task_id"');

  assertNegative('10. Unexpected field in strict governed object', () => {
    const c = buildSampleProvisionalCapsule();
    c.payload.scope_boundary.unauthorized_extra_field = true;
    return validateCapsuleComplete(schema, c);
  }, 'Unexpected additional property "unauthorized_extra_field"');

  assertNegative('11. Invalid execution timestamp format', () => {
    const c = buildSampleProvisionalCapsule();
    c.payload.execution_metadata.execution_timestamp = 'not-a-datetime';
    return validateCapsuleComplete(schema, c);
  }, 'Format mismatch');

  assertNegative('12. Invalid Git commit SHA format', () => {
    const c = buildSampleProvisionalCapsule();
    c.payload.changes_and_evidence.commit_sha = 'short_sha';
    return validateCapsuleComplete(schema, c);
  }, 'Pattern mismatch');

  assertNegative('13. Malformed capsule JSON text parsing via production parseCapsuleJson', () => {
    const parsed = parseCapsuleJson('{ malformed json');
    if (!parsed.ok) {
      return { valid: false, error: parsed.error };
    }
    return { valid: true };
  }, 'JSON_PARSE_ERROR');

  assertNegative('14. Unsupported schema assertion keyword', () => {
    const badSchema = JSON.parse(JSON.stringify(schema));
    badSchema.properties.payload.properties.unsupported_keyword_field = {
      unsupportedKeyword: true
    };
    const c = buildSampleProvisionalCapsule();
    return validateInstance(badSchema, c);
  }, 'Unsupported schema assertion keyword "unsupportedKeyword"');

  assertNegative('15. Changed-file count exceeding declared write-file limit', () => {
    const c = buildSampleProvisionalCapsule();
    c.payload.scope_boundary.max_write_files_limit = 1;
    c.payload.changes_and_evidence.actual_changed_files = ['file1.js', 'file2.js'];
    return validateCapsuleComplete(schema, c);
  }, 'exceeds declared write-file limit');

  assertNegative('16. Capsule referencing itself as parent', () => {
    const c = buildSampleProvisionalCapsule();
    c.payload.lineage.parent_capsules.push({
      capsule_id: c.payload.capsule_id,
      command_id: c.payload.command_id,
      payload_sha256: null,
      relationship_type: 'LINEAR_PARENT'
    });
    return validateCapsuleComplete(schema, c);
  }, 'Capsule cannot reference itself as parent');

  assertNegative('17. Invalid source_blob_shas value failing additionalProperties schema', () => {
    const c = buildSampleProvisionalCapsule();
    c.payload.changes_and_evidence.source_blob_shas = {
      'file1.txt': 'invalid-sha'
    };
    return validateCapsuleComplete(schema, c);
  }, 'Pattern mismatch');

  assertNegative('18. Unsupported assertion keyword inside nested additionalProperties schema', () => {
    const badSchema = JSON.parse(JSON.stringify(schema));
    badSchema.properties.payload.properties.changes_and_evidence.properties.source_blob_shas.additionalProperties = {
      type: 'string',
      unsupportedNestedKey: 123
    };
    const c = buildSampleProvisionalCapsule();
    return validateInstance(badSchema, c);
  }, 'Unsupported schema assertion keyword "unsupportedNestedKey"');

  assertNegative('19. Impossible calendar date rejected (2026-02-30)', () => {
    const c = buildSampleProvisionalCapsule();
    c.payload.execution_metadata.execution_timestamp = '2026-02-30T02:00:00Z';
    return validateCapsuleComplete(schema, c);
  }, 'Format mismatch');

  assertNegative('20. Strict CLI argument rejection for unsupported or surplus arguments', () => {
    const testCases = [
      ['--self-test', '--unexpected'],
      ['--help', '--unexpected'],
      ['capsule.json', '--unexpected'],
      ['--unknown']
    ];
    for (const testArgs of testCases) {
      const run = child_process.spawnSync(process.execPath, [__filename, ...testArgs], { encoding: 'utf-8' });
      if (run.status === 0) {
        return { valid: true }; // Should not succeed!
      }
    }
    return { valid: false, error: 'CLI_STRICT_ARGUMENTS_REJECTED' };
  }, 'CLI_STRICT_ARGUMENTS_REJECTED');

  // 21. Extra own property "constructor" at root rejected (NEGATIVE A)
  assertNegative('21. Extra own property "constructor" at root rejected (NEGATIVE A)', () => {
    const c = buildSampleProvisionalCapsule();
    Object.defineProperty(c, 'constructor', {
      value: 'malicious',
      enumerable: true,
      configurable: true,
      writable: true
    });
    return validateCapsuleComplete(schema, c);
  }, 'Unexpected additional property "constructor"');

  // 22. Extra own property "toString" at root rejected (NEGATIVE B)
  assertNegative('22. Extra own property "toString" at root rejected (NEGATIVE B)', () => {
    const c = buildSampleProvisionalCapsule();
    Object.defineProperty(c, 'toString', {
      value: () => 'malicious',
      enumerable: true,
      configurable: true,
      writable: true
    });
    return validateCapsuleComplete(schema, c);
  }, 'Unexpected additional property "toString"');

  // 23. Extra own property "__proto__" at root rejected (NEGATIVE C)
  assertNegative('23. Extra own property "__proto__" at root rejected (NEGATIVE C)', () => {
    const c = buildSampleProvisionalCapsule();
    Object.defineProperty(c, '__proto__', {
      value: { polluted: true },
      enumerable: true,
      configurable: true,
      writable: true
    });
    return validateCapsuleComplete(schema, c);
  }, 'Unexpected additional property "__proto__"');

  // 24. Extra own property "proto" at root rejected (NEGATIVE C variant)
  assertNegative('24. Extra own property "proto" at root rejected (NEGATIVE C variant)', () => {
    const c = buildSampleProvisionalCapsule();
    Object.defineProperty(c, 'proto', {
      value: { polluted: true },
      enumerable: true,
      configurable: true,
      writable: true
    });
    return validateCapsuleComplete(schema, c);
  }, 'Unexpected additional property "proto"');

  // 25. Nested object additionalProperties: false rejects own property "constructor" (NEGATIVE D)
  assertNegative('25. Nested object additionalProperties: false rejects own property "constructor" (NEGATIVE D)', () => {
    const c = buildSampleProvisionalCapsule();
    Object.defineProperty(c.payload, 'constructor', {
      value: 'nested_ctor',
      enumerable: true,
      configurable: true,
      writable: true
    });
    return validateCapsuleComplete(schema, c);
  }, 'Unexpected additional property "constructor"');

  // 26. Inherited prototype property cannot satisfy missing required own property payload.task_id (NEGATIVE E)
  assertNegative('26. Inherited prototype property cannot satisfy missing required own property payload.task_id (NEGATIVE E)', () => {
    const c = buildSampleProvisionalCapsule();
    delete c.payload.task_id;
    const protoWithTaskId = Object.create(Object.prototype);
    protoWithTaskId.task_id = 'SYN-MINI-INHERITED-TASK-ID';
    Object.setPrototypeOf(c.payload, protoWithTaskId);
    return validateCapsuleComplete(schema, c);
  }, 'Missing required property "task_id"');

  // 27. Inherited property cannot satisfy nested required field lineage.genesis_anchor_reference.pinned_sha256 (NEGATIVE F)
  assertNegative('27. Inherited property cannot satisfy nested required field lineage.genesis_anchor_reference.pinned_sha256 (NEGATIVE F)', () => {
    const c = buildSampleProvisionalCapsule();
    delete c.payload.lineage.genesis_anchor_reference.pinned_sha256;
    const protoWithSha = { pinned_sha256: 'b3d47a6f732512a9f5b19668a07bb4d2c662adf316f5a1d33a6d52c57860ec60' };
    Object.setPrototypeOf(c.payload.lineage.genesis_anchor_reference, protoWithSha);
    return validateCapsuleComplete(schema, c);
  }, 'Missing required property "pinned_sha256"');

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

  if (args.length !== 1) {
    console.error(`Error: Expected exactly 1 argument, got ${args.length}: [${args.join(', ')}]`);
    console.error(`Usage:`);
    console.error(`  node scripts/governance/validate_command_capsule.mjs --self-test`);
    console.error(`  node scripts/governance/validate_command_capsule.mjs --help`);
    console.error(`  node scripts/governance/validate_command_capsule.mjs <path-to-capsule.json>`);
    process.exit(1);
  }

  const arg = args[0];

  if (arg === '--help' || arg === '-h') {
    console.log(`Synthesis CMS mini — Command Capsule Validator`);
    console.log(`Usage:`);
    console.log(`  node scripts/governance/validate_command_capsule.mjs --self-test`);
    console.log(`  node scripts/governance/validate_command_capsule.mjs --help`);
    console.log(`  node scripts/governance/validate_command_capsule.mjs <path-to-capsule.json>`);
    process.exit(0);
  }

  if (arg === '--self-test') {
    console.log(`Running Command Capsule Validator self-tests...`);
    const results = runSelfTests(repoRoot);
    console.log(`POSITIVE_TESTS_PASSED: ${results.positivePassed}`);
    console.log(`NEGATIVE_TESTS_PASSED: ${results.negativePassed}`);
    console.log(`FAILED_TESTS: ${results.failedTests}`);
    console.log(`SCHEMA_INSTANCE_VALIDATION_STATUS: ${results.failedTests === 0 ? 'PASS' : 'FAIL'}`);
    console.log(`CRYPTOGRAPHIC_VERIFICATION_STATUS: CRYPTOGRAPHIC_SEAL_NOT_VERIFIED`);

    if (results.failedTests > 0 || results.positivePassed < 5 || results.negativePassed < 20) {
      process.exit(1);
    }
    process.exit(0);
  }

  if (arg.startsWith('--')) {
    console.error(`Error: Unsupported option "${arg}". Only --self-test and --help are supported.`);
    process.exit(1);
  }

  // Validate single file
  const filePath = arg;
  if (!fs.existsSync(filePath)) {
    console.error(`Error: File not found: ${filePath}`);
    process.exit(1);
  }

  try {
    const schema = loadSchema(repoRoot);
    const rawContent = fs.readFileSync(filePath, 'utf-8');
    const parsed = parseCapsuleJson(rawContent);
    if (!parsed.ok) {
      console.error(`VALIDATION FAILED [JSON_PARSE]: ${parsed.error}`);
      process.exit(1);
    }
    const capsule = parsed.data;
    const res = validateCapsuleComplete(schema, capsule);
    if (res.valid) {
      console.log(`SCHEMA_INSTANCE_VALIDATION_STATUS: PASS`);
      console.log(`SEALED_STRUCTURAL_VALIDATION: ${res.status}`);
      console.log(`CRYPTOGRAPHIC_VERIFICATION_STATUS: CRYPTOGRAPHIC_SEAL_NOT_VERIFIED`);
      process.exit(0);
    } else {
      console.error(`VALIDATION FAILED [${res.stage}]: ${res.error}`);
      process.exit(1);
    }
  } catch (err) {
    console.error(`Error validating capsule: ${err.message}`);
    process.exit(1);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  main();
}
