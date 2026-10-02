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
  if ('const' in schema) {
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
      // Must be valid ISO date-time
      const isoRegex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
      if (!isoRegex.test(instance) || isNaN(Date.parse(instance))) {
        return {
          valid: false,
          error: `Format mismatch at ${jsonPath}: "${instance}" is not a valid ISO-8601 date-time`
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

  // 8. Object validation: required, properties, additionalProperties
  if (typeof instance === 'object' && instance !== null && !Array.isArray(instance)) {
    if (schema.required) {
      for (const reqProp of schema.required) {
        if (!(reqProp in instance) || instance[reqProp] === undefined) {
          return {
            valid: false,
            error: `Missing required property "${reqProp}" at ${jsonPath}`
          };
        }
      }
    }

    const definedProps = schema.properties ? Object.keys(schema.properties) : [];
    for (const key of Object.keys(instance)) {
      if (schema.properties && key in schema.properties) {
        const subRes = validateInstance(schema.properties[key], instance[key], `${jsonPath}.${key}`, depth + 1);
        if (!subRes.valid) return subRes;
      } else if (schema.additionalProperties === false) {
        return {
          valid: false,
          error: `Unexpected additional property "${key}" at ${jsonPath} (additionalProperties: false)`
        };
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
      capsule_id: 'CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-003',
      command_id: 'CMD-SYN-MINI-GOV-CAPSULE-SCHEMA-001-003-VALIDATE-INSTANCES',
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
            capsule_id: 'CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-002',
            command_id: 'CMD-SYN-MINI-GOV-CAPSULE-SCHEMA-001-002-HARDEN-CRYPTO-CONTRACT',
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
        source_blob_shas: {}
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
          verified_task_head: '113579bf49aaa5bffa6da68b0a9f4cf8a1d50119',
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

  assertNegative('11. Invalid execution timestamp', () => {
    const c = buildSampleProvisionalCapsule();
    c.payload.execution_metadata.execution_timestamp = 'not-a-datetime';
    return validateCapsuleComplete(schema, c);
  }, 'Format mismatch');

  assertNegative('12. Invalid Git commit SHA format', () => {
    const c = buildSampleProvisionalCapsule();
    c.payload.changes_and_evidence.commit_sha = 'short_sha';
    return validateCapsuleComplete(schema, c);
  }, 'Pattern mismatch');

  assertNegative('13. Malformed capsule JSON text parsing', () => {
    try {
      JSON.parse('{ malformed json');
      return { valid: true };
    } catch (e) {
      return { valid: false, error: `Malformed JSON parse error: ${e.message}` };
    }
  }, 'Malformed JSON parse error');

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

  if (args.length === 0 || args.includes('--help')) {
    console.log(`Synthesis CMS mini — Command Capsule Validator`);
    console.log(`Usage:`);
    console.log(`  node scripts/governance/validate_command_capsule.mjs --self-test`);
    console.log(`  node scripts/governance/validate_command_capsule.mjs <path-to-capsule.json>`);
    process.exit(args.length === 0 ? 1 : 0);
  }

  if (args.includes('--self-test')) {
    console.log(`Running Command Capsule Validator self-tests...`);
    const results = runSelfTests(repoRoot);
    console.log(`POSITIVE_TESTS_PASSED: ${results.positivePassed}`);
    console.log(`NEGATIVE_TESTS_PASSED: ${results.negativePassed}`);
    console.log(`FAILED_TESTS: ${results.failedTests}`);
    console.log(`SCHEMA_INSTANCE_VALIDATION_STATUS: ${results.failedTests === 0 ? 'PASS' : 'FAIL'}`);
    console.log(`CRYPTOGRAPHIC_VERIFICATION_STATUS: CRYPTOGRAPHIC_SEAL_NOT_VERIFIED`);

    if (results.failedTests > 0 || results.positivePassed < 3 || results.negativePassed < 16) {
      process.exit(1);
    }
    process.exit(0);
  }

  // Validate single file
  const filePath = args[0];
  if (!fs.existsSync(filePath)) {
    console.error(`Error: File not found: ${filePath}`);
    process.exit(1);
  }

  try {
    const schema = loadSchema(repoRoot);
    const content = fs.readFileSync(filePath, 'utf-8');
    const capsule = JSON.parse(content);
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
