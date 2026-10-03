#!/usr/bin/env node
/**
 * Synthesis CMS mini — Capability Registry JSON Schema Integrity Verifier
 *
 * Task: SYN-MINI-GOV-CAPABILITY-REGISTRY-001
 * Roadmap Step: 3/60 — CAPABILITY / FEATURE REGISTRY
 *
 * Permanently guards the formal JSON Schema Draft 2020-12 definition of the
 * Capability Registry against malformed keywords, empty properties, broken
 * local $ref references, missing definitions, and schema drift.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseStrictIJson } from "./verify_capsule_seal.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const DEFAULT_SCHEMA_REL_PATH = ".synthesis/schemas/capability-registry.schema.json";
export const EXPECTED_DIALECT = "https://json-schema.org/draft/2020-12/schema";
export const EXPECTED_SCHEMA_ID = "https://synthesis-cms-mini.org/schemas/capability-registry.schema.json";

export function findRepoRoot(startDir = __dirname) {
  let curr = path.resolve(startDir);
  while (true) {
    if (fs.existsSync(path.join(curr, ".synthesis", "lineage", "genesis.json"))) {
      return curr;
    }
    const parent = path.dirname(curr);
    if (parent === curr) break;
    curr = parent;
  }
  return path.resolve(__dirname, "..", "..");
}

/**
 * Validates a parsed capability schema object for strict structural and referential integrity.
 */
export function validateCapabilitySchemaObject(schemaObj) {
  if (!schemaObj || typeof schemaObj !== "object" || Array.isArray(schemaObj)) {
    return { valid: false, stage: "SCHEMA_ROOT_TYPE_INVALID", error: "Root schema must be a non-null JSON object." };
  }

  // 1. Dialect & ID
  if (schemaObj["$schema"] !== EXPECTED_DIALECT) {
    return { valid: false, stage: "SCHEMA_DIALECT_MISMATCH", error: `Expected $schema dialect "${EXPECTED_DIALECT}", got "${schemaObj["$schema"]}".` };
  }
  if (schemaObj["$id"] !== EXPECTED_SCHEMA_ID) {
    return { valid: false, stage: "SCHEMA_ID_MISMATCH", error: `Expected $id "${EXPECTED_SCHEMA_ID}", got "${schemaObj["$id"]}".` };
  }

  // 2. Reject empty keys at root or in objects
  function checkNoEmptyKeys(obj, pathStr = "$") {
    if (!obj || typeof obj !== "object") return null;
    for (const key of Object.keys(obj)) {
      if (key === "") {
        return `Empty property name detected at ${pathStr}`;
      }
      const val = obj[key];
      if (val && typeof val === "object") {
        const err = checkNoEmptyKeys(val, `${pathStr}.${key}`);
        if (err) return err;
      }
    }
    return null;
  }
  const emptyKeyErr = checkNoEmptyKeys(schemaObj);
  if (emptyKeyErr) {
    return { valid: false, stage: "EMPTY_PROPERTY_NAME_DETECTED", error: emptyKeyErr };
  }

  // 3. Root mandatory fields and constraints
  const rootRequired = ["schema_version", "format_version", "record_kind", "status", "capabilities"];
  if (!Array.isArray(schemaObj.required) || !rootRequired.every(r => schemaObj.required.includes(r))) {
    return { valid: false, stage: "ROOT_REQUIRED_FIELDS_INVALID", error: "Root schema required array missing required property declarations." };
  }
  if (schemaObj.additionalProperties !== false) {
    return { valid: false, stage: "ROOT_ADDITIONAL_PROPERTIES_NOT_FALSE", error: "Root schema must declare additionalProperties: false." };
  }

  // 4. Validate $defs
  if (!schemaObj["$defs"] || typeof schemaObj["$defs"] !== "object" || Array.isArray(schemaObj["$defs"])) {
    return { valid: false, stage: "SCHEMA_DEFS_MISSING_OR_INVALID", error: "Root schema must contain a valid $defs object." };
  }
  const defs = schemaObj["$defs"];
  if (!defs.capability_entry || typeof defs.capability_entry !== "object") {
    return { valid: false, stage: "CAPABILITY_ENTRY_DEF_MISSING", error: "$defs must define capability_entry." };
  }
  if (!defs.capability_dependency || typeof defs.capability_dependency !== "object") {
    return { valid: false, stage: "CAPABILITY_DEPENDENCY_DEF_MISSING", error: "$defs must define capability_dependency." };
  }

  // 5. Check all $ref pointers in schema
  function validateAllRefs(obj, pathStr = "$") {
    if (!obj || typeof obj !== "object") return null;
    if (typeof obj["$ref"] === "string") {
      const ref = obj["$ref"];
      if (!ref.startsWith("#/$defs/")) {
        return `Malformed local $ref "${ref}" at ${pathStr}; must start with "#/$defs/"`;
      }
      const defName = ref.slice("#/$defs/".length);
      if (!defs[defName]) {
        return `Dangling $ref "${ref}" at ${pathStr}; definition "${defName}" does not exist in $defs.`;
      }
    }
    for (const key of Object.keys(obj)) {
      if (key !== "$ref" && obj[key] && typeof obj[key] === "object") {
        const err = validateAllRefs(obj[key], `${pathStr}.${key}`);
        if (err) return err;
      }
    }
    return null;
  }
  const refErr = validateAllRefs(schemaObj);
  if (refErr) {
    return { valid: false, stage: "SCHEMA_REF_INVALID", error: refErr };
  }

  // 6. Verify required $ref relationships
  const capItems = schemaObj.properties?.capabilities?.items;
  if (!capItems || capItems["$ref"] !== "#/$defs/capability_entry") {
    return { valid: false, stage: "CAPABILITIES_ITEMS_REF_INVALID", error: "capabilities.items must reference #/$defs/capability_entry via $ref." };
  }
  const reqItems = defs.capability_entry?.properties?.requires?.items;
  if (!reqItems || reqItems["$ref"] !== "#/$defs/capability_dependency") {
    return { valid: false, stage: "REQUIRES_ITEMS_REF_INVALID", error: "capability_entry.requires.items must reference #/$defs/capability_dependency via $ref." };
  }

  return { valid: true, stage: "SCHEMA_VALID", error: null };
}

/**
 * Validates the capability registry schema file from disk.
 */
export function verifyCapabilitySchemaFile(filePath) {
  if (!fs.existsSync(filePath)) {
    return { valid: false, stage: "FILE_NOT_FOUND", error: `Schema file not found at ${filePath}` };
  }
  const stat = fs.lstatSync(filePath);
  if (stat.isSymbolicLink()) {
    return { valid: false, stage: "UNSAFE_SYMLINK", error: `Schema file must not be a symlink: ${filePath}` };
  }

  const rawBytes = fs.readFileSync(filePath);
  const rawText = rawBytes.toString("utf-8");

  let parsed;
  try {
    parsed = parseStrictIJson(rawText);
  } catch (err) {
    return { valid: false, stage: "JSON_PARSE_ERROR", error: `I-JSON parse failed: ${err.message}` };
  }

  return validateCapabilitySchemaObject(parsed);
}

/**
 * Self-test suite for capability schema integrity verifier.
 */
export function runSelfTests(repoRoot = findRepoRoot()) {
  console.log("[SCHEMA-GUARD] Running Capability Schema Verifier Behavioral Self-Tests...");
  let positivePassed = 0;
  let negativePassed = 0;
  let failed = 0;

  function passPositive(name) {
    positivePassed++;
    console.log(`  ✓ POSITIVE ${positivePassed}: ${name}`);
  }
  function passNegative(code, name) {
    negativePassed++;
    console.log(`  ✓ NEGATIVE ${code}: ${name}`);
  }
  function failTest(name, err) {
    failed++;
    console.error(`  ✗ FAILED: ${name}: ${err.message || err}`);
  }

  const schemaPath = path.join(repoRoot, DEFAULT_SCHEMA_REL_PATH);
  const validRaw = fs.readFileSync(schemaPath, "utf-8");
  const validObj = parseStrictIJson(validRaw);

  // POSITIVE 1: Valid schema file passes
  try {
    const res = verifyCapabilitySchemaFile(schemaPath);
    if (res.valid) {
      passPositive("Current live capability-registry.schema.json passes verification");
    } else {
      throw new Error(`Expected live schema to pass, got: ${res.stage}: ${res.error}`);
    }
  } catch (err) { failTest("Positive 1: live schema valid", err); }

  // Helper to assert negative case
  function assertNegative(code, name, modifier, expectedStage) {
    try {
      const clone = JSON.parse(JSON.stringify(validObj));
      modifier(clone);
      const res = validateCapabilitySchemaObject(clone);
      if (!res.valid && (!expectedStage || res.stage === expectedStage)) {
        passNegative(code, `${name} (rejected with ${res.stage})`);
      } else if (res.valid) {
        throw new Error(`Expected failure with stage ${expectedStage}, but validator returned VALID`);
      } else {
        throw new Error(`Expected stage ${expectedStage}, got ${res.stage}: ${res.error}`);
      }
    } catch (err) { failTest(`Negative ${code}: ${name}`, err); }
  }

  // NEG-01: Missing $schema
  assertNegative("NEG-01", "Missing $schema dialect", c => { delete c["$schema"]; }, "SCHEMA_DIALECT_MISMATCH");

  // NEG-02: Missing $defs
  assertNegative("NEG-02", "Missing $defs object", c => { delete c["$defs"]; }, "SCHEMA_DEFS_MISSING_OR_INVALID");

  // NEG-03: Empty definition keyword
  assertNegative("NEG-03", "Empty keyword in root object", c => { c[""] = c["$defs"]; delete c["$defs"]; }, "EMPTY_PROPERTY_NAME_DETECTED");

  // NEG-04: Empty reference keyword in items
  assertNegative("NEG-04", "Empty keyword in items reference", c => {
    c.properties.capabilities.items = { "": "#/$defs/capability_entry" };
  }, "EMPTY_PROPERTY_NAME_DETECTED");

  // NEG-05: Malformed JSON Pointer in $ref
  assertNegative("NEG-05", "Malformed JSON Pointer in $ref", c => {
    c.properties.capabilities.items = { "$ref": "#//capability_entry" };
  }, "SCHEMA_REF_INVALID");

  // NEG-06: Missing referenced definition (dangling pointer)
  assertNegative("NEG-06", "Dangling $ref to non-existent definition", c => {
    c.properties.capabilities.items = { "$ref": "#/$defs/non_existent_entry" };
  }, "SCHEMA_REF_INVALID");

  // NEG-07: Duplicate JSON property rejected by parser
  try {
    const jsonWithDup = '{"$schema":"https://json-schema.org/draft/2020-12/schema","$schema":"duplicate"}';
    let dupFailed = false;
    try {
      parseStrictIJson(jsonWithDup);
    } catch (e) {
      dupFailed = true;
    }
    if (dupFailed) {
      passNegative("NEG-07", "Duplicate JSON property rejected by strict parser");
    } else {
      throw new Error("Strict parser accepted duplicate property key");
    }
  } catch (err) { failTest("Negative NEG-07: duplicate property", err); }

  // NEG-08: Missing capability_entry definition
  assertNegative("NEG-08", "Missing capability_entry in $defs", c => {
    delete c["$defs"].capability_entry;
  }, "CAPABILITY_ENTRY_DEF_MISSING");

  // NEG-09: Missing capability_dependency definition
  assertNegative("NEG-09", "Missing capability_dependency in $defs", c => {
    delete c["$defs"].capability_dependency;
  }, "CAPABILITY_DEPENDENCY_DEF_MISSING");

  // NEG-10: Invalid required-field structure
  assertNegative("NEG-10", "Missing required field in root declaration", c => {
    c.required = ["schema_version"];
  }, "ROOT_REQUIRED_FIELDS_INVALID");

  console.log(`[SCHEMA-GUARD] Summary: ${positivePassed} positive passed, ${negativePassed} negative passed, ${failed} failed.`);
  return { positivePassed, negativePassed, failed, ok: failed === 0 };
}

// CLI entry point
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.length === 0) {
    console.log("Synthesis CMS mini — Capability Schema Integrity Verifier");
    console.log("Usage:");
    console.log("  node scripts/governance/verify_capability_schema.mjs --self-test");
    console.log("  node scripts/governance/verify_capability_schema.mjs --verify-all");
    console.log("  node scripts/governance/verify_capability_schema.mjs --help");
    process.exit(0);
  }

  if (args.includes("--self-test")) {
    const res = runSelfTests();
    process.exit(res.ok ? 0 : 1);
  }

  if (args.includes("--verify-all")) {
    const repoRoot = findRepoRoot();
    const schemaPath = path.join(repoRoot, DEFAULT_SCHEMA_REL_PATH);
    const res = verifyCapabilitySchemaFile(schemaPath);
    if (res.valid) {
      console.log("CAPABILITY_SCHEMA_VERIFICATION: PASS");
      console.log(`SCHEMA_PATH: ${DEFAULT_SCHEMA_REL_PATH}`);
      console.log(`DIALECT: ${EXPECTED_DIALECT}`);
      console.log("SCHEMA_FULL_DRAFT_2020_12_VALIDATION: NOT_EXECUTED");
      process.exit(0);
    } else {
      console.error(`CAPABILITY_SCHEMA_VERIFICATION: FAIL [${res.stage}]: ${res.error}`);
      process.exit(1);
    }
  }

  console.error("Unknown argument. Use --help for usage instructions.");
  process.exit(1);
}
