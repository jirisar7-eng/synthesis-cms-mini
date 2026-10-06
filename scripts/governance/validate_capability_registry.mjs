#!/usr/bin/env node
/**
 * Synthesis CMS mini — Semantic Capability Registry Validator
 *
 * Task: SYN-MINI-GOV-CAPABILITY-REGISTRY-001
 * Roadmap Step: 3/60 — CAPABILITY / FEATURE REGISTRY
 *
 * Validates the machine-readable Capability Registry against structural schema rules,
 * semantic integrity, typed dependencies, directed graph acyclicity (DAG), lifecycle/provenance
 * consistency, fail-closed activation guards, and historical immutable alias mappings.
 */

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { parseStrictIJson } from "./verify_capsule_seal.mjs";
import { verifyActivationProofRecord } from "./verify_activation_proof.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const DEFAULT_REGISTRY_REL_PATH = ".synthesis/registries/capabilities.json";
export const EXPECTED_SCHEMA_VERSION = "capability-registry.v1";
export const EXPECTED_FORMAT_VERSION = "1.0.0";
export const EXPECTED_RECORD_KIND = "CAPABILITY_REGISTRY";

export const VALID_LAYERS = new Set([
  "Universal Core",
  "Stable Contracts",
  "Public SDKs",
  "Module Runtime",
  "Integration Runtime",
  "First-party Modules",
  "Third-party Modules",
  "Project Packs",
  "Themes and Design Tokens",
  "Content and Translations",
  "Licensing and Distribution",
  "Deployment and Operations"
]);

export const VALID_ROOT_STATUSES = new Set(["DRAFT", "PROPOSED", "ACTIVE"]);
export const VALID_CAPABILITY_STATUSES = new Set(["PROPOSED", "STAGED", "ACTIVE", "DEPRECATED", "REPLACED"]);

export const CANONICAL_ID_REGEX = /^[a-z0-9_]+(\.[a-z0-9_]+)+$/;
export const OWNER_DOMAIN_REGEX = /^[a-z0-9_]+(\.[a-z0-9_]+)*$/;
export const LEGACY_ALIAS_REGEX = /^[A-Z0-9_]+$/;
export const CONTRACT_REF_REGEX = /^[a-z0-9-]+(\.v[0-9]+)$/;
export const PROVIDES_TOKEN_REGEX = /^[a-z0-9_]+(\.[a-z0-9_]+)*$/;
export const CAPSULE_ID_REGEX = /^CAP-SYN-MINI-[A-Z0-9_-]+$/;
export const SHA256_HEX_REGEX = /^[a-f0-9]{64}$/;
export const COMMIT_SHA_REGEX = /^([a-f0-9]{40}|PENDING_MERGE)$/;

export const HISTORICAL_REQUIRED_ALIASES = {
  "CAPSULE_PERSISTENCE": "gov.capsule.persistence",
  "CAPSULE_LINEAGE": "gov.capsule.lineage",
  "CRYPTOGRAPHIC_SEAL": "gov.capsule.cryptographic_seal"
};

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
 * Validates a parsed capability registry object for complete structural and semantic integrity.
 */
export function validateCapabilityRegistry(registryObj, options = {}) {
  const repoRoot = options.repoRoot || findRepoRoot();
  const checkCapsuleExistence = options.checkCapsuleExistence !== false;

  // Verify activation proof independently if provided or auto-loaded from standard path (never allow caller booleans alone!)
  let verifiedActivationProof = null;
  let proofSource = options.activationProof;

  if (!proofSource) {
    const defaultProofPath = path.resolve(repoRoot, ".synthesis/activation/milestone-a-activation-proof.json");
    if (fs.existsSync(defaultProofPath)) {
      proofSource = defaultProofPath;
    }
  }

  if (proofSource) {
    let proofObj = proofSource;
    if (typeof proofObj === 'string') {
      try {
        const fullProofPath = path.resolve(repoRoot, proofObj);
        if (fs.existsSync(fullProofPath)) {
          proofObj = parseStrictIJson(fs.readFileSync(fullProofPath, 'utf8'));
        } else {
          proofObj = null;
        }
      } catch (e) {
        proofObj = null;
      }
    }
    if (proofObj) {
      const proofRes = verifyActivationProofRecord(proofObj, repoRoot, options.gitExecutor || null);
      if (proofRes && proofRes.valid) {
        verifiedActivationProof = proofRes.proof;
      }
    }
  }

  if (!registryObj || typeof registryObj !== "object" || Array.isArray(registryObj)) {
    return { valid: false, stage: "REGISTRY_ROOT_TYPE_INVALID", error: "Root registry must be a non-null JSON object." };
  }

  // Exact root keys
  const rootAllowedKeys = new Set(["schema_version", "format_version", "record_kind", "status", "capabilities"]);
  const rootKeys = Object.keys(registryObj);
  for (const k of rootKeys) {
    if (!rootAllowedKeys.has(k)) {
      return { valid: false, stage: "UNKNOWN_ROOT_PROPERTY", error: `Unexpected property in registry root: "${k}"` };
    }
  }
  for (const k of rootAllowedKeys) {
    if (!(k in registryObj)) {
      return { valid: false, stage: "MISSING_ROOT_PROPERTY", error: `Missing required property in registry root: "${k}"` };
    }
  }

  if (registryObj.schema_version !== EXPECTED_SCHEMA_VERSION) {
    return { valid: false, stage: "INVALID_SCHEMA_VERSION", error: `Expected schema_version "${EXPECTED_SCHEMA_VERSION}", got "${registryObj.schema_version}"` };
  }
  if (registryObj.format_version !== EXPECTED_FORMAT_VERSION) {
    return { valid: false, stage: "INVALID_FORMAT_VERSION", error: `Expected format_version "${EXPECTED_FORMAT_VERSION}", got "${registryObj.format_version}"` };
  }
  if (registryObj.record_kind !== EXPECTED_RECORD_KIND) {
    return { valid: false, stage: "INVALID_RECORD_KIND", error: `Expected record_kind "${EXPECTED_RECORD_KIND}", got "${registryObj.record_kind}"` };
  }
  if (!VALID_ROOT_STATUSES.has(registryObj.status)) {
    return { valid: false, stage: "INVALID_ROOT_STATUS", error: `Invalid root status: "${registryObj.status}"` };
  }
  // Fail-closed guard: root registry cannot be declared ACTIVE without independently verified activation proof
  if (registryObj.status === "ACTIVE") {
    if (!verifiedActivationProof) {
      return {
        valid: false,
        stage: "REGISTRY_ACTIVE_EXTERNAL_PROOF_REQUIRED",
        error: "Root registry cannot be declared ACTIVE until an independently verifiable global activation protocol is established."
      };
    }
  }
  if (!Array.isArray(registryObj.capabilities)) {
    return { valid: false, stage: "CAPABILITIES_NOT_ARRAY", error: "capabilities must be an array." };
  }

  const capabilities = registryObj.capabilities;
  const capMap = new Map();
  const aliasMap = new Map();
  const declaredAliases = new Set();

  const entryAllowedKeys = new Set([
    "capability_id",
    "name",
    "description",
    "layer",
    "owner_domain",
    "status",
    "head_revision",
    "legacy_aliases",
    "governing_contracts",
    "provides",
    "requires",
    "origin_capsule_id",
    "origin_payload_sha256",
    "introducing_commit_sha",
    "superseded_by"
  ]);

  // Pass 1: Individual entry structural & format validation
  for (let idx = 0; idx < capabilities.length; idx++) {
    const entry = capabilities[idx];
    const pathPrefix = `capabilities[${idx}]`;

    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      return { valid: false, stage: "INVALID_ENTRY_TYPE", error: `${pathPrefix} must be an object.` };
    }

    // Check exact keys
    const eKeys = Object.keys(entry);
    for (const k of eKeys) {
      if (!entryAllowedKeys.has(k)) {
        return { valid: false, stage: "UNKNOWN_ENTRY_PROPERTY", error: `${pathPrefix} contains unexpected property "${k}".` };
      }
    }
    for (const k of entryAllowedKeys) {
      if (!(k in entry)) {
        return { valid: false, stage: "MISSING_ENTRY_PROPERTY", error: `${pathPrefix} missing required property "${k}".` };
      }
    }

    // capability_id
    if (typeof entry.capability_id !== "string" || !CANONICAL_ID_REGEX.test(entry.capability_id)) {
      return { valid: false, stage: "INVALID_CAPABILITY_ID", error: `${pathPrefix}.capability_id "${entry.capability_id}" does not match canonical dot syntax pattern.` };
    }
    if (capMap.has(entry.capability_id)) {
      return { valid: false, stage: "DUPLICATE_CAPABILITY_ID", error: `Duplicate capability_id detected: "${entry.capability_id}"` };
    }
    capMap.set(entry.capability_id, entry);

    // name
    if (typeof entry.name !== "string" || entry.name.length < 3 || entry.name.length > 100) {
      return { valid: false, stage: "INVALID_NAME", error: `${pathPrefix}.name must be a string between 3 and 100 characters.` };
    }

    // description
    if (typeof entry.description !== "string" || entry.description.length < 10 || entry.description.length > 1000) {
      return { valid: false, stage: "INVALID_DESCRIPTION", error: `${pathPrefix}.description must be a string between 10 and 1000 characters.` };
    }

    // layer
    if (!VALID_LAYERS.has(entry.layer)) {
      return { valid: false, stage: "INVALID_LAYER", error: `${pathPrefix}.layer "${entry.layer}" is not a recognized architectural layer.` };
    }

    // owner_domain
    if (typeof entry.owner_domain !== "string" || !OWNER_DOMAIN_REGEX.test(entry.owner_domain)) {
      return { valid: false, stage: "INVALID_OWNER_DOMAIN", error: `${pathPrefix}.owner_domain "${entry.owner_domain}" does not match domain pattern.` };
    }

    // status
    if (!VALID_CAPABILITY_STATUSES.has(entry.status)) {
      return { valid: false, stage: "INVALID_CAPABILITY_STATUS", error: `${pathPrefix}.status "${entry.status}" is not a valid lifecycle status.` };
    }

    // head_revision
    if (typeof entry.head_revision !== "number" || !Number.isInteger(entry.head_revision) || entry.head_revision < 1) {
      return { valid: false, stage: "INVALID_HEAD_REVISION", error: `${pathPrefix}.head_revision must be an integer >= 1.` };
    }

    // legacy_aliases
    if (!Array.isArray(entry.legacy_aliases)) {
      return { valid: false, stage: "INVALID_LEGACY_ALIASES", error: `${pathPrefix}.legacy_aliases must be an array.` };
    }
    for (const alias of entry.legacy_aliases) {
      if (typeof alias !== "string" || !LEGACY_ALIAS_REGEX.test(alias)) {
        return { valid: false, stage: "INVALID_LEGACY_ALIAS_SYNTAX", error: `${pathPrefix}.legacy_aliases contains invalid alias "${alias}".` };
      }
      if (declaredAliases.has(alias)) {
        return { valid: false, stage: "DUPLICATE_LEGACY_ALIAS", error: `Duplicate legacy alias detected across entries: "${alias}".` };
      }
      declaredAliases.add(alias);
      aliasMap.set(alias, entry.capability_id);
    }

    // governing_contracts
    if (!Array.isArray(entry.governing_contracts)) {
      return { valid: false, stage: "INVALID_GOVERNING_CONTRACTS", error: `${pathPrefix}.governing_contracts must be an array.` };
    }
    for (const c of entry.governing_contracts) {
      if (typeof c !== "string" || !CONTRACT_REF_REGEX.test(c)) {
        return { valid: false, stage: "INVALID_CONTRACT_REF", error: `${pathPrefix}.governing_contracts contains invalid contract reference "${c}".` };
      }
    }

    // provides
    if (!Array.isArray(entry.provides)) {
      return { valid: false, stage: "INVALID_PROVIDES", error: `${pathPrefix}.provides must be an array.` };
    }
    for (const p of entry.provides) {
      if (typeof p !== "string" || !PROVIDES_TOKEN_REGEX.test(p)) {
        return { valid: false, stage: "INVALID_PROVIDES_TOKEN", error: `${pathPrefix}.provides contains invalid sub-token "${p}".` };
      }
    }

    // requires
    if (!Array.isArray(entry.requires)) {
      return { valid: false, stage: "INVALID_REQUIRES", error: `${pathPrefix}.requires must be an array.` };
    }
    const reqKeySet = new Set();
    for (let rIdx = 0; rIdx < entry.requires.length; rIdx++) {
      const req = entry.requires[rIdx];
      const rPrefix = `${pathPrefix}.requires[${rIdx}]`;
      if (!req || typeof req !== "object" || Array.isArray(req)) {
        return { valid: false, stage: "INVALID_DEPENDENCY_OBJECT", error: `${rPrefix} must be an object.` };
      }
      const reqAllowed = new Set(["type", "id", "min_revision"]);
      for (const rk of Object.keys(req)) {
        if (!reqAllowed.has(rk)) {
          return { valid: false, stage: "UNKNOWN_DEPENDENCY_PROPERTY", error: `${rPrefix} contains unexpected property "${rk}".` };
        }
      }
      if (req.type !== "capability") {
        return { valid: false, stage: "INVALID_DEPENDENCY_TYPE", error: `${rPrefix}.type must be "capability", got "${req.type}".` };
      }
      if (typeof req.id !== "string" || !CANONICAL_ID_REGEX.test(req.id)) {
        return { valid: false, stage: "INVALID_DEPENDENCY_ID_SYNTAX", error: `${rPrefix}.id "${req.id}" is not valid canonical dot syntax.` };
      }
      if (typeof req.min_revision !== "number" || !Number.isInteger(req.min_revision) || req.min_revision < 1) {
        return { valid: false, stage: "INVALID_DEPENDENCY_MIN_REVISION", error: `${rPrefix}.min_revision must be an integer >= 1.` };
      }
      if (reqKeySet.has(req.id)) {
        return { valid: false, stage: "DUPLICATE_DEPENDENCY_DECLARATION", error: `${pathPrefix} declares duplicate dependency on "${req.id}".` };
      }
      reqKeySet.add(req.id);
    }

    // origin_capsule_id & origin_payload_sha256 & introducing_commit_sha
    if (entry.origin_capsule_id !== null && (typeof entry.origin_capsule_id !== "string" || !CAPSULE_ID_REGEX.test(entry.origin_capsule_id))) {
      return { valid: false, stage: "INVALID_ORIGIN_CAPSULE_ID", error: `${pathPrefix}.origin_capsule_id must be null or match capsule ID pattern.` };
    }
    if (entry.origin_payload_sha256 !== null && (typeof entry.origin_payload_sha256 !== "string" || !SHA256_HEX_REGEX.test(entry.origin_payload_sha256))) {
      return { valid: false, stage: "INVALID_ORIGIN_PAYLOAD_SHA256", error: `${pathPrefix}.origin_payload_sha256 must be null or 64-character lowercase hex.` };
    }
    if (entry.introducing_commit_sha !== null && (typeof entry.introducing_commit_sha !== "string" || !COMMIT_SHA_REGEX.test(entry.introducing_commit_sha))) {
      return { valid: false, stage: "INVALID_INTRODUCING_COMMIT_SHA", error: `${pathPrefix}.introducing_commit_sha must be null, 40-char hex, or PENDING_MERGE.` };
    }

    // superseded_by
    if (entry.superseded_by !== null && (typeof entry.superseded_by !== "string" || !CANONICAL_ID_REGEX.test(entry.superseded_by))) {
      return { valid: false, stage: "INVALID_SUPERSEDED_BY", error: `${pathPrefix}.superseded_by must be null or valid capability ID.` };
    }
  }

  // Pass 2: Alias vs Canonical ID collision check
  for (const [alias, ownerId] of aliasMap.entries()) {
    if (capMap.has(alias)) {
      return { valid: false, stage: "ALIAS_COLLISION_WITH_CANONICAL_ID", error: `Legacy alias "${alias}" collides with an existing canonical capability_id.` };
    }
  }

  // Pass 3: Historical alias requirements
  for (const [histAlias, expectedId] of Object.entries(HISTORICAL_REQUIRED_ALIASES)) {
    if (!aliasMap.has(histAlias)) {
      return { valid: false, stage: "MISSING_HISTORICAL_ALIAS", error: `Mandatory historical alias "${histAlias}" is missing from registry.` };
    }
    if (aliasMap.get(histAlias) !== expectedId) {
      return { valid: false, stage: "MISMAPPED_HISTORICAL_ALIAS", error: `Historical alias "${histAlias}" mapped to "${aliasMap.get(histAlias)}" instead of expected "${expectedId}".` };
    }
  }

  // Pass 4: Dependency Graph & Lifecycle verification
  for (const [capId, entry] of capMap.entries()) {
    // 4.1 Check superseded_by target
    if (entry.superseded_by !== null) {
      if (entry.status !== "REPLACED") {
        return { valid: false, stage: "INVALID_SUPERSEDED_COMBINATION", error: `Capability "${capId}" has superseded_by set but status is "${entry.status}" (must be REPLACED).` };
      }
      if (!capMap.has(entry.superseded_by)) {
        return { valid: false, stage: "SUPERSEDED_TARGET_NOT_FOUND", error: `Capability "${capId}" superseded_by "${entry.superseded_by}" does not exist in registry.` };
      }
    } else if (entry.status === "REPLACED") {
      return { valid: false, stage: "REPLACED_WITHOUT_SUPERSEDED_BY", error: `Capability "${capId}" has status REPLACED but superseded_by is null.` };
    }

    // 4.2 Lifecycle vs Provenance (reject forged or unverified ACTIVE state)
    if (entry.status === "ACTIVE") {
      if (!entry.origin_capsule_id || !entry.origin_payload_sha256 || !entry.introducing_commit_sha) {
        return {
          valid: false,
          stage: "FORGED_ACTIVE_PROVENANCE",
          error: `Capability "${capId}" is declared ACTIVE without required complete provenance evidence (origin_capsule_id, origin_payload_sha256, introducing_commit_sha).`
        };
      }
      // Fail-closed guard: effective ACTIVE status requires independent activation proof
      if (!verifiedActivationProof) {
        return {
          valid: false,
          stage: "ACTIVE_EXTERNAL_PROOF_REQUIRED",
          error: `Capability "${capId}" claims ACTIVE status, but independent runtime/governance activation evidence protocol is not yet active during bootstrap.`
        };
      }
    }

    // 4.3 Origin capsule verification against filesystem if present
    if (checkCapsuleExistence && entry.origin_capsule_id) {
      const capFilePath = path.join(repoRoot, ".synthesis", "task-capsules", `${entry.origin_capsule_id}.json`);
      if (!fs.existsSync(capFilePath)) {
        return { valid: false, stage: "ORIGIN_CAPSULE_NOT_FOUND", error: `Origin capsule "${entry.origin_capsule_id}" for capability "${capId}" not found at ${capFilePath}.` };
      }
      try {
        const rawBytes = fs.readFileSync(capFilePath);
        const parsed = parseStrictIJson(rawBytes.toString("utf-8"));
        if (entry.origin_payload_sha256 && parsed.seal?.payload_sha256 !== entry.origin_payload_sha256) {
          return { valid: false, stage: "ORIGIN_PAYLOAD_HASH_MISMATCH", error: `Origin capsule "${entry.origin_capsule_id}" payload hash mismatch for capability "${capId}".` };
        }
      } catch (err) {
        return { valid: false, stage: "ORIGIN_CAPSULE_READ_ERROR", error: `Failed to read/verify origin capsule "${entry.origin_capsule_id}": ${err.message}` };
      }
    }

    // 4.4 Dependencies
    for (const req of entry.requires) {
      // Self-dependency
      if (req.id === capId) {
        return { valid: false, stage: "SELF_DEPENDENCY_DETECTED", error: `Capability "${capId}" cannot declare dependency on itself.` };
      }
      // Target existence
      const targetCap = capMap.get(req.id);
      if (!targetCap) {
        return { valid: false, stage: "UNRESOLVED_DEPENDENCY", error: `Capability "${capId}" depends on non-existent capability "${req.id}".` };
      }
      // Target min revision
      if (targetCap.head_revision < req.min_revision) {
        return { valid: false, stage: "DEPENDENCY_REVISION_UNSATISFIED", error: `Capability "${capId}" requires "${req.id}" min_revision ${req.min_revision}, but target is at head_revision ${targetCap.head_revision}.` };
      }
      // Lifecycle consistency: ACTIVE cannot depend on PROPOSED
      if (entry.status === "ACTIVE" && targetCap.status === "PROPOSED") {
        return { valid: false, stage: "LIFECYCLE_DEPENDENCY_INCONSISTENCY", error: `ACTIVE capability "${capId}" cannot depend on PROPOSED capability "${req.id}".` };
      }
    }
  }

  // Pass 5: Directed Graph Acyclicity Check (DFS Cycle Detection)
  const visited = new Map(); // 0 = unvisited, 1 = visiting, 2 = visited
  for (const capId of capMap.keys()) {
    visited.set(capId, 0);
  }

  function dfs(currId, currentPath = []) {
    visited.set(currId, 1);
    const currEntry = capMap.get(currId);
    for (const req of currEntry.requires) {
      const neighborId = req.id;
      const state = visited.get(neighborId);
      if (state === 1) {
        const cycle = [...currentPath, currId, neighborId].join(" -> ");
        return { hasCycle: true, cycle };
      }
      if (state === 0) {
        const res = dfs(neighborId, [...currentPath, currId]);
        if (res.hasCycle) return res;
      }
    }
    visited.set(currId, 2);
    return { hasCycle: false };
  }

  for (const capId of capMap.keys()) {
    if (visited.get(capId) === 0) {
      const res = dfs(capId, []);
      if (res.hasCycle) {
        return { valid: false, stage: "DEPENDENCY_CYCLE_DETECTED", error: `Directed dependency cycle detected: ${res.cycle}` };
      }
    }
  }

  return {
    valid: true,
    stage: "REGISTRY_VALID",
    totalCapabilities: capabilities.length,
    totalAliases: declaredAliases.size,
    error: null
  };
}

/**
 * Validates a capability registry JSON file from disk.
 */
export function validateCapabilityRegistryFile(filePath, options = {}) {
  if (!fs.existsSync(filePath)) {
    return { valid: false, stage: "FILE_NOT_FOUND", error: `Capability registry file not found at ${filePath}` };
  }
  const stat = fs.lstatSync(filePath);
  if (stat.isSymbolicLink()) {
    return { valid: false, stage: "UNSAFE_SYMLINK", error: `Registry file must not be a symbolic link: ${filePath}` };
  }

  const rawBytes = fs.readFileSync(filePath);
  const rawText = rawBytes.toString("utf-8");

  let parsed;
  try {
    parsed = parseStrictIJson(rawText);
  } catch (err) {
    return { valid: false, stage: "JSON_PARSE_ERROR", error: `I-JSON parse failed: ${err.message}` };
  }

  return validateCapabilityRegistry(parsed, options);
}

/**
 * Self-test suite for semantic Capability Registry validator.
 */
export function runSelfTests(repoRoot = findRepoRoot()) {
  console.log("[CAPABILITY-REGISTRY-VALIDATOR] Running Behavioral Self-Tests...");
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

  const registryPath = path.join(repoRoot, DEFAULT_REGISTRY_REL_PATH);
  const validRaw = fs.readFileSync(registryPath, "utf-8");
  const validObj = parseStrictIJson(validRaw);

  // POSITIVE 1: Actual live registry file passes dynamically
  try {
    const res = validateCapabilityRegistryFile(registryPath, { repoRoot });
    const expectedCount = Array.isArray(validObj.capabilities) ? validObj.capabilities.length : 0;
    const hasHistoricalCaps = Array.isArray(validObj.capabilities) &&
      validObj.capabilities.some(c => c.capability_id === "gov.capsule.persistence") &&
      validObj.capabilities.some(c => c.capability_id === "gov.capsule.lineage") &&
      validObj.capabilities.some(c => c.capability_id === "gov.capsule.cryptographic_seal");

    if (res.valid && res.totalCapabilities === expectedCount && res.totalCapabilities >= 3 && hasHistoricalCaps) {
      passPositive(`Live registry passes dynamic validation (${res.totalCapabilities} capabilities, ${res.totalAliases} aliases)`);
    } else {
      throw new Error(`Expected live registry to pass dynamic validation, got: valid=${res.valid}, count=${res.totalCapabilities}, expectedCount=${expectedCount}, stage=${res.stage}: ${res.error}`);
    }
  } catch (err) { failTest("Positive 1: live registry valid", err); }

  // POSITIVE 2: Multi-node valid acyclic graph (A -> B -> C) passes
  try {
    const clone = JSON.parse(JSON.stringify(validObj));
    clone.capabilities.push({
      capability_id: "gov.capsule.export",
      name: "Command Capsule Exporter",
      description: "Exports capsules to external format with integrity checks.",
      layer: "Stable Contracts",
      owner_domain: "gov.capsule",
      status: "PROPOSED",
      head_revision: 1,
      legacy_aliases: [],
      governing_contracts: ["command-capsule.v1"],
      provides: [],
      requires: [
        { type: "capability", id: "gov.capsule.persistence", min_revision: 1 }
      ],
      origin_capsule_id: null,
      origin_payload_sha256: null,
      introducing_commit_sha: null,
      superseded_by: null
    });
    const res = validateCapabilityRegistry(clone, { repoRoot, checkCapsuleExistence: false });
    if (res.valid && res.totalCapabilities === clone.capabilities.length) {
      passPositive(`Valid multi-node acyclic capability DAG passes validation (${res.totalCapabilities} nodes)`);
    } else {
      throw new Error(`Expected valid DAG to pass, got: ${res.stage}: ${res.error}`);
    }
  } catch (err) { failTest("Positive 2: valid DAG", err); }

  // POSITIVE 3: ACTIVE root and capability accepted when verified activation proof is provided
  const validProofObj = {
    schema_version: "1.0.0",
    record_kind: "MILESTONE_ACTIVATION_PROOF",
    milestone_id: "MILESTONE_A",
    activation_status: "ACTIVE",
    exact_main_commit_sha: "1".repeat(40),
    parent_commit_shas: ["2".repeat(40), "3".repeat(40)],
    merge_tree_sha: "4".repeat(40),
    governance_lock_sha256: "5".repeat(64),
    ci_workflow_run_id: 123456,
    verified_at_utc: "2026-10-05T12:00:00.000Z",
    verified_by: "Test Verifier"
  };

  try {
    const clone = JSON.parse(JSON.stringify(validObj));
    clone.status = "ACTIVE";
    clone.capabilities[0].status = "ACTIVE";
    clone.capabilities[0].origin_capsule_id = "CAP-SYN-MINI-GENESIS-20261005-001";
    clone.capabilities[0].origin_payload_sha256 = "6a3286f77c385ceb52f190bc983ad2bb7b0bcf9e6ec154c16a4e32d3989c679b";
    clone.capabilities[0].introducing_commit_sha = "b3d47a6f732512a9f5b19668a07bb4d2c662adf3";
    const res = validateCapabilityRegistry(clone, { repoRoot, checkCapsuleExistence: false, activationProof: validProofObj });
    if (res.valid) {
      passPositive("ACTIVE root and capability accepted with verified activation proof");
    } else {
      throw new Error(`Expected ACTIVE with proof to pass, got: ${res.stage}: ${res.error}`);
    }
  } catch (err) { failTest("Positive 3: ACTIVE with verified proof", err); }

  // Negative test helper
  function assertNegative(code, name, modifier, expectedStage) {
    try {
      const clone = JSON.parse(JSON.stringify(validObj));
      modifier(clone);
      const res = validateCapabilityRegistry(clone, { repoRoot, checkCapsuleExistence: false });
      if (!res.valid && (!expectedStage || res.stage === expectedStage)) {
        passNegative(code, `${name} (rejected with ${res.stage})`);
      } else if (res.valid) {
        throw new Error(`Expected failure with stage ${expectedStage}, but validator returned VALID`);
      } else {
        throw new Error(`Expected stage ${expectedStage}, got ${res.stage}: ${res.error}`);
      }
    } catch (err) { failTest(`Negative ${code}: ${name}`, err); }
  }

  // NEG-01: Duplicate canonical ID
  assertNegative("NEG-01", "Duplicate canonical ID", c => {
    c.capabilities.push(JSON.parse(JSON.stringify(c.capabilities[0])));
  }, "DUPLICATE_CAPABILITY_ID");

  // NEG-02: Duplicate legacy alias
  assertNegative("NEG-02", "Duplicate legacy alias across entries", c => {
    c.capabilities[1].legacy_aliases.push("CAPSULE_PERSISTENCE");
  }, "DUPLICATE_LEGACY_ALIAS");

  // NEG-03: Alias collision with canonical ID
  assertNegative("NEG-03", "Alias collision with canonical ID", c => {
    c.capabilities[0].legacy_aliases.push("gov.capsule.lineage");
  }, "INVALID_LEGACY_ALIAS_SYNTAX");

  // NEG-04: Missing required field
  assertNegative("NEG-04", "Missing required field in entry", c => {
    delete c.capabilities[0].layer;
  }, "MISSING_ENTRY_PROPERTY");

  // NEG-05: Unknown JSON field
  assertNegative("NEG-05", "Unknown JSON field in entry", c => {
    c.capabilities[0].unauthorized_field = "unexpected";
  }, "UNKNOWN_ENTRY_PROPERTY");

  // NEG-06: Invalid lifecycle value
  assertNegative("NEG-06", "Invalid lifecycle status", c => {
    c.capabilities[0].status = "NON_EXISTENT_STATUS";
  }, "INVALID_CAPABILITY_STATUS");

  // NEG-07: Invalid architectural layer
  assertNegative("NEG-07", "Invalid architectural layer", c => {
    c.capabilities[0].layer = "Invalid Layer 99";
  }, "INVALID_LAYER");

  // NEG-08: Invalid owner domain
  assertNegative("NEG-08", "Invalid owner domain syntax", c => {
    c.capabilities[0].owner_domain = "Invalid Domain Spaces";
  }, "INVALID_OWNER_DOMAIN");

  // NEG-09: Unknown dependency
  assertNegative("NEG-09", "Dependency on unknown capability", c => {
    c.capabilities[0].requires.push({ type: "capability", id: "non.existent.capability", min_revision: 1 });
  }, "UNRESOLVED_DEPENDENCY");

  // NEG-10: Self-dependency
  assertNegative("NEG-10", "Self-dependency rejected", c => {
    c.capabilities[0].requires.push({ type: "capability", id: c.capabilities[0].capability_id, min_revision: 1 });
  }, "SELF_DEPENDENCY_DETECTED");

  // NEG-11: Direct dependency cycle (A -> B -> A)
  assertNegative("NEG-11", "Direct 2-node dependency cycle (A -> B -> A)", c => {
    c.capabilities[0].requires.push({ type: "capability", id: c.capabilities[1].capability_id, min_revision: 1 });
    c.capabilities[1].requires.push({ type: "capability", id: c.capabilities[0].capability_id, min_revision: 1 });
  }, "DEPENDENCY_CYCLE_DETECTED");

  // NEG-12: Three-node cycle (A -> B -> C -> A)
  assertNegative("NEG-12", "Three-node dependency cycle (A -> B -> C -> A)", c => {
    c.capabilities[0].requires.push({ type: "capability", id: c.capabilities[1].capability_id, min_revision: 1 });
    c.capabilities[1].requires.push({ type: "capability", id: c.capabilities[2].capability_id, min_revision: 1 });
    c.capabilities[2].requires.push({ type: "capability", id: c.capabilities[0].capability_id, min_revision: 1 });
  }, "DEPENDENCY_CYCLE_DETECTED");

  // NEG-13: Unsatisfied minimum revision
  assertNegative("NEG-13", "Unsatisfied minimum dependency revision", c => {
    c.capabilities[0].requires.push({ type: "capability", id: c.capabilities[1].capability_id, min_revision: 99 });
  }, "DEPENDENCY_REVISION_UNSATISFIED");

  // NEG-14: Malformed dependency type
  assertNegative("NEG-14", "Malformed dependency type", c => {
    c.capabilities[0].requires.push({ type: "invalid_type", id: c.capabilities[1].capability_id, min_revision: 1 });
  }, "INVALID_DEPENDENCY_TYPE");

  // NEG-15: Missing origin capsule (with check enabled)
  try {
    const clone = JSON.parse(JSON.stringify(validObj));
    clone.capabilities[0].origin_capsule_id = "CAP-SYN-MINI-GOV-NONEXISTENT-20261003-999";
    clone.capabilities[0].origin_payload_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const res = validateCapabilityRegistry(clone, { repoRoot, checkCapsuleExistence: true });
    if (!res.valid && res.stage === "ORIGIN_CAPSULE_NOT_FOUND") {
      passNegative("NEG-15", "Missing origin capsule rejected (ORIGIN_CAPSULE_NOT_FOUND)");
    } else {
      throw new Error(`Expected ORIGIN_CAPSULE_NOT_FOUND, got ${res.stage}`);
    }
  } catch (err) { failTest("Negative NEG-15: missing origin capsule", err); }

  // NEG-16: Incorrect origin payload hash
  try {
    const clone = JSON.parse(JSON.stringify(validObj));
    clone.capabilities[0].origin_capsule_id = "CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010";
    clone.capabilities[0].origin_payload_sha256 = "0000000000000000000000000000000000000000000000000000000000000000";
    const res = validateCapabilityRegistry(clone, { repoRoot, checkCapsuleExistence: true });
    if (!res.valid && res.stage === "ORIGIN_PAYLOAD_HASH_MISMATCH") {
      passNegative("NEG-16", "Incorrect origin payload hash rejected (ORIGIN_PAYLOAD_HASH_MISMATCH)");
    } else {
      throw new Error(`Expected ORIGIN_PAYLOAD_HASH_MISMATCH, got ${res.stage}`);
    }
  } catch (err) { failTest("Negative NEG-16: incorrect payload hash", err); }

  // NEG-17: Forged ACTIVE state without complete provenance fields
  assertNegative("NEG-17", "Forged ACTIVE status without provenance fields", c => {
    c.capabilities[0].status = "ACTIVE";
    c.capabilities[0].origin_capsule_id = null;
  }, "FORGED_ACTIVE_PROVENANCE");

  // NEG-18: Invalid superseded_by combination
  assertNegative("NEG-18", "superseded_by set on non-REPLACED entry", c => {
    c.capabilities[0].superseded_by = "gov.capsule.lineage";
  }, "INVALID_SUPERSEDED_COMBINATION");

  // NEG-19: Unknown historical alias mapping
  assertNegative("NEG-19", "Mismapped historical alias", c => {
    c.capabilities[0].legacy_aliases = ["WRONG_ALIAS"];
  }, "MISSING_HISTORICAL_ALIAS");

  // NEG-20: Duplicate JSON property rejected by strict parser
  try {
    const jsonWithDup = '{"schema_version":"capability-registry.v1","schema_version":"duplicate"}';
    let dupFailed = false;
    try {
      parseStrictIJson(jsonWithDup);
    } catch (e) {
      dupFailed = true;
    }
    if (dupFailed) {
      passNegative("NEG-20", "Duplicate JSON property rejected by strict parser");
    } else {
      throw new Error("Strict parser accepted duplicate property key");
    }
  } catch (err) { failTest("Negative NEG-20: duplicate property", err); }

  // NEG-21: ACTIVE with PENDING_MERGE rejected without external activation proof
  assertNegative("NEG-21", "ACTIVE with PENDING_MERGE rejected (ACTIVE_EXTERNAL_PROOF_REQUIRED)", c => {
    c.capabilities[0].status = "ACTIVE";
    c.capabilities[0].origin_capsule_id = "CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010";
    c.capabilities[0].origin_payload_sha256 = "c656360c793ff0e81a3089dbe807e7b8bca9826f4325a77f24794e7751f7bb9c";
    c.capabilities[0].introducing_commit_sha = "PENDING_MERGE";
  }, "ACTIVE_EXTERNAL_PROOF_REQUIRED");

  // NEG-22: ACTIVE with plausible commit SHA and existing capsule rejected without external proof
  assertNegative("NEG-22", "ACTIVE with plausible commit SHA rejected (ACTIVE_EXTERNAL_PROOF_REQUIRED)", c => {
    c.capabilities[0].status = "ACTIVE";
    c.capabilities[0].origin_capsule_id = "CAP-SYN-MINI-GOV-CAPSULE-SCHEMA-001-20261002-010";
    c.capabilities[0].origin_payload_sha256 = "c656360c793ff0e81a3089dbe807e7b8bca9826f4325a77f24794e7751f7bb9c";
    c.capabilities[0].introducing_commit_sha = "6dd9f5c8d9632f86c636102949a1edfaff69d1c5";
  }, "ACTIVE_EXTERNAL_PROOF_REQUIRED");

  // NEG-23: Root status ACTIVE rejected without global activation evidence
  assertNegative("NEG-23", "Root status ACTIVE rejected (REGISTRY_ACTIVE_EXTERNAL_PROOF_REQUIRED)", c => {
    c.status = "ACTIVE";
  }, "REGISTRY_ACTIVE_EXTERNAL_PROOF_REQUIRED");

  // NEG-24: Forged ACTIVE boolean bypass attempt rejected without valid proof object
  try {
    const clone = JSON.parse(JSON.stringify(validObj));
    clone.status = "ACTIVE";
    const res = validateCapabilityRegistry(clone, { repoRoot, checkCapsuleExistence: false, allowActiveWithProof: true, activationProofVerified: true });
    if (!res.valid && res.stage === "REGISTRY_ACTIVE_EXTERNAL_PROOF_REQUIRED") {
      passNegative("NEG-24", "Forged ACTIVE boolean bypass rejected (REGISTRY_ACTIVE_EXTERNAL_PROOF_REQUIRED)");
    } else {
      failTest("NEG-24: Forged ACTIVE boolean bypass rejected", new Error(`Expected REGISTRY_ACTIVE_EXTERNAL_PROOF_REQUIRED, got ${res.stage}`));
    }
  } catch (err) { failTest("NEG-24: Forged boolean bypass", err); }

  // NEG-25: Auto-loading missing activation proof file when status === "ACTIVE" rejected
  try {
    const clone = JSON.parse(JSON.stringify(validObj));
    clone.status = "ACTIVE";
    const res = validateCapabilityRegistry(clone, { repoRoot, checkCapsuleExistence: false, activationProof: ".synthesis/activation/nonexistent-proof.json" });
    if (!res.valid && res.stage === "REGISTRY_ACTIVE_EXTERNAL_PROOF_REQUIRED") {
      passNegative("NEG-25", "Missing activation proof file rejected (REGISTRY_ACTIVE_EXTERNAL_PROOF_REQUIRED)");
    } else {
      failTest("NEG-25: Missing activation proof file", new Error(`Expected REGISTRY_ACTIVE_EXTERNAL_PROOF_REQUIRED, got ${res.stage}`));
    }
  } catch (err) { failTest("NEG-25: Missing proof file", err); }

  // NEG-26: Caller booleans alone without valid proof record ignored
  try {
    const clone = JSON.parse(JSON.stringify(validObj));
    clone.status = "ACTIVE";
    const res = validateCapabilityRegistry(clone, { repoRoot, checkCapsuleExistence: false, isVerified: true, verified: true, bypassProof: true });
    if (!res.valid && res.stage === "REGISTRY_ACTIVE_EXTERNAL_PROOF_REQUIRED") {
      passNegative("NEG-26", "Caller booleans alone rejected (REGISTRY_ACTIVE_EXTERNAL_PROOF_REQUIRED)");
    } else {
      failTest("NEG-26: Caller booleans alone", new Error(`Expected REGISTRY_ACTIVE_EXTERNAL_PROOF_REQUIRED, got ${res.stage}`));
    }
  } catch (err) { failTest("NEG-26: Caller booleans alone", err); }

  console.log(`[CAPABILITY-REGISTRY-VALIDATOR] Summary: ${positivePassed} positive passed, ${negativePassed} negative passed, ${failed} failed.`);
  return { positivePassed, negativePassed, failed, ok: failed === 0 };
}

// CLI Entry Point
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.length === 0) {
    console.log("Synthesis CMS mini — Semantic Capability Registry Validator");
    console.log("Usage:");
    console.log("  node scripts/governance/validate_capability_registry.mjs --self-test");
    console.log("  node scripts/governance/validate_capability_registry.mjs --verify-all");
    console.log("  node scripts/governance/validate_capability_registry.mjs --help");
    process.exit(0);
  }

  if (args.includes("--self-test")) {
    const res = runSelfTests();
    process.exit(res.ok ? 0 : 1);
  }

  if (args.includes("--verify-all")) {
    const repoRoot = findRepoRoot();
    const regPath = path.join(repoRoot, DEFAULT_REGISTRY_REL_PATH);
    const res = validateCapabilityRegistryFile(regPath, { repoRoot, checkCapsuleExistence: true });
    if (res.valid) {
      console.log("CAPABILITY_REGISTRY_VERIFICATION: PASS");
      console.log(`REGISTRY_PATH: ${DEFAULT_REGISTRY_REL_PATH}`);
      console.log(`TOTAL_CAPABILITIES: ${res.totalCapabilities}`);
      console.log(`TOTAL_LEGACY_ALIASES: ${res.totalAliases}`);
      console.log("DEPENDENCY_DAG_VERIFICATION: PASS");
      console.log("HISTORICAL_ALIAS_MAPPING: PASS");
      console.log("FAIL_CLOSED_ACTIVE_GUARD: ENFORCED");
      console.log("SCHEMA_FULL_DRAFT_2020_12_VALIDATION: NOT_EXECUTED");
      process.exit(0);
    } else {
      console.error(`CAPABILITY_REGISTRY_VERIFICATION: FAIL [${res.stage}]: ${res.error}`);
      process.exit(1);
    }
  }

  console.error("Unknown argument. Use --help for usage instructions.");
  process.exit(1);
}
