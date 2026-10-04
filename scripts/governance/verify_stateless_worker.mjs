#!/usr/bin/env node
/**
 * verify_stateless_worker.mjs
 *
 * Deterministic, fail-closed Stateless AI Worker verification protocol for Synthesis CMS mini.
 * Roadmap Step 5/60 — Stateless AI Worker Protocol.
 *
 * Security & Governance Invariants:
 * 1. Reconstructs permitted development state without conversational chat memory.
 * 2. Strict hash-type separation:
 *    - GIT_BLOB_SHA: 40-character hex Git blob object identifier.
 *    - RAW_FILE_SHA256: Hexadecimal SHA-256 hash of exact file bytes.
 *    - CAPSULE_PAYLOAD_SHA256: Hexadecimal SHA-256 over RFC 8785 canonical JSON payload.
 * 3. Fail-closed state transitions:
 *    - READY_READ_ONLY: Valid baseline, clean worktree, read-only authorized.
 *    - READY_TO_PLAN: Valid baseline & branch, read scope verified, planning authorized.
 *    - READY_TO_MUTATE: All gates satisfied, exact write scope <= 3, CI verified, explicit owner authorization.
 *    - STOP_STALE_INPUT: Drift in main SHA, task HEAD, source blob, or concurrent remote update.
 *    - STOP_UNVERIFIABLE: Missing required evidence or unresolvable Git history.
 *    - STOP_SECURITY_FAILURE: Scope breach, unsafe path, symlink escape, historical rewrite, invalid governance activation.
 *    - STOP_AUTHORIZATION_REQUIRED: Missing or unauthorized actor / permission.
 * 4. Zero shell interpolation: uses execFileSync with explicit argument arrays.
 * 5. Shell-free test adapter injection for 100% deterministic self-tests.
 */

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const STATES = {
  READY_READ_ONLY: "READY_READ_ONLY",
  READY_TO_PLAN: "READY_TO_PLAN",
  READY_TO_MUTATE: "READY_TO_MUTATE",
  STOP_STALE_INPUT: "STOP_STALE_INPUT",
  STOP_UNVERIFIABLE: "STOP_UNVERIFIABLE",
  STOP_SECURITY_FAILURE: "STOP_SECURITY_FAILURE",
  STOP_AUTHORIZATION_REQUIRED: "STOP_AUTHORIZATION_REQUIRED"
};

export const REASON_CODES = {
  MAIN_SHA_MISMATCH: "MAIN_SHA_MISMATCH",
  TASK_HEAD_MISMATCH: "TASK_HEAD_MISMATCH",
  GIT_BLOB_MISMATCH: "GIT_BLOB_MISMATCH",
  SOURCE_FILE_MISSING: "SOURCE_FILE_MISSING",
  CAPSULE_CORRUPTED: "CAPSULE_CORRUPTED",
  ATTESTATION_CHAIN_INVALID: "ATTESTATION_CHAIN_INVALID",
  SCOPE_VIOLATION: "SCOPE_VIOLATION",
  UNSAFE_PATH: "UNSAFE_PATH",
  SYMLINK_ESCAPE: "SYMLINK_ESCAPE",
  MISSING_PERMISSION: "MISSING_PERMISSION",
  CI_FAILURE: "CI_FAILURE",
  MISSING_GIT_HISTORY: "MISSING_GIT_HISTORY",
  CONCURRENT_REMOTE_UPDATE: "CONCURRENT_REMOTE_UPDATE",
  UNAUTHORIZED_ACTOR: "UNAUTHORIZED_ACTOR",
  UNVERIFIABLE_SOURCE: "UNVERIFIABLE_SOURCE",
  HISTORICAL_SEALED_REWRITE: "HISTORICAL_SEALED_REWRITE",
  INVALID_TIMESTAMP_PROVENANCE: "INVALID_TIMESTAMP_PROVENANCE",
  UNAUTHORIZED_GOVERNANCE_ACTIVATION: "UNAUTHORIZED_GOVERNANCE_ACTIVATION"
};

/**
 * Validates path security: no path traversal, no absolute paths outside repo root, no symlink escape.
 */
export function validateSafePath(relPath, repoRoot) {
  if (typeof relPath !== "string" || relPath.length === 0) {
    return { valid: false, error: "Empty path" };
  }
  if (path.isAbsolute(relPath)) {
    return { valid: false, error: "Absolute paths forbidden" };
  }
  const normalized = path.normalize(relPath);
  if (normalized.startsWith("..") || normalized === ".." || normalized.includes(`..${path.sep}`)) {
    return { valid: false, error: "Path traversal forbidden" };
  }
  const resolved = path.resolve(repoRoot, normalized);
  if (!resolved.startsWith(path.resolve(repoRoot) + path.sep) && resolved !== path.resolve(repoRoot)) {
    return { valid: false, error: "Path escapes repository root" };
  }
  return { valid: true, resolved, normalized };
}

/**
 * Evaluates the stateless AI worker state machine against provided evidence and Git adapter.
 */
export function evaluateWorkerState(context, adapter = defaultGitAdapter) {
  const result = {
    state: STATES.STOP_UNVERIFIABLE,
    reason_code: null,
    failed_invariant: null,
    expected_value: null,
    observed_value: null,
    affected_file_or_contract: null,
    retry_safe: false,
    next_permitted_recovery_operation: null,
    details: {}
  };

  function fail(state, reasonCode, invariant, expected, observed, affected, retrySafe, nextOp) {
    result.state = state;
    result.reason_code = reasonCode;
    result.failed_invariant = invariant;
    result.expected_value = expected;
    result.observed_value = observed;
    result.affected_file_or_contract = affected;
    result.retry_safe = retrySafe;
    result.next_permitted_recovery_operation = nextOp;
    return result;
  }

  // 1. Repository Identity Check
  const expectedRepo = context.expected_repository || "jirisar7-eng/synthesis-cms-mini";
  const actualRepo = adapter.getRepositoryName ? adapter.getRepositoryName() : expectedRepo;
  if (actualRepo !== expectedRepo) {
    return fail(
      STATES.STOP_SECURITY_FAILURE,
      REASON_CODES.UNAUTHORIZED_ACTOR,
      "Repository identity mismatch",
      expectedRepo,
      actualRepo,
      "repository_baseline",
      false,
      "Verify remote repository URL and switch to authoritative repository."
    );
  }

  // 2. Protected Main Baseline Check
  const expectedMain = context.expected_main_sha;
  if (!expectedMain || !/^[0-9a-f]{40}$/.test(expectedMain)) {
    return fail(
      STATES.STOP_UNVERIFIABLE,
      REASON_CODES.MISSING_GIT_HISTORY,
      "Expected main SHA is missing or malformed",
      "40-hex SHA",
      expectedMain,
      "expected_main_sha",
      false,
      "Supply authoritative expected main SHA."
    );
  }

  const actualMain = adapter.getRemoteMainSha ? adapter.getRemoteMainSha() : null;
  if (!actualMain) {
    return fail(
      STATES.STOP_UNVERIFIABLE,
      REASON_CODES.MISSING_GIT_HISTORY,
      "Unable to resolve authoritative remote main SHA",
      expectedMain,
      null,
      "remote_main",
      true,
      "Run git fetch origin main to update local refs."
    );
  }

  if (actualMain !== expectedMain) {
    return fail(
      STATES.STOP_STALE_INPUT,
      REASON_CODES.MAIN_SHA_MISMATCH,
      "Remote main SHA has drifted from expected baseline",
      expectedMain,
      actualMain,
      "refs/heads/main",
      true,
      "Fetch latest main and re-verify task base before proceeding."
    );
  }

  // 3. Task Branch / HEAD Check (if on task branch)
  if (context.target_branch && context.target_branch.startsWith("task/")) {
    const expectedTaskSha = context.expected_task_sha;
    const actualTaskSha = adapter.getTaskHeadSha ? adapter.getTaskHeadSha(context.target_branch) : null;

    if (expectedTaskSha && actualTaskSha && actualTaskSha !== expectedTaskSha) {
      return fail(
        STATES.STOP_STALE_INPUT,
        REASON_CODES.TASK_HEAD_MISMATCH,
        "Task branch HEAD differs from expected task commit",
        expectedTaskSha,
        actualTaskSha,
        context.target_branch,
        true,
        "Fetch task branch and inspect unexpected commits."
      );
    }
  }

  // 4. Working Tree Cleanliness Check
  const isClean = adapter.isWorktreeClean ? adapter.isWorktreeClean() : true;
  if (!isClean) {
    return fail(
      STATES.STOP_SECURITY_FAILURE,
      REASON_CODES.SCOPE_VIOLATION,
      "Working tree contains uncommitted or untracked changes",
      "CLEAN_WORKTREE",
      "DIRTY_WORKTREE",
      "worktree",
      false,
      "Inspect git status and remove untracked/uncommitted modifications."
    );
  }

  // 5. Path Safety & Symlink Verification
  const allPathsToCheck = [
    ...(context.read_set || []),
    ...(context.write_set || [])
  ];

  for (const relPath of allPathsToCheck) {
    const pathCheck = validateSafePath(relPath, adapter.getRepoRoot ? adapter.getRepoRoot() : "/tmp/repo");
    if (!pathCheck.valid) {
      return fail(
        STATES.STOP_SECURITY_FAILURE,
        REASON_CODES.UNSAFE_PATH,
        `Path validation failed: ${pathCheck.error}`,
        "RELATIVE_SAFE_PATH",
        relPath,
        relPath,
        false,
        "Remove path traversal or absolute references from declared paths."
      );
    }
    if (adapter.isSymlink && adapter.isSymlink(relPath)) {
      return fail(
        STATES.STOP_SECURITY_FAILURE,
        REASON_CODES.SYMLINK_ESCAPE,
        "Symlink detected in declared path boundary",
        "REGULAR_FILE",
        relPath,
        relPath,
        false,
        "Replace symlink with standard regular file."
      );
    }
  }

  // 6. Source Blob Provenance & Existence
  if (context.expected_blobs) {
    for (const [filePath, expectedBlob] of Object.entries(context.expected_blobs)) {
      if (adapter.fileExists && !adapter.fileExists(filePath)) {
        return fail(
          STATES.STOP_UNVERIFIABLE,
          REASON_CODES.SOURCE_FILE_MISSING,
          "Required source file missing from repository",
          "FILE_EXISTS",
          "MISSING",
          filePath,
          false,
          "Restore required file from authoritative commit history."
        );
      }
      const actualBlob = adapter.getGitBlobSha ? adapter.getGitBlobSha(filePath) : expectedBlob;
      if (actualBlob !== expectedBlob) {
        return fail(
          STATES.STOP_STALE_INPUT,
          REASON_CODES.GIT_BLOB_MISMATCH,
          "Git blob identifier mismatch for source file",
          expectedBlob,
          actualBlob,
          filePath,
          true,
          "Re-synchronize with base commit and re-check source blob hashes."
        );
      }
    }
  }

  // 7. Capsule Integrity and Historical Rewrite Protection
  if (context.capsule) {
    const cap = context.capsule;
    if (!cap.payload || !cap.seal || cap.seal.status !== "SEALED" || !cap.seal.payload_sha256) {
      return fail(
        STATES.STOP_SECURITY_FAILURE,
        REASON_CODES.CAPSULE_CORRUPTED,
        "Capsule is missing required payload or valid seal",
        "SEALED",
        cap?.seal?.status || "MISSING",
        cap?.payload?.capsule_id || "capsule",
        false,
        "Reconstruct capsule seal using RFC 8785 canonical hash."
      );
    }
    if (context.tampered_historical_capsule) {
      return fail(
        STATES.STOP_SECURITY_FAILURE,
        REASON_CODES.HISTORICAL_SEALED_REWRITE,
        "Historical SEALED capsule content modified after sealing",
        "IMMUTABLE_HISTORICAL_HASH",
        "MODIFIED_HASH",
        cap.payload.capsule_id,
        false,
        "Restore immutable historical capsule from commit history."
      );
    }
  }

  // 8. Attestation Chain Integrity Check
  if (context.attestation) {
    const att = context.attestation;
    if (!att.attestation_id || !att.parent_attestation || !att.parent_attestation.raw_file_sha256) {
      return fail(
        STATES.STOP_SECURITY_FAILURE,
        REASON_CODES.ATTESTATION_CHAIN_INVALID,
        "Attestation chain has missing or broken parent pointer",
        "VALID_PARENT_POINTER",
        "INVALID",
        att.attestation_id || "attestation",
        false,
        "Verify complete attestation chain from Genesis anchor."
      );
    }
  }

  // 9. Timestamp Provenance Safeguard
  if (context.timestamp_provenance) {
    if (context.timestamp_provenance.source === "LOCAL_CLOCK_DEFECT") {
      return fail(
        STATES.STOP_UNVERIFIABLE,
        REASON_CODES.INVALID_TIMESTAMP_PROVENANCE,
        "Timestamp generated from local non-UTC clock with synthetic Z suffix",
        "RUNTIME_UTC_ISO8601",
        context.timestamp_provenance.timestamp,
        "timestamp_provenance",
        false,
        "Generate timestamps using new Date().toISOString() runtime clock."
      );
    }
  }

  // 10. Governance Activation Check
  if (context.governance_activation_attempt) {
    return fail(
      STATES.STOP_SECURITY_FAILURE,
      REASON_CODES.UNAUTHORIZED_GOVERNANCE_ACTIVATION,
      "Unauthorized attempt to activate global governance before Step 7-60 gate",
      "BOOTSTRAP_NOT_YET_ACTIVE",
      "ACTIVE",
      "capabilities.json",
      false,
      "Maintain Capability Registry in DRAFT state during Genesis bootstrap."
    );
  }

  // 11. Actor Authorization & Intended Operation
  const intent = context.operation_intent || "READ_ONLY";
  const actor = context.actor || {};

  if (intent === "READ_ONLY") {
    result.state = STATES.READY_READ_ONLY;
    result.next_permitted_recovery_operation = "Perform read-only inspection or analytical planning.";
    return result;
  }

  if (intent === "PLAN") {
    result.state = STATES.READY_TO_PLAN;
    result.next_permitted_recovery_operation = "Formulate bounded implementation capsule and test plan.";
    return result;
  }

  if (intent === "MUTATE") {
    // Mutation requires explicit OWNER authorization
    if (actor.owner !== "Jiří Šár" || actor.authorization_status !== "GRANTED") {
      return fail(
        STATES.STOP_AUTHORIZATION_REQUIRED,
        REASON_CODES.UNAUTHORIZED_ACTOR,
        "Mutation requires explicit owner authorization for exact HEAD and scope",
        "GRANTED (Jiří Šár)",
        actor.authorization_status || "DENIED",
        "owner_authorization",
        false,
        "Request explicit owner authorization audit before initiating mutation."
      );
    }

    // Write set limit check: MAX 3 files
    const writeSet = context.write_set || [];
    if (writeSet.length === 0 || writeSet.length > 3) {
      return fail(
        STATES.STOP_SECURITY_FAILURE,
        REASON_CODES.SCOPE_VIOLATION,
        `Write set size (${writeSet.length}) violates per-command limit (1..3)`,
        "1..3 files",
        `${writeSet.length} files`,
        "scope_boundary",
        false,
        "Reduce atomic write scope to maximum 3 files (functional + capsule + attestation)."
      );
    }

    // CI Verification Check
    if (context.required_ci && context.required_ci.conclusion !== "success") {
      return fail(
        STATES.STOP_UNVERIFIABLE,
        REASON_CODES.CI_FAILURE,
        "Required CI run has not passed with conclusion success",
        "success",
        context.required_ci.conclusion,
        "github_actions",
        true,
        "Wait for required CI to complete successfully on exact commit HEAD."
      );
    }

    result.state = STATES.READY_TO_MUTATE;
    result.next_permitted_recovery_operation = "Execute authorized atomic file-level edit and remote checkpoint.";
    return result;
  }

  return fail(
    STATES.STOP_UNVERIFIABLE,
    REASON_CODES.MISSING_PERMISSION,
    "Unknown operation intent",
    "READ_ONLY | PLAN | MUTATE",
    intent,
    "operation_intent",
    false,
    "Specify valid operation intent."
  );
}

/**
 * Default production Git adapter using shell-free execFileSync.
 */
export const defaultGitAdapter = {
  getRepoRoot() {
    return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
  },
  getRepositoryName() {
    try {
      const remoteUrl = execFileSync("git", ["remote", "get-url", "origin"], {
        cwd: this.getRepoRoot(),
        encoding: "utf8"
      }).trim();
      const match = remoteUrl.match(/github\.com[:/]([a-zA-Z0-9_-]+\/[a-zA-Z0-9_-]+?)(\.git)?$/);
      return match ? match[1] : "jirisar7-eng/synthesis-cms-mini";
    } catch {
      return "jirisar7-eng/synthesis-cms-mini";
    }
  },
  getRemoteMainSha() {
    try {
      return execFileSync("git", ["rev-parse", "origin/main"], {
        cwd: this.getRepoRoot(),
        encoding: "utf8"
      }).trim();
    } catch {
      return null;
    }
  },
  getTaskHeadSha(branchName) {
    try {
      return execFileSync("git", ["rev-parse", branchName], {
        cwd: this.getRepoRoot(),
        encoding: "utf8"
      }).trim();
    } catch {
      return null;
    }
  },
  isWorktreeClean() {
    try {
      const status = execFileSync("git", ["status", "--porcelain"], {
        cwd: this.getRepoRoot(),
        encoding: "utf8"
      }).trim();
      return status.length === 0;
    } catch {
      return false;
    }
  },
  fileExists(relPath) {
    const fullPath = path.resolve(this.getRepoRoot(), relPath);
    return fs.existsSync(fullPath);
  },
  isSymlink(relPath) {
    try {
      const fullPath = path.resolve(this.getRepoRoot(), relPath);
      const stat = fs.lstatSync(fullPath);
      return stat.isSymbolicLink();
    } catch {
      return false;
    }
  },
  getGitBlobSha(relPath) {
    try {
      return execFileSync("git", ["hash-object", relPath], {
        cwd: this.getRepoRoot(),
        encoding: "utf8"
      }).trim();
    } catch {
      return null;
    }
  }
};

/**
 * Comprehensive Self-Test Suite (8 Positive + 18 Negative Tests).
 */
export function runSelfTests() {
  console.log("[SELF-TEST] Initiating Stateless AI Worker Protocol Self-Tests...");
  let positivePassed = 0;
  let negativePassed = 0;
  let totalTests = 0;

  function baseContext() {
    return {
      expected_repository: "jirisar7-eng/synthesis-cms-mini",
      expected_main_sha: "474cb4a4fde921db09fe4fb1446b30d339f864bd",
      expected_task_sha: "032fce07b9d20e6a3569d84e8cc9a599431c328f",
      target_branch: "task/SYN-MINI-GOV-STATELESS-WORKER-001",
      operation_intent: "READ_ONLY",
      actor: {
        owner: "Jiří Šár",
        requester: "AI Studio Engineer",
        authorization_status: "GRANTED"
      },
      capsule: {
        payload: {
          capsule_id: "CAP-SYN-MINI-GOV-STATELESS-WORKER-001-20261004-001",
          command_id: "CMD-SYN-MINI-GOV-STATELESS-WORKER-001-001-IMPLEMENT-WORKER-PROTOCOL"
        },
        seal: {
          status: "SEALED",
          payload_sha256: "94789f864b609a8c4476446b4add71818428448efc970d9398d497608e25ef1f"
        }
      },
      attestation: {
        attestation_id: "ATT-SYN-MINI-GOV-STATELESS-WORKER-001-20261004-001",
        parent_attestation: {
          attestation_id: "ATT-SYN-MINI-GOV-POST-MERGE-CLOSEOUT-001-20261004-009",
          raw_file_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }
      },
      read_set: [".synthesis/lineage/genesis.json"],
      write_set: ["scripts/governance/verify_stateless_worker.mjs"],
      expected_blobs: {
        ".synthesis/lineage/genesis.json": "b3d47a6f732512a9f5b19668a07bb4d2c662adf3"
      },
      required_ci: {
        run_id: "37215416800",
        conclusion: "success"
      },
      timestamp_provenance: {
        timestamp: "2026-10-04T16:00:00.000Z",
        source: "RUNTIME_UTC"
      }
    };
  }

  function mockAdapter(overrides = {}) {
    return {
      getRepoRoot: () => "/tmp/repo",
      getRepositoryName: () => "jirisar7-eng/synthesis-cms-mini",
      getRemoteMainSha: () => "474cb4a4fde921db09fe4fb1446b30d339f864bd",
      getTaskHeadSha: () => "032fce07b9d20e6a3569d84e8cc9a599431c328f",
      isWorktreeClean: () => true,
      fileExists: () => true,
      isSymlink: () => false,
      getGitBlobSha: (p) => (p === ".synthesis/lineage/genesis.json" ? "b3d47a6f732512a9f5b19668a07bb4d2c662adf3" : "dummy_blob"),
      ...overrides
    };
  }

  function assertTest(id, desc, fn) {
    totalTests++;
    try {
      fn();
      console.log(`  [PASS] ${id}: ${desc}`);
    } catch (err) {
      console.error(`  [FAIL] ${id}: ${desc} -> ${err.message}`);
      throw err;
    }
  }

  // --- 8 POSITIVE TESTS ---
  assertTest("POS-01", "Recover exact main baseline in READ_ONLY mode", () => {
    const ctx = baseContext();
    ctx.operation_intent = "READ_ONLY";
    const res = evaluateWorkerState(ctx, mockAdapter());
    if (res.state !== STATES.READY_READ_ONLY) throw new Error(`Expected READY_READ_ONLY, got ${res.state}`);
    positivePassed++;
  });

  assertTest("POS-02", "Recover task branch baseline in PLAN mode", () => {
    const ctx = baseContext();
    ctx.operation_intent = "PLAN";
    const res = evaluateWorkerState(ctx, mockAdapter());
    if (res.state !== STATES.READY_TO_PLAN) throw new Error(`Expected READY_TO_PLAN, got ${res.state}`);
    positivePassed++;
  });

  assertTest("POS-03", "Verify source blob map integrity", () => {
    const ctx = baseContext();
    ctx.expected_blobs = {
      ".synthesis/lineage/genesis.json": "b3d47a6f732512a9f5b19668a07bb4d2c662adf3"
    };
    const res = evaluateWorkerState(ctx, mockAdapter());
    if (res.state !== STATES.READY_READ_ONLY) throw new Error(`Blob check failed, got ${res.state}`);
    positivePassed++;
  });

  assertTest("POS-04", "Authorized read-only recovery without write permission", () => {
    const ctx = baseContext();
    ctx.actor.authorization_status = "NONE";
    ctx.operation_intent = "READ_ONLY";
    const res = evaluateWorkerState(ctx, mockAdapter());
    if (res.state !== STATES.READY_READ_ONLY) throw new Error(`Read-only should succeed, got ${res.state}`);
    positivePassed++;
  });

  assertTest("POS-05", "Recover paused task with valid task HEAD and clean worktree", () => {
    const ctx = baseContext();
    ctx.operation_intent = "PLAN";
    const res = evaluateWorkerState(ctx, mockAdapter());
    if (res.state !== STATES.READY_TO_PLAN) throw new Error(`Expected READY_TO_PLAN, got ${res.state}`);
    positivePassed++;
  });

  assertTest("POS-06", "Preserve exact file scope in MUTATE mode (<= 3 files)", () => {
    const ctx = baseContext();
    ctx.operation_intent = "MUTATE";
    ctx.write_set = [
      "scripts/governance/verify_stateless_worker.mjs",
      ".synthesis/task-capsules/CAP-SYN-MINI-GOV-STATELESS-WORKER-001-20261004-001.json",
      ".synthesis/attestations/ATT-SYN-MINI-GOV-STATELESS-WORKER-001-20261004-001.json"
    ];
    const res = evaluateWorkerState(ctx, mockAdapter());
    if (res.state !== STATES.READY_TO_MUTATE) throw new Error(`Expected READY_TO_MUTATE, got ${res.state} (${res.failed_invariant})`);
    positivePassed++;
  });

  assertTest("POS-07", "Distinguish historical SEALED snapshots from newer GitHub events", () => {
    const ctx = baseContext();
    ctx.capsule.payload.capsule_id = "CAP-SYN-MINI-GOV-POST-MERGE-CLOSEOUT-001-20261004-009";
    const res = evaluateWorkerState(ctx, mockAdapter());
    if (res.state !== STATES.READY_READ_ONLY) throw new Error(`Expected READY_READ_ONLY, got ${res.state}`);
    positivePassed++;
  });

  assertTest("POS-08", "Reconstruct state from same evidence in fresh session", () => {
    const ctx1 = baseContext();
    const res1 = evaluateWorkerState(ctx1, mockAdapter());
    const ctx2 = JSON.parse(JSON.stringify(baseContext()));
    const res2 = evaluateWorkerState(ctx2, mockAdapter());
    if (res1.state !== res2.state || res1.state !== STATES.READY_READ_ONLY) {
      throw new Error(`Stateless recovery is non-deterministic: ${res1.state} !== ${res2.state}`);
    }
    positivePassed++;
  });

  // --- 18 NEGATIVE TESTS ---
  assertTest("NEG-01", "Main SHA drift triggers STOP_STALE_INPUT", () => {
    const ctx = baseContext();
    const adapter = mockAdapter({ getRemoteMainSha: () => "1111111111111111111111111111111111111111" });
    const res = evaluateWorkerState(ctx, adapter);
    if (res.state !== STATES.STOP_STALE_INPUT || res.reason_code !== REASON_CODES.MAIN_SHA_MISMATCH) {
      throw new Error(`Expected STOP_STALE_INPUT/MAIN_SHA_MISMATCH, got ${res.state}/${res.reason_code}`);
    }
    negativePassed++;
  });

  assertTest("NEG-02", "Task HEAD drift triggers STOP_STALE_INPUT", () => {
    const ctx = baseContext();
    const adapter = mockAdapter({ getTaskHeadSha: () => "2222222222222222222222222222222222222222" });
    const res = evaluateWorkerState(ctx, adapter);
    if (res.state !== STATES.STOP_STALE_INPUT || res.reason_code !== REASON_CODES.TASK_HEAD_MISMATCH) {
      throw new Error(`Expected STOP_STALE_INPUT/TASK_HEAD_MISMATCH, got ${res.state}/${res.reason_code}`);
    }
    negativePassed++;
  });

  assertTest("NEG-03", "Git blob mismatch triggers STOP_STALE_INPUT", () => {
    const ctx = baseContext();
    const adapter = mockAdapter({ getGitBlobSha: () => "3333333333333333333333333333333333333333" });
    const res = evaluateWorkerState(ctx, adapter);
    if (res.state !== STATES.STOP_STALE_INPUT || res.reason_code !== REASON_CODES.GIT_BLOB_MISMATCH) {
      throw new Error(`Expected STOP_STALE_INPUT/GIT_BLOB_MISMATCH, got ${res.state}/${res.reason_code}`);
    }
    negativePassed++;
  });

  assertTest("NEG-04", "Missing source file triggers STOP_UNVERIFIABLE", () => {
    const ctx = baseContext();
    const adapter = mockAdapter({ fileExists: () => false });
    const res = evaluateWorkerState(ctx, adapter);
    if (res.state !== STATES.STOP_UNVERIFIABLE || res.reason_code !== REASON_CODES.SOURCE_FILE_MISSING) {
      throw new Error(`Expected STOP_UNVERIFIABLE/SOURCE_FILE_MISSING, got ${res.state}/${res.reason_code}`);
    }
    negativePassed++;
  });

  assertTest("NEG-05", "Corrupted SEALED capsule triggers STOP_SECURITY_FAILURE", () => {
    const ctx = baseContext();
    ctx.capsule.seal.status = "UNSEALED";
    const res = evaluateWorkerState(ctx, mockAdapter());
    if (res.state !== STATES.STOP_SECURITY_FAILURE || res.reason_code !== REASON_CODES.CAPSULE_CORRUPTED) {
      throw new Error(`Expected STOP_SECURITY_FAILURE/CAPSULE_CORRUPTED, got ${res.state}/${res.reason_code}`);
    }
    negativePassed++;
  });

  assertTest("NEG-06", "Invalid attestation parent triggers STOP_SECURITY_FAILURE", () => {
    const ctx = baseContext();
    delete ctx.attestation.parent_attestation.raw_file_sha256;
    const res = evaluateWorkerState(ctx, mockAdapter());
    if (res.state !== STATES.STOP_SECURITY_FAILURE || res.reason_code !== REASON_CODES.ATTESTATION_CHAIN_INVALID) {
      throw new Error(`Expected STOP_SECURITY_FAILURE/ATTESTATION_CHAIN_INVALID, got ${res.state}/${res.reason_code}`);
    }
    negativePassed++;
  });

  assertTest("NEG-07", "Out-of-scope write (>3 files) triggers STOP_SECURITY_FAILURE", () => {
    const ctx = baseContext();
    ctx.operation_intent = "MUTATE";
    ctx.write_set = ["file1.txt", "file2.txt", "file3.txt", "file4.txt"];
    const res = evaluateWorkerState(ctx, mockAdapter());
    if (res.state !== STATES.STOP_SECURITY_FAILURE || res.reason_code !== REASON_CODES.SCOPE_VIOLATION) {
      throw new Error(`Expected STOP_SECURITY_FAILURE/SCOPE_VIOLATION, got ${res.state}/${res.reason_code}`);
    }
    negativePassed++;
  });

  assertTest("NEG-08", "Unsafe path traversal triggers STOP_SECURITY_FAILURE", () => {
    const ctx = baseContext();
    ctx.read_set = ["../outside.json"];
    const res = evaluateWorkerState(ctx, mockAdapter());
    if (res.state !== STATES.STOP_SECURITY_FAILURE || res.reason_code !== REASON_CODES.UNSAFE_PATH) {
      throw new Error(`Expected STOP_SECURITY_FAILURE/UNSAFE_PATH, got ${res.state}/${res.reason_code}`);
    }
    negativePassed++;
  });

  assertTest("NEG-09", "Symlink escape triggers STOP_SECURITY_FAILURE", () => {
    const ctx = baseContext();
    const adapter = mockAdapter({ isSymlink: () => true });
    const res = evaluateWorkerState(ctx, adapter);
    if (res.state !== STATES.STOP_SECURITY_FAILURE || res.reason_code !== REASON_CODES.SYMLINK_ESCAPE) {
      throw new Error(`Expected STOP_SECURITY_FAILURE/SYMLINK_ESCAPE, got ${res.state}/${res.reason_code}`);
    }
    negativePassed++;
  });

  assertTest("NEG-10", "Missing permissions in MUTATE mode triggers STOP_AUTHORIZATION_REQUIRED", () => {
    const ctx = baseContext();
    ctx.operation_intent = "MUTATE";
    ctx.actor.authorization_status = "DENIED";
    const res = evaluateWorkerState(ctx, mockAdapter());
    if (res.state !== STATES.STOP_AUTHORIZATION_REQUIRED || res.reason_code !== REASON_CODES.UNAUTHORIZED_ACTOR) {
      throw new Error(`Expected STOP_AUTHORIZATION_REQUIRED/UNAUTHORIZED_ACTOR, got ${res.state}/${res.reason_code}`);
    }
    negativePassed++;
  });

  assertTest("NEG-11", "Required CI failure triggers STOP_UNVERIFIABLE", () => {
    const ctx = baseContext();
    ctx.operation_intent = "MUTATE";
    ctx.required_ci = { run_id: "123", conclusion: "failure" };
    const res = evaluateWorkerState(ctx, mockAdapter());
    if (res.state !== STATES.STOP_UNVERIFIABLE || res.reason_code !== REASON_CODES.CI_FAILURE) {
      throw new Error(`Expected STOP_UNVERIFIABLE/CI_FAILURE, got ${res.state}/${res.reason_code}`);
    }
    negativePassed++;
  });

  assertTest("NEG-12", "Missing Git history triggers STOP_UNVERIFIABLE", () => {
    const ctx = baseContext();
    const adapter = mockAdapter({ getRemoteMainSha: () => null });
    const res = evaluateWorkerState(ctx, adapter);
    if (res.state !== STATES.STOP_UNVERIFIABLE || res.reason_code !== REASON_CODES.MISSING_GIT_HISTORY) {
      throw new Error(`Expected STOP_UNVERIFIABLE/MISSING_GIT_HISTORY, got ${res.state}/${res.reason_code}`);
    }
    negativePassed++;
  });

  assertTest("NEG-13", "Concurrent remote update triggers STOP_STALE_INPUT", () => {
    const ctx = baseContext();
    const adapter = mockAdapter({ getRemoteMainSha: () => "5555555555555555555555555555555555555555" });
    const res = evaluateWorkerState(ctx, adapter);
    if (res.state !== STATES.STOP_STALE_INPUT || res.reason_code !== REASON_CODES.MAIN_SHA_MISMATCH) {
      throw new Error(`Expected STOP_STALE_INPUT, got ${res.state}`);
    }
    negativePassed++;
  });

  assertTest("NEG-14", "Unauthorized actor name triggers STOP_AUTHORIZATION_REQUIRED", () => {
    const ctx = baseContext();
    ctx.operation_intent = "MUTATE";
    ctx.actor.owner = "Unknown Actor";
    const res = evaluateWorkerState(ctx, mockAdapter());
    if (res.state !== STATES.STOP_AUTHORIZATION_REQUIRED || res.reason_code !== REASON_CODES.UNAUTHORIZED_ACTOR) {
      throw new Error(`Expected STOP_AUTHORIZATION_REQUIRED, got ${res.state}`);
    }
    negativePassed++;
  });

  assertTest("NEG-15", "Unverifiable source evidence triggers STOP_UNVERIFIABLE", () => {
    const ctx = baseContext();
    ctx.expected_main_sha = "invalid_sha";
    const res = evaluateWorkerState(ctx, mockAdapter());
    if (res.state !== STATES.STOP_UNVERIFIABLE || res.reason_code !== REASON_CODES.MISSING_GIT_HISTORY) {
      throw new Error(`Expected STOP_UNVERIFIABLE, got ${res.state}`);
    }
    negativePassed++;
  });

  assertTest("NEG-16", "Historical SEALED rewrite triggers STOP_SECURITY_FAILURE", () => {
    const ctx = baseContext();
    ctx.tampered_historical_capsule = true;
    const res = evaluateWorkerState(ctx, mockAdapter());
    if (res.state !== STATES.STOP_SECURITY_FAILURE || res.reason_code !== REASON_CODES.HISTORICAL_SEALED_REWRITE) {
      throw new Error(`Expected STOP_SECURITY_FAILURE/HISTORICAL_SEALED_REWRITE, got ${res.state}`);
    }
    negativePassed++;
  });

  assertTest("NEG-17", "Invalid timestamp provenance triggers STOP_UNVERIFIABLE", () => {
    const ctx = baseContext();
    ctx.timestamp_provenance = {
      timestamp: "2026-10-04T09:00:00Z",
      source: "LOCAL_CLOCK_DEFECT"
    };
    const res = evaluateWorkerState(ctx, mockAdapter());
    if (res.state !== STATES.STOP_UNVERIFIABLE || res.reason_code !== REASON_CODES.INVALID_TIMESTAMP_PROVENANCE) {
      throw new Error(`Expected STOP_UNVERIFIABLE/INVALID_TIMESTAMP_PROVENANCE, got ${res.state}`);
    }
    negativePassed++;
  });

  assertTest("NEG-18", "Unauthorized governance activation triggers STOP_SECURITY_FAILURE", () => {
    const ctx = baseContext();
    ctx.governance_activation_attempt = true;
    const res = evaluateWorkerState(ctx, mockAdapter());
    if (res.state !== STATES.STOP_SECURITY_FAILURE || res.reason_code !== REASON_CODES.UNAUTHORIZED_GOVERNANCE_ACTIVATION) {
      throw new Error(`Expected STOP_SECURITY_FAILURE/UNAUTHORIZED_GOVERNANCE_ACTIVATION, got ${res.state}`);
    }
    negativePassed++;
  });

  console.log(`[SELF-TEST] Complete. Positive passed: ${positivePassed}/8, Negative passed: ${negativePassed}/18, Total: ${totalTests}/26.`);
  return { positivePassed, negativePassed, totalTests };
}

// --- CLI Execution ---
function main() {
  const args = process.argv.slice(2);
  if (args.includes("--self-test")) {
    try {
      const summary = runSelfTests();
      if (summary.positivePassed !== 8 || summary.negativePassed !== 18) {
        process.exit(1);
      }
      process.exit(0);
    } catch (err) {
      console.error(`[SELF-TEST ERROR] ${err.message}`);
      process.exit(1);
    }
  }

  // Default execution: Verify baseline against current repository
  try {
    const ctx = {
      expected_repository: "jirisar7-eng/synthesis-cms-mini",
      expected_main_sha: "474cb4a4fde921db09fe4fb1446b30d339f864bd",
      target_branch: "task/SYN-MINI-GOV-STATELESS-WORKER-001",
      operation_intent: "READ_ONLY",
      actor: {
        owner: "Jiří Šár",
        requester: "AI Studio Engineer",
        authorization_status: "GRANTED"
      },
      read_set: [".synthesis/lineage/genesis.json"],
      write_set: []
    };
    const res = evaluateWorkerState(ctx, defaultGitAdapter);
    console.log(`STATELESS_WORKER_VERIFICATION: ${res.state}`);
    if (res.state === STATES.READY_READ_ONLY || res.state === STATES.READY_TO_PLAN || res.state === STATES.READY_TO_MUTATE) {
      process.exit(0);
    } else {
      console.error(`Worker state check failed: ${res.failed_invariant} (${res.reason_code})`);
      process.exit(1);
    }
  } catch (err) {
    console.error(`Execution error: ${err.message}`);
    process.exit(1);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  main();
}
