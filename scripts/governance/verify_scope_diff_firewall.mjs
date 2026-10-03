#!/usr/bin/env node

/**
 * Synthesis CMS mini — Scope & Diff Firewall Verifier
 *
 * Implements a deterministic, fail-closed two-phase firewall:
 *  - Phase A (Pre-commit): Inspects working tree, index, untracked files, and file modes.
 *  - Phase B (Post-commit): Inspects git diff-tree, file modes, exact commit ancestry,
 *                           and enforces exact declared scope match against the commit diff.
 *
 * Built-in Node.js modules only (no external dependencies).
 * No shell interpolation (execFileSync with explicit argument arrays and shell: false).
 */

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

/**
 * Validates path format according to strict security invariants.
 */
export function validatePath(p) {
  if (typeof p !== "string" || p.length === 0) {
    throw new Error("UNTRUSTED_PATH_REJECTED: Path must be a non-empty string");
  }

  // Reject ASCII control characters
  for (let i = 0; i < p.length; i++) {
    const code = p.charCodeAt(i);
    if (code < 32 || code === 127) {
      throw new Error(`UNTRUSTED_PATH_REJECTED: Control character detected in path: ${JSON.stringify(p)}`);
    }
  }

  // Reject shell metacharacters: $;&|`<>\"'\\\n\r\t*?[]!()
  if (/[\$\;\&\|\`\<\>\"\'\\\n\r\t\*\?\[\]\!\(\)]/.test(p)) {
    throw new Error(`UNTRUSTED_PATH_REJECTED: Shell metacharacter detected in path: ${p}`);
  }

  // Reject absolute paths
  if (path.isAbsolute(p) || p.startsWith("/")) {
    throw new Error(`UNTRUSTED_PATH_REJECTED: Absolute path forbidden: ${p}`);
  }

  // Reject option injection
  if (p.startsWith("-")) {
    throw new Error(`UNTRUSTED_PATH_REJECTED: Option injection forbidden: ${p}`);
  }

  // Reject traversal segments and unnormalized paths
  const segments = p.split("/");
  if (segments.some(seg => seg === ".." || seg === "." || seg === "")) {
    throw new Error(`UNTRUSTED_PATH_REJECTED: Traversal or unnormalized segments forbidden: ${p}`);
  }

  return true;
}

/**
 * Validates the static scope policy of a command capsule.
 */
export function validateCapsuleScopePolicy(capsule) {
  if (!capsule || typeof capsule !== "object") {
    throw new Error("CAPSULE_POLICY_ERROR: Invalid capsule object");
  }
  const payload = capsule.payload || capsule;
  const boundary = payload.scope_boundary;
  const changes = payload.changes_and_evidence;

  if (!boundary || typeof boundary !== "object") {
    throw new Error("CAPSULE_POLICY_ERROR: Missing scope_boundary in capsule");
  }
  if (!changes || typeof changes !== "object") {
    throw new Error("CAPSULE_POLICY_ERROR: Missing changes_and_evidence in capsule");
  }

  const {
    permitted_read_paths = [],
    permitted_write_paths = [],
    protected_paths = [],
    max_write_files_limit = 0
  } = boundary;

  const {
    expected_changed_files = [],
    actual_changed_files = []
  } = changes;

  // Validate path syntax on all declared collections
  const allCollections = [
    { name: "permitted_read_paths", paths: permitted_read_paths },
    { name: "permitted_write_paths", paths: permitted_write_paths },
    { name: "protected_paths", paths: protected_paths },
    { name: "expected_changed_files", paths: expected_changed_files },
    { name: "actual_changed_files", paths: actual_changed_files }
  ];

  for (const coll of allCollections) {
    if (!Array.isArray(coll.paths)) {
      throw new Error(`CAPSULE_POLICY_ERROR: ${coll.name} must be an array`);
    }
    const seen = new Set();
    for (const p of coll.paths) {
      validatePath(p);
      if (seen.has(p)) {
        throw new Error(`DUPLICATE_PATH_REJECTED: Duplicate path in ${coll.name}: ${p}`);
      }
      seen.add(p);
    }
  }

  // Enforce zero overlap between permitted_write_paths and protected_paths
  const protectedSet = new Set(protected_paths);
  for (const p of permitted_write_paths) {
    if (protectedSet.has(p)) {
      throw new Error(`PROTECTED_WRITE_OVERLAP_REJECTED: Permitted write path cannot overlap protected path: ${p}`);
    }
  }

  // Enforce expected_changed_files is subset of permitted_write_paths
  const permittedWriteSet = new Set(permitted_write_paths);
  for (const p of expected_changed_files) {
    if (!permittedWriteSet.has(p)) {
      throw new Error(`UNPERMITTED_FILE_MODIFIED_REJECTED: Expected changed file is not in permitted_write_paths: ${p}`);
    }
    if (protectedSet.has(p)) {
      throw new Error(`PROTECTED_PATH_MODIFIED_REJECTED: Expected changed file is protected: ${p}`);
    }
  }

  // Enforce exact set equality between expected_changed_files and actual_changed_files
  if (expected_changed_files.length !== actual_changed_files.length) {
    throw new Error(
      `EXPECTED_ACTUAL_MISMATCH_REJECTED: expected_changed_files count (${expected_changed_files.length}) != actual_changed_files count (${actual_changed_files.length})`
    );
  }
  const actualSet = new Set(actual_changed_files);
  for (const p of expected_changed_files) {
    if (!actualSet.has(p)) {
      throw new Error(`EXPECTED_ACTUAL_MISMATCH_REJECTED: File in expected_changed_files not in actual_changed_files: ${p}`);
    }
  }

  // Enforce max_write_files_limit
  if (actual_changed_files.length > max_write_files_limit) {
    throw new Error(
      `DECLARED_WRITE_LIMIT_EXCEEDED_REJECTED: actual_changed_files count (${actual_changed_files.length}) exceeds max_write_files_limit (${max_write_files_limit})`
    );
  }

  return {
    valid: true,
    permittedWriteSet,
    protectedSet,
    expectedChangedSet: new Set(expected_changed_files)
  };
}

/**
 * Default Git execution helper using execFileSync (no shell).
 */
export function defaultGitExecutor(args, cwd) {
  try {
    return execFileSync("git", args, {
      cwd,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      encoding: "utf8"
    });
  } catch (err) {
    const stderr = err.stderr ? err.stderr.trim() : err.message;
    throw new Error(`GIT_EXECUTION_FAILURE: git ${args.join(" ")} failed: ${stderr}`);
  }
}

/**
 * Phase A — Pre-commit scope verification.
 */
export function verifyPreCommitScope(capsule, repoRoot, gitExecutor = defaultGitExecutor) {
  const policy = validateCapsuleScopePolicy(capsule);
  const { permittedWriteSet, protectedSet, expectedChangedSet } = policy;

  // Run git status in porcelain v1 null-delimited format
  const statusOutput = gitExecutor(["status", "--porcelain=v1", "-z", "--untracked-files=all"], repoRoot);
  const entries = statusOutput.split("\0").filter(Boolean);

  const candidateChanges = new Set();

  for (const entry of entries) {
    if (entry.length < 3) continue;
    const x = entry[0];
    const y = entry[1];
    const filePath = entry.slice(3).trim();

    // Check for unmerged index entries
    if (x === "U" || y === "U" || (x === "A" && y === "A") || (x === "D" && y === "D")) {
      throw new Error(`UNMERGED_INDEX_REJECTED: Unmerged index entry detected: ${filePath}`);
    }

    // Check for unsupported rename / copy operations in worktree
    if (x === "R" || y === "R" || x === "C" || y === "C") {
      throw new Error(`UNSUPPORTED_RENAME_COPY_REJECTED: Rename/copy detected in working tree: ${filePath}`);
    }

    validatePath(filePath);

    // Check for unauthorized deletions
    if (x === "D" || y === "D") {
      if (!expectedChangedSet.has(filePath)) {
        throw new Error(`UNEXPECTED_DELETION_REJECTED: Unexpected deleted file in working tree: ${filePath}`);
      }
    }

    // Check for unexpected untracked file
    if (x === "?" && y === "?") {
      if (!permittedWriteSet.has(filePath)) {
        throw new Error(`UNEXPECTED_UNTRACKED_FILE_REJECTED: Untracked file outside permitted_write_paths: ${filePath}`);
      }
    }

    // Check for unstaged modification outside permitted writes
    if (y === "M" || y === "D") {
      if (!permittedWriteSet.has(filePath)) {
        throw new Error(`UNEXPECTED_UNSTAGED_MODIFICATION_REJECTED: Unstaged changes outside permitted_write_paths: ${filePath}`);
      }
    }

    // Check for protected paths
    if (protectedSet.has(filePath)) {
      throw new Error(`PROTECTED_PATH_MODIFIED_REJECTED: Protected path touched in working tree: ${filePath}`);
    }

    // Check against permitted write paths
    if (!permittedWriteSet.has(filePath)) {
      throw new Error(`UNPERMITTED_FILE_MODIFIED_REJECTED: File touched outside permitted_write_paths: ${filePath}`);
    }

    candidateChanges.add(filePath);
  }

  // Ensure all expected changed files exist in worktree or candidate set
  for (const expected of expectedChangedSet) {
    const fullPath = path.join(repoRoot, expected);
    if (!candidateChanges.has(expected) && !fs.existsSync(fullPath)) {
      throw new Error(`MISSING_EXPECTED_FILE_REJECTED: Expected changed file does not exist in working tree: ${expected}`);
    }
  }

  return {
    valid: true,
    candidateChanges: Array.from(candidateChanges).sort()
  };
}

/**
 * Phase B — Post-commit diff firewall verification.
 */
export function verifyPostCommitDiff(capsule, baseSha, headSha, repoRoot, gitExecutor = defaultGitExecutor) {
  const policy = validateCapsuleScopePolicy(capsule);
  const { permittedWriteSet, protectedSet, expectedChangedSet } = policy;
  const maxLimit = capsule.payload?.scope_boundary?.max_write_files_limit ?? 3;

  if (!baseSha || typeof baseSha !== "string" || !/^[0-9a-f]{40}$/.test(baseSha)) {
    throw new Error(`STALE_BASE_COMMIT_REJECTED: Invalid base SHA format: ${baseSha}`);
  }
  if (!headSha || typeof headSha !== "string" || !/^[0-9a-f]{40}$/.test(headSha)) {
    throw new Error(`GIT_EXECUTION_FAILURE: Invalid head SHA format: ${headSha}`);
  }

  // Verify baseSha and headSha exist in repository
  try {
    gitExecutor(["rev-parse", "--verify", `${baseSha}^{commit}`], repoRoot);
  } catch (err) {
    throw new Error(`STALE_BASE_COMMIT_REJECTED: Base commit does not exist or is unreachable: ${baseSha}`);
  }
  try {
    gitExecutor(["rev-parse", "--verify", `${headSha}^{commit}`], repoRoot);
  } catch (err) {
    throw new Error(`GIT_EXECUTION_FAILURE: Head commit does not exist: ${headSha}`);
  }

  // Run git diff-tree -r --raw -z --no-commit-id baseSha headSha
  const rawDiff = gitExecutor(
    ["diff-tree", "-r", "--raw", "-z", "--no-commit-id", baseSha, headSha],
    repoRoot
  );

  const tokens = rawDiff.split("\0").filter(Boolean);
  const diffFiles = new Set();

  let i = 0;
  while (i < tokens.length) {
    const header = tokens[i];
    if (!header.startsWith(":")) {
      i++;
      continue;
    }

    // Header format: :old_mode new_mode old_sha new_sha status
    const parts = header.slice(1).split(/\s+/);
    if (parts.length < 5) {
      i++;
      continue;
    }

    const oldMode = parts[0];
    const newMode = parts[1];
    const status = parts[4];
    const filePath = tokens[i + 1];
    i += 2;

    if (!filePath) continue;

    validatePath(filePath);

    // Reject symlink file modes: 120000
    if (oldMode === "120000" || newMode === "120000") {
      throw new Error(`SYMLINK_MODE_REJECTED: File mode 120000 (symlink) forbidden in diff: ${filePath}`);
    }

    // Reject submodule file modes: 160000
    if (oldMode === "160000" || newMode === "160000") {
      throw new Error(`SUBMODULE_MODE_REJECTED: File mode 160000 (gitlink/submodule) forbidden in diff: ${filePath}`);
    }

    // Reject unsupported rename / copy status
    if (status.startsWith("R") || status.startsWith("C")) {
      throw new Error(`UNSUPPORTED_RENAME_COPY_REJECTED: Rename/copy detected in diff: ${filePath}`);
    }

    // Reject unexpected deletions
    if (status === "D" && !expectedChangedSet.has(filePath)) {
      throw new Error(`UNEXPECTED_DELETION_REJECTED: Unexpected deleted file in diff: ${filePath}`);
    }

    // Reject unexpected changes
    if (!expectedChangedSet.has(filePath)) {
      throw new Error(`UNEXPECTED_CHANGED_FILE_REJECTED: Diff contains file not declared in expected_changed_files: ${filePath}`);
    }

    // Reject changes outside permitted write paths
    if (!permittedWriteSet.has(filePath)) {
      throw new Error(`UNPERMITTED_FILE_MODIFIED_REJECTED: Diff contains file outside permitted_write_paths: ${filePath}`);
    }

    // Reject changes to protected paths
    if (protectedSet.has(filePath)) {
      throw new Error(`PROTECTED_PATH_MODIFIED_REJECTED: Diff touches protected file: ${filePath}`);
    }

    diffFiles.add(filePath);
  }

  // Reject empty diff for mutation commands
  if (diffFiles.size === 0 && expectedChangedSet.size > 0) {
    throw new Error("EMPTY_MUTATION_DIFF_REJECTED: Diff is empty but mutation was expected");
  }

  // Reject missing expected files in diff
  for (const expected of expectedChangedSet) {
    if (!diffFiles.has(expected)) {
      throw new Error(`MISSING_EXPECTED_FILE_REJECTED: Expected file missing from commit diff: ${expected}`);
    }
  }

  // Reject exceeding max write files limit
  if (diffFiles.size > maxLimit) {
    throw new Error(
      `DECLARED_WRITE_LIMIT_EXCEEDED_REJECTED: Committed diff file count (${diffFiles.size}) exceeds limit (${maxLimit})`
    );
  }

  return {
    valid: true,
    diffFiles: Array.from(diffFiles).sort()
  };
}

/**
 * Behavioral self-test suite covering POS-01..POS-03 and NEG-01..NEG-20.
 */
export function runSelfTests() {
  console.log("Running Scope & Diff Firewall Behavioral Self-Tests...");
  let passed = 0;
  let failed = 0;

  function assertPositive(name, fn) {
    try {
      fn();
      passed++;
      console.log(`  [PASS] ${name}`);
    } catch (err) {
      failed++;
      console.error(`  [FAIL] ${name}: Unexpected failure: ${err.message}`);
    }
  }

  function assertNegative(name, expectedErrorSubstr, fn) {
    try {
      fn();
      failed++;
      console.error(`  [FAIL] ${name}: Expected error containing '${expectedErrorSubstr}', but succeeded`);
    } catch (err) {
      if (err.message.includes(expectedErrorSubstr)) {
        passed++;
        console.log(`  [PASS] ${name} (rejected with: ${expectedErrorSubstr})`);
      } else {
        failed++;
        console.error(`  [FAIL] ${name}: Expected '${expectedErrorSubstr}', got '${err.message}'`);
      }
    }
  }

  const sampleCapsule = {
    payload: {
      scope_boundary: {
        permitted_read_paths: ["LICENSE", "README.md"],
        permitted_write_paths: ["file1.txt", "file2.txt", "file3.txt"],
        protected_paths: ["LICENSE", "README.md"],
        max_write_files_limit: 3
      },
      changes_and_evidence: {
        expected_changed_files: ["file1.txt", "file2.txt", "file3.txt"],
        actual_changed_files: ["file1.txt", "file2.txt", "file3.txt"]
      }
    }
  };

  // --- POSITIVE TESTS ---
  assertPositive("POS-01: Exact authorized three-file change passes static policy", () => {
    validateCapsuleScopePolicy(sampleCapsule);
  });

  assertPositive("POS-02: Permitted pre-commit candidate passes", () => {
    const mockGit = (args) => {
      if (args[0] === "status") {
        return "A  file1.txt\0A  file2.txt\0?? file3.txt\0";
      }
      return "";
    };
    verifyPreCommitScope(sampleCapsule, "/tmp", mockGit);
  });

  assertPositive("POS-03: Exact committed diff passes post-commit firewall", () => {
    const mockGit = (args) => {
      if (args[0] === "rev-parse") return "ok";
      if (args[0] === "diff-tree") {
        return ":000000 100644 0000000 1111111 A\0file1.txt\0:000000 100644 0000000 2222222 A\0file2.txt\0:000000 100644 0000000 3333333 A\0file3.txt\0";
      }
      return "";
    };
    verifyPostCommitDiff(sampleCapsule, "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222", "/tmp", mockGit);
  });

  // --- NEGATIVE TESTS (NEG-01 to NEG-20) ---
  assertNegative("NEG-01: Parent traversal", "UNTRUSTED_PATH_REJECTED", () => {
    validatePath("../secret.txt");
  });

  assertNegative("NEG-02: Absolute path", "UNTRUSTED_PATH_REJECTED", () => {
    validatePath("/etc/passwd");
  });

  assertNegative("NEG-03: Shell metacharacters", "UNTRUSTED_PATH_REJECTED", () => {
    validatePath("file$(id).txt");
  });

  assertNegative("NEG-04: Git option injection", "UNTRUSTED_PATH_REJECTED", () => {
    validatePath("--output=exploit");
  });

  assertNegative("NEG-05: Protected/write overlap", "PROTECTED_WRITE_OVERLAP_REJECTED", () => {
    const badCapsule = JSON.parse(JSON.stringify(sampleCapsule));
    badCapsule.payload.scope_boundary.permitted_write_paths.push("LICENSE");
    validateCapsuleScopePolicy(badCapsule);
  });

  assertNegative("NEG-06: Read-only path modified", "UNPERMITTED_FILE_MODIFIED_REJECTED", () => {
    const badCapsule = JSON.parse(JSON.stringify(sampleCapsule));
    badCapsule.payload.changes_and_evidence.expected_changed_files = ["LICENSE"];
    badCapsule.payload.changes_and_evidence.actual_changed_files = ["LICENSE"];
    validateCapsuleScopePolicy(badCapsule);
  });

  assertNegative("NEG-07: Unexpected changed file in diff", "UNEXPECTED_CHANGED_FILE_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "rev-parse") return "ok";
      if (args[0] === "diff-tree") {
        return ":000000 100644 000 111 A\0file1.txt\0:000000 100644 000 222 A\0file2.txt\0:000000 100644 000 333 A\0file3.txt\0:000000 100644 000 444 A\0unauthorized.txt\0";
      }
      return "";
    };
    verifyPostCommitDiff(sampleCapsule, "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222", "/tmp", mockGit);
  });

  assertNegative("NEG-08: Missing expected file in diff", "MISSING_EXPECTED_FILE_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "rev-parse") return "ok";
      if (args[0] === "diff-tree") {
        return ":000000 100644 000 111 A\0file1.txt\0";
      }
      return "";
    };
    verifyPostCommitDiff(sampleCapsule, "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222", "/tmp", mockGit);
  });

  assertNegative("NEG-09: Declared write-limit exceeded", "DECLARED_WRITE_LIMIT_EXCEEDED_REJECTED", () => {
    const badCapsule = JSON.parse(JSON.stringify(sampleCapsule));
    badCapsule.payload.scope_boundary.max_write_files_limit = 2; // actual is 3
    validateCapsuleScopePolicy(badCapsule);
  });

  assertNegative("NEG-10: Empty mutation diff", "EMPTY_MUTATION_DIFF_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "rev-parse") return "ok";
      if (args[0] === "diff-tree") return "";
      return "";
    };
    verifyPostCommitDiff(sampleCapsule, "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222", "/tmp", mockGit);
  });

  assertNegative("NEG-11: Unexpected untracked file in pre-commit", "UNEXPECTED_UNTRACKED_FILE_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "status") {
        return "?? file1.txt\0?? intruder.sh\0";
      }
      return "";
    };
    verifyPreCommitScope(sampleCapsule, "/tmp", mockGit);
  });

  assertNegative("NEG-12: Unexpected unstaged modification", "UNEXPECTED_UNSTAGED_MODIFICATION_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "status") {
        return " M unauthorized.txt\0";
      }
      return "";
    };
    verifyPreCommitScope(sampleCapsule, "/tmp", mockGit);
  });

  assertNegative("NEG-13: Unexpected deletion", "UNEXPECTED_DELETION_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "status") {
        return " D unannounced_delete.txt\0";
      }
      return "";
    };
    verifyPreCommitScope(sampleCapsule, "/tmp", mockGit);
  });

  assertNegative("NEG-14: Symlink mode 120000", "SYMLINK_MODE_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "rev-parse") return "ok";
      if (args[0] === "diff-tree") {
        return ":000000 120000 000 111 A\0file1.txt\0";
      }
      return "";
    };
    verifyPostCommitDiff(sampleCapsule, "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222", "/tmp", mockGit);
  });

  assertNegative("NEG-15: Submodule mode 160000", "SUBMODULE_MODE_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "rev-parse") return "ok";
      if (args[0] === "diff-tree") {
        return ":000000 160000 000 111 A\0file1.txt\0";
      }
      return "";
    };
    verifyPostCommitDiff(sampleCapsule, "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222", "/tmp", mockGit);
  });

  assertNegative("NEG-16: Stale base commit", "STALE_BASE_COMMIT_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "rev-parse") {
        throw new Error("fatal: Needed a single revision");
      }
      return "";
    };
    verifyPostCommitDiff(sampleCapsule, "0000000000000000000000000000000000000000", "2222222222222222222222222222222222222222", "/tmp", mockGit);
  });

  assertNegative("NEG-17: Unmerged Git index entry", "UNMERGED_INDEX_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "status") {
        return "UU conflicted.txt\0";
      }
      return "";
    };
    verifyPreCommitScope(sampleCapsule, "/tmp", mockGit);
  });

  assertNegative("NEG-18: Duplicate normalized path", "DUPLICATE_PATH_REJECTED", () => {
    const badCapsule = JSON.parse(JSON.stringify(sampleCapsule));
    badCapsule.payload.scope_boundary.permitted_write_paths.push("file1.txt");
    validateCapsuleScopePolicy(badCapsule);
  });

  assertNegative("NEG-19: Git command failure", "GIT_EXECUTION_FAILURE", () => {
    const mockGit = (args) => {
      if (args[0] === "rev-parse") return "ok";
      throw new Error("GIT_EXECUTION_FAILURE: git command failed");
    };
    verifyPostCommitDiff(sampleCapsule, "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222", "/tmp", mockGit);
  });

  assertNegative("NEG-20: Unsupported rename/copy", "UNSUPPORTED_RENAME_COPY_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "rev-parse") return "ok";
      if (args[0] === "diff-tree") {
        return ":100644 100644 111 222 R100\0file1.txt\0";
      }
      return "";
    };
    verifyPostCommitDiff(sampleCapsule, "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222", "/tmp", mockGit);
  });

  console.log(`\nSelf-test summary: Passed: ${passed}, Failed: ${failed}`);
  if (failed > 0) {
    throw new Error(`Self-tests failed: ${failed} failure(s)`);
  }
}

// --- CLI Execution ---
function main() {
  const args = process.argv.slice(2);
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

  if (args.includes("--self-test")) {
    runSelfTests();
    process.exit(0);
  }

  if (args.includes("--pre-commit")) {
    const idx = args.indexOf("--pre-commit");
    const capsulePath = args[idx + 1];
    if (!capsulePath) {
      console.error("Error: --pre-commit requires <capsule-path>");
      process.exit(1);
    }
    const resolvedPath = path.resolve(repoRoot, capsulePath);
    const capsule = JSON.parse(fs.readFileSync(resolvedPath, "utf-8"));
    const res = verifyPreCommitScope(capsule, repoRoot);
    console.log("PRE_COMMIT_SCOPE_CHECK: PASS", res);
    process.exit(0);
  }

  if (args.includes("--post-commit")) {
    const idx = args.indexOf("--post-commit");
    const capsulePath = args[idx + 1];
    const baseSha = args[idx + 2];
    const headSha = args[idx + 3];
    if (!capsulePath || !baseSha || !headSha) {
      console.error("Error: --post-commit requires <capsule-path> <base-sha> <head-sha>");
      process.exit(1);
    }
    const resolvedPath = path.resolve(repoRoot, capsulePath);
    const capsule = JSON.parse(fs.readFileSync(resolvedPath, "utf-8"));
    const res = verifyPostCommitDiff(capsule, baseSha, headSha, repoRoot);
    console.log("POST_COMMIT_DIFF_CHECK: PASS", res);
    process.exit(0);
  }

  console.log("Usage: node scripts/governance/verify_scope_diff_firewall.mjs --self-test | --pre-commit <capsule> | --post-commit <capsule> <base> <head>");
}

if (process.argv[1] && import.meta.url.endsWith(path.basename(process.argv[1]))) {
  main();
}
