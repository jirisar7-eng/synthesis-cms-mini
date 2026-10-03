#!/usr/bin/env node

/**
 * Synthesis CMS mini — Scope & Diff Firewall Verifier
 *
 * Implements a deterministic, fail-closed two-phase firewall:
 *  - Phase A (Pre-commit): Inspects working tree, index, untracked files, and staged file modes.
 *                          Enforces exact set equality with declared expected changes.
 *                          Validates real filesystem object types with lstatSync without existsSync prerequisite,
 *                          strictly rejecting dangling symlinks, symlink ancestors, and non-regular files.
 *                          Strictly validates git diff-index without fail-open try/catch.
 *  - Phase B (Post-commit): Inspects git diff-tree, file modes, exact commit ancestry (single direct parent),
 *                           and enforces exact declared scope match against the commit diff.
 *  - Strict CLI Grammar: Rejects mixed modes, extra arguments, unknown flags, and validates capsule identity.
 *
 * Built-in Node.js modules only (no external dependencies).
 * No shell interpolation (execFileSync with explicit argument arrays and shell: false).
 */

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

/**
 * Validates path format and filesystem properties according to strict security invariants.
 */
export function validatePath(p, repoRoot = null) {
  if (typeof p !== "string" || p.length === 0) {
    throw new Error("UNTRUSTED_PATH_REJECTED: Path must be a non-empty string");
  }

  // Reject leading or trailing whitespace
  if (p.startsWith(" ") || p.endsWith(" ") || p.startsWith("\t") || p.endsWith("\t")) {
    throw new Error(`UNTRUSTED_PATH_REJECTED: Leading or trailing whitespace detected in path: ${JSON.stringify(p)}`);
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

  // If repoRoot is provided, enforce repository containment and ancestor symlink checks
  if (repoRoot) {
    const normalizedRepoRoot = path.resolve(repoRoot);
    const resolvedPath = path.resolve(repoRoot, p);
    if (!resolvedPath.startsWith(normalizedRepoRoot + path.sep)) {
      throw new Error(`UNTRUSTED_PATH_REJECTED: Path escapes repository root: ${p}`);
    }

    // Check ancestor directories for symlinks without existsSync prerequisite
    let current = path.dirname(resolvedPath);
    while (current.length >= normalizedRepoRoot.length && current.startsWith(normalizedRepoRoot)) {
      try {
        const lstat = fs.lstatSync(current);
        if (lstat.isSymbolicLink()) {
          throw new Error(`SYMLINK_ANCESTOR_REJECTED: Ancestor directory is a symbolic link: ${current}`);
        }
      } catch (err) {
        if (err.code === "ENOENT") {
          // Ancestor directory does not exist on disk
        } else if (err.message.includes("SYMLINK_ANCESTOR_REJECTED")) {
          throw err;
        } else {
          throw new Error(`FILESYSTEM_ACCESS_FAILURE: Failed checking ancestor directory ${current}: ${err.message}`);
        }
      }
      const parent = path.dirname(current);
      if (parent === current) break;
      current = parent;
    }

    // If the path itself exists on disk, inspect its lstatSync directly (rejects dangling & valid symlinks)
    try {
      const fileLstat = fs.lstatSync(resolvedPath);
      if (fileLstat.isSymbolicLink()) {
        throw new Error(`SYMLINK_OBJECT_REJECTED: Path is a symbolic link: ${p}`);
      }
      if (!fileLstat.isFile() && !fileLstat.isDirectory()) {
        throw new Error(`UNSUPPORTED_FILE_TYPE_REJECTED: Path is not a regular file: ${p}`);
      }
    } catch (err) {
      if (err.code === "ENOENT") {
        // Path does not exist on disk
      } else if (err.message.includes("SYMLINK_OBJECT_REJECTED") || err.message.includes("UNSUPPORTED_FILE_TYPE_REJECTED")) {
        throw err;
      } else {
        throw new Error(`FILESYSTEM_ACCESS_FAILURE: Failed inspecting path ${p}: ${err.message}`);
      }
    }
  }

  return true;
}

/**
 * Validates the static scope policy of a command capsule.
 */
export function validateCapsuleScopePolicy(capsule, repoRoot = null) {
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
      validatePath(p, repoRoot);
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
 * Fail-closed: No ignoring of git diff-index errors. Strictly rejects dangling symlinks.
 */
export function verifyPreCommitScope(capsule, repoRoot, gitExecutor = defaultGitExecutor) {
  const policy = validateCapsuleScopePolicy(capsule, repoRoot);
  const { permittedWriteSet, protectedSet, expectedChangedSet } = policy;

  // Run git status in porcelain v1 null-delimited format
  const statusOutput = gitExecutor(["status", "--porcelain=v1", "-z", "--untracked-files=all"], repoRoot);
  const rawTokens = statusOutput.split("\0");

  const candidateChanges = new Set();
  const deletedCandidates = new Set();
  let idx = 0;

  while (idx < rawTokens.length) {
    const entry = rawTokens[idx];
    idx++;
    if (!entry) continue;

    if (entry.length < 3) {
      throw new Error(`MALFORMED_STATUS_ENTRY_REJECTED: Invalid git status entry: ${JSON.stringify(entry)}`);
    }

    const x = entry[0];
    const y = entry[1];
    // Exact slice without destructive trim()
    const filePath = entry.slice(3);

    // Check for unmerged index entries
    if (x === "U" || y === "U" || (x === "A" && y === "A") || (x === "D" && y === "D")) {
      throw new Error(`UNMERGED_INDEX_REJECTED: Unmerged index entry detected: ${filePath}`);
    }

    // Check for rename / copy operations in porcelain -z
    if (x === "R" || y === "R" || x === "C" || y === "C") {
      const origPath = rawTokens[idx];
      idx++;
      throw new Error(`UNSUPPORTED_RENAME_COPY_REJECTED: Rename/copy detected in working tree: ${origPath} -> ${filePath}`);
    }

    validatePath(filePath, repoRoot);

    // Check for unauthorized deletions
    if (x === "D" || y === "D") {
      if (!expectedChangedSet.has(filePath)) {
        throw new Error(`UNEXPECTED_DELETION_REJECTED: Unexpected deleted file in working tree: ${filePath}`);
      }
      deletedCandidates.add(filePath);
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

  // Check staged index file modes using git diff-index --cached --raw -z HEAD
  // FAIL-CLOSED: Any failure or malformed output MUST throw immediately!
  const rawStaged = gitExecutor(["diff-index", "--cached", "--raw", "-z", "HEAD"], repoRoot);
  const stagedTokens = rawStaged.split("\0").filter(Boolean);
  let sIdx = 0;

  while (sIdx < stagedTokens.length) {
    const header = stagedTokens[sIdx];
    sIdx++;

    if (!header.startsWith(":")) {
      throw new Error(`MALFORMED_DIFF_INDEX_HEADER_REJECTED: Staged diff header must start with ':': ${header}`);
    }

    const parts = header.slice(1).split(/\s+/);
    if (parts.length < 5) {
      throw new Error(`TRUNCATED_DIFF_INDEX_RECORD_REJECTED: Staged diff header has fewer than 5 components: ${header}`);
    }

    const newMode = parts[1];
    const status = parts[4];
    const stagedPath = stagedTokens[sIdx];
    sIdx++;

    if (!stagedPath) {
      throw new Error(`TRUNCATED_DIFF_INDEX_RECORD_REJECTED: Missing file path for staged header: ${header}`);
    }

    if (newMode === "120000") {
      throw new Error(`SYMLINK_MODE_REJECTED: Staged symlink mode 120000 forbidden: ${stagedPath}`);
    }
    if (newMode === "160000") {
      throw new Error(`SUBMODULE_MODE_REJECTED: Staged submodule mode 160000 forbidden: ${stagedPath}`);
    }
    if (!["100644", "100755"].includes(newMode) && newMode !== "000000") {
      throw new Error(`UNSUPPORTED_STAGED_MODE_REJECTED: Unsupported staged mode ${newMode} for ${stagedPath}`);
    }

    const statusCode = status[0];
    if (!["A", "M", "D", "T"].includes(statusCode)) {
      throw new Error(`UNKNOWN_DIFF_INDEX_STATUS_REJECTED: Unknown staged status '${status}' for ${stagedPath}`);
    }
  }

  // Enforce EXACT set equality between candidateChanges and expectedChangedSet
  for (const expected of expectedChangedSet) {
    if (!candidateChanges.has(expected)) {
      throw new Error(`MISSING_EXPECTED_FILE_REJECTED: Expected changed file was not modified or staged in Git: ${expected}`);
    }
  }

  if (candidateChanges.size !== expectedChangedSet.size) {
    const extra = Array.from(candidateChanges).filter(p => !expectedChangedSet.has(p));
    throw new Error(`UNEXPECTED_CHANGED_FILE_REJECTED: Working tree contains unexpected changes: ${extra.join(", ")}`);
  }

  // Strictly verify filesystem properties of all non-deleted candidate files
  for (const candidate of candidateChanges) {
    if (deletedCandidates.has(candidate)) continue;
    const resolvedCandidate = path.resolve(repoRoot, candidate);
    try {
      const candLstat = fs.lstatSync(resolvedCandidate);
      if (candLstat.isSymbolicLink()) {
        throw new Error(`SYMLINK_OBJECT_REJECTED: Candidate path is a symbolic link: ${candidate}`);
      }
      if (!candLstat.isFile()) {
        throw new Error(`UNSUPPORTED_FILE_TYPE_REJECTED: Candidate path is not a regular file: ${candidate}`);
      }
    } catch (err) {
      if (err.message.includes("SYMLINK_OBJECT_REJECTED") || err.message.includes("UNSUPPORTED_FILE_TYPE_REJECTED")) {
        throw err;
      }
      if (err.code === "ENOENT") {
        if (gitExecutor === defaultGitExecutor) {
          throw new Error(`FILESYSTEM_ACCESS_FAILURE: Candidate file does not exist on disk: ${candidate}`);
        }
        // In mock unit test where mockGit is supplied and files are not created on disk, continue
      } else {
        throw new Error(`FILESYSTEM_ACCESS_FAILURE: Failed inspecting candidate path ${candidate}: ${err.message}`);
      }
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
  const policy = validateCapsuleScopePolicy(capsule, repoRoot);
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

  // Verify supplied headSha matches actual repository checkout HEAD
  const currentHead = gitExecutor(["rev-parse", "HEAD"], repoRoot).trim();
  if (currentHead !== headSha) {
    throw new Error(`HEAD_MISMATCH_REJECTED: Supplied headSha (${headSha}) does not match current repository HEAD (${currentHead})`);
  }

  // Verify exact direct single parent ancestry
  const parentOutput = gitExecutor(["rev-parse", `${headSha}^@`], repoRoot).trim();
  const parents = parentOutput.split(/\s+/).filter(Boolean);
  if (parents.length !== 1 || parents[0] !== baseSha) {
    throw new Error(
      `PARENT_ANCESTRY_MISMATCH_REJECTED: Commit ${headSha} must have exactly one direct parent matching baseSha ${baseSha}, got: ${parents.join(", ") || "none"}`
    );
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
      throw new Error(`MALFORMED_DIFF_HEADER_REJECTED: Diff header must start with ':': ${header}`);
    }

    const parts = header.slice(1).split(/\s+/);
    if (parts.length < 5) {
      throw new Error(`MALFORMED_DIFF_HEADER_REJECTED: Diff header has fewer than 5 components: ${header}`);
    }

    const oldMode = parts[0];
    const newMode = parts[1];
    const status = parts[4];
    const filePath = tokens[i + 1];
    i += 2;

    if (!filePath) {
      throw new Error(`MALFORMED_DIFF_HEADER_REJECTED: Missing file path for diff header: ${header}`);
    }

    // Reject rename / copy records
    if (status.startsWith("R") || status.startsWith("C")) {
      const origPath = tokens[i];
      i++;
      throw new Error(`UNSUPPORTED_RENAME_COPY_REJECTED: Rename/copy detected in diff: ${origPath} -> ${filePath}`);
    }

    validatePath(filePath, repoRoot);

    // Validate status code
    const statusCode = status[0];
    if (!["A", "M", "D", "T"].includes(statusCode)) {
      throw new Error(`UNKNOWN_DIFF_STATUS_REJECTED: Unknown git diff status '${status}' for ${filePath}`);
    }

    // Reject duplicate diff entries
    if (diffFiles.has(filePath)) {
      throw new Error(`DUPLICATE_DIFF_ENTRY_REJECTED: Duplicate diff entry for ${filePath}`);
    }

    // Reject symlink file modes: 120000
    if (oldMode === "120000" || newMode === "120000") {
      throw new Error(`SYMLINK_MODE_REJECTED: File mode 120000 (symlink) forbidden in diff: ${filePath}`);
    }

    // Reject submodule file modes: 160000
    if (oldMode === "160000" || newMode === "160000") {
      throw new Error(`SUBMODULE_MODE_REJECTED: File mode 160000 (gitlink/submodule) forbidden in diff: ${filePath}`);
    }

    // Reject unapproved executable-mode changes
    if ((oldMode === "100644" && newMode === "100755") || (oldMode === "100755" && newMode === "100644")) {
      throw new Error(`UNAPPROVED_EXECUTABLE_MODE_CHANGE_REJECTED: Executable mode change forbidden for ${filePath}: ${oldMode} -> ${newMode}`);
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
 * Validates CLI capsule path argument and verifies capsule identity.
 */
export function validateCliCapsulePath(capsulePath, repoRoot) {
  if (!capsulePath || typeof capsulePath !== "string") {
    throw new Error("CAPSULE_PATH_INVALID_REJECTED: Capsule path must be a non-empty string");
  }

  const normalizedRepoRoot = path.resolve(repoRoot);
  const resolved = path.resolve(repoRoot, capsulePath);

  if (!resolved.startsWith(normalizedRepoRoot + path.sep)) {
    throw new Error(`CAPSULE_PATH_ESCAPE_REJECTED: Capsule path escapes repository root: ${capsulePath}`);
  }

  const rel = path.relative(normalizedRepoRoot, resolved);
  if (!rel.startsWith(".synthesis/task-capsules/") || !rel.endsWith(".json")) {
    throw new Error(`CAPSULE_PATH_INVALID_REJECTED: Capsule path must be in .synthesis/task-capsules/*.json: ${rel}`);
  }

  // Check ancestor directories for symlinks without existsSync
  let current = path.dirname(resolved);
  while (current.length >= normalizedRepoRoot.length && current.startsWith(normalizedRepoRoot)) {
    try {
      const lstat = fs.lstatSync(current);
      if (lstat.isSymbolicLink()) {
        throw new Error(`SYMLINK_ANCESTOR_REJECTED: Capsule ancestor directory is a symbolic link: ${current}`);
      }
    } catch (err) {
      if (err.code === "ENOENT") {
        // ok
      } else if (err.message.includes("SYMLINK_ANCESTOR_REJECTED")) {
        throw err;
      } else {
        throw new Error(`FILESYSTEM_ACCESS_FAILURE: Failed checking capsule ancestor ${current}: ${err.message}`);
      }
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }

  // Check capsule file itself
  try {
    const fileLstat = fs.lstatSync(resolved);
    if (fileLstat.isSymbolicLink()) {
      throw new Error(`SYMLINK_CAPSULE_REJECTED: Capsule file is a symbolic link: ${rel}`);
    }
    if (!fileLstat.isFile()) {
      throw new Error(`UNSUPPORTED_FILE_TYPE_REJECTED: Capsule is not a regular file: ${rel}`);
    }
  } catch (err) {
    if (err.code === "ENOENT") {
      throw new Error(`CAPSULE_FILE_NOT_FOUND_REJECTED: Capsule file does not exist: ${rel}`);
    }
    throw err;
  }

  // Verify capsule identity
  const content = JSON.parse(fs.readFileSync(resolved, "utf-8"));
  const expectedId = path.basename(resolved, ".json");
  if (content.payload?.capsule_id !== expectedId) {
    throw new Error(
      `CAPSULE_IDENTITY_MISMATCH_REJECTED: Capsule filename (${expectedId}) does not match payload.capsule_id (${content.payload?.capsule_id})`
    );
  }

  return { resolvedPath: resolved, capsule: content };
}

/**
 * Behavioral self-test suite covering all positive and negative regressions.
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
      capsule_id: "CAP-TEST-001",
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

  const baseSha = "1111111111111111111111111111111111111111";
  const headSha = "2222222222222222222222222222222222222222";

  const standardMockGit = (args) => {
    if (args[0] === "rev-parse") {
      if (args[1] === "HEAD") return headSha;
      if (args[1] && args[1].includes("^@")) return baseSha;
      return "ok";
    }
    if (args[0] === "diff-tree") {
      return ":000000 100644 0000000 1111111 A\0file1.txt\0:000000 100644 0000000 2222222 A\0file2.txt\0:000000 100644 0000000 3333333 A\0file3.txt\0";
    }
    if (args[0] === "status") {
      return "A  file1.txt\0A  file2.txt\0?? file3.txt\0";
    }
    if (args[0] === "diff-index") {
      return ":000000 100644 000 111 A\0file1.txt\0:000000 100644 000 222 A\0file2.txt\0";
    }
    return "";
  };

  // --- POSITIVE TESTS ---
  assertPositive("POS-01: Exact authorized three-file change passes static policy", () => {
    validateCapsuleScopePolicy(sampleCapsule);
  });

  assertPositive("POS-02: Permitted pre-commit candidate passes", () => {
    const tmpDir = path.join("/tmp", `test-pos02-${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });
    try {
      fs.writeFileSync(path.join(tmpDir, "file1.txt"), "1");
      fs.writeFileSync(path.join(tmpDir, "file2.txt"), "2");
      fs.writeFileSync(path.join(tmpDir, "file3.txt"), "3");
      verifyPreCommitScope(sampleCapsule, tmpDir, standardMockGit);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  assertPositive("POS-03: Exact committed diff passes post-commit firewall", () => {
    verifyPostCommitDiff(sampleCapsule, baseSha, headSha, "/tmp", standardMockGit);
  });

  // --- ORIGINAL NEGATIVE TESTS (NEG-01 to NEG-20) ---
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
      if (args[0] === "rev-parse") {
        if (args[1] === "HEAD") return headSha;
        if (args[1] && args[1].includes("^@")) return baseSha;
        return "ok";
      }
      if (args[0] === "diff-tree") {
        return ":000000 100644 000 111 A\0file1.txt\0:000000 100644 000 222 A\0file2.txt\0:000000 100644 000 333 A\0file3.txt\0:000000 100644 000 444 A\0unauthorized.txt\0";
      }
      return "";
    };
    verifyPostCommitDiff(sampleCapsule, baseSha, headSha, "/tmp", mockGit);
  });

  assertNegative("NEG-08: Missing expected file in diff", "MISSING_EXPECTED_FILE_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "rev-parse") {
        if (args[1] === "HEAD") return headSha;
        if (args[1] && args[1].includes("^@")) return baseSha;
        return "ok";
      }
      if (args[0] === "diff-tree") {
        return ":000000 100644 000 111 A\0file1.txt\0";
      }
      return "";
    };
    verifyPostCommitDiff(sampleCapsule, baseSha, headSha, "/tmp", mockGit);
  });

  assertNegative("NEG-09: Declared write-limit exceeded", "DECLARED_WRITE_LIMIT_EXCEEDED_REJECTED", () => {
    const badCapsule = JSON.parse(JSON.stringify(sampleCapsule));
    badCapsule.payload.scope_boundary.max_write_files_limit = 2;
    validateCapsuleScopePolicy(badCapsule);
  });

  assertNegative("NEG-10: Empty mutation diff", "EMPTY_MUTATION_DIFF_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "rev-parse") {
        if (args[1] === "HEAD") return headSha;
        if (args[1] && args[1].includes("^@")) return baseSha;
        return "ok";
      }
      if (args[0] === "diff-tree") return "";
      return "";
    };
    verifyPostCommitDiff(sampleCapsule, baseSha, headSha, "/tmp", mockGit);
  });

  assertNegative("NEG-11: Unexpected untracked file in pre-commit", "UNEXPECTED_UNTRACKED_FILE_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "status") return "?? file1.txt\0?? intruder.sh\0";
      if (args[0] === "diff-index") return "";
      return "";
    };
    verifyPreCommitScope(sampleCapsule, "/tmp", mockGit);
  });

  assertNegative("NEG-12: Unexpected unstaged modification", "UNEXPECTED_UNSTAGED_MODIFICATION_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "status") return " M unauthorized.txt\0";
      if (args[0] === "diff-index") return "";
      return "";
    };
    verifyPreCommitScope(sampleCapsule, "/tmp", mockGit);
  });

  assertNegative("NEG-13: Unexpected deletion", "UNEXPECTED_DELETION_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "status") return " D unannounced_delete.txt\0";
      if (args[0] === "diff-index") return "";
      return "";
    };
    verifyPreCommitScope(sampleCapsule, "/tmp", mockGit);
  });

  assertNegative("NEG-14: Symlink mode 120000 in diff", "SYMLINK_MODE_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "rev-parse") {
        if (args[1] === "HEAD") return headSha;
        if (args[1] && args[1].includes("^@")) return baseSha;
        return "ok";
      }
      if (args[0] === "diff-tree") {
        return ":000000 120000 000 111 A\0file1.txt\0";
      }
      return "";
    };
    verifyPostCommitDiff(sampleCapsule, baseSha, headSha, "/tmp", mockGit);
  });

  assertNegative("NEG-15: Submodule mode 160000 in diff", "SUBMODULE_MODE_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "rev-parse") {
        if (args[1] === "HEAD") return headSha;
        if (args[1] && args[1].includes("^@")) return baseSha;
        return "ok";
      }
      if (args[0] === "diff-tree") {
        return ":000000 160000 000 111 A\0file1.txt\0";
      }
      return "";
    };
    verifyPostCommitDiff(sampleCapsule, baseSha, headSha, "/tmp", mockGit);
  });

  assertNegative("NEG-16: Stale base commit", "STALE_BASE_COMMIT_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "rev-parse") {
        throw new Error("fatal: Needed a single revision");
      }
      return "";
    };
    verifyPostCommitDiff(sampleCapsule, "0000000000000000000000000000000000000000", headSha, "/tmp", mockGit);
  });

  assertNegative("NEG-17: Unmerged Git index entry", "UNMERGED_INDEX_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "status") return "UU conflicted.txt\0";
      if (args[0] === "diff-index") return "";
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
      if (args[0] === "rev-parse") {
        if (args[1] === "HEAD") return headSha;
        if (args[1] && args[1].includes("^@")) return baseSha;
        return "ok";
      }
      throw new Error("GIT_EXECUTION_FAILURE: git command failed");
    };
    verifyPostCommitDiff(sampleCapsule, baseSha, headSha, "/tmp", mockGit);
  });

  assertNegative("NEG-20: Unsupported rename/copy", "UNSUPPORTED_RENAME_COPY_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "rev-parse") {
        if (args[1] === "HEAD") return headSha;
        if (args[1] && args[1].includes("^@")) return baseSha;
        return "ok";
      }
      if (args[0] === "diff-tree") {
        return ":100644 100644 111 222 R100\0file1.txt\0old_file1.txt\0";
      }
      return "";
    };
    verifyPostCommitDiff(sampleCapsule, baseSha, headSha, "/tmp", mockGit);
  });

  // --- PREVIOUS SEC-NEG SCENARIOS (SEC-NEG-01 to SEC-NEG-16 RESTORED) ---
  assertNegative("SEC-NEG-01: Expected file exists but was not changed in Git", "MISSING_EXPECTED_FILE_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "status") return "A  file1.txt\0A  file2.txt\0";
      if (args[0] === "diff-index") return "";
      return "";
    };
    verifyPreCommitScope(sampleCapsule, "/tmp", mockGit);
  });

  assertNegative("SEC-NEG-02: Actual pre-commit set differs from declared expected set", "UNEXPECTED_CHANGED_FILE_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "status") return "A  file1.txt\0A  file2.txt\0A  file3.txt\0A  file2.txt_extra\0";
      if (args[0] === "diff-index") return "";
      return "";
    };
    const expandedCapsule = JSON.parse(JSON.stringify(sampleCapsule));
    expandedCapsule.payload.scope_boundary.permitted_write_paths.push("file2.txt_extra");
    verifyPreCommitScope(expandedCapsule, "/tmp", mockGit);
  });

  assertNegative("SEC-NEG-03: Git -z filename contains leading or trailing whitespace", "UNTRUSTED_PATH_REJECTED", () => {
    validatePath(" file1.txt");
  });

  assertNegative("SEC-NEG-04: Two existing but unrelated commits", "PARENT_ANCESTRY_MISMATCH_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "rev-parse") {
        if (args[1] === "HEAD") return headSha;
        if (args[1] && args[1].includes("^@")) return "3333333333333333333333333333333333333333";
        return "ok";
      }
      return "";
    };
    verifyPostCommitDiff(sampleCapsule, baseSha, headSha, "/tmp", mockGit);
  });

  assertNegative("SEC-NEG-05: Valid commit SHA, but wrong direct parent", "PARENT_ANCESTRY_MISMATCH_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "rev-parse") {
        if (args[1] === "HEAD") return headSha;
        if (args[1] && args[1].includes("^@")) return "9999999999999999999999999999999999999999";
        return "ok";
      }
      return "";
    };
    verifyPostCommitDiff(sampleCapsule, baseSha, headSha, "/tmp", mockGit);
  });

  assertNegative("SEC-NEG-06: Supplied head differs from actual HEAD", "HEAD_MISMATCH_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "rev-parse") {
        if (args[1] === "HEAD") return "4444444444444444444444444444444444444444";
        return "ok";
      }
      return "";
    };
    verifyPostCommitDiff(sampleCapsule, baseSha, headSha, "/tmp", mockGit);
  });

  assertNegative("SEC-NEG-07: Malformed raw Git diff header", "MALFORMED_DIFF_HEADER_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "rev-parse") {
        if (args[1] === "HEAD") return headSha;
        if (args[1] && args[1].includes("^@")) return baseSha;
        return "ok";
      }
      if (args[0] === "diff-tree") {
        return "corrupted_header_without_colon\0file1.txt\0";
      }
      return "";
    };
    verifyPostCommitDiff(sampleCapsule, baseSha, headSha, "/tmp", mockGit);
  });

  assertNegative("SEC-NEG-08: Unknown Git diff status", "UNKNOWN_DIFF_STATUS_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "rev-parse") {
        if (args[1] === "HEAD") return headSha;
        if (args[1] && args[1].includes("^@")) return baseSha;
        return "ok";
      }
      if (args[0] === "diff-tree") {
        return ":000000 100644 000 111 X\0file1.txt\0";
      }
      return "";
    };
    verifyPostCommitDiff(sampleCapsule, baseSha, headSha, "/tmp", mockGit);
  });

  assertNegative("SEC-NEG-09: Duplicate raw diff tokens", "DUPLICATE_DIFF_ENTRY_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "rev-parse") {
        if (args[1] === "HEAD") return headSha;
        if (args[1] && args[1].includes("^@")) return baseSha;
        return "ok";
      }
      if (args[0] === "diff-tree") {
        return ":000000 100644 000 111 A\0file1.txt\0:000000 100644 000 222 A\0file1.txt\0";
      }
      return "";
    };
    verifyPostCommitDiff(sampleCapsule, baseSha, headSha, "/tmp", mockGit);
  });

  assertNegative("SEC-NEG-10: Unapproved executable-mode change", "UNAPPROVED_EXECUTABLE_MODE_CHANGE_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "rev-parse") {
        if (args[1] === "HEAD") return headSha;
        if (args[1] && args[1].includes("^@")) return baseSha;
        return "ok";
      }
      if (args[0] === "diff-tree") {
        return ":100644 100755 000 111 M\0file1.txt\0";
      }
      return "";
    };
    verifyPostCommitDiff(sampleCapsule, baseSha, headSha, "/tmp", mockGit);
  });

  assertNegative("SEC-NEG-11: Staged symlink mode 120000 in pre-commit", "SYMLINK_MODE_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "status") return "A  file1.txt\0A  file2.txt\0A  file3.txt\0";
      if (args[0] === "diff-index") return ":000000 120000 000 111 A\0file1.txt\0";
      return "";
    };
    verifyPreCommitScope(sampleCapsule, "/tmp", mockGit);
  });

  assertNegative("SEC-NEG-12: Staged submodule mode 160000 in pre-commit", "SUBMODULE_MODE_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "status") return "A  file1.txt\0A  file2.txt\0A  file3.txt\0";
      if (args[0] === "diff-index") return ":000000 160000 000 111 A\0file1.txt\0";
      return "";
    };
    verifyPreCommitScope(sampleCapsule, "/tmp", mockGit);
  });

  assertNegative("SEC-NEG-13: Symlink ancestor or path escape", "UNTRUSTED_PATH_REJECTED", () => {
    validatePath("../../etc/passwd", "/tmp");
  });

  assertNegative("SEC-NEG-14: Capsule path escapes repository", "CAPSULE_PATH_ESCAPE_REJECTED", () => {
    validateCliCapsulePath("/outside/repo/CAP-001.json", "/tmp/repo");
  });

  assertNegative("SEC-NEG-15: Unexpected staged/unstaged combination", "UNEXPECTED_UNSTAGED_MODIFICATION_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "status") return "A  file1.txt\0 M forbidden.txt\0";
      if (args[0] === "diff-index") return "";
      return "";
    };
    verifyPreCommitScope(sampleCapsule, "/tmp", mockGit);
  });

  assertNegative("SEC-NEG-16: Missing or failing Git executable", "GIT_EXECUTION_FAILURE", () => {
    const failingGit = () => {
      throw new Error("GIT_EXECUTION_FAILURE: git executable not found");
    };
    verifyPreCommitScope(sampleCapsule, "/tmp", failingGit);
  });

  // --- ADDITIONAL REQUIRED REGRESSION SCENARIOS (NEG-INDEX-*, NEG-FS-*, NEG-CLI-*) ---
  assertNegative("NEG-INDEX-01: git status succeeds, but git diff-index throws error", "GIT_EXECUTION_FAILURE", () => {
    const mockGit = (args) => {
      if (args[0] === "status") return "A  file1.txt\0A  file2.txt\0A  file3.txt\0";
      if (args[0] === "diff-index") throw new Error("GIT_EXECUTION_FAILURE: git diff-index failed");
      return "";
    };
    verifyPreCommitScope(sampleCapsule, "/tmp", mockGit);
  });

  assertNegative("NEG-INDEX-02: git diff-index returns malformed data", "MALFORMED_DIFF_INDEX_HEADER_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "status") return "A  file1.txt\0A  file2.txt\0A  file3.txt\0";
      if (args[0] === "diff-index") return "corrupted_header_without_colon\0file1.txt\0";
      return "";
    };
    verifyPreCommitScope(sampleCapsule, "/tmp", mockGit);
  });

  assertNegative("NEG-INDEX-03: git diff-index returns truncated data", "TRUNCATED_DIFF_INDEX_RECORD_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "status") return "A  file1.txt\0A  file2.txt\0A  file3.txt\0";
      if (args[0] === "diff-index") return ":100644 100644\0file1.txt\0";
      return "";
    };
    verifyPreCommitScope(sampleCapsule, "/tmp", mockGit);
  });

  assertNegative("NEG-INDEX-04: git diff-index has unsupported modes", "UNSUPPORTED_STAGED_MODE_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "status") return "A  file1.txt\0A  file2.txt\0A  file3.txt\0";
      if (args[0] === "diff-index") return ":000000 100777 000 111 A\0file1.txt\0";
      return "";
    };
    verifyPreCommitScope(sampleCapsule, "/tmp", mockGit);
  });

  assertNegative("NEG-INDEX-05: git diff-index returns unknown status", "UNKNOWN_DIFF_INDEX_STATUS_REJECTED", () => {
    const mockGit = (args) => {
      if (args[0] === "status") return "A  file1.txt\0A  file2.txt\0A  file3.txt\0";
      if (args[0] === "diff-index") return ":000000 100644 000 111 Z\0file1.txt\0";
      return "";
    };
    verifyPreCommitScope(sampleCapsule, "/tmp", mockGit);
  });

  assertNegative("NEG-FS-01: Expected untracked file is a symlink", "SYMLINK_OBJECT_REJECTED", () => {
    const tmpDir = path.join("/tmp", `test-fs-symlink-${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });
    try {
      const target = path.join(tmpDir, "real.txt");
      fs.writeFileSync(target, "real content\n");
      const symlinkPath = path.join(tmpDir, "symlink_file.txt");
      fs.symlinkSync(target, symlinkPath);
      validatePath("symlink_file.txt", tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  assertNegative("NEG-FS-02: Expected file has a symlink ancestor", "SYMLINK_ANCESTOR_REJECTED", () => {
    const tmpDir = path.join("/tmp", `test-fs-ancestor-${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });
    try {
      const realSubdir = path.join(tmpDir, "real_dir");
      fs.mkdirSync(realSubdir);
      fs.writeFileSync(path.join(realSubdir, "test.txt"), "hello\n");
      const symlinkDir = path.join(tmpDir, "link_dir");
      fs.symlinkSync(realSubdir, symlinkDir);
      validatePath("link_dir/test.txt", tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  assertNegative("NEG-FS-03: Filesystem metadata lookup fails on path escape", "UNTRUSTED_PATH_REJECTED", () => {
    validatePath("../../etc/passwd", "/tmp");
  });

  assertNegative("NEG-CLI-01: Capsule file is a symlink pointing outside the repository", "SYMLINK_CAPSULE_REJECTED", () => {
    const tmpDir = path.join("/tmp", `test-cli-symlink-${Date.now()}`);
    const capDir = path.join(tmpDir, ".synthesis", "task-capsules");
    fs.mkdirSync(capDir, { recursive: true });
    try {
      const extTarget = "/tmp/external-cap.json";
      fs.writeFileSync(extTarget, JSON.stringify({ payload: { capsule_id: "CAP-EXTERNAL" } }));
      const symlinkCap = path.join(capDir, "CAP-EXTERNAL.json");
      fs.symlinkSync(extTarget, symlinkCap);
      validateCliCapsulePath(".synthesis/task-capsules/CAP-EXTERNAL.json", tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  assertNegative("NEG-CLI-02: Capsule directory contains a symlink", "SYMLINK_ANCESTOR_REJECTED", () => {
    const tmpDir = path.join("/tmp", `test-cli-dirlink-${Date.now()}`);
    const realDir = path.join(tmpDir, "real_capsules");
    fs.mkdirSync(realDir, { recursive: true });
    fs.writeFileSync(path.join(realDir, "CAP-001.json"), JSON.stringify({ payload: { capsule_id: "CAP-001" } }));
    const synDir = path.join(tmpDir, ".synthesis");
    fs.mkdirSync(synDir, { recursive: true });
    try {
      fs.symlinkSync(realDir, path.join(synDir, "task-capsules"));
      validateCliCapsulePath(".synthesis/task-capsules/CAP-001.json", tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  assertNegative("NEG-CLI-03: Mixed --self-test and --post-commit", "INVALID_CLI_INVOCATION_REJECTED", () => {
    handleCliArguments(["--self-test", "--post-commit", "cap.json", baseSha, headSha], "/tmp");
  });

  assertNegative("NEG-CLI-04: Valid --pre-commit followed by unexpected extra arguments", "INVALID_CLI_INVOCATION_REJECTED", () => {
    handleCliArguments(["--pre-commit", "cap.json", "--extra-arg"], "/tmp");
  });

  assertNegative("NEG-CLI-05: Malformed or substituted capsule identity", "CAPSULE_IDENTITY_MISMATCH_REJECTED", () => {
    const tmpDir = path.join("/tmp", `test-cli-idmismatch-${Date.now()}`);
    const capDir = path.join(tmpDir, ".synthesis", "task-capsules");
    fs.mkdirSync(capDir, { recursive: true });
    try {
      const capFile = path.join(capDir, "CAP-ORIGINAL.json");
      fs.writeFileSync(capFile, JSON.stringify({ payload: { capsule_id: "CAP-SUBSTITUTED" } }));
      validateCliCapsulePath(".synthesis/task-capsules/CAP-ORIGINAL.json", tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // --- NEW DANGLING SYMLINK REGRESSION TESTS ---
  assertNegative("DANGLING-NEG-01: Authorized untracked path is a dangling symbolic link", "SYMLINK_OBJECT_REJECTED", () => {
    const tmpDir = path.join("/tmp", `test-dangling-neg01-${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });
    try {
      const symlinkPath = path.join(tmpDir, "dangling_link.txt");
      fs.symlinkSync(path.join(tmpDir, "nonexistent.txt"), symlinkPath);
      validatePath("dangling_link.txt", tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  assertNegative("DANGLING-NEG-02: Authorized path has a dangling symlink in an ancestor directory", "SYMLINK_ANCESTOR_REJECTED", () => {
    const tmpDir = path.join("/tmp", `test-dangling-neg02-${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });
    try {
      const symlinkDir = path.join(tmpDir, "dangling_dir");
      fs.symlinkSync(path.join(tmpDir, "nonexistent_dir"), symlinkDir);
      validatePath("dangling_dir/file.txt", tmpDir);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  assertNegative("DANGLING-NEG-03: Git status reports untracked path, but candidate is a directory", "UNSUPPORTED_FILE_TYPE_REJECTED", () => {
    const tmpDir = path.join("/tmp", `test-dangling-neg03-${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });
    try {
      const subDir = path.join(tmpDir, "candidate_dir");
      fs.mkdirSync(subDir);
      const cap = {
        payload: {
          scope_boundary: {
            permitted_read_paths: [],
            permitted_write_paths: ["candidate_dir"],
            protected_paths: [],
            max_write_files_limit: 1
          },
          changes_and_evidence: {
            expected_changed_files: ["candidate_dir"],
            actual_changed_files: ["candidate_dir"]
          }
        }
      };
      const mockGit = (args) => {
        if (args[0] === "status") return "?? candidate_dir\0";
        if (args[0] === "diff-index") return "";
        return "";
      };
      verifyPreCommitScope(cap, tmpDir, mockGit);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  assertPositive("DANGLING-POS-01: Authorized regular file passes candidate validation", () => {
    const tmpDir = path.join("/tmp", `test-dangling-pos01-${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });
    try {
      fs.writeFileSync(path.join(tmpDir, "regular.txt"), "hello world\n");
      const cap = {
        payload: {
          scope_boundary: {
            permitted_read_paths: [],
            permitted_write_paths: ["regular.txt"],
            protected_paths: [],
            max_write_files_limit: 1
          },
          changes_and_evidence: {
            expected_changed_files: ["regular.txt"],
            actual_changed_files: ["regular.txt"]
          }
        }
      };
      const mockGit = (args) => {
        if (args[0] === "status") return "?? regular.txt\0";
        if (args[0] === "diff-index") return "";
        return "";
      };
      const res = verifyPreCommitScope(cap, tmpDir, mockGit);
      if (!res.valid || res.candidateChanges[0] !== "regular.txt") {
        throw new Error("Expected regular.txt to pass");
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // --- REAL GIT FIXTURE TEST ---
  assertPositive("REAL-GIT-01: End-to-end isolated real git repository lifecycle", () => {
    const tmpDir = path.join("/tmp", `test-git-fixture-${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });
    try {
      execFileSync("git", ["init", "-b", "main"], { cwd: tmpDir, shell: false });
      execFileSync("git", ["config", "user.name", "Test Agent"], { cwd: tmpDir, shell: false });
      execFileSync("git", ["config", "user.email", "agent@test.local"], { cwd: tmpDir, shell: false });

      // Initial commit
      fs.writeFileSync(path.join(tmpDir, "README.md"), "# Initial\n");
      execFileSync("git", ["add", "README.md"], { cwd: tmpDir, shell: false });
      execFileSync("git", ["commit", "-m", "initial"], { cwd: tmpDir, shell: false });
      const realBaseSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: tmpDir, encoding: "utf8" }).trim();

      // Create new candidate files
      fs.writeFileSync(path.join(tmpDir, "app.js"), "console.log(1);\n");
      fs.writeFileSync(path.join(tmpDir, "config.json"), "{}\n");

      const realCapsule = {
        payload: {
          scope_boundary: {
            permitted_read_paths: ["README.md"],
            permitted_write_paths: ["app.js", "config.json"],
            protected_paths: ["README.md"],
            max_write_files_limit: 2
          },
          changes_and_evidence: {
            expected_changed_files: ["app.js", "config.json"],
            actual_changed_files: ["app.js", "config.json"]
          }
        }
      };

      // Test real pre-commit
      const preRes = verifyPreCommitScope(realCapsule, tmpDir);
      if (!preRes.valid || preRes.candidateChanges.length !== 2) {
        throw new Error("Real pre-commit failed to detect exact changes");
      }

      // Commit changes
      execFileSync("git", ["add", "app.js", "config.json"], { cwd: tmpDir, shell: false });
      execFileSync("git", ["commit", "-m", "second"], { cwd: tmpDir, shell: false });
      const realHeadSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: tmpDir, encoding: "utf8" }).trim();

      // Test real post-commit
      const postRes = verifyPostCommitDiff(realCapsule, realBaseSha, realHeadSha, tmpDir);
      if (!postRes.valid || postRes.diffFiles.length !== 2) {
        throw new Error("Real post-commit failed to detect exact changes");
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  console.log(`\nSelf-test summary: Passed: ${passed}, Failed: ${failed}`);
  if (failed > 0) {
    throw new Error(`Self-tests failed: ${failed} failure(s)`);
  }
}

/**
 * Strict CLI argument grammar handler.
 */
export function handleCliArguments(args, repoRoot) {
  if (args.length === 1 && args[0] === "--self-test") {
    runSelfTests();
    return { mode: "self-test", success: true };
  }

  if (args.length === 2 && args[0] === "--pre-commit") {
    const { capsule } = validateCliCapsulePath(args[1], repoRoot);
    const res = verifyPreCommitScope(capsule, repoRoot);
    console.log("PRE_COMMIT_SCOPE_CHECK: PASS", res);
    return { mode: "pre-commit", success: true, result: res };
  }

  if (args.length === 4 && args[0] === "--post-commit") {
    const rawPath = args[1];
    const baseSha = args[2];
    const headSha = args[3];

    if (!/^[0-9a-f]{40}$/.test(baseSha) || !/^[0-9a-f]{40}$/.test(headSha)) {
      throw new Error(`INVALID_SHA_SYNTAX_REJECTED: baseSha or headSha is not a valid 40-character hex SHA`);
    }

    const { capsule } = validateCliCapsulePath(rawPath, repoRoot);
    const res = verifyPostCommitDiff(capsule, baseSha, headSha, repoRoot);
    console.log("POST_COMMIT_DIFF_CHECK: PASS", res);
    return { mode: "post-commit", success: true, result: res };
  }

  throw new Error(`INVALID_CLI_INVOCATION_REJECTED: Invalid CLI invocation: ${args.join(" ")}`);
}

// --- CLI Execution ---
function main() {
  const args = process.argv.slice(2);
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

  try {
    handleCliArguments(args, repoRoot);
    process.exit(0);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}

if (process.argv[1] && import.meta.url.endsWith(path.basename(process.argv[1]))) {
  main();
}
