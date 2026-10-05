#!/usr/bin/env node
/**
 * SYNTHESIS CMS MINI — MILESTONE ACTIVATION PROOF VERIFIER
 *
 * Verifies the canonical activation proof record against strict schema rules,
 * exact Git commit objects, exact 2-parent merge topology, tree SHA,
 * ancestry reachability from HEAD, and governance.lock.json SHA-256.
 *
 * Used universally across global governance health gate and capability registry.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import child_process from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { parseStrictIJson, timingSafeHexCompare } from './verify_capsule_seal.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_REPO_ROOT = path.resolve(__dirname, '..', '..');

export const ALLOWED_PROOF_KEYS = new Set([
  'schema_version',
  'record_kind',
  'milestone_id',
  'activation_status',
  'exact_main_commit_sha',
  'parent_commit_shas',
  'merge_tree_sha',
  'governance_lock_sha256',
  'ci_workflow_run_id',
  'verified_at_utc',
  'verified_by'
]);

export function defaultGitExecutor(args, cwd = DEFAULT_REPO_ROOT) {
  try {
    return child_process.execFileSync('git', args, {
      cwd,
      shell: false,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe']
    });
  } catch (err) {
    throw new Error(`GIT_COMMAND_FAILED [git ${args.join(' ')}]: ${err.stderr || err.message}`);
  }
}

export function computeFileSha256(filePath) {
  const bytes = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

export function verifyActivationProofRecord(proofObj, repoRoot = DEFAULT_REPO_ROOT, gitExecutor = defaultGitExecutor) {
  if (!proofObj || typeof proofObj !== 'object' || Array.isArray(proofObj)) {
    return { valid: false, error: 'MALFORMED_PROOF: Activation proof must be a non-null object' };
  }

  // Strict keys: no extra or missing keys
  const keys = Object.keys(proofObj);
  for (const k of keys) {
    if (!ALLOWED_PROOF_KEYS.has(k)) {
      return { valid: false, error: `EXTRA_KEY_FORBIDDEN: Unexpected property "${k}" in activation proof` };
    }
  }
  for (const k of ALLOWED_PROOF_KEYS) {
    if (!(k in proofObj)) {
      return { valid: false, error: `MISSING_KEY: Required property "${k}" missing from activation proof` };
    }
  }

  if (proofObj.schema_version !== '1.0.0') {
    return { valid: false, error: `SCHEMA_VERSION_MISMATCH: Expected 1.0.0, got ${proofObj.schema_version}` };
  }
  if (proofObj.record_kind !== 'MILESTONE_ACTIVATION_PROOF') {
    return { valid: false, error: `RECORD_KIND_MISMATCH: Expected MILESTONE_ACTIVATION_PROOF, got ${proofObj.record_kind}` };
  }
  if (typeof proofObj.milestone_id !== 'string' || !/^MILESTONE_[A-Z0-9_]+$/.test(proofObj.milestone_id)) {
    return { valid: false, error: `INVALID_MILESTONE_ID: Invalid milestone_id format: ${proofObj.milestone_id}` };
  }
  if (proofObj.activation_status !== 'ACTIVE') {
    return { valid: false, error: `INACTIVE_PROOF_STATUS: Activation status is ${proofObj.activation_status}, expected ACTIVE` };
  }
  if (typeof proofObj.exact_main_commit_sha !== 'string' || !/^[a-f0-9]{40}$/.test(proofObj.exact_main_commit_sha)) {
    return { valid: false, error: 'INVALID_COMMIT_SHA: exact_main_commit_sha is not a 40-char hex SHA' };
  }

  // Exactly 2 merge parents required
  if (!Array.isArray(proofObj.parent_commit_shas) || proofObj.parent_commit_shas.length !== 2) {
    return { valid: false, error: `INVALID_PARENT_COUNT: Activation proof requires exactly 2 merge parents, got ${Array.isArray(proofObj.parent_commit_shas) ? proofObj.parent_commit_shas.length : 'non-array'}` };
  }
  for (const p of proofObj.parent_commit_shas) {
    if (typeof p !== 'string' || !/^[a-f0-9]{40}$/.test(p)) {
      return { valid: false, error: `INVALID_PARENT_SHA: Malformed parent SHA: ${p}` };
    }
  }

  if (typeof proofObj.merge_tree_sha !== 'string' || !/^[a-f0-9]{40}$/.test(proofObj.merge_tree_sha)) {
    return { valid: false, error: 'INVALID_TREE_SHA: merge_tree_sha is not a 40-char hex SHA' };
  }
  if (typeof proofObj.governance_lock_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(proofObj.governance_lock_sha256)) {
    return { valid: false, error: 'INVALID_LOCK_SHA: governance_lock_sha256 is not a 64-char hex SHA' };
  }

  if (typeof proofObj.ci_workflow_run_id !== 'number' || !Number.isInteger(proofObj.ci_workflow_run_id) || proofObj.ci_workflow_run_id <= 0) {
    return { valid: false, error: `INVALID_CI_RUN_ID: ci_workflow_run_id must be a positive integer, got ${proofObj.ci_workflow_run_id}` };
  }

  if (typeof proofObj.verified_at_utc !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(proofObj.verified_at_utc) || isNaN(Date.parse(proofObj.verified_at_utc))) {
    return { valid: false, error: `INVALID_UTC_TIMESTAMP: verified_at_utc must be a valid UTC ISO 8601 timestamp ending in Z` };
  }

  if (typeof proofObj.verified_by !== 'string' || proofObj.verified_by.trim().length === 0) {
    return { valid: false, error: 'INVALID_VERIFIED_BY: verified_by must be a non-empty string' };
  }

  // Real Git verification
  if (gitExecutor && repoRoot) {
    // 1. Commit existence
    try {
      gitExecutor(['rev-parse', '--verify', `${proofObj.exact_main_commit_sha}^{commit}`], repoRoot);
    } catch (e) {
      return { valid: false, error: `FORGED_PROOF_NONEXISTENT_COMMIT: exact_main_commit_sha ${proofObj.exact_main_commit_sha} does not exist in repository` };
    }

    // 2. Commit tree SHA
    try {
      const actualTree = gitExecutor(['rev-parse', `${proofObj.exact_main_commit_sha}^{tree}`], repoRoot).trim();
      if (actualTree !== proofObj.merge_tree_sha) {
        return { valid: false, error: `FORGED_PROOF_TREE_MISMATCH: Declared merge_tree_sha ${proofObj.merge_tree_sha} does not match actual tree ${actualTree}` };
      }
    } catch (e) {
      return { valid: false, error: `GIT_TREE_VERIFICATION_FAILED: ${e.message}` };
    }

    // 3. Commit parents
    try {
      const parentOut = gitExecutor(['rev-parse', `${proofObj.exact_main_commit_sha}^@`], repoRoot).trim();
      const actualParents = parentOut ? parentOut.split(/\s+/).filter(Boolean) : [];
      if (actualParents.length !== 2 ||
          actualParents[0] !== proofObj.parent_commit_shas[0] ||
          actualParents[1] !== proofObj.parent_commit_shas[1]) {
        return { valid: false, error: `FORGED_PROOF_PARENTS_MISMATCH: Declared parent_commit_shas do not match actual commit parents: declared [${proofObj.parent_commit_shas.join(', ')}], actual [${actualParents.join(', ')}]` };
      }
    } catch (e) {
      return { valid: false, error: `GIT_PARENTS_VERIFICATION_FAILED: ${e.message}` };
    }

    // 4. Ancestry reachability from HEAD
    try {
      gitExecutor(['merge-base', '--is-ancestor', proofObj.exact_main_commit_sha, 'HEAD'], repoRoot);
    } catch (e) {
      return { valid: false, error: `FORGED_PROOF_NON_ANCESTOR_COMMIT: exact_main_commit_sha ${proofObj.exact_main_commit_sha} is not an ancestor of current HEAD` };
    }

    // 5. Governance lockfile hash on disk
    const lockPath = path.resolve(repoRoot, '.synthesis/governance.lock.json');
    if (!fs.existsSync(lockPath)) {
      return { valid: false, error: 'GOVERNANCE_LOCK_MISSING: .synthesis/governance.lock.json missing during activation proof verification' };
    }
    try {
      const stat = fs.lstatSync(lockPath);
      if (!stat.isFile() || stat.isSymbolicLink()) {
        return { valid: false, error: 'GOVERNANCE_LOCK_UNSAFE_FILE: governance.lock.json must be a regular file, not a symlink' };
      }
    } catch (e) {
      return { valid: false, error: `GOVERNANCE_LOCK_STAT_ERROR: Cannot stat governance.lock.json: ${e.message}` };
    }
    const actualLockSha = computeFileSha256(lockPath);
    if (!timingSafeHexCompare(actualLockSha, proofObj.governance_lock_sha256)) {
      return { valid: false, error: `FORGED_PROOF_LOCK_SHA_MISMATCH: Lockfile SHA mismatch in activation proof: expected ${proofObj.governance_lock_sha256}, actual ${actualLockSha}` };
    }
  }

  return { valid: true, proof: proofObj };
}

export function runSelfTest() {
  let positivePassed = 0;
  let negativePassed = 0;

  const validProof = {
    schema_version: '1.0.0',
    record_kind: 'MILESTONE_ACTIVATION_PROOF',
    milestone_id: 'MILESTONE_A',
    activation_status: 'ACTIVE',
    exact_main_commit_sha: '1'.repeat(40),
    parent_commit_shas: ['2'.repeat(40), '3'.repeat(40)],
    merge_tree_sha: '4'.repeat(40),
    governance_lock_sha256: '5'.repeat(64),
    ci_workflow_run_id: 123456,
    verified_at_utc: '2026-10-05T12:00:00.000Z',
    verified_by: 'Genesis Activation Gate'
  };

  const res = verifyActivationProofRecord(validProof, null, null);
  if (res.valid) positivePassed++;
  else throw new Error(`Initial valid proof test failed: ${JSON.stringify(res)}`);

  const negativeCases = [
    { name: 'Null proof', generate: () => null, expected: 'MALFORMED_PROOF' },
    { name: 'Array proof', generate: () => [], expected: 'MALFORMED_PROOF' },
    { name: 'Extra key forbidden', generate: m => { m.extra_token = 'malicious'; return m; }, expected: 'EXTRA_KEY_FORBIDDEN' },
    { name: 'Missing required key', generate: m => { delete m.ci_workflow_run_id; return m; }, expected: 'MISSING_KEY' },
    { name: 'Bad schema_version', generate: m => { m.schema_version = '2.0'; return m; }, expected: 'SCHEMA_VERSION_MISMATCH' },
    { name: 'Bad record_kind', generate: m => { m.record_kind = 'UNKNOWN'; return m; }, expected: 'RECORD_KIND_MISMATCH' },
    { name: 'Bad milestone_id', generate: m => { m.milestone_id = 'milestone-a'; return m; }, expected: 'INVALID_MILESTONE_ID' },
    { name: 'Inactive status', generate: m => { m.activation_status = 'PENDING_EXACT_MAIN'; return m; }, expected: 'INACTIVE_PROOF_STATUS' },
    { name: 'Bad commit SHA', generate: m => { m.exact_main_commit_sha = 'short'; return m; }, expected: 'INVALID_COMMIT_SHA' },
    { name: 'One-parent proof', generate: m => { m.parent_commit_shas = ['2'.repeat(40)]; return m; }, expected: 'INVALID_PARENT_COUNT' },
    { name: 'Three-parent proof', generate: m => { m.parent_commit_shas = ['2'.repeat(40), '3'.repeat(40), '4'.repeat(40)]; return m; }, expected: 'INVALID_PARENT_COUNT' },
    { name: 'Bad parent SHA', generate: m => { m.parent_commit_shas = ['bad_sha', '3'.repeat(40)]; return m; }, expected: 'INVALID_PARENT_SHA' },
    { name: 'Bad tree SHA', generate: m => { m.merge_tree_sha = 'bad_tree'; return m; }, expected: 'INVALID_TREE_SHA' },
    { name: 'Bad lock SHA', generate: m => { m.governance_lock_sha256 = 'bad_lock'; return m; }, expected: 'INVALID_LOCK_SHA' },
    { name: 'Invalid CI run ID (zero)', generate: m => { m.ci_workflow_run_id = 0; return m; }, expected: 'INVALID_CI_RUN_ID' },
    { name: 'Invalid CI run ID (negative)', generate: m => { m.ci_workflow_run_id = -5; return m; }, expected: 'INVALID_CI_RUN_ID' },
    { name: 'Invalid CI run ID (float)', generate: m => { m.ci_workflow_run_id = 12.34; return m; }, expected: 'INVALID_CI_RUN_ID' },
    { name: 'Non-UTC timestamp (no Z)', generate: m => { m.verified_at_utc = '2026-10-05T12:00:00+02:00'; return m; }, expected: 'INVALID_UTC_TIMESTAMP' },
    { name: 'Invalid timestamp string', generate: m => { m.verified_at_utc = 'not-a-date'; return m; }, expected: 'INVALID_UTC_TIMESTAMP' },
    { name: 'Empty verified_by', generate: m => { m.verified_by = '   '; return m; }, expected: 'INVALID_VERIFIED_BY' }
  ];

  for (const tc of negativeCases) {
    const clone = JSON.parse(JSON.stringify(validProof));
    const testObj = tc.generate(clone);
    const r = verifyActivationProofRecord(testObj, null, null);
    if (!r.valid && r.error && r.error.includes(tc.expected)) {
      negativePassed++;
    } else {
      throw new Error(`Self-test negative case '${tc.name}' failed. Expected ${tc.expected}, got: ${JSON.stringify(r)}`);
    }
  }

  // Disk + Mock Git Executor tests
  const tempDir = fs.mkdtempSync(path.join('/tmp', 'proof-test-'));
  try {
    fs.mkdirSync(path.join(tempDir, '.synthesis'), { recursive: true });
    const lockFile = path.join(tempDir, '.synthesis', 'governance.lock.json');
    fs.writeFileSync(lockFile, '{"lock":true}');
    const lockSha = computeFileSha256(lockFile);

    const fullValidProof = {
      ...validProof,
      governance_lock_sha256: lockSha
    };

    const mockGit = (args) => {
      const cmd = args.join(' ');
      if (cmd.includes('rev-parse --verify') && cmd.includes(validProof.exact_main_commit_sha)) return validProof.exact_main_commit_sha + '\n';
      if (cmd.includes('rev-parse') && cmd.includes('^{tree}')) return validProof.merge_tree_sha + '\n';
      if (cmd.includes('rev-parse') && cmd.includes('^@')) return validProof.parent_commit_shas.join(' ') + '\n';
      if (cmd.includes('merge-base --is-ancestor')) return '';
      throw new Error(`Unexpected mock cmd: ${cmd}`);
    };

    const passDisk = verifyActivationProofRecord(fullValidProof, tempDir, mockGit);
    if (passDisk.valid) {
      positivePassed++;
    } else {
      throw new Error(`Disk + mock git valid test failed: ${JSON.stringify(passDisk)}`);
    }

    // Negative Git 1: Nonexistent commit
    const badCommitGit = () => { throw new Error('Not a valid commit'); };
    const resBadCommit = verifyActivationProofRecord(fullValidProof, tempDir, badCommitGit);
    if (!resBadCommit.valid && resBadCommit.error.includes('FORGED_PROOF_NONEXISTENT_COMMIT')) negativePassed++;
    else throw new Error(`Expected FORGED_PROOF_NONEXISTENT_COMMIT, got: ${JSON.stringify(resBadCommit)}`);

    // Negative Git 2: Tree mismatch
    const badTreeGit = (args) => {
      const cmd = args.join(' ');
      if (cmd.includes('rev-parse --verify')) return validProof.exact_main_commit_sha + '\n';
      if (cmd.includes('rev-parse') && cmd.includes('^{tree}')) return 'wrong_tree_sha_0000000000000000000000000\n';
      if (cmd.includes('rev-parse') && cmd.includes('^@')) return validProof.parent_commit_shas.join(' ') + '\n';
      if (cmd.includes('merge-base --is-ancestor')) return '';
      throw new Error(`Unexpected mock cmd: ${cmd}`);
    };
    const resBadTree = verifyActivationProofRecord(fullValidProof, tempDir, badTreeGit);
    if (!resBadTree.valid && resBadTree.error.includes('FORGED_PROOF_TREE_MISMATCH')) negativePassed++;
    else throw new Error(`Expected FORGED_PROOF_TREE_MISMATCH, got: ${JSON.stringify(resBadTree)}`);

    // Negative Git 3: Parents mismatch
    const badParentsGit = (args) => {
      const cmd = args.join(' ');
      if (cmd.includes('rev-parse --verify')) return validProof.exact_main_commit_sha + '\n';
      if (cmd.includes('rev-parse') && cmd.includes('^{tree}')) return validProof.merge_tree_sha + '\n';
      if (cmd.includes('rev-parse') && cmd.includes('^@')) return 'wrong_parent1 wrong_parent2\n';
      if (cmd.includes('merge-base --is-ancestor')) return '';
      throw new Error(`Unexpected mock cmd: ${cmd}`);
    };
    const resBadParents = verifyActivationProofRecord(fullValidProof, tempDir, badParentsGit);
    if (!resBadParents.valid && resBadParents.error.includes('FORGED_PROOF_PARENTS_MISMATCH')) negativePassed++;
    else throw new Error(`Expected FORGED_PROOF_PARENTS_MISMATCH, got: ${JSON.stringify(resBadParents)}`);

    // Negative Git 4: Non-ancestor
    const nonAncestorGit = (args) => {
      const cmd = args.join(' ');
      if (cmd.includes('rev-parse --verify')) return validProof.exact_main_commit_sha + '\n';
      if (cmd.includes('rev-parse') && cmd.includes('^{tree}')) return validProof.merge_tree_sha + '\n';
      if (cmd.includes('rev-parse') && cmd.includes('^@')) return validProof.parent_commit_shas.join(' ') + '\n';
      if (cmd.includes('merge-base --is-ancestor')) throw new Error('Not an ancestor');
      throw new Error(`Unexpected mock cmd: ${cmd}`);
    };
    const resNonAncestor = verifyActivationProofRecord(fullValidProof, tempDir, nonAncestorGit);
    if (!resNonAncestor.valid && resNonAncestor.error.includes('FORGED_PROOF_NON_ANCESTOR_COMMIT')) negativePassed++;
    else throw new Error(`Expected FORGED_PROOF_NON_ANCESTOR_COMMIT, got: ${JSON.stringify(resNonAncestor)}`);

    // Negative Lock 5: Lock hash mismatch
    const forgedLockProof = {
      ...fullValidProof,
      governance_lock_sha256: 'f'.repeat(64)
    };
    const resForgedLock = verifyActivationProofRecord(forgedLockProof, tempDir, mockGit);
    if (!resForgedLock.valid && resForgedLock.error.includes('FORGED_PROOF_LOCK_SHA_MISMATCH')) negativePassed++;
    else throw new Error(`Expected FORGED_PROOF_LOCK_SHA_MISMATCH, got: ${JSON.stringify(resForgedLock)}`);

    // Negative Lock 6: Symlink lockfile
    const realLock = path.join(tempDir, '.synthesis', 'real.lock.json');
    fs.writeFileSync(realLock, '{"lock":true}');
    fs.unlinkSync(lockFile);
    fs.symlinkSync(realLock, lockFile);
    const resSymlink = verifyActivationProofRecord(fullValidProof, tempDir, mockGit);
    if (!resSymlink.valid && resSymlink.error.includes('GOVERNANCE_LOCK_UNSAFE_FILE')) negativePassed++;
    else throw new Error(`Expected GOVERNANCE_LOCK_UNSAFE_FILE, got: ${JSON.stringify(resSymlink)}`);

  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }

  const result = {
    positivePassed,
    negativePassed,
    totalTests: positivePassed + negativePassed
  };
  console.log(`ACTIVATION_PROOF_SELFTEST: ${JSON.stringify(result)}`);
  return result;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.includes('--self-test')) {
    runSelfTest();
    process.exit(0);
  } else if (args.includes('--verify')) {
    const proofIdx = args.indexOf('--verify') + 1;
    const targetPath = args[proofIdx] || path.resolve(DEFAULT_REPO_ROOT, '.synthesis/activation/milestone-a-activation-proof.json');
    if (!fs.existsSync(targetPath)) {
      console.log('ACTIVATION_PROOF_STATUS: BOOTSTRAP_PENDING_ACTIVATION');
      process.exit(0);
    }
    const raw = fs.readFileSync(targetPath, 'utf8');
    const parsed = parseStrictIJson(raw);
    const res = verifyActivationProofRecord(parsed, DEFAULT_REPO_ROOT);
    if (!res.valid) {
      console.error(`ACTIVATION_PROOF_FAILED: ${res.error}`);
      process.exit(1);
    }
    console.log(`ACTIVATION_PROOF_VERIFIED: Milestone ${parsed.milestone_id} proof valid.`);
    process.exit(0);
  } else {
    console.log('Usage: node verify_activation_proof.mjs [--self-test|--verify [path]]');
    process.exit(1);
  }
}
