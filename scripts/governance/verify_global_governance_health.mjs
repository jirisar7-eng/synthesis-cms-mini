#!/usr/bin/env node
/**
 * SYNTHESIS CMS MINI — GLOBAL GOVERNANCE HEALTH EVALUATOR
 *
 * Implements the machine-enforced anti-drift gate required before Step 7.
 * Evaluates Genesis anchor, Contract Registry, Governance Lockfile,
 * Capability Registry, and Exact-Main Activation Proof against real Git commits,
 * trees, parents, and ancestry without external network or Notion dependencies.
 *
 * FAIL CLOSED: Returns PASS only when complete, sealed, and verified
 * evidence exists on exact main.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import child_process from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { parseStrictIJson, timingSafeHexCompare } from './verify_capsule_seal.mjs';
import { validateContractRegistry } from './verify_contract_registry.mjs';
import { validateGovernanceLock } from './verify_governance_lock.mjs';
import { validateCapabilityRegistry } from './validate_capability_registry.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_REPO_ROOT = path.resolve(__dirname, '..', '..');

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
    return { valid: false, error: 'MALFORMED_PROOF: Activation proof must be an object' };
  }
  if (proofObj.schema_version !== '1.0.0') {
    return { valid: false, error: `SCHEMA_VERSION_MISMATCH: Expected 1.0.0, got ${proofObj.schema_version}` };
  }
  if (proofObj.record_kind !== 'MILESTONE_ACTIVATION_PROOF') {
    return { valid: false, error: `RECORD_KIND_MISMATCH: Expected MILESTONE_ACTIVATION_PROOF, got ${proofObj.record_kind}` };
  }
  if (proofObj.activation_status !== 'ACTIVE') {
    return { valid: false, error: `INACTIVE_PROOF_STATUS: Activation status is ${proofObj.activation_status}, expected ACTIVE` };
  }
  if (!/^[a-f0-9]{40}$/.test(proofObj.exact_main_commit_sha)) {
    return { valid: false, error: 'INVALID_COMMIT_SHA: exact_main_commit_sha is not a 40-char hex SHA' };
  }
  if (!Array.isArray(proofObj.parent_commit_shas) || proofObj.parent_commit_shas.length === 0) {
    return { valid: false, error: 'INVALID_PARENT_SHAS: parent_commit_shas must be a non-empty array' };
  }
  for (const p of proofObj.parent_commit_shas) {
    if (!/^[a-f0-9]{40}$/.test(p)) {
      return { valid: false, error: `INVALID_PARENT_SHA: Malformed parent SHA: ${p}` };
    }
  }
  if (!/^[a-f0-9]{40}$/.test(proofObj.merge_tree_sha)) {
    return { valid: false, error: 'INVALID_TREE_SHA: merge_tree_sha is not a 40-char hex SHA' };
  }
  if (!/^[a-f0-9]{64}$/.test(proofObj.governance_lock_sha256)) {
    return { valid: false, error: 'INVALID_LOCK_SHA: governance_lock_sha256 is not a 64-char hex SHA' };
  }

  // Real Git verification when gitExecutor and repoRoot are provided
  if (gitExecutor && repoRoot) {
    // 1. Verify commit exists
    try {
      gitExecutor(['rev-parse', '--verify', `${proofObj.exact_main_commit_sha}^{commit}`], repoRoot);
    } catch (e) {
      return { valid: false, error: `FORGED_PROOF_NONEXISTENT_COMMIT: exact_main_commit_sha ${proofObj.exact_main_commit_sha} does not exist in repository` };
    }

    // 2. Verify commit tree SHA
    try {
      const actualTree = gitExecutor(['rev-parse', `${proofObj.exact_main_commit_sha}^{tree}`], repoRoot).trim();
      if (actualTree !== proofObj.merge_tree_sha) {
        return { valid: false, error: `FORGED_PROOF_TREE_MISMATCH: Declared merge_tree_sha ${proofObj.merge_tree_sha} does not match actual tree ${actualTree}` };
      }
    } catch (e) {
      return { valid: false, error: `GIT_TREE_VERIFICATION_FAILED: ${e.message}` };
    }

    // 3. Verify commit parents
    try {
      const parentOut = gitExecutor(['rev-parse', `${proofObj.exact_main_commit_sha}^@`], repoRoot).trim();
      const actualParents = parentOut ? parentOut.split(/\s+/).filter(Boolean) : [];
      if (actualParents.length !== proofObj.parent_commit_shas.length ||
          !actualParents.every((p, idx) => p === proofObj.parent_commit_shas[idx])) {
        return { valid: false, error: `FORGED_PROOF_PARENTS_MISMATCH: Declared parent_commit_shas do not match actual commit parents: declared [${proofObj.parent_commit_shas.join(', ')}], actual [${actualParents.join(', ')}]` };
      }
    } catch (e) {
      return { valid: false, error: `GIT_PARENTS_VERIFICATION_FAILED: ${e.message}` };
    }

    // 4. Verify ancestry (commit must be ancestor of HEAD or main)
    try {
      gitExecutor(['merge-base', '--is-ancestor', proofObj.exact_main_commit_sha, 'HEAD'], repoRoot);
    } catch (e) {
      return { valid: false, error: `FORGED_PROOF_NON_ANCESTOR_COMMIT: exact_main_commit_sha ${proofObj.exact_main_commit_sha} is not an ancestor of current HEAD` };
    }

    // 5. Verify actual governance-lock SHA256 against file on disk
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

export function evaluateGlobalGovernanceHealth(repoRoot = DEFAULT_REPO_ROOT, options = {}) {
  const gitExecutor = options.gitExecutor || defaultGitExecutor;

  const genesisPath = path.resolve(repoRoot, '.synthesis/lineage/genesis.json');
  const contractRegPath = path.resolve(repoRoot, '.synthesis/registries/contracts.json');
  const govLockPath = path.resolve(repoRoot, '.synthesis/governance.lock.json');
  const capRegPath = path.resolve(repoRoot, '.synthesis/registries/capabilities.json');
  const activationProofPath = path.resolve(repoRoot, '.synthesis/activation/milestone-a-activation-proof.json');

  // 1. Genesis anchor must exist in all modes
  if (!fs.existsSync(genesisPath)) {
    return {
      status: 'BLOCKED_BY_GOVERNANCE_DRIFT',
      error: 'CRITICAL_DRIFT: Genesis anchor file is missing'
    };
  }
  try {
    const genStat = fs.lstatSync(genesisPath);
    if (!genStat.isFile() || genStat.isSymbolicLink()) {
      return {
        status: 'BLOCKED_BY_GOVERNANCE_DRIFT',
        error: 'CRITICAL_DRIFT: Genesis anchor file must be a regular file, not a symlink'
      };
    }
  } catch (e) {
    return {
      status: 'BLOCKED_BY_GOVERNANCE_DRIFT',
      error: `GENESIS_STAT_ERROR: Cannot stat genesis: ${e.message}`
    };
  }

  // 2. Check for bootstrap state
  const contractsExist = fs.existsSync(contractRegPath);
  const lockExists = fs.existsSync(govLockPath);
  const proofExists = fs.existsSync(activationProofPath);

  if (!contractsExist || !lockExists || !proofExists) {
    return {
      status: 'BOOTSTRAP_NOT_YET_ACTIVE',
      details: {
        contracts_registry: contractsExist ? 'PRESENT' : 'MISSING',
        governance_lock: lockExists ? 'PRESENT' : 'MISSING',
        activation_proof: proofExists ? 'PRESENT' : 'MISSING'
      },
      message: 'Governance bootstrap is in progress. Milestone A activation required before normal mutations.'
    };
  }

  // 3. Verify Activation Proof Record
  let verifiedProofObj = null;
  try {
    const proofRaw = fs.readFileSync(activationProofPath, 'utf8');
    const proofObj = parseStrictIJson(proofRaw);
    const proofRes = verifyActivationProofRecord(proofObj, repoRoot, gitExecutor);
    if (!proofRes.valid) {
      return {
        status: 'BLOCKED_BY_GOVERNANCE_DRIFT',
        error: `ACTIVATION_PROOF_VERIFICATION_FAILED: ${proofRes.error}`
      };
    }
    verifiedProofObj = proofObj;
  } catch (err) {
    return {
      status: 'BLOCKED_BY_GOVERNANCE_DRIFT',
      error: `ACTIVATION_PROOF_ERROR: ${err.message}`
    };
  }

  // 4. Verify Governance Lockfile
  try {
    const lockRaw = fs.readFileSync(govLockPath, 'utf8');
    const lockObj = parseStrictIJson(lockRaw);
    const lockRes = validateGovernanceLock(lockObj, repoRoot, { checkContractRegistry: true });
    if (!lockRes.valid) {
      return {
        status: 'BLOCKED_BY_GOVERNANCE_DRIFT',
        error: `GOVERNANCE_LOCK_DRIFT: ${lockRes.error}`
      };
    }
    if (lockObj.root_governance_health_gate !== 'PASS') {
      return {
        status: 'BOOTSTRAP_NOT_YET_ACTIVE',
        message: `Governance lock root gate is ${lockObj.root_governance_health_gate}, expected PASS.`
      };
    }
  } catch (err) {
    return {
      status: 'BLOCKED_BY_GOVERNANCE_DRIFT',
      error: `GOVERNANCE_LOCK_PARSE_ERROR: ${err.message}`
    };
  }

  // 5. Verify Contract Registry
  try {
    const contractsRaw = fs.readFileSync(contractRegPath, 'utf8');
    const contractsObj = parseStrictIJson(contractsRaw);
    const crRes = validateContractRegistry(contractsObj, repoRoot);
    if (!crRes.valid) {
      return {
        status: 'BLOCKED_BY_GOVERNANCE_DRIFT',
        error: `CONTRACT_REGISTRY_DRIFT: ${crRes.error}`
      };
    }
    if (contractsObj.lifecycle_state !== 'ACTIVE') {
      return {
        status: 'BOOTSTRAP_NOT_YET_ACTIVE',
        message: `Contract registry is ${contractsObj.lifecycle_state}, not yet ACTIVE.`
      };
    }
  } catch (err) {
    return {
      status: 'BLOCKED_BY_GOVERNANCE_DRIFT',
      error: `CONTRACT_REGISTRY_PARSE_ERROR: ${err.message}`
    };
  }

  // 6. Verify Capability Registry with independently verified proof
  if (fs.existsSync(capRegPath)) {
    try {
      const capRaw = fs.readFileSync(capRegPath, 'utf8');
      const capObj = parseStrictIJson(capRaw);
      const capRes = validateCapabilityRegistry(capObj, {
        repoRoot,
        checkCapsuleExistence: true,
        allowActiveWithProof: true,
        activationProofVerified: true
      });
      if (!capRes.valid) {
        return {
          status: 'BLOCKED_BY_GOVERNANCE_DRIFT',
          error: `CAPABILITY_REGISTRY_DRIFT: [${capRes.stage}] ${capRes.error}`
        };
      }
    } catch (err) {
      return {
        status: 'BLOCKED_BY_GOVERNANCE_DRIFT',
        error: `CAPABILITY_REGISTRY_PARSE_ERROR: ${err.message}`
      };
    }
  }

  // All gates verified!
  return {
    status: 'PASS',
    message: 'All governance anti-drift gates verified. GLOBAL_GOVERNANCE_HEALTH = PASS'
  };
}

export function runSelfTest() {
  let positivePassed = 0;
  let negativePassed = 0;

  // Test 1: Missing genesis triggers BLOCKED_BY_GOVERNANCE_DRIFT
  const resNoGenesis = evaluateGlobalGovernanceHealth('/tmp/nonexistent-dir-for-genesis-test');
  if (resNoGenesis.status === 'BLOCKED_BY_GOVERNANCE_DRIFT') {
    negativePassed++;
  } else {
    throw new Error(`Self-test failed: Expected BLOCKED_BY_GOVERNANCE_DRIFT for missing genesis, got: ${JSON.stringify(resNoGenesis)}`);
  }

  // Test 2: Standard bootstrap directory (missing lockfile/contracts) returns BOOTSTRAP_NOT_YET_ACTIVE
  const testRoot = fs.mkdtempSync(path.join('/tmp', 'health-test-'));
  try {
    fs.mkdirSync(path.join(testRoot, '.synthesis', 'lineage'), { recursive: true });
    fs.writeFileSync(path.join(testRoot, '.synthesis', 'lineage', 'genesis.json'), '{}');
    const genesisSha = computeFileSha256(path.join(testRoot, '.synthesis', 'lineage', 'genesis.json'));

    const resBootstrap = evaluateGlobalGovernanceHealth(testRoot);
    if (resBootstrap.status === 'BOOTSTRAP_NOT_YET_ACTIVE') {
      positivePassed++;
    } else {
      throw new Error(`Self-test failed: Expected BOOTSTRAP_NOT_YET_ACTIVE, got: ${JSON.stringify(resBootstrap)}`);
    }

    // Mock git executor for controlled testing
    const mockCommitSha = '1'.repeat(40);
    const mockTreeSha = '2'.repeat(40);
    const mockParentSha = '3'.repeat(40);

    const mockGitExecutor = (args, cwd) => {
      const cmd = args.join(' ');
      if (cmd.includes('rev-parse --verify') && cmd.includes(mockCommitSha)) {
        return mockCommitSha + '\n';
      }
      if (cmd.includes('rev-parse') && cmd.includes('^{tree}')) {
        return mockTreeSha + '\n';
      }
      if (cmd.includes('rev-parse') && cmd.includes('^@')) {
        return mockParentSha + '\n';
      }
      if (cmd.includes('merge-base --is-ancestor')) {
        return '';
      }
      throw new Error(`Unexpected mock git command: ${cmd}`);
    };

    fs.mkdirSync(path.join(testRoot, '.synthesis', 'registries'), { recursive: true });
    fs.mkdirSync(path.join(testRoot, '.synthesis', 'activation'), { recursive: true });

    // Test 3: Corrupt contract registry triggers BLOCKED_BY_GOVERNANCE_DRIFT
    fs.writeFileSync(path.join(testRoot, '.synthesis', 'registries', 'contracts.json'), '{ bad json');
    fs.writeFileSync(path.join(testRoot, '.synthesis', 'governance.lock.json'), '{}');
    fs.writeFileSync(path.join(testRoot, '.synthesis', 'activation', 'milestone-a-activation-proof.json'), '{}');

    const resCorrupt = evaluateGlobalGovernanceHealth(testRoot, { gitExecutor: mockGitExecutor });
    if (resCorrupt.status === 'BLOCKED_BY_GOVERNANCE_DRIFT') {
      negativePassed++;
    } else {
      throw new Error(`Self-test failed: Expected BLOCKED_BY_GOVERNANCE_DRIFT on parse error, got: ${JSON.stringify(resCorrupt)}`);
    }

    // Prepare valid lockfile and contract registry
    const activeContracts = {
      schema_version: 'contract-registry.v1',
      format_version: '1.0.0',
      record_kind: 'CONTRACT_REGISTRY',
      lifecycle_state: 'ACTIVE',
      contracts: []
    };
    fs.writeFileSync(path.join(testRoot, '.synthesis', 'registries', 'contracts.json'), JSON.stringify(activeContracts));

    const passLock = {
      schema_version: '1.0.0',
      lockfile_kind: 'GOVERNANCE_REQUIREMENTS_LOCK',
      locked_at_utc: '2026-10-05T00:00:00.000Z',
      root_governance_health_gate: 'PASS',
      genesis_anchor: {
        path: '.synthesis/lineage/genesis.json',
        pinned_sha256: genesisSha
      },
      pinned_items: [],
      required_contracts: []
    };
    fs.writeFileSync(path.join(testRoot, '.synthesis', 'governance.lock.json'), JSON.stringify(passLock));
    const passLockSha = computeFileSha256(path.join(testRoot, '.synthesis', 'governance.lock.json'));

    // Test 4: Forged proof with non-existent commit rejected
    const nonExistentGitExecutor = (args) => {
      throw new Error('fatal: Not a valid object name');
    };
    const passProof = {
      schema_version: '1.0.0',
      record_kind: 'MILESTONE_ACTIVATION_PROOF',
      milestone_id: 'MILESTONE_A',
      activation_status: 'ACTIVE',
      exact_main_commit_sha: mockCommitSha,
      parent_commit_shas: [mockParentSha],
      merge_tree_sha: mockTreeSha,
      governance_lock_sha256: passLockSha,
      ci_workflow_run_id: 12345,
      verified_at_utc: '2026-10-05T00:00:00.000Z',
      verified_by: 'CI Evaluator'
    };
    fs.writeFileSync(path.join(testRoot, '.synthesis', 'activation', 'milestone-a-activation-proof.json'), JSON.stringify(passProof));
    const resNonExistent = evaluateGlobalGovernanceHealth(testRoot, { gitExecutor: nonExistentGitExecutor });
    if (resNonExistent.status === 'BLOCKED_BY_GOVERNANCE_DRIFT' && resNonExistent.error.includes('FORGED_PROOF_NONEXISTENT_COMMIT')) {
      negativePassed++;
    } else {
      throw new Error(`Self-test failed: Expected FORGED_PROOF_NONEXISTENT_COMMIT, got: ${JSON.stringify(resNonExistent)}`);
    }

    // Test 5: Forged proof with wrong tree rejected
    const wrongTreeGitExecutor = (args) => {
      const cmd = args.join(' ');
      if (cmd.includes('rev-parse --verify')) return mockCommitSha + '\n';
      if (cmd.includes('rev-parse') && cmd.includes('^{tree}')) return 'wrong_tree_sha_0000000000000000000000000\n';
      if (cmd.includes('rev-parse') && cmd.includes('^@')) return mockParentSha + '\n';
      if (cmd.includes('merge-base --is-ancestor')) return '';
      throw new Error(`Unexpected cmd: ${cmd}`);
    };
    const resWrongTree = evaluateGlobalGovernanceHealth(testRoot, { gitExecutor: wrongTreeGitExecutor });
    if (resWrongTree.status === 'BLOCKED_BY_GOVERNANCE_DRIFT' && resWrongTree.error.includes('FORGED_PROOF_TREE_MISMATCH')) {
      negativePassed++;
    } else {
      throw new Error(`Self-test failed: Expected FORGED_PROOF_TREE_MISMATCH, got: ${JSON.stringify(resWrongTree)}`);
    }

    // Test 6: Forged proof with wrong parents rejected
    const wrongParentsGitExecutor = (args) => {
      const cmd = args.join(' ');
      if (cmd.includes('rev-parse --verify')) return mockCommitSha + '\n';
      if (cmd.includes('rev-parse') && cmd.includes('^{tree}')) return mockTreeSha + '\n';
      if (cmd.includes('rev-parse') && cmd.includes('^@')) return 'wrong_parent_sha_000000000000000000000000\n';
      if (cmd.includes('merge-base --is-ancestor')) return '';
      throw new Error(`Unexpected cmd: ${cmd}`);
    };
    const resWrongParents = evaluateGlobalGovernanceHealth(testRoot, { gitExecutor: wrongParentsGitExecutor });
    if (resWrongParents.status === 'BLOCKED_BY_GOVERNANCE_DRIFT' && resWrongParents.error.includes('FORGED_PROOF_PARENTS_MISMATCH')) {
      negativePassed++;
    } else {
      throw new Error(`Self-test failed: Expected FORGED_PROOF_PARENTS_MISMATCH, got: ${JSON.stringify(resWrongParents)}`);
    }

    // Test 7: Forged proof with non-ancestor commit rejected
    const nonAncestorGitExecutor = (args) => {
      const cmd = args.join(' ');
      if (cmd.includes('rev-parse --verify')) return mockCommitSha + '\n';
      if (cmd.includes('rev-parse') && cmd.includes('^{tree}')) return mockTreeSha + '\n';
      if (cmd.includes('rev-parse') && cmd.includes('^@')) return mockParentSha + '\n';
      if (cmd.includes('merge-base --is-ancestor')) throw new Error('Not an ancestor');
      throw new Error(`Unexpected cmd: ${cmd}`);
    };
    const resNonAncestor = evaluateGlobalGovernanceHealth(testRoot, { gitExecutor: nonAncestorGitExecutor });
    if (resNonAncestor.status === 'BLOCKED_BY_GOVERNANCE_DRIFT' && resNonAncestor.error.includes('FORGED_PROOF_NON_ANCESTOR_COMMIT')) {
      negativePassed++;
    } else {
      throw new Error(`Self-test failed: Expected FORGED_PROOF_NON_ANCESTOR_COMMIT, got: ${JSON.stringify(resNonAncestor)}`);
    }

    // Test 8: Forged proof with mismatched lock hash rejected
    const forgedLockProof = JSON.parse(JSON.stringify(passProof));
    forgedLockProof.governance_lock_sha256 = 'f'.repeat(64);
    fs.writeFileSync(path.join(testRoot, '.synthesis', 'activation', 'milestone-a-activation-proof.json'), JSON.stringify(forgedLockProof));
    const resForgedLock = evaluateGlobalGovernanceHealth(testRoot, { gitExecutor: mockGitExecutor });
    if (resForgedLock.status === 'BLOCKED_BY_GOVERNANCE_DRIFT' && resForgedLock.error.includes('FORGED_PROOF_LOCK_SHA_MISMATCH')) {
      negativePassed++;
    } else {
      throw new Error(`Self-test failed: Expected FORGED_PROOF_LOCK_SHA_MISMATCH, got: ${JSON.stringify(resForgedLock)}`);
    }

    // Test 9: Complete valid PASS state simulation
    fs.writeFileSync(path.join(testRoot, '.synthesis', 'activation', 'milestone-a-activation-proof.json'), JSON.stringify(passProof));
    const resPass = evaluateGlobalGovernanceHealth(testRoot, { gitExecutor: mockGitExecutor });
    if (resPass.status === 'PASS') {
      positivePassed++;
    } else {
      throw new Error(`Self-test failed: Expected PASS, got: ${JSON.stringify(resPass)}`);
    }

  } finally {
    fs.rmSync(testRoot, { recursive: true, force: true });
  }

  const result = {
    positivePassed,
    negativePassed,
    totalTests: positivePassed + negativePassed
  };
  console.log(`GLOBAL_GOVERNANCE_HEALTH_SELFTEST: ${JSON.stringify(result)}`);
  return result;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.includes('--self-test')) {
    runSelfTest();
    process.exit(0);
  } else if (args.includes('--verify-all')) {
    const res = evaluateGlobalGovernanceHealth(DEFAULT_REPO_ROOT);
    if (res.status === 'BLOCKED_BY_GOVERNANCE_DRIFT') {
      console.error(`GLOBAL_GOVERNANCE_HEALTH: BLOCKED_BY_GOVERNANCE_DRIFT: ${res.error}`);
      process.exit(1);
    }
    console.log(`GLOBAL_GOVERNANCE_HEALTH: ${res.status}`);
    if (res.message) console.log(res.message);
    process.exit(0);
  } else {
    console.log('Usage: node verify_global_governance_health.mjs [--self-test|--verify-all]');
    process.exit(1);
  }
}
