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
 * evidence exists on exact main. Missing Capability Registry is a critical DRIFT blocker.
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
import { verifyActivationProofRecord, defaultGitExecutor } from './verify_activation_proof.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_REPO_ROOT = path.resolve(__dirname, '..', '..');

export function computeFileSha256(filePath) {
  const bytes = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(bytes).digest('hex');
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

  // 2. Capability Registry must exist in all modes; missing = GOVERNANCE FAIL
  if (!fs.existsSync(capRegPath)) {
    return {
      status: 'BLOCKED_BY_GOVERNANCE_DRIFT',
      error: 'CRITICAL_DRIFT: Capability registry (.synthesis/registries/capabilities.json) is missing'
    };
  }
  try {
    const capStat = fs.lstatSync(capRegPath);
    if (!capStat.isFile() || capStat.isSymbolicLink()) {
      return {
        status: 'BLOCKED_BY_GOVERNANCE_DRIFT',
        error: 'CRITICAL_DRIFT: Capability registry must be a regular file, not a symlink'
      };
    }
  } catch (e) {
    return {
      status: 'BLOCKED_BY_GOVERNANCE_DRIFT',
      error: `CAPABILITY_REGISTRY_STAT_ERROR: Cannot stat capabilities.json: ${e.message}`
    };
  }

  // 3. Check for bootstrap state of Milestone A files
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

  // 4. Verify Activation Proof Record
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

  // 5. Verify Governance Lockfile
  try {
    const lockRaw = fs.readFileSync(govLockPath, 'utf8');
    const lockObj = parseStrictIJson(lockRaw);
    const lockRes = validateGovernanceLock(lockObj, repoRoot, { checkContractRegistry: true, gitExecutor });
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

  // 6. Verify Contract Registry
  try {
    const contractsRaw = fs.readFileSync(contractRegPath, 'utf8');
    const contractsObj = parseStrictIJson(contractsRaw);
    const crRes = validateContractRegistry(contractsObj, repoRoot, { gitExecutor });
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

  // 7. Verify Capability Registry with independently verified proof
  try {
    const capRaw = fs.readFileSync(capRegPath, 'utf8');
    const capObj = parseStrictIJson(capRaw);
    const capRes = validateCapabilityRegistry(capObj, {
      repoRoot,
      checkCapsuleExistence: true,
      activationProof: verifiedProofObj,
      gitExecutor
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
  if (resNoGenesis.status === 'BLOCKED_BY_GOVERNANCE_DRIFT' && resNoGenesis.error.includes('Genesis anchor file is missing')) {
    negativePassed++;
  } else {
    throw new Error(`Self-test failed: Expected BLOCKED_BY_GOVERNANCE_DRIFT for missing genesis, got: ${JSON.stringify(resNoGenesis)}`);
  }

  const testRoot = fs.mkdtempSync(path.join('/tmp', 'health-test-'));
  try {
    fs.mkdirSync(path.join(testRoot, '.synthesis', 'lineage'), { recursive: true });
    fs.writeFileSync(path.join(testRoot, '.synthesis', 'lineage', 'genesis.json'), '{}');
    const genesisSha = computeFileSha256(path.join(testRoot, '.synthesis', 'lineage', 'genesis.json'));

    // Test 2: Missing capability registry triggers BLOCKED_BY_GOVERNANCE_DRIFT
    const resNoCap = evaluateGlobalGovernanceHealth(testRoot);
    if (resNoCap.status === 'BLOCKED_BY_GOVERNANCE_DRIFT' && resNoCap.error.includes('Capability registry (.synthesis/registries/capabilities.json) is missing')) {
      negativePassed++;
    } else {
      throw new Error(`Self-test failed: Expected BLOCKED_BY_GOVERNANCE_DRIFT for missing capability registry, got: ${JSON.stringify(resNoCap)}`);
    }

    fs.mkdirSync(path.join(testRoot, '.synthesis', 'registries'), { recursive: true });
    const liveCapRaw = fs.readFileSync(path.resolve(DEFAULT_REPO_ROOT, '.synthesis/registries/capabilities.json'), 'utf8');
    fs.writeFileSync(path.join(testRoot, '.synthesis', 'registries', 'capabilities.json'), liveCapRaw);
    fs.cpSync(path.resolve(DEFAULT_REPO_ROOT, '.synthesis/task-capsules'), path.join(testRoot, '.synthesis', 'task-capsules'), { recursive: true });

    // Test 3: Standard bootstrap directory (missing lockfile/contracts) returns BOOTSTRAP_NOT_YET_ACTIVE
    const resBootstrap = evaluateGlobalGovernanceHealth(testRoot);
    if (resBootstrap.status === 'BOOTSTRAP_NOT_YET_ACTIVE') {
      positivePassed++;
    } else {
      throw new Error(`Self-test failed: Expected BOOTSTRAP_NOT_YET_ACTIVE, got: ${JSON.stringify(resBootstrap)}`);
    }

    // Mock git executor for controlled testing
    const mockCommitSha = '1'.repeat(40);
    const mockTreeSha = '2'.repeat(40);
    const mockParent1Sha = '3'.repeat(40);
    const mockParent2Sha = '4'.repeat(40);

    const mockGitExecutor = (args, cwd) => {
      const cmd = args.join(' ');
      if (cmd.includes('rev-parse --verify') && cmd.includes(mockCommitSha)) {
        return mockCommitSha + '\n';
      }
      if (cmd.includes('rev-parse') && cmd.includes('^{tree}')) {
        return mockTreeSha + '\n';
      }
      if (cmd.includes('rev-parse') && cmd.includes('^@')) {
        return mockParent1Sha + ' ' + mockParent2Sha + '\n';
      }
      if (cmd.includes('merge-base --is-ancestor')) {
        return '';
      }
      throw new Error(`Unexpected mock git command: ${cmd}`);
    };

    fs.mkdirSync(path.join(testRoot, '.synthesis', 'activation'), { recursive: true });

    // Test 4: Corrupt contract registry triggers BLOCKED_BY_GOVERNANCE_DRIFT
    fs.writeFileSync(path.join(testRoot, '.synthesis', 'registries', 'contracts.json'), '{ bad json');
    fs.writeFileSync(path.join(testRoot, '.synthesis', 'governance.lock.json'), '{}');
    fs.writeFileSync(path.join(testRoot, '.synthesis', 'activation', 'milestone-a-activation-proof.json'), '{}');

    const resCorrupt = evaluateGlobalGovernanceHealth(testRoot, { gitExecutor: mockGitExecutor });
    if (resCorrupt.status === 'BLOCKED_BY_GOVERNANCE_DRIFT') {
      negativePassed++;
    } else {
      throw new Error(`Self-test failed: Expected BLOCKED_BY_GOVERNANCE_DRIFT on parse error, got: ${JSON.stringify(resCorrupt)}`);
    }

    // Valid active contracts and lockfile
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

    const passProof = {
      schema_version: '1.0.0',
      record_kind: 'MILESTONE_ACTIVATION_PROOF',
      milestone_id: 'MILESTONE_A',
      activation_status: 'ACTIVE',
      exact_main_commit_sha: mockCommitSha,
      parent_commit_shas: [mockParent1Sha, mockParent2Sha],
      merge_tree_sha: mockTreeSha,
      governance_lock_sha256: passLockSha,
      ci_workflow_run_id: 12345,
      verified_at_utc: '2026-10-05T00:00:00.000Z',
      verified_by: 'CI Evaluator'
    };
    fs.writeFileSync(path.join(testRoot, '.synthesis', 'activation', 'milestone-a-activation-proof.json'), JSON.stringify(passProof));

    // Test 5: Forged proof with non-existent commit rejected
    const nonExistentGit = () => { throw new Error('Not a valid commit'); };
    const resNonExistent = evaluateGlobalGovernanceHealth(testRoot, { gitExecutor: nonExistentGit });
    if (resNonExistent.status === 'BLOCKED_BY_GOVERNANCE_DRIFT' && resNonExistent.error.includes('FORGED_PROOF_NONEXISTENT_COMMIT')) {
      negativePassed++;
    } else {
      throw new Error(`Expected FORGED_PROOF_NONEXISTENT_COMMIT, got: ${JSON.stringify(resNonExistent)}`);
    }

    // Test 6: Forged proof with wrong tree rejected
    const wrongTreeGit = (args) => {
      const cmd = args.join(' ');
      if (cmd.includes('rev-parse --verify')) return mockCommitSha + '\n';
      if (cmd.includes('rev-parse') && cmd.includes('^{tree}')) return 'wrong_tree_sha_0000000000000000000000000\n';
      if (cmd.includes('rev-parse') && cmd.includes('^@')) return mockParent1Sha + ' ' + mockParent2Sha + '\n';
      if (cmd.includes('merge-base --is-ancestor')) return '';
      throw new Error(`Unexpected mock cmd: ${cmd}`);
    };
    const resWrongTree = evaluateGlobalGovernanceHealth(testRoot, { gitExecutor: wrongTreeGit });
    if (resWrongTree.status === 'BLOCKED_BY_GOVERNANCE_DRIFT' && resWrongTree.error.includes('FORGED_PROOF_TREE_MISMATCH')) {
      negativePassed++;
    } else {
      throw new Error(`Expected FORGED_PROOF_TREE_MISMATCH, got: ${JSON.stringify(resWrongTree)}`);
    }

    // Test 7: Forged proof with wrong parents rejected
    const wrongParentsGit = (args) => {
      const cmd = args.join(' ');
      if (cmd.includes('rev-parse --verify')) return mockCommitSha + '\n';
      if (cmd.includes('rev-parse') && cmd.includes('^{tree}')) return mockTreeSha + '\n';
      if (cmd.includes('rev-parse') && cmd.includes('^@')) return 'wrong_p1 wrong_p2\n';
      if (cmd.includes('merge-base --is-ancestor')) return '';
      throw new Error(`Unexpected mock cmd: ${cmd}`);
    };
    const resWrongParents = evaluateGlobalGovernanceHealth(testRoot, { gitExecutor: wrongParentsGit });
    if (resWrongParents.status === 'BLOCKED_BY_GOVERNANCE_DRIFT' && resWrongParents.error.includes('FORGED_PROOF_PARENTS_MISMATCH')) {
      negativePassed++;
    } else {
      throw new Error(`Expected FORGED_PROOF_PARENTS_MISMATCH, got: ${JSON.stringify(resWrongParents)}`);
    }

    // Test 8: Forged proof with non-ancestor commit rejected
    const nonAncestorGit = (args) => {
      const cmd = args.join(' ');
      if (cmd.includes('rev-parse --verify')) return mockCommitSha + '\n';
      if (cmd.includes('rev-parse') && cmd.includes('^{tree}')) return mockTreeSha + '\n';
      if (cmd.includes('rev-parse') && cmd.includes('^@')) return mockParent1Sha + ' ' + mockParent2Sha + '\n';
      if (cmd.includes('merge-base --is-ancestor')) throw new Error('Not an ancestor');
      throw new Error(`Unexpected mock cmd: ${cmd}`);
    };
    const resNonAncestor = evaluateGlobalGovernanceHealth(testRoot, { gitExecutor: nonAncestorGit });
    if (resNonAncestor.status === 'BLOCKED_BY_GOVERNANCE_DRIFT' && resNonAncestor.error.includes('FORGED_PROOF_NON_ANCESTOR_COMMIT')) {
      negativePassed++;
    } else {
      throw new Error(`Expected FORGED_PROOF_NON_ANCESTOR_COMMIT, got: ${JSON.stringify(resNonAncestor)}`);
    }

    // Test 9: Forged proof with mismatched lock hash rejected
    const forgedLockProof = JSON.parse(JSON.stringify(passProof));
    forgedLockProof.governance_lock_sha256 = 'f'.repeat(64);
    fs.writeFileSync(path.join(testRoot, '.synthesis', 'activation', 'milestone-a-activation-proof.json'), JSON.stringify(forgedLockProof));
    const resForgedLock = evaluateGlobalGovernanceHealth(testRoot, { gitExecutor: mockGitExecutor });
    if (resForgedLock.status === 'BLOCKED_BY_GOVERNANCE_DRIFT' && resForgedLock.error.includes('FORGED_PROOF_LOCK_SHA_MISMATCH')) {
      negativePassed++;
    } else {
      throw new Error(`Expected FORGED_PROOF_LOCK_SHA_MISMATCH, got: ${JSON.stringify(resForgedLock)}`);
    }

    // Test 10: Complete valid PASS state simulation
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
