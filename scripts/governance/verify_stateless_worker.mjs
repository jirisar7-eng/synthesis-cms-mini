#!/usr/bin/env node
/**
 * CMD002 fail-closed recovery verifier. READY_TO_MUTATE is deliberately unreachable.
 * READY_* observations are point-in-time read/plan results, never write capabilities.
 * Trust boundary: this executable, Node, Git and the fixed repository validators must
 * be obtained from verified source. Caller claims and injected adapters confer no trust.
 * CLI: --verify <repository-relative context.json> (a tracked envelope at task HEAD).
 * No context defaults; fixtures are private to --self-test and never production inputs.
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import https from 'node:https';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseStrictIJson, computePayloadSha256, verifyCapsuleSeal } from './verify_capsule_seal.mjs';
import { verifyAttestationChain } from './verify_capsule_attestation_chain.mjs';

export const STATES = Object.freeze(Object.fromEntries([
  'READY_READ_ONLY', 'READY_TO_PLAN', 'READY_TO_MUTATE', 'STOP_STALE_INPUT',
  'STOP_UNVERIFIABLE', 'STOP_SECURITY_FAILURE', 'STOP_AUTHORIZATION_REQUIRED'
].map(x => [x, x])));
const REPOSITORY = 'jirisar7-eng/synthesis-cms-mini';
const REMOTE = `https://github.com/${REPOSITORY}.git`;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SHA = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const MAX_BYTES = 2 * 1024 * 1024;
const HISTORICAL = p => p.startsWith('.synthesis/task-capsules/') || p.startsWith('.synthesis/attestations/');
export const REASON_CODES = Object.freeze(Object.fromEntries([
  'REPOSITORY_UNVERIFIABLE', 'REPOSITORY_MISMATCH', 'MAIN_SHA_MISMATCH', 'TASK_HEAD_MISMATCH',
  'MISSING_GIT_HISTORY', 'TASK_BRANCH_INVALID', 'ANCESTRY_INVALID', 'LOCAL_HEAD_MISMATCH',
  'ADAPTER_UNTRUSTED', 'EVIDENCE_METHOD_MISSING', 'EVIDENCE_READ_FAILED', 'WORKTREE_UNVERIFIABLE',
  'DIRTY_WORKTREE', 'UNSAFE_PATH', 'SYMLINK_ESCAPE', 'SOURCE_FILE_MISSING', 'SOURCE_MAP_INCOMPLETE',
  'UNVERIFIABLE_SOURCE', 'GIT_BLOB_MISMATCH', 'RAW_SHA256_MISMATCH', 'CAPSULE_CORRUPTED',
  'ATTESTATION_CHAIN_INVALID', 'HISTORICAL_SEALED_REWRITE', 'CI_MISSING', 'CI_FAILURE',
  'CI_BINDING_MISMATCH', 'CONCURRENT_REMOTE_UPDATE', 'MUTATION_GATE_DISABLED', 'SCOPE_VIOLATION',
  'INVALID_TIMESTAMP_PROVENANCE', 'UNAUTHORIZED_GOVERNANCE_ACTIVATION', 'INVALID_CONTEXT'
].map(x => [x, x])));

class GateError extends Error {
  constructor(state, code, message, affected, recovery) {
    super(message); Object.assign(this, { state, code, affected, recovery });
  }
}
function stop(code, message, affected, recovery, state = STATES.STOP_UNVERIFIABLE) {
  throw new GateError(state, code, message, affected, recovery);
}
function diagnostic(e, stage) {
  return { state: e instanceof GateError ? e.state : STATES.STOP_UNVERIFIABLE,
    reason_code: e instanceof GateError ? e.code : 'EVIDENCE_READ_FAILED',
    failed_invariant: e instanceof GateError ? e.message : `Evidence acquisition failed at ${stage}`,
    affected_file_or_contract: e instanceof GateError ? e.affected : stage,
    evidence_error_code: e instanceof GateError ? null : (typeof e?.code === 'string' ? e.code : 'INSPECTION_FAILED'),
    retry_safe: false,
    next_permitted_recovery_operation: e instanceof GateError ? e.recovery : 'Restore access to this evidence and repeat complete verification; do not mutate.',
    production_mutation_gate: 'DISABLED', checked_at_utc: new Date().toISOString() };
}
export function validateSafePath(p, root = ROOT) {
  const valid = typeof p === 'string' && p.length <= 512 &&
    /^[A-Za-z0-9_.\/-]+$/.test(p) && !path.isAbsolute(p) &&
    p.split('/').every(c => c && c !== '.' && c !== '..' && c !== '.git' && !c.startsWith('-'));
  return { valid, ...(valid ? { resolved: path.join(root, p), normalized: p } : { error: 'Unsafe raw path components' }) };
}
function safe(p) {
  if (!validateSafePath(p).valid) stop('UNSAFE_PATH', 'Raw path must be repository-relative without traversal/options', 'path', 'Use explicit regular repository paths.', STATES.STOP_SECURITY_FAILURE);
}
function inspect(root, p, missingLeaf = false) {
  safe(p);
  // Inspect root ancestors too. Never resolve symlinks away before checking them.
  const full = path.resolve(root, p);
  const parts = full.split(path.sep).filter(Boolean);
  let current = path.parse(full).root;
  for (let i = 0; i < parts.length; i++) {
    current = path.join(current, parts[i]);
    let stat;
    try { stat = fs.lstatSync(current); }
    catch (e) {
      if (e.code === 'ENOENT' && missingLeaf && i === parts.length - 1) return;
      if (e.code === 'ENOENT') stop('SOURCE_FILE_MISSING', 'Required file or ancestor is missing', p, 'Restore the exact source from Git.');
      throw e;
    }
    if (stat.isSymbolicLink()) stop('SYMLINK_ESCAPE', 'Symlink in file or ancestor', p, 'Use a regular directory and file.', STATES.STOP_SECURITY_FAILURE);
    if (i < parts.length - 1 ? !stat.isDirectory() : !stat.isFile())
      stop('UNSAFE_PATH', 'Non-regular filesystem object', p, 'Restore regular directories and files.', STATES.STOP_SECURITY_FAILURE);
  }
}
function readSafe(root, p) {
  inspect(root, p);
  const fd = fs.openSync(path.join(root, p), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const s = fs.fstatSync(fd);
    if (!s.isFile() || s.size > MAX_BYTES) stop('UNVERIFIABLE_SOURCE', 'File is not regular or exceeds size bound', p, 'Inspect the source file.');
    const b = fs.readFileSync(fd);
    inspect(root, p);
    return b;
  } finally { fs.closeSync(fd); }
}
const rawHash = b => crypto.createHash('sha256').update(b).digest('hex');
const blobHash = b => crypto.createHash('sha1').update(`blob ${b.length}\0`).update(b).digest('hex');
function git(root, args, binary = false) {
  return execFileSync('git', ['--no-replace-objects', ...args], {
    cwd: root, encoding: binary ? undefined : 'utf8', timeout: 20000,
    maxBuffer: 8 * MAX_BYTES, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_NO_REPLACE_OBJECTS: '1' }
  });
}
function parseTree(raw) {
  const entries = raw.split('\0').filter(Boolean).map(row => {
    const m = /^(100644|100755) blob ([0-9a-f]{40})\t(.+)$/.exec(row);
    if (!m) stop('UNVERIFIABLE_SOURCE', 'Git tree contains unsupported mode/type', 'git_tree', 'Inspect symlinks, submodules or malformed objects.');
    safe(m[3]); return [m[3], m[2]];
  });
  if (!entries.length || entries.length > 2000 || new Set(entries.map(x => x[0])).size !== entries.length)
    stop('UNVERIFIABLE_SOURCE', 'Empty, oversized or duplicate tree', 'git_tree', 'Fetch complete authoritative Git objects.');
  return Object.fromEntries(entries);
}
function github(resource) {
  return new Promise((resolve, reject) => {
    const req = https.get({ hostname: 'api.github.com', path: `/repos/${REPOSITORY}${resource ? `/${resource}` : ""}`,
      headers: { 'User-Agent': 'synthesis-stateless-worker', Accept: 'application/vnd.github+json', 'Cache-Control': 'no-cache' } }, res => {
      if (res.statusCode !== 200) { res.resume(); reject(Object.assign(new Error('GITHUB_EVIDENCE_UNAVAILABLE'), { code: `GITHUB_HTTP_${res.statusCode}` })); return; }
      const chunks = []; let size = 0;
      res.on('data', b => { size += b.length; if (size > MAX_BYTES) req.destroy(new Error('EVIDENCE_TOO_LARGE')); else chunks.push(b); });
      res.on('error', reject);
      res.on('end', () => { try { resolve(parseStrictIJson(Buffer.concat(chunks).toString('utf8'))); } catch (e) { reject(e); } });
    });
    req.setTimeout(15000, () => req.destroy(new Error('GITHUB_TIMEOUT')));
    req.on('error', reject);
  });
}
export const defaultGitAdapter = Object.freeze({
  root: ROOT,
  async repository() {
    const origin = git(ROOT, ['remote', 'get-url', 'origin']).trim();
    if (![REMOTE, REMOTE.slice(0, -4), `git@github.com:${REPOSITORY}.git`].includes(origin))
      stop('REPOSITORY_UNVERIFIABLE', 'Origin is absent or unrecognized', 'origin', 'Verify the authoritative GitHub origin.');
    const repo = await github('');
    if (repo.full_name !== REPOSITORY || repo.id !== 1401215700)
      stop('REPOSITORY_MISMATCH', 'GitHub repository identity mismatch', 'repository', 'Select the authoritative repository.', STATES.STOP_SECURITY_FAILURE);
    return REPOSITORY;
  },
  async refs(branch) {
    const [main, task] = await Promise.all([
      github('git/ref/heads/main'), github(`git/ref/heads/${branch}`)
    ]);
    if (main.ref !== 'refs/heads/main' || task.ref !== `refs/heads/${branch}` ||
        main.object?.type !== 'commit' || task.object?.type !== 'commit')
      stop('MISSING_GIT_HISTORY', 'Live GitHub refs are incomplete', 'remote_refs', 'Fetch live authoritative refs again.');
    return { main: main.object.sha, task: task.object.sha };
  },
  local() { return { head: git(ROOT, ['rev-parse', '--verify', 'HEAD']).trim(), branch: git(ROOT, ['symbolic-ref', '--short', 'HEAD']).trim() }; },
  ancestor(base, head) { git(ROOT, ['merge-base', '--is-ancestor', base, head]); return true; },
  historicalChanges(base, head) {
    const commits = git(ROOT, ['rev-list', `${base}..${head}`]).trim().split('\n').filter(Boolean);
    return commits.flatMap(sha => git(ROOT, ['diff-tree', '--no-commit-id', '-r', '-m', '--no-renames', '--diff-filter=CDMRTUXB', '--name-only', sha]).trim().split('\n').filter(p => p && HISTORICAL(p)));
  },
  clean() { return git(ROOT, ['status', '--porcelain=v1', '--untracked-files=all']).length === 0; },
  tree(sha) { return parseTree(git(ROOT, ['ls-tree', '-rz', '--full-tree', sha])); },
  blob(sha) { return git(ROOT, ['cat-file', 'blob', sha], true); },
  read(p) { return readSafe(ROOT, p); },
  inspect(p, missing) { inspect(ROOT, p, missing); },
  ci(id) { return github(`actions/runs/${id}`); }
});

// Private engine: only the exported production entry point or built-in tests can call it.
async function evaluate(context, adapter) {
  let stage = 'context';
  try {
    if (!context || typeof context !== 'object' || Array.isArray(context)) stop('INVALID_CONTEXT', 'Missing explicit context', stage, 'Provide a complete verified recovery envelope.');
    const c = structuredClone(context); // Prevent caller mutation across network awaits.
    const call = async (method, ...args) => {
      stage = method;
      if (typeof adapter[method] !== 'function') stop('EVIDENCE_METHOD_MISSING', `Missing evidence method: ${method}`, method, 'Restore the production evidence provider.');
      return adapter[method](...args);
    };
    if (c.expected_repository !== REPOSITORY) stop('REPOSITORY_UNVERIFIABLE', 'Expected repository is missing or unsupported', 'expected_repository', 'Supply the authoritative repository.');
    if (await call('repository') !== REPOSITORY) stop('REPOSITORY_UNVERIFIABLE', 'Repository could not be independently verified', 'origin', 'Restore authoritative GitHub identity evidence.');
    if (!SHA.test(c.expected_main_sha ?? '') || !SHA.test(c.expected_task_sha ?? '')) stop('MISSING_GIT_HISTORY', 'Expected main and task SHAs are both required', 'baseline', 'Supply exact independently verified baseline SHAs.');
    if (typeof c.target_branch !== 'string' || !/^task\/[A-Za-z0-9_-]+$/.test(c.target_branch)) stop('TASK_BRANCH_INVALID', 'Task branch identity is missing or unsafe', 'target_branch', 'Supply the exact task branch.');
    if (!['READ_ONLY', 'PLAN', 'MUTATE'].includes(c.operation_intent)) stop('INVALID_CONTEXT', 'Explicit operation intent required', 'operation_intent', 'Choose READ_ONLY, PLAN or MUTATE.');
    const checkRefs = (r, repeat = false) => {
      if (!r || !SHA.test(r.main ?? '') || !SHA.test(r.task ?? '')) stop('MISSING_GIT_HISTORY', 'Live remote SHA unavailable', 'remote_refs', 'Restore live GitHub access and repeat verification.');
      if (r.main !== c.expected_main_sha || r.task !== c.expected_task_sha)
        stop(repeat ? 'CONCURRENT_REMOTE_UPDATE' : r.main !== c.expected_main_sha ? 'MAIN_SHA_MISMATCH' : 'TASK_HEAD_MISMATCH',
          'Verified remote drift from the requested baseline', 'remote_refs', 'Inspect the new remote state; obtain a newly authorized baseline.', STATES.STOP_STALE_INPUT);
    };
    checkRefs(await call('refs', c.target_branch));
    const local = await call('local');
    if (local?.head !== c.expected_task_sha || local?.branch !== c.target_branch) stop('LOCAL_HEAD_MISMATCH', 'Local branch/HEAD differs from verified remote task', 'HEAD', 'Check out the exact task commit in a clean workspace.', STATES.STOP_STALE_INPUT);
    if (await call('ancestor', c.expected_main_sha, c.expected_task_sha) !== true) stop('ANCESTRY_INVALID', 'Main is not a proven ancestor of task HEAD', 'ancestry', 'Inspect authoritative Git ancestry.');
    const cleanliness = async () => {
      const clean = await call('clean');
      if (clean !== true) stop(clean === false ? 'DIRTY_WORKTREE' : 'WORKTREE_UNVERIFIABLE', 'Worktree cleanliness is not proven', 'worktree', 'Inspect and preserve local changes; repeat in a clean checkout.');
    };
    await cleanliness();
    stage = 'scope';
    if (!Array.isArray(c.read_set) || !c.read_set.length || !Array.isArray(c.write_set) ||
        new Set(c.read_set).size !== c.read_set.length || new Set(c.write_set).size !== c.write_set.length || c.write_set.length > 3)
      stop('SCOPE_VIOLATION', 'Explicit unique read/write sets with at most three writes required', 'scope', 'Correct the bounded scope.', STATES.STOP_SECURITY_FAILURE);
    for (const p of [...c.read_set, ...c.write_set]) { safe(p); await call('inspect', p, c.write_set.includes(p) && !c.read_set.includes(p)); }
    const tree = await call('tree', c.expected_task_sha);
    const baseTree = await call('tree', c.expected_main_sha);
    if (!tree || !baseTree || !Object.keys(tree).length || !Object.keys(baseTree).length) stop('UNVERIFIABLE_SOURCE', 'Complete commit trees required', 'source_tree', 'Fetch authoritative Git trees.');
    if (!c.expected_blobs || typeof c.expected_blobs !== 'object' || Array.isArray(c.expected_blobs) ||
        Object.keys(c.expected_blobs).length !== c.read_set.length || c.read_set.some(p => !Object.hasOwn(c.expected_blobs, p)))
      stop('SOURCE_MAP_INCOMPLETE', 'Source map must cover every declared required input exactly once', 'expected_blobs', 'Record actual commit/blob/raw digests for the complete read-set.');
    for (const p of c.read_set) {
      const e = c.expected_blobs[p];
      if (!e || e.source_commit_sha !== c.expected_task_sha || !SHA.test(e.git_blob_sha ?? '') || !SHA256.test(e.raw_file_sha256 ?? ''))
        stop('UNVERIFIABLE_SOURCE', 'Source commit, Git blob and raw SHA-256 must be distinct typed evidence', p, 'Read the file from the exact authoritative task tree.');
      if (tree[p] !== e.git_blob_sha) stop('GIT_BLOB_MISMATCH', 'Declared source differs from commit tree', p, 'Reconcile the source map with the exact commit.', STATES.STOP_STALE_INPUT);
    }
    const bytes = new Map();
    // Verify EVERY tracked file, including validators, schemas and all historical records.
    // This also defeats Git status shortcuts (assume-unchanged, cached stat information).
    const verifyFiles = async () => {
      for (const [p, sha] of Object.entries(tree)) {
        safe(p);
        if (!SHA.test(sha)) stop('UNVERIFIABLE_SOURCE', 'Malformed observed Git blob', p, 'Fetch complete Git objects.');
        await call('inspect', p, false);
        const observed = await call('blob', sha);
        if (!Buffer.isBuffer(observed) || blobHash(observed) !== sha) stop('UNVERIFIABLE_SOURCE', 'Actual Git blob bytes missing or corrupt', p, 'Restore the exact Git object.');
        const working = await call('read', p);
        if (!Buffer.isBuffer(working) || !working.equals(observed)) stop(HISTORICAL(p) ? 'HISTORICAL_SEALED_REWRITE' : 'GIT_BLOB_MISMATCH', 'Working bytes differ from authoritative Git object', p, 'Preserve diagnostics and restore the authoritative bytes.', STATES.STOP_SECURITY_FAILURE);
        if (c.expected_blobs[p] && rawHash(observed) !== c.expected_blobs[p].raw_file_sha256) stop('RAW_SHA256_MISMATCH', 'Raw-file SHA-256 differs from actual bytes', p, 'Correct the source provenance from exact Git bytes.', STATES.STOP_STALE_INPUT);
        bytes.set(p, observed);
      }
    };
    await verifyFiles();
    stage = 'capsule_integrity';
    for (const p of [c.capsule_path, c.attestation_path]) {
      safe(p);
      if (!c.read_set.includes(p) || !bytes.has(p)) stop('SOURCE_MAP_INCOMPLETE', 'Current capsule and attestation must be required reads', p, 'Include exact capsule and attestation provenance.');
    }
    if (!c.capsule_path.startsWith('.synthesis/task-capsules/') || !c.attestation_path.startsWith('.synthesis/attestations/')) stop('INVALID_CONTEXT', 'Invalid capsule/attestation location', 'integrity', 'Select records from the canonical directories.');
    const cap = parseStrictIJson(bytes.get(c.capsule_path).toString('utf8'));
    const schema = parseStrictIJson(bytes.get('.synthesis/schemas/command-capsule.schema.json')?.toString('utf8'));
    const seal = verifyCapsuleSeal(schema, cap);
    if (!seal.valid || !seal.isSealed || !seal.payloadHashMatch) stop('CAPSULE_CORRUPTED', `Capsule integrity failed: ${seal.stage}`, c.capsule_path, 'Inspect corruption; never reseal or rewrite history.', STATES.STOP_SECURITY_FAILURE);
    const chain = verifyAttestationChain(adapter.root);
    if (!chain.valid) stop('ATTESTATION_CHAIN_INVALID', `Cryptographic chain failed: ${chain.stage}`, c.attestation_path, 'Restore valid immutable ancestry and raw digests.', STATES.STOP_SECURITY_FAILURE);
    const att = parseStrictIJson(bytes.get(c.attestation_path).toString('utf8'));
    if (chain.headAttestationPath !== c.attestation_path || att.new_capsule?.file_path !== c.capsule_path ||
        att.new_capsule?.payload_sha256 !== cap.seal.payload_sha256 || cap.payload.task_id !== c.target_branch.slice(5))
      stop('ATTESTATION_CHAIN_INVALID', 'Selected task capsule is not the current attestation head', c.attestation_path, 'Select the authoritative task head records.', STATES.STOP_SECURITY_FAILURE);
    for (const [p, sha] of Object.entries(baseTree)) {
      if (HISTORICAL(p) && tree[p] !== sha) stop('HISTORICAL_SEALED_REWRITE', 'Task changed or deleted historical main record', p, 'Restore history via a separately authorized repair.', STATES.STOP_SECURITY_FAILURE);
    }
    const changedHistory = await call('historicalChanges', c.expected_main_sha, c.expected_task_sha);
    if (!Array.isArray(changedHistory)) stop('UNVERIFIABLE_SOURCE', 'Historical change inspection unavailable', 'history', 'Fetch complete task history.');
    if (changedHistory.length) stop('HISTORICAL_SEALED_REWRITE', 'Task history contains a modification/deletion of an existing record', 'history', 'Inspect historical changes; use append-only repair records.', STATES.STOP_SECURITY_FAILURE);
    for (const p of c.write_set) if (HISTORICAL(p) && Object.hasOwn(tree, p)) stop('HISTORICAL_SEALED_REWRITE', 'Write scope includes existing historical record', p, 'Use new forward-linked capsule and attestation paths.', STATES.STOP_SECURITY_FAILURE);
    if (c.timestamp_provenance?.source === 'LOCAL_CLOCK_DEFECT') stop('INVALID_TIMESTAMP_PROVENANCE', 'Known invalid UTC claim', 'timestamp_provenance', 'Use runtime new Date().toISOString(); preserve historical diagnostics.');
    if (c.governance_activation_attempt) stop('UNAUTHORIZED_GOVERNANCE_ACTIVATION', 'Governance activation is outside this protocol', 'governance', 'Keep bootstrap governance inactive.', STATES.STOP_SECURITY_FAILURE);
    // CI is required even for READY_READ_ONLY/PLAN in this conservative protocol.
    if (!c.required_ci || !/^\d+$/.test(String(c.required_ci.run_id ?? ''))) stop('CI_MISSING', 'An exact required GitHub Actions run is mandatory', 'required_ci', 'Obtain the exact task push run ID.');
    const ci = await call('ci', String(c.required_ci.run_id));
    if (!ci || String(ci.id) !== String(c.required_ci.run_id) || ci.repository?.full_name !== REPOSITORY ||
        ci.head_repository?.full_name !== REPOSITORY || ci.head_branch !== c.target_branch || ci.head_sha !== c.expected_task_sha ||
        ci.event !== 'push' || ci.path !== '.github/workflows/genesis-integrity.yml')
      stop('CI_BINDING_MISMATCH', 'Live CI must match run, repository, workflow, push event, branch and exact task SHA', 'required_ci', 'Locate the correct task push CI run.');
    if (ci.status !== 'completed' || ci.conclusion !== 'success') stop('CI_FAILURE', 'Required exact-head CI has not succeeded', 'required_ci', 'Wait for successful exact-head CI; do not substitute other runs.');
    // Re-read all bytes, local state, remote identity and refs after expensive checks.
    await verifyFiles(); await cleanliness();
    const lastLocal = await call('local');
    if (lastLocal?.head !== local.head || lastLocal?.branch !== local.branch) stop('CONCURRENT_REMOTE_UPDATE', 'Local checkout changed during verification', 'HEAD', 'Repeat verification from a stable workspace.', STATES.STOP_STALE_INPUT);
    if (await call('repository') !== REPOSITORY) stop('REPOSITORY_UNVERIFIABLE', 'Repository identity changed during verification', 'origin', 'Restore authoritative origin and repeat.');
    checkRefs(await call('refs', c.target_branch), true);
    if (c.operation_intent === 'MUTATE') stop('MUTATION_GATE_DISABLED',
      'Independent action/command/scope/exact-state authorization and atomic write guard are not implemented',
      'owner_authorization', 'Use a separately authorized implementation of verified authorization and an atomic remote precondition; caller owner/status claims cannot enable mutation.', STATES.STOP_AUTHORIZATION_REQUIRED);
    return { state: c.operation_intent === 'PLAN' ? STATES.READY_TO_PLAN : STATES.READY_READ_ONLY,
      reason_code: null, failed_invariant: null, production_mutation_gate: 'DISABLED',
      checked_at_utc: new Date().toISOString(), source_files_verified: bytes.size,
      capsule_payload_sha256: cap.seal.payload_sha256, attestation_chain_length: chain.attestationChainLength,
      next_permitted_recovery_operation: 'Read or plan against this observed snapshot only; reverify before reuse. No mutation authorized.',
      limitations: ['POINT_IN_TIME_NOT_A_WRITE_LEASE', 'NO_INDEPENDENT_TIMESTAMP_ANCHOR', 'WORKER_NOT_YET_REQUIRED_IN_CI'] };
  } catch (e) { return diagnostic(e, stage); }
}
export async function evaluateWorkerState(context, adapter = defaultGitAdapter) {
  if (adapter !== defaultGitAdapter) return diagnostic(new GateError(STATES.STOP_UNVERIFIABLE,
    'ADAPTER_UNTRUSTED', 'Caller-provided adapters are not production evidence', 'adapter', 'Use the fixed production provider.'), 'adapter');
  return evaluate(context, defaultGitAdapter);
}

/** Real baseline bytes and real filesystem/crypto; only network/Git observations are fixtures.
 * Each fixture is isolated. No fixture entry point or permissive adapter is exported.
 * POS-06 now asserts safe denial (the old positive accepted unverified mutation).
 */
export async function runSelfTests() {
  const main = '474cb4a4fde921db09fe4fb1446b30d339f864bd';
  const head = '8bd8cdb0bac58119722565e88251b9aa6004a837';
  const branch = 'task/SYN-MINI-GOV-STATELESS-WORKER-001';
  const capPath = '.synthesis/task-capsules/CAP-SYN-MINI-GOV-STATELESS-WORKER-001-20261004-001.json';
  const attPath = '.synthesis/attestations/ATT-SYN-MINI-GOV-STATELESS-WORKER-001-20261004-001.json';
  const originalTree = parseTree(git(ROOT, ['ls-tree', '-rz', '--full-tree', head]));
  const mainTree = parseTree(git(ROOT, ['ls-tree', '-rz', '--full-tree', main]));
  const objects = new Map(Object.values(originalTree).map(sha => [sha, git(ROOT, ['cat-file', 'blob', sha], true)]));
  let positivePassed = 0, negativePassed = 0;
  async function test(id, description, change, state, reason) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'stateless-worker-'));
    try {
      const tree = { ...originalTree }, blobs = new Map(objects);
      for (const [p, sha] of Object.entries(tree)) {
        fs.mkdirSync(path.dirname(path.join(root, p)), { recursive: true });
        fs.writeFileSync(path.join(root, p), blobs.get(sha));
      }
      const readSet = [capPath, attPath, '.synthesis/lineage/genesis.json', '.synthesis/schemas/command-capsule.schema.json'];
      const c = { expected_repository: REPOSITORY, expected_main_sha: main, expected_task_sha: head,
        target_branch: branch, operation_intent: 'READ_ONLY', read_set: readSet,
        write_set: ['scripts/governance/verify_stateless_worker.mjs'], capsule_path: capPath, attestation_path: attPath,
        expected_blobs: Object.fromEntries(readSet.map(p => [p, { source_commit_sha: head, git_blob_sha: tree[p], raw_file_sha256: rawHash(blobs.get(tree[p])) }])),
        required_ci: { run_id: '37218694921' }, actor: { owner: 'Jiří Šár', authorization_status: 'GRANTED' } };
      const run = { id: 37218694921, repository: { full_name: REPOSITORY }, head_repository: { full_name: REPOSITORY },
        head_branch: branch, head_sha: head, event: 'push', path: '.github/workflows/genesis-integrity.yml', status: 'completed', conclusion: 'success' };
      const a = { root, repository: () => REPOSITORY, refs: () => ({ main, task: head }), local: () => ({ head, branch }),
        ancestor: () => true, historicalChanges: () => [], clean: () => true, tree: sha => sha === main ? mainTree : tree, blob: sha => blobs.get(sha),
        read: p => readSafe(root, p), inspect: (p, missing) => inspect(root, p, missing), ci: () => run };
      // Model bytes actually present in a malicious commit, not a mere tampered flag.
      function put(p, bytes, committed = true) {
        const b = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
        fs.writeFileSync(path.join(root, p), b);
        if (committed) {
          tree[p] = blobHash(b); blobs.set(tree[p], b);
          if (c.expected_blobs[p]) c.expected_blobs[p] = { source_commit_sha: head, git_blob_sha: tree[p], raw_file_sha256: rawHash(b) };
        }
      }
      const json = p => JSON.parse(fs.readFileSync(path.join(root, p), 'utf8'));
      const putJson = (p, x) => put(p, JSON.stringify(x, null, 2) + '\n');
      await change({ c, a, run, tree, root, put, json, putJson });
      const result = await evaluate(c, a);
      assert.equal(result.state, state, `${id}: ${JSON.stringify(result)}`);
      if (reason) assert.equal(result.reason_code, reason, `${id}: ${JSON.stringify(result)}`);
      assert.notEqual(result.state, STATES.READY_TO_MUTATE);
      if (id.startsWith('POS')) positivePassed++; else negativePassed++;
      console.log(`[PASS] ${id}: ${description}`);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
  const ro = STATES.READY_READ_ONLY, plan = STATES.READY_TO_PLAN;
  const unverifiable = STATES.STOP_UNVERIFIABLE, security = STATES.STOP_SECURITY_FAILURE;
  const stale = STATES.STOP_STALE_INPUT, auth = STATES.STOP_AUTHORIZATION_REQUIRED;
  await test('POS-01', 'Recover exact baseline using real Git bytes and chain', () => {}, ro);
  await test('POS-02', 'Recover task baseline for planning', ({ c }) => { c.operation_intent = 'PLAN'; }, plan);
  await test('POS-03', 'Verify complete typed blob/raw map', ({ c }) => { assert.ok(Object.values(c.expected_blobs).every(e => SHA256.test(e.raw_file_sha256))); }, ro);
  await test('POS-04', 'Read-only needs no owner claim', ({ c }) => { delete c.actor; }, ro);
  await test('POS-05', 'Paused task planning verifies real immutable history', ({ c }) => { c.operation_intent = 'PLAN'; c.write_set = []; }, plan);
  await test('POS-06', 'Corrected: bounded write scope cannot grant mutation', ({ c }) => { c.operation_intent = 'MUTATE'; }, auth, 'MUTATION_GATE_DISABLED');
  await test('POS-07', 'Historical timestamp defect does not rewrite sealed records', ({ json }) => {
    const old = json('.synthesis/task-capsules/CAP-SYN-MINI-GOV-POST-MERGE-CLOSEOUT-001-20261004-004.json');
    assert.ok(old.seal.sealed_at.startsWith('2026-10-04T02:'));
  }, ro);
  await test('POS-08', 'Fresh isolated reconstruction', ({ c }) => { Object.assign(c, JSON.parse(JSON.stringify(c))); }, ro);
  await test('NEG-01', 'Verified main drift', ({ a }) => { a.refs = () => ({ main: '1'.repeat(40), task: head }); }, stale, 'MAIN_SHA_MISMATCH');
  await test('NEG-02', 'Verified task drift', ({ a }) => { a.refs = () => ({ main, task: '2'.repeat(40) }); }, stale, 'TASK_HEAD_MISMATCH');
  await test('NEG-03', 'Observed Git tree differs from expected blob', ({ c }) => { c.expected_blobs[capPath].git_blob_sha = '3'.repeat(40); }, stale, 'GIT_BLOB_MISMATCH');
  await test('NEG-04', 'Missing actual source file', ({ root }) => { fs.unlinkSync(path.join(root, capPath)); }, unverifiable, 'SOURCE_FILE_MISSING');
  await test('NEG-05', 'Corrupt SEALED payload with unchanged claimed seal', ({ json, putJson }) => {
    const cap = json(capPath); cap.payload.actors.executor = 'tampered'; putJson(capPath, cap);
  }, security, 'CAPSULE_CORRUPTED');
  await test('NEG-06', 'Incorrect actual attestation-parent raw digest', ({ json, putJson }) => {
    const att = json(attPath); att.parent_attestation.raw_file_sha256 = '0'.repeat(64); putJson(attPath, att);
  }, security, 'ATTESTATION_CHAIN_INVALID');
  await test('NEG-07', 'More than three writes', ({ c }) => { c.write_set = ['a', 'b', 'c', 'd']; }, security, 'SCOPE_VIOLATION');
  await test('NEG-08', 'Raw traversal rejected before normalization', ({ c }) => { c.read_set.push('scripts/../LICENSE'); }, security, 'UNSAFE_PATH');
  await test('NEG-09', 'Real leaf symlink', ({ root }) => { const p = path.join(root, capPath); fs.unlinkSync(p); fs.symlinkSync(path.join(ROOT, capPath), p); }, security, 'SYMLINK_ESCAPE');
  await test('NEG-10', 'Denied caller authorization never permits mutation', ({ c }) => { c.operation_intent = 'MUTATE'; c.actor.authorization_status = 'DENIED'; }, auth, 'MUTATION_GATE_DISABLED');
  await test('NEG-11', 'Actual CI failure despite caller success', ({ c, run }) => { c.required_ci.conclusion = 'success'; run.conclusion = 'failure'; }, unverifiable, 'CI_FAILURE');
  await test('NEG-12', 'Unverifiable live remote main', ({ a }) => { a.refs = () => ({ main: null, task: head }); }, unverifiable, 'MISSING_GIT_HISTORY');
  await test('NEG-13', 'Remote update between initial and final observations', ({ a }) => { let reads = 0; a.refs = () => ({ main, task: ++reads === 1 ? head : '5'.repeat(40) }); }, stale, 'CONCURRENT_REMOTE_UPDATE');
  await test('NEG-14', 'Counterfeit owner string confers no authority', ({ c }) => { c.operation_intent = 'MUTATE'; c.actor.owner = 'Unknown Actor'; }, auth, 'MUTATION_GATE_DISABLED');
  await test('NEG-15', 'Missing Git blob verifier cannot recycle expected digest', ({ a }) => { delete a.blob; }, unverifiable, 'EVIDENCE_METHOD_MISSING');
  await test('NEG-16', 'Actual historical immutable bytes modified, flag absent', ({ put }) => { put('.synthesis/task-capsules/CAP-SYN-MINI-GOV-POST-MERGE-CLOSEOUT-001-20261004-004.json', '{}\n', false); }, security, 'HISTORICAL_SEALED_REWRITE');
  await test('NEG-17', 'Known invalid timestamp provenance', ({ c }) => { c.timestamp_provenance = { source: 'LOCAL_CLOCK_DEFECT' }; }, unverifiable, 'INVALID_TIMESTAMP_PROVENANCE');
  await test('NEG-18', 'Governance activation denied', ({ c }) => { c.governance_activation_attempt = true; }, security, 'UNAUTHORIZED_GOVERNANCE_ACTIVATION');
  await test('NEG-19', 'Missing remote identity provider', ({ a }) => { delete a.repository; }, unverifiable, 'EVIDENCE_METHOD_MISSING');
  await test('NEG-20', 'Unrecognized repository origin', ({ a }) => { a.repository = () => null; }, unverifiable, 'REPOSITORY_UNVERIFIABLE');
  await test('NEG-21', 'Missing expected task SHA', ({ c }) => { delete c.expected_task_sha; }, unverifiable, 'MISSING_GIT_HISTORY');
  await test('NEG-22', 'Missing observed live task SHA', ({ a }) => { a.refs = () => ({ main }); }, unverifiable, 'MISSING_GIT_HISTORY');
  await test('NEG-23', 'Incomplete required source blob map', ({ c }) => { delete c.expected_blobs[capPath]; }, unverifiable, 'SOURCE_MAP_INCOMPLETE');
  await test('NEG-24', 'Resealed broken capsule ancestry still rejected', ({ json, putJson }) => {
    const cap = json(capPath); cap.payload.lineage.parent_capsules[0].payload_sha256 = '0'.repeat(64);
    cap.seal.payload_sha256 = computePayloadSha256(cap.payload).sha256Hex; putJson(capPath, cap);
    const raw = Buffer.from(JSON.stringify(cap, null, 2) + '\n');
    const att = json(attPath); Object.assign(att.new_capsule, { payload_sha256: cap.seal.payload_sha256, raw_file_sha256: rawHash(raw), git_blob_sha: blobHash(raw), file_size_bytes: raw.length }); putJson(attPath, att);
  }, security, 'ATTESTATION_CHAIN_INVALID');
  await test('NEG-25', 'Missing required CI', ({ c }) => { delete c.required_ci; }, unverifiable, 'CI_MISSING');
  await test('NEG-26', 'Successful CI for wrong commit', ({ run }) => { run.head_sha = main; }, unverifiable, 'CI_BINDING_MISMATCH');
  await test('NEG-27', 'Unverified GRANTED owner cannot reach mutation', ({ c }) => { c.operation_intent = 'MUTATE'; c.authorization = { verified: true, owner: 'Jiří Šár', status: 'GRANTED' }; }, auth, 'MUTATION_GATE_DISABLED');
  await test('NEG-28', 'Authorization for another command cannot reach mutation', ({ c }) => { c.operation_intent = 'MUTATE'; c.authorization = { command_id: 'OTHER', status: 'GRANTED' }; }, auth, 'MUTATION_GATE_DISABLED');
  await test('NEG-29', 'Authorization for another scope cannot reach mutation', ({ c }) => { c.operation_intent = 'MUTATE'; c.authorization = { write_set: ['LICENSE'], status: 'GRANTED' }; }, auth, 'MUTATION_GATE_DISABLED');
  await test('NEG-30', 'Unavailable cleanliness provider with actual dirty file', ({ a, put }) => { put('LICENSE', 'dirty', false); delete a.clean; }, unverifiable, 'EVIDENCE_METHOD_MISSING');
  await test('NEG-31', 'Real symlink ancestor', ({ root }) => { fs.renameSync(path.join(root, '.synthesis/task-capsules'), path.join(root, 'capsules-real')); fs.symlinkSync('../capsules-real', path.join(root, '.synthesis/task-capsules')); }, security, 'SYMLINK_ESCAPE');
  await test('NEG-32', 'Filesystem read error never becomes safe absence', ({ a }) => { a.read = () => fs.readFileSync(path.join(a.root, 'missing-file')); }, unverifiable, 'EVIDENCE_READ_FAILED');
  await test('NEG-33', 'Unknown cleanliness is not CLEAN', ({ a }) => { a.clean = () => undefined; }, unverifiable, 'WORKTREE_UNVERIFIABLE');
  await test('NEG-34', 'Dirty worktree denied', ({ a }) => { a.clean = () => false; }, unverifiable, 'DIRTY_WORKTREE');
  await test('NEG-35', 'Unavailable ancestry rejected', ({ a }) => { delete a.ancestor; }, unverifiable, 'EVIDENCE_METHOD_MISSING');
  await test('NEG-36', 'Diverged ancestry rejected', ({ a }) => { a.ancestor = () => false; }, unverifiable, 'ANCESTRY_INVALID');
  await test('NEG-37', 'Wrong local task identity rejected', ({ a }) => { a.local = () => ({ head, branch: 'main' }); }, stale, 'LOCAL_HEAD_MISMATCH');
  await test('NEG-38', 'Raw SHA-256 cannot be replaced by canonical payload hash', ({ c }) => { c.expected_blobs[capPath].raw_file_sha256 = 'c5209929241002ae28b59a4729700ef0f159b9721a787a6f0a0615bc1864ace7'; }, stale, 'RAW_SHA256_MISMATCH');
  await test('NEG-39', 'Historical record cannot be declared writable', ({ c }) => { c.write_set = [capPath]; }, security, 'HISTORICAL_SEALED_REWRITE');
  await test('NEG-40', 'Actual Git object absent', ({ a }) => { a.blob = () => undefined; }, unverifiable, 'UNVERIFIABLE_SOURCE');
  await test('NEG-41', 'Wrong CI branch', ({ run }) => { run.head_branch = 'main'; }, unverifiable, 'CI_BINDING_MISMATCH');
  await test('NEG-42', 'Wrong CI event', ({ run }) => { run.event = 'pull_request'; }, unverifiable, 'CI_BINDING_MISMATCH');
  await test('NEG-43', 'Missing CI evidence provider', ({ a }) => { delete a.ci; }, unverifiable, 'EVIDENCE_METHOD_MISSING');
  await test('NEG-44', 'Unsafe option-shaped path', ({ c }) => { c.write_set = ['--output']; }, security, 'UNSAFE_PATH');
  await test('NEG-45', 'Changed working bytes during verification', ({ a }) => {
    let reads = 0; const original = a.read; a.read = p => p === 'LICENSE' && ++reads > 1 ? Buffer.from('race') : original(p);
  }, security, 'GIT_BLOB_MISMATCH');
  await test('NEG-46', 'Read inspection provider missing', ({ a }) => { delete a.inspect; }, unverifiable, 'EVIDENCE_METHOD_MISSING');
  await test('NEG-48', 'Historical rewrite discovered in task commit history', ({ a }) => { a.historicalChanges = () => [capPath]; }, security, 'HISTORICAL_SEALED_REWRITE');
  await test('NEG-49', 'Historical inspection cannot be omitted', ({ a }) => { delete a.historicalChanges; }, unverifiable, 'EVIDENCE_METHOD_MISSING');
  const denied = await evaluateWorkerState({}, { repository: () => REPOSITORY });
  assert.equal(denied.reason_code, 'ADAPTER_UNTRUSTED'); negativePassed++;
  console.log('[PASS] NEG-47: Public production API rejects injected test adapters');
  const summary = { positivePassed, negativePassed, totalTests: positivePassed + negativePassed };
  console.log(`WORKER_SELFTEST: ${JSON.stringify(summary)}`);
  return summary;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--self-test') { await runSelfTests(); return; }
  if (args.length !== 2 || args[0] !== '--verify') {
    console.log(JSON.stringify(diagnostic(new GateError(STATES.STOP_UNVERIFIABLE,
      'INVALID_CONTEXT', 'No implicit baseline: use --verify <tracked-context.json> or --self-test', 'CLI', 'Supply an authoritative complete tracked recovery envelope.'), 'CLI')));
    process.exitCode = 1; return;
  }
  const bytes = readSafe(ROOT, args[1]);
  const context = parseStrictIJson(bytes.toString('utf8'));
  if (!SHA.test(context.expected_task_sha ?? '')) throw new Error('CONTEXT_TASK_SHA_REQUIRED');
  const tree = defaultGitAdapter.tree(context.expected_task_sha);
  if (tree[args[1]] !== blobHash(bytes)) throw new Error('CONTEXT_NOT_IN_AUTHORITATIVE_TASK_TREE');
  const result = await evaluateWorkerState(context);
  console.log(JSON.stringify(result, null, 2));
  if (![STATES.READY_READ_ONLY, STATES.READY_TO_PLAN].includes(result.state)) process.exitCode = 1;
}
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main().catch(e => { console.error(JSON.stringify(diagnostic(e, 'CLI'))); process.exitCode = 1; });
}
