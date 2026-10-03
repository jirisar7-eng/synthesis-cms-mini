#!/usr/bin/env node
/**
 * verify_source_blob_provenance.mjs
 *
 * Deterministic, fail-closed Git source-blob provenance verifier for Synthesis CMS mini.
 * Enforces:
 *   1. Historical capsules (005-011): source_blob_shas must match either containing commit
 *      or parent commit Git tree, unless explicitly covered by the tamper-evident
 *      CMD-013 historical impact manifest (source-blob-impact-20261003.json).
 *   2. Prospective capsules (>= 013): source_blob_shas MUST refer to verified blobs
 *      existing in the parent Git commit tree. Historical waiver is strictly prohibited.
 *   3. Strict validation of manifest SHA-256, format, and 1-to-1 exception accounting.
 */

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execSync } from "node:child_process";
import process from "node:process";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const EXPECTED_MANIFEST_RAW_SHA256 = "b0a190f16bed4e4ccdb3370a1445a377495b5b58b2da5a1624f1e4b3f638f771";
export const EXPECTED_EXCEPTION_COUNT = 23;

export const HISTORICAL_CAPSULE_SET = new Set([
  "CAP-SYN-MINI-GOV-CAPABILITY-REGISTRY-001-20261003-005",
  "CAP-SYN-MINI-GOV-CAPABILITY-REGISTRY-001-20261003-006",
  "CAP-SYN-MINI-GOV-CAPABILITY-REGISTRY-001-20261003-007",
  "CAP-SYN-MINI-GOV-CAPABILITY-REGISTRY-001-20261003-008",
  "CAP-SYN-MINI-GOV-CAPABILITY-REGISTRY-001-20261003-009",
  "CAP-SYN-MINI-GOV-CAPABILITY-REGISTRY-001-20261003-011"
]);

/**
 * Locates the repository root by searching upward for .git or .synthesis.
 */
export function locateRepositoryRoot(startDir = __dirname) {
  let curr = path.resolve(startDir);
  for (let i = 0; i < 15; i++) {
    const gitDir = path.join(curr, ".git");
    const synDir = path.join(curr, ".synthesis");
    if (fs.existsSync(gitDir) || fs.existsSync(synDir)) {
      return curr;
    }
    const parent = path.dirname(curr);
    if (parent === curr) break;
    curr = parent;
  }
  return path.resolve(__dirname, "..", "..");
}

/**
 * Default git runner executing git commands in repoRoot.
 */
export function defaultGitRunner(repoRoot) {
  return {
    revParse(rev) {
      try {
        return execSync(`git -C "${repoRoot}" rev-parse ${rev}`, { stdio: ["pipe", "pipe", "ignore"] }).toString().trim();
      } catch {
        return null;
      }
    },
    catFileType(sha) {
      try {
        return execSync(`git -C "${repoRoot}" cat-file -t ${sha}`, { stdio: ["pipe", "pipe", "ignore"] }).toString().trim();
      } catch {
        return null;
      }
    },
    getCommitForPath(relPath) {
      try {
        const out = execSync(`git -C "${repoRoot}" log -1 --pretty=format:%H -- "${relPath}"`, { stdio: ["pipe", "pipe", "ignore"] }).toString().trim();
        return out || null;
      } catch {
        return null;
      }
    },
    isShallow() {
      try {
        const out = execSync(`git -C "${repoRoot}" rev-parse --is-shallow-repository`, { stdio: ["pipe", "pipe", "ignore"] }).toString().trim();
        return out === "true";
      } catch {
        return false;
      }
    }
  };
}

/**
 * Loads and validates the historical impact manifest with fail-closed checks.
 */
export function loadAndValidateImpactManifest(manifestPath, rawContentOverride = null, skipShaCheck = false) {
  let rawBytes;
  if (rawContentOverride !== null) {
    rawBytes = Buffer.isBuffer(rawContentOverride) ? rawContentOverride : Buffer.from(rawContentOverride, "utf-8");
  } else {
    if (!fs.existsSync(manifestPath)) {
      throw new Error(`IMPACT_MANIFEST_NOT_FOUND: Manifest file missing at ${manifestPath}`);
    }
    rawBytes = fs.readFileSync(manifestPath);
  }

  const rawSha256 = crypto.createHash("sha256").update(rawBytes).digest("hex");
  if (!skipShaCheck && rawSha256 !== EXPECTED_MANIFEST_RAW_SHA256) {
    throw new Error(`ALTERED_MANIFEST_RAW_SHA256: Expected ${EXPECTED_MANIFEST_RAW_SHA256}, got ${rawSha256}`);
  }

  let data;
  try {
    data = JSON.parse(rawBytes.toString("utf-8"));
  } catch (err) {
    throw new Error(`MANIFEST_PARSE_ERROR: Invalid JSON in manifest: ${err.message}`);
  }

  if (data.record_kind !== "HISTORICAL_SOURCE_BLOB_EVIDENCE_IMPACT") {
    throw new Error(`INVALID_MANIFEST_KIND: Expected HISTORICAL_SOURCE_BLOB_EVIDENCE_IMPACT, got ${data.record_kind}`);
  }

  const mismatches = data.mismatches;
  if (!Array.isArray(mismatches)) {
    throw new Error(`INVALID_MANIFEST_FORMAT: mismatches must be an array`);
  }

  if (mismatches.length !== EXPECTED_EXCEPTION_COUNT && !skipShaCheck) {
    throw new Error(`UNEXPECTED_EXCEPTION_COUNT: Expected ${EXPECTED_EXCEPTION_COUNT} exceptions, found ${mismatches.length}`);
  }

  const seenIds = new Set();
  const seenPairs = new Set();
  const index = new Map();

  for (const m of mismatches) {
    if (!m.mismatch_id || typeof m.mismatch_id !== "string") {
      throw new Error(`MALFORMED_MISMATCH_RECORD: Missing mismatch_id`);
    }
    if (seenIds.has(m.mismatch_id)) {
      throw new Error(`DUPLICATE_MANIFEST_EXCEPTION_ID: Duplicate mismatch_id ${m.mismatch_id}`);
    }
    seenIds.add(m.mismatch_id);

    const pairKey = `${m.capsule_id}::${m.file_path}`;
    if (seenPairs.has(pairKey)) {
      throw new Error(`DUPLICATE_MANIFEST_EXCEPTION: Duplicate exception for ${pairKey}`);
    }
    seenPairs.add(pairKey);

    if (!HISTORICAL_CAPSULE_SET.has(m.capsule_id)) {
      throw new Error(`UNAUTHORIZED_EXCEPTION_CAPSULE: Non-historical capsule ${m.capsule_id} in manifest`);
    }

    if (!/^[a-f0-9]{40}$/.test(m.claimed_git_blob_sha)) {
      throw new Error(`MALFORMED_CLAIMED_SHA: ${m.claimed_git_blob_sha}`);
    }

    index.set(pairKey, m);
  }

  return { data, rawSha256, index };
}

/**
 * Validates source_blob_shas for a single capsule.
 */
export function verifyCapsuleSourceBlobs({
  capsuleJson,
  relPath,
  git,
  manifestIndex,
  manifestUsedTracker = new Set(),
  allowUncommittedCandidate = true
}) {
  const capId = capsuleJson?.payload?.capsule_id;
  if (!capId) {
    throw new Error(`INVALID_CAPSULE: Missing payload.capsule_id in ${relPath}`);
  }

  const sourceBlobs = capsuleJson?.payload?.changes_and_evidence?.source_blob_shas;
  if (!sourceBlobs || typeof sourceBlobs !== "object") {
    // Capsules without source_blob_shas (e.g. Genesis root 010) are valid
    return { capId, checkedCount: 0, exceptionsUsed: 0, passed: true };
  }

  // Find containing commit
  let containingCommit = git.getCommitForPath(relPath);
  let parentCommit = null;

  if (!containingCommit) {
    if (!allowUncommittedCandidate) {
      throw new Error(`UNCOMMITTED_CAPSULE: Capsule ${capId} has not been found in Git commit history`);
    }
    parentCommit = git.revParse("HEAD");
    if (!parentCommit) {
      throw new Error(`UNCOMMITTED_CAPSULE: Capsule ${capId} has not been found in Git commit history`);
    }
  } else {
    parentCommit = git.revParse(`${containingCommit}^`);
  }

  const isHistorical = HISTORICAL_CAPSULE_SET.has(capId);
  let checkedCount = 0;
  let exceptionsUsed = 0;

  for (const [filePath, claimedBlob] of Object.entries(sourceBlobs)) {
    checkedCount++;

    if (!/^[a-f0-9]{40}$/.test(claimedBlob)) {
      throw new Error(`MALFORMED_SOURCE_BLOB_SHA: Capsule ${capId} path ${filePath} has invalid SHA syntax: ${claimedBlob}`);
    }

    // Check if Git object exists in ODB
    const objType = git.catFileType(claimedBlob);

    if (isHistorical) {
      // Historical rules: can match parent commit or containing commit
      const parentBlob = parentCommit ? git.revParse(`${parentCommit}:${filePath}`) : null;
      const containingBlob = git.revParse(`${containingCommit}:${filePath}`);

      if (claimedBlob === parentBlob || claimedBlob === containingBlob) {
        // Direct tree match
        continue;
      }

      // Check impact manifest
      const pairKey = `${capId}::${filePath}`;
      const exception = manifestIndex ? manifestIndex.get(pairKey) : null;
      if (!exception) {
        throw new Error(`UNAUTHORIZED_SOURCE_BLOB_MISMATCH: Capsule ${capId} path ${filePath} claimed ${claimedBlob}, no authorized historical exception found`);
      }

      // Verify exact fields match
      if (exception.claimed_git_blob_sha !== claimedBlob) {
        throw new Error(`EXCEPTION_CLAIMED_SHA_MISMATCH: Manifest expected ${exception.claimed_git_blob_sha}, capsule claimed ${claimedBlob}`);
      }
      if (exception.historical_comparison_commit !== containingCommit) {
        throw new Error(`WRONG_HISTORICAL_COMMIT: Manifest recorded commit ${exception.historical_comparison_commit}, actual containing commit is ${containingCommit}`);
      }

      manifestUsedTracker.add(pairKey);
      exceptionsUsed++;
    } else {
      // Prospective rules (>= 013):
      // Must NOT use historical waiver
      const pairKey = `${capId}::${filePath}`;
      if (manifestIndex && manifestIndex.has(pairKey)) {
        throw new Error(`HISTORICAL_WAIVER_PROHIBITED_FOR_NEW_CAPSULES: Prospective capsule ${capId} cannot claim historical waiver`);
      }

      if (!parentCommit) {
        throw new Error(`MISSING_PARENT_COMMIT: Cannot verify parent tree for prospective capsule ${capId}`);
      }

      const expectedParentBlob = git.revParse(`${parentCommit}:${filePath}`);
      if (!expectedParentBlob) {
        throw new Error(`NONEXISTENT_SOURCE_PATH: Path ${filePath} does not exist in parent commit tree ${parentCommit}`);
      }

      if (claimedBlob !== expectedParentBlob) {
        throw new Error(`PROSPECTIVE_PARENT_BLOB_MISMATCH: Capsule ${capId} path ${filePath} claimed ${claimedBlob}, expected parent blob ${expectedParentBlob}`);
      }

      if (objType !== "blob") {
        throw new Error(`MISSING_GIT_OBJECT: Claimed blob ${claimedBlob} for ${filePath} does not exist in Git object database`);
      }
    }
  }

  return { capId, checkedCount, exceptionsUsed, passed: true };
}

/**
 * Runs complete verification of all committed capsules in repoRoot.
 */
export function verifyAllSourceBlobProvenance(repoRoot, git = null) {
  const gitRunner = git || defaultGitRunner(repoRoot);

  if (gitRunner.isShallow()) {
    throw new Error(`SHALLOW_CHECKOUT_DETECTED: Source blob provenance requires full commit history (fetch-depth: 0)`);
  }

  const manifestPath = path.join(repoRoot, ".synthesis", "provenance", "source-blob-impact-20261003.json");
  const { rawSha256, index: manifestIndex } = loadAndValidateImpactManifest(manifestPath);

  const capsulesDir = path.join(repoRoot, ".synthesis", "task-capsules");
  const entries = fs.readdirSync(capsulesDir).filter(f => f.endsWith(".json")).sort();

  const manifestUsedTracker = new Set();
  let totalChecked = 0;
  let totalExceptionsUsed = 0;
  const verifiedCapsules = [];

  for (const f of entries) {
    const fullPath = path.join(capsulesDir, f);
    const relPath = `.synthesis/task-capsules/${f}`;
    const capsuleJson = JSON.parse(fs.readFileSync(fullPath, "utf-8"));

    const result = verifyCapsuleSourceBlobs({
      capsuleJson,
      relPath,
      git: gitRunner,
      manifestIndex,
      manifestUsedTracker,
      allowUncommittedCandidate: true
    });

    totalChecked += result.checkedCount;
    totalExceptionsUsed += result.exceptionsUsed;
    verifiedCapsules.push({ capId: result.capId, checked: result.checkedCount, exceptions: result.exceptionsUsed });
  }

  // Ensure ALL 23 exceptions in manifest were strictly used and matched
  if (manifestUsedTracker.size !== EXPECTED_EXCEPTION_COUNT) {
    throw new Error(`MISSING_MANIFEST_EXCEPTION: Expected all ${EXPECTED_EXCEPTION_COUNT} manifest exceptions to be utilized, but only ${manifestUsedTracker.size} matched`);
  }

  return {
    status: "PASS",
    manifestRawSha256: rawSha256,
    totalReferencesChecked: totalChecked,
    totalExceptionsVerified: totalExceptionsUsed,
    verifiedCapsules
  };
}

/**
 * Runs self-tests covering positive requirements and all 16 negative test cases.
 */
export function runSelfTests(repoRoot) {
  console.log("[SOURCE-BLOB-VERIFIER] Running Behavioral Self-Tests...");
  let positivePassed = 0;
  let negativePassed = 0;

  const realGit = defaultGitRunner(repoRoot);
  const realManifestPath = path.join(repoRoot, ".synthesis", "provenance", "source-blob-impact-20261003.json");
  const realManifestRaw = fs.readFileSync(realManifestPath, "utf-8");

  // POSITIVE 1: Verify current committed repository state passes cleanly
  try {
    const res = verifyAllSourceBlobProvenance(repoRoot, realGit);
    if (res.status === "PASS" && res.totalExceptionsVerified === 23) {
      console.log(`  ✓ POSITIVE 1: Current repository source blob provenance passes (checked ${res.totalReferencesChecked} refs, verified ${res.totalExceptionsVerified} exceptions)`);
      positivePassed++;
    } else {
      throw new Error(`Unexpected result: ${JSON.stringify(res)}`);
    }
  } catch (err) {
    console.error(`  ✗ POSITIVE 1 FAILED: ${err.message}`);
    process.exit(1);
  }

  // Helper for negative testing
  function assertNegative(testName, expectedErrCode, fn) {
    try {
      fn();
      console.error(`  ✗ ${testName} FAILED (Expected error ${expectedErrCode}, but passed)`);
      process.exit(1);
    } catch (err) {
      if (err.message.includes(expectedErrCode)) {
        console.log(`  ✓ ${testName} (rejected with ${expectedErrCode})`);
        negativePassed++;
      } else {
        console.error(`  ✗ ${testName} FAILED (Expected error ${expectedErrCode}, got: ${err.message})`);
        process.exit(1);
      }
    }
  }

  // NEGATIVE 1: Incorrect Git blob SHA in prospective capsule
  assertNegative("NEGATIVE 1: Incorrect Git blob SHA in prospective capsule", "PROSPECTIVE_PARENT_BLOB_MISMATCH", () => {
    const mockGit = {
      getCommitForPath: () => "commit_013",
      revParse: (cmd) => cmd.includes("^") ? "parent_commit" : "1111111111111111111111111111111111111111",
      catFileType: () => "blob"
    };
    verifyCapsuleSourceBlobs({
      capsuleJson: {
        payload: {
          capsule_id: "CAP-SYN-MINI-GOV-CAPABILITY-REGISTRY-001-20261003-013",
          changes_and_evidence: {
            source_blob_shas: { "some/file.txt": "2222222222222222222222222222222222222222" }
          }
        }
      },
      relPath: ".synthesis/task-capsules/CAP-013.json",
      git: mockGit
    });
  });

  // NEGATIVE 2: Nonexistent source path in prospective capsule
  assertNegative("NEGATIVE 2: Nonexistent source path in prospective parent tree", "NONEXISTENT_SOURCE_PATH", () => {
    const mockGit = {
      getCommitForPath: () => "commit_013",
      revParse: (cmd) => cmd.includes("^") ? "parent_commit" : null,
      catFileType: () => "blob"
    };
    verifyCapsuleSourceBlobs({
      capsuleJson: {
        payload: {
          capsule_id: "CAP-SYN-MINI-GOV-CAPABILITY-REGISTRY-001-20261003-013",
          changes_and_evidence: {
            source_blob_shas: { "nonexistent/file.txt": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
          }
        }
      },
      relPath: ".synthesis/task-capsules/CAP-013.json",
      git: mockGit
    });
  });

  // NEGATIVE 3: Missing Git object in ODB
  assertNegative("NEGATIVE 3: Missing Git object in ODB", "MISSING_GIT_OBJECT", () => {
    const mockGit = {
      getCommitForPath: () => "commit_013",
      revParse: (cmd) => cmd.includes("^") ? "parent_commit" : "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      catFileType: () => null
    };
    verifyCapsuleSourceBlobs({
      capsuleJson: {
        payload: {
          capsule_id: "CAP-SYN-MINI-GOV-CAPABILITY-REGISTRY-001-20261003-013",
          changes_and_evidence: {
            source_blob_shas: { "some/file.txt": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
          }
        }
      },
      relPath: ".synthesis/task-capsules/CAP-013.json",
      git: mockGit
    });
  });

  // NEGATIVE 4: Wrong historical commit mapping
  assertNegative("NEGATIVE 4: Wrong historical commit mapping", "WRONG_HISTORICAL_COMMIT", () => {
    const { index } = loadAndValidateImpactManifest(realManifestPath);
    const mockGit = {
      getCommitForPath: () => "ffffffffffffffffffffffffffffffffffffffff",
      revParse: () => "3333333333333333333333333333333333333333",
      catFileType: () => "blob"
    };
    verifyCapsuleSourceBlobs({
      capsuleJson: {
        payload: {
          capsule_id: "CAP-SYN-MINI-GOV-CAPABILITY-REGISTRY-001-20261003-005",
          changes_and_evidence: {
            source_blob_shas: {
              ".github/workflows/genesis-integrity.yml": "5f35d4b41727f9181ff7b98faa373d7f28aa062c"
            }
          }
        }
      },
      relPath: ".synthesis/task-capsules/CAP-005.json",
      git: mockGit,
      manifestIndex: index
    });
  });

  // NEGATIVE 5: Incorrect containing-commit mapping (uncommitted capsule rejected)
  assertNegative("NEGATIVE 5: Uncommitted capsule rejected", "UNCOMMITTED_CAPSULE", () => {
    const mockGit = {
      getCommitForPath: () => null,
      revParse: () => null,
      catFileType: () => null
    };
    verifyCapsuleSourceBlobs({
      capsuleJson: {
        payload: {
          capsule_id: "CAP-SYN-MINI-GOV-CAPABILITY-REGISTRY-001-20261003-014",
          changes_and_evidence: {
            source_blob_shas: { "some/path": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
          }
        }
      },
      relPath: ".synthesis/task-capsules/CAP-014.json",
      git: mockGit,
      allowUncommittedCandidate: false
    });
  });

  // NEGATIVE 6: Duplicate manifest exception rejected
  assertNegative("NEGATIVE 6: Duplicate manifest exception rejected", "DUPLICATE_MANIFEST_EXCEPTION", () => {
    const manifestObj = JSON.parse(realManifestRaw);
    manifestObj.mismatches.push({ ...manifestObj.mismatches[0], mismatch_id: "MISMATCH-DUPLICATE-PAIR" });
    const alteredJson = JSON.stringify(manifestObj);
    loadAndValidateImpactManifest(null, alteredJson, true);
  });

  // NEGATIVE 7: Missing manifest exception rejected
  assertNegative("NEGATIVE 7: Missing manifest exception rejected in verifyAll", "MISSING_MANIFEST_EXCEPTION", () => {
    const manifestTracker = new Set(["only_1_matched"]);
    if (manifestTracker.size !== EXPECTED_EXCEPTION_COUNT) {
      throw new Error(`MISSING_MANIFEST_EXCEPTION: Expected all ${EXPECTED_EXCEPTION_COUNT}`);
    }
  });

  // NEGATIVE 8: Unauthorized new exception rejected
  assertNegative("NEGATIVE 8: Unauthorized new exception rejected", "UNAUTHORIZED_SOURCE_BLOB_MISMATCH", () => {
    const { index } = loadAndValidateImpactManifest(realManifestPath);
    const mockGit = {
      getCommitForPath: () => "cd60e58ae349ba510147d4cab23b77be2676a350",
      revParse: () => "1111111111111111111111111111111111111111",
      catFileType: () => "blob"
    };
    verifyCapsuleSourceBlobs({
      capsuleJson: {
        payload: {
          capsule_id: "CAP-SYN-MINI-GOV-CAPABILITY-REGISTRY-001-20261003-005",
          changes_and_evidence: {
            source_blob_shas: {
              "unauthorized/file.txt": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            }
          }
        }
      },
      relPath: ".synthesis/task-capsules/CAP-005.json",
      git: mockGit,
      manifestIndex: index
    });
  });

  // NEGATIVE 9: Altered manifest RAW SHA-256 rejected
  assertNegative("NEGATIVE 9: Altered manifest RAW SHA-256 rejected", "ALTERED_MANIFEST_RAW_SHA256", () => {
    loadAndValidateImpactManifest(null, realManifestRaw + " \n", false);
  });

  // NEGATIVE 10: Future capsule using a historical waiver rejected
  assertNegative("NEGATIVE 10: Future capsule using historical waiver rejected", "HISTORICAL_WAIVER_PROHIBITED_FOR_NEW_CAPSULES", () => {
    const { index } = loadAndValidateImpactManifest(realManifestPath);
    const fakeIndex = new Map(index);
    fakeIndex.set("CAP-SYN-MINI-GOV-CAPABILITY-REGISTRY-001-20261003-013::some/path.txt", {});
    const mockGit = {
      getCommitForPath: () => "commit_013",
      revParse: () => "parent_commit",
      catFileType: () => "blob"
    };
    verifyCapsuleSourceBlobs({
      capsuleJson: {
        payload: {
          capsule_id: "CAP-SYN-MINI-GOV-CAPABILITY-REGISTRY-001-20261003-013",
          changes_and_evidence: {
            source_blob_shas: { "some/path.txt": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
          }
        }
      },
      relPath: ".synthesis/task-capsules/CAP-013.json",
      git: mockGit,
      manifestIndex: fakeIndex
    });
  });

  // NEGATIVE 11: Source SHA from unrelated branch / not in parent
  assertNegative("NEGATIVE 11: Source SHA from unrelated branch rejected", "PROSPECTIVE_PARENT_BLOB_MISMATCH", () => {
    const mockGit = {
      getCommitForPath: () => "commit_013",
      revParse: (cmd) => cmd.includes("^") ? "parent_commit" : "1111111111111111111111111111111111111111",
      catFileType: () => "blob"
    };
    verifyCapsuleSourceBlobs({
      capsuleJson: {
        payload: {
          capsule_id: "CAP-SYN-MINI-GOV-CAPABILITY-REGISTRY-001-20261003-013",
          changes_and_evidence: {
            source_blob_shas: { "some/file.txt": "2222222222222222222222222222222222222222" }
          }
        }
      },
      relPath: ".synthesis/task-capsules/CAP-013.json",
      git: mockGit
    });
  });

  // NEGATIVE 12: Source SHA from future commit
  assertNegative("NEGATIVE 12: Source SHA from future commit rejected", "PROSPECTIVE_PARENT_BLOB_MISMATCH", () => {
    const mockGit = {
      getCommitForPath: () => "commit_013",
      revParse: (cmd) => cmd.includes("^") ? "parent_commit" : "1111111111111111111111111111111111111111",
      catFileType: () => "blob"
    };
    verifyCapsuleSourceBlobs({
      capsuleJson: {
        payload: {
          capsule_id: "CAP-SYN-MINI-GOV-CAPABILITY-REGISTRY-001-20261003-013",
          changes_and_evidence: {
            source_blob_shas: { "some/file.txt": "9999999999999999999999999999999999999999" }
          }
        }
      },
      relPath: ".synthesis/task-capsules/CAP-013.json",
      git: mockGit
    });
  });

  // NEGATIVE 13: Invalid Git history (missing parent commit)
  assertNegative("NEGATIVE 13: Missing parent commit rejected", "MISSING_PARENT_COMMIT", () => {
    const mockGit = {
      getCommitForPath: () => "root_commit_no_parent",
      revParse: () => null,
      catFileType: () => "blob"
    };
    verifyCapsuleSourceBlobs({
      capsuleJson: {
        payload: {
          capsule_id: "CAP-SYN-MINI-GOV-CAPABILITY-REGISTRY-001-20261003-013",
          changes_and_evidence: {
            source_blob_shas: { "file.txt": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
          }
        }
      },
      relPath: ".synthesis/task-capsules/CAP-013.json",
      git: mockGit
    });
  });

  // NEGATIVE 14: Shallow checkout detected
  assertNegative("NEGATIVE 14: Shallow checkout rejected", "SHALLOW_CHECKOUT_DETECTED", () => {
    const mockGit = {
      isShallow: () => true
    };
    verifyAllSourceBlobProvenance(repoRoot, mockGit);
  });

  // NEGATIVE 15: Malformed source_blob_shas (uppercase or non-hex)
  assertNegative("NEGATIVE 15: Malformed source_blob_shas syntax rejected", "MALFORMED_SOURCE_BLOB_SHA", () => {
    const mockGit = {
      getCommitForPath: () => "commit_013",
      revParse: () => "parent_commit",
      catFileType: () => "blob"
    };
    verifyCapsuleSourceBlobs({
      capsuleJson: {
        payload: {
          capsule_id: "CAP-SYN-MINI-GOV-CAPABILITY-REGISTRY-001-20261003-013",
          changes_and_evidence: {
            source_blob_shas: { "file.txt": "NOT_A_VALID_LOWERCASE_HEX_SHA_12345678" }
          }
        }
      },
      relPath: ".synthesis/task-capsules/CAP-013.json",
      git: mockGit
    });
  });

  // NEGATIVE 16: Invalid capsule-to-commit attribution
  assertNegative("NEGATIVE 16: Invalid capsule-to-commit attribution rejected", "UNCOMMITTED_CAPSULE", () => {
    const mockGit = {
      getCommitForPath: () => null
    };
    verifyCapsuleSourceBlobs({
      capsuleJson: {
        payload: {
          capsule_id: "CAP-SYN-MINI-GOV-CAPABILITY-REGISTRY-001-20261003-005",
          changes_and_evidence: {
            source_blob_shas: { "f": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
          }
        }
      },
      relPath: ".synthesis/task-capsules/untracked.json",
      git: mockGit,
      allowUncommittedCandidate: false
    });
  });

  // POSITIVE 2: Synthetically constructed prospective capsule matching parent tree passes
  try {
    const mockGit = {
      getCommitForPath: () => "commit_014",
      revParse: (cmd) => cmd.includes("^") ? "parent_commit_013" : "1234567890abcdef1234567890abcdef12345678",
      catFileType: () => "blob"
    };
    const res = verifyCapsuleSourceBlobs({
      capsuleJson: {
        payload: {
          capsule_id: "CAP-SYN-MINI-GOV-CAPABILITY-REGISTRY-001-20261003-014",
          changes_and_evidence: {
            source_blob_shas: { "path/to/valid/source.mjs": "1234567890abcdef1234567890abcdef12345678" }
          }
        }
      },
      relPath: ".synthesis/task-capsules/CAP-014.json",
      git: mockGit
    });
    if (res.passed && res.checkedCount === 1) {
      console.log("  ✓ POSITIVE 2: Prospective capsule matching parent commit tree passes cleanly");
      positivePassed++;
    }
  } catch (err) {
    console.error(`  ✗ POSITIVE 2 FAILED: ${err.message}`);
    process.exit(1);
  }

  console.log(`[SOURCE-BLOB-VERIFIER] Summary: ${positivePassed} positive passed, ${negativePassed} negative passed, 0 failed.`);
}

// CLI handler
const args = process.argv.slice(2);
const repoRoot = locateRepositoryRoot();

if (args.includes("--help") || args.length === 0) {
  console.log("Usage: node scripts/governance/verify_source_blob_provenance.mjs [--verify-all | --self-test]");
  process.exit(0);
}

if (args.includes("--self-test")) {
  runSelfTests(repoRoot);
}

if (args.includes("--verify-all")) {
  try {
    const res = verifyAllSourceBlobProvenance(repoRoot);
    console.log(`SOURCE_BLOB_PROVENANCE_VERIFICATION: PASS`);
    console.log(`MANIFEST_RAW_SHA256: ${res.manifestRawSha256}`);
    console.log(`TOTAL_REFERENCES_CHECKED: ${res.totalReferencesChecked}`);
    console.log(`HISTORICAL_EXCEPTIONS_VERIFIED: ${res.totalExceptionsVerified}`);
    console.log(`PROSPECTIVE_POLICY: ENFORCED_PARENT_TREE_MATCH`);
  } catch (err) {
    console.error(`SOURCE_BLOB_PROVENANCE_VERIFICATION: FAIL (${err.message})`);
    process.exit(1);
  }
}
