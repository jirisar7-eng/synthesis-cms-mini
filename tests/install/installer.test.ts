/// <reference types="node" />
/**
 * Synthesis CMS mini — Clean-Install / Bootstrap Framework Unit Tests
 *
 * Scenarios:
 * - Deterministic stage progression (PREFLIGHT -> ... -> COMPLETE)
 * - Truthful zero migration execution handling (NO_MIGRATIONS_TO_APPLY)
 * - Zero bootstrap participants completion
 * - Deterministic bootstrap participants ordering (order asc, then id asc)
 * - Multi-participant execution chain
 * - Preflight failure when dependencies are invalid
 * - Configuration validation failure
 * - Database probe failure
 * - Migration execution failure
 * - Duplicate participant ID detection failure
 * - Non-finite order participant failure
 * - Participant execution failure
 * - Installer self-check failure
 * - Secret credentials redaction in error messages
 * - Prisma CLI adapter validation & probing
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  type BootstrapParticipant,
  type InstallDependencies,
  extractSecretsFromDatabaseUrl,
  runCleanInstall,
} from "../../core/src/install/installer.ts";
import {
  applyMigrationsWithPrisma,
  getFilesystemMigrationCount,
  probeDatabaseWithPrisma,
  validateDatabaseConfig,
} from "../../core/src/install/prisma-cli.ts";

const validMockDbUrl =
  "postgresql://synthesis_user:synthesis_fixture_pass@localhost:5432/synthesis_db";

function createValidDependencies(overrides?: Partial<InstallDependencies>): InstallDependencies {
  return {
    validateConfig: (env) => ({
      valid: true,
      databaseUrl: env.SYNTHESIS_SECRET_DATABASE_URL ?? validMockDbUrl,
    }),
    probeDatabase: () => Promise.resolve({ ready: true }),
    getMigrationCount: () => 0,
    applyMigrations: () =>
      Promise.resolve({
        count: 0,
        applied: true,
        result: "NO_MIGRATIONS_TO_APPLY",
      }),
    bootstrapParticipants: [],
    selfCheck: () => ({ ok: true }),
    ...overrides,
  };
}

void describe("Clean-Install / Bootstrap Framework Unit Tests", () => {
  void it("1. Successfully executes clean install with zero migrations and zero participants", async () => {
    const deps = createValidDependencies();
    const env = { SYNTHESIS_SECRET_DATABASE_URL: validMockDbUrl };

    const result = await runCleanInstall(env, deps);

    assert.equal(result.status, "SUCCESS");
    assert.equal(result.stage, "COMPLETE");
    assert.deepEqual(result.migrationResult, {
      count: 0,
      result: "NO_MIGRATIONS_TO_APPLY",
    });
    assert.equal(result.participantsExecuted, 0);
    assert.equal(result.error, undefined);
  });

  void it("2. Successfully applies migrations when migration count > 0", async () => {
    const deps = createValidDependencies({
      getMigrationCount: () => 3,
      applyMigrations: () =>
        Promise.resolve({
          count: 3,
          applied: true,
          result: "MIGRATIONS_APPLIED",
        }),
    });
    const env = { SYNTHESIS_SECRET_DATABASE_URL: validMockDbUrl };

    const result = await runCleanInstall(env, deps);

    assert.equal(result.status, "SUCCESS");
    assert.equal(result.stage, "COMPLETE");
    assert.deepEqual(result.migrationResult, {
      count: 3,
      result: "MIGRATIONS_APPLIED",
    });
    assert.equal(result.participantsExecuted, 0);
  });

  void it("3. Executes bootstrap participants in deterministic order (order ascending, then id ascending)", async () => {
    const executionLog: string[] = [];

    const participants: BootstrapParticipant[] = [
      {
        id: "participant-z",
        name: "Participant Z",
        order: 20,
        execute: () => {
          executionLog.push("participant-z");
          return Promise.resolve({ ok: true });
        },
      },
      {
        id: "participant-b",
        name: "Participant B",
        order: 10,
        execute: () => {
          executionLog.push("participant-b");
          return Promise.resolve({ ok: true });
        },
      },
      {
        id: "participant-a",
        name: "Participant A",
        order: 10,
        execute: () => {
          executionLog.push("participant-a");
          return Promise.resolve({ ok: true });
        },
      },
    ];

    const deps = createValidDependencies({
      bootstrapParticipants: participants,
    });
    const env = { SYNTHESIS_SECRET_DATABASE_URL: validMockDbUrl };

    const result = await runCleanInstall(env, deps);

    assert.equal(result.status, "SUCCESS");
    assert.equal(result.stage, "COMPLETE");
    assert.equal(result.participantsExecuted, 3);
    // order 10: a before b (tie-break by id), then order 20: z
    assert.deepEqual(executionLog, ["participant-a", "participant-b", "participant-z"]);
  });

  void it("4. Fails closed during PREFLIGHT when dependencies are malformed", async () => {
    const invalidDeps = {} as unknown as InstallDependencies;
    const env = { SYNTHESIS_SECRET_DATABASE_URL: validMockDbUrl };

    const result = await runCleanInstall(env, invalidDeps);

    assert.equal(result.status, "FAILED");
    assert.equal(result.stage, "PREFLIGHT");
    assert.match(result.error ?? "", /PREFLIGHT_FAILURE/);
  });

  void it("5. Fails closed during CONFIG_VALIDATED when configuration is invalid", async () => {
    const deps = createValidDependencies({
      validateConfig: () => ({ valid: false, error: "Invalid URI scheme" }),
    });
    const env = { SYNTHESIS_SECRET_DATABASE_URL: "invalid-url" };

    const result = await runCleanInstall(env, deps);

    assert.equal(result.status, "FAILED");
    assert.equal(result.stage, "CONFIG_VALIDATED");
    assert.match(result.error ?? "", /CONFIG_VALIDATION_FAILURE.*Invalid URI scheme/);
  });

  void it("6. Fails closed during DATABASE_READY when database probe fails", async () => {
    const deps = createValidDependencies({
      probeDatabase: () => Promise.resolve({ ready: false, error: "Connection refused at 5432" }),
    });
    const env = { SYNTHESIS_SECRET_DATABASE_URL: validMockDbUrl };

    const result = await runCleanInstall(env, deps);

    assert.equal(result.status, "FAILED");
    assert.equal(result.stage, "DATABASE_READY");
    assert.match(result.error ?? "", /DATABASE_READY_FAILURE.*Connection refused/);
  });

  void it("7. Fails closed during MIGRATIONS_APPLIED when forward migrations fail", async () => {
    const deps = createValidDependencies({
      getMigrationCount: () => 1,
      applyMigrations: () =>
        Promise.resolve({
          applied: false,
          error: "Migration failed at P3009",
        }),
    });
    const env = { SYNTHESIS_SECRET_DATABASE_URL: validMockDbUrl };

    const result = await runCleanInstall(env, deps);

    assert.equal(result.status, "FAILED");
    assert.equal(result.stage, "MIGRATIONS_APPLIED");
    assert.match(result.error ?? "", /MIGRATION_EXECUTION_FAILURE.*Migration failed/);
  });

  void it("8. Fails closed when duplicate bootstrap participant IDs are detected", async () => {
    const participants: BootstrapParticipant[] = [
      {
        id: "duplicate-id",
        name: "First Instance",
        order: 10,
        execute: () => Promise.resolve({ ok: true }),
      },
      {
        id: "duplicate-id",
        name: "Second Instance",
        order: 20,
        execute: () => Promise.resolve({ ok: true }),
      },
    ];

    const deps = createValidDependencies({
      bootstrapParticipants: participants,
    });
    const env = { SYNTHESIS_SECRET_DATABASE_URL: validMockDbUrl };

    const result = await runCleanInstall(env, deps);

    assert.equal(result.status, "FAILED");
    assert.equal(result.stage, "BOOTSTRAP_PARTICIPANTS_COMPLETE");
    assert.match(result.error ?? "", /Duplicate participant id "duplicate-id"/);
  });

  void it("9. Fails closed when bootstrap participant has non-finite order", async () => {
    const participants: BootstrapParticipant[] = [
      {
        id: "invalid-order",
        name: "Bad Order",
        order: Number.NaN,
        execute: () => Promise.resolve({ ok: true }),
      },
    ];

    const deps = createValidDependencies({
      bootstrapParticipants: participants,
    });
    const env = { SYNTHESIS_SECRET_DATABASE_URL: validMockDbUrl };

    const result = await runCleanInstall(env, deps);

    assert.equal(result.status, "FAILED");
    assert.equal(result.stage, "BOOTSTRAP_PARTICIPANTS_COMPLETE");
    assert.match(result.error ?? "", /Invalid non-finite order/);
  });

  void it("10. Fails closed when a bootstrap participant returns failure or throws", async () => {
    const participants: BootstrapParticipant[] = [
      {
        id: "failing-participant",
        name: "Fails gracefully",
        order: 10,
        execute: () =>
          Promise.resolve({
            ok: false,
            error: "Participant assertion failed",
          }),
      },
    ];

    const deps = createValidDependencies({
      bootstrapParticipants: participants,
    });
    const env = { SYNTHESIS_SECRET_DATABASE_URL: validMockDbUrl };

    const result = await runCleanInstall(env, deps);

    assert.equal(result.status, "FAILED");
    assert.equal(result.stage, "BOOTSTRAP_PARTICIPANTS_COMPLETE");
    assert.match(result.error ?? "", /Participant assertion failed/);
  });

  void it("11. Fails closed when installer self-check fails", async () => {
    const deps = createValidDependencies({
      selfCheck: () => ({ ok: false, error: "State consistency check failed" }),
    });
    const env = { SYNTHESIS_SECRET_DATABASE_URL: validMockDbUrl };

    const result = await runCleanInstall(env, deps);

    assert.equal(result.status, "FAILED");
    assert.equal(result.stage, "SELF_CHECK_PASS");
    assert.match(result.error ?? "", /SELF_CHECK_FAILURE.*State consistency check failed/);
  });

  void it("12. Redacts sensitive credentials (password and full URL) from error output", async () => {
    const secretPassword = "super_secret_pw";
    const sensitiveDbUrl = `postgresql://user:${secretPassword}@127.0.0.1:5432/db`;
    const deps = createValidDependencies({
      probeDatabase: () =>
        Promise.resolve({
          ready: false,
          error: `Authentication failed for connection ${sensitiveDbUrl} with password ${secretPassword}`,
        }),
    });
    const env = { SYNTHESIS_SECRET_DATABASE_URL: sensitiveDbUrl };

    const result = await runCleanInstall(env, deps);

    assert.equal(result.status, "FAILED");
    const errText = result.error ?? "";
    assert.equal(errText.includes(secretPassword), false);
    assert.equal(errText.includes(sensitiveDbUrl), false);
    assert.match(errText, /\[REDACTED\]/);
  });

  void it("13. Tests prisma-cli adapter validateDatabaseConfig with valid and invalid input", () => {
    const validRes = validateDatabaseConfig({
      SYNTHESIS_SECRET_DATABASE_URL: validMockDbUrl,
    });
    assert.equal(validRes.valid, true);
    assert.equal(validRes.databaseUrl, validMockDbUrl);

    const invalidRes = validateDatabaseConfig({
      SYNTHESIS_SECRET_DATABASE_URL: "invalid://uri",
    });
    assert.equal(invalidRes.valid, false);
    assert.ok(invalidRes.error);
  });

  void it("14. Tests prisma-cli adapter getFilesystemMigrationCount with non-existent directory", () => {
    const count = getFilesystemMigrationCount("/tmp/non_existent_migrations_dir_12345");
    assert.equal(count, 0);
  });

  void it("15. Tests prisma-cli adapter probeDatabaseWithPrisma success and failure", async () => {
    const successRunner = () =>
      Promise.resolve({
        exitCode: 0,
        stdout: "1 row returned\n",
        stderr: "",
      });
    const probeOk = await probeDatabaseWithPrisma(validMockDbUrl, successRunner);
    assert.equal(probeOk.ready, true);

    const failRunner = () =>
      Promise.resolve({
        exitCode: 1,
        stdout: "",
        stderr: `Error connecting to ${validMockDbUrl}: timeout`,
      });
    const probeFail = await probeDatabaseWithPrisma(validMockDbUrl, failRunner);
    assert.equal(probeFail.ready, false);
    const probeErr = probeFail.error ?? "";
    assert.equal(probeErr.includes("super_secret_pw"), false);
    assert.match(probeErr, /\[REDACTED\]/);
  });

  void it("16. Tests prisma-cli adapter applyMigrationsWithPrisma success and failure", async () => {
    const successRunner = () =>
      Promise.resolve({
        exitCode: 0,
        stdout: "No migrations to apply\n",
        stderr: "",
      });
    const applyOk = await applyMigrationsWithPrisma(validMockDbUrl, successRunner);
    assert.equal(applyOk.applied, true);

    const failRunner = () =>
      Promise.resolve({
        exitCode: 1,
        stdout: "",
        stderr: `Fatal migration error with ${validMockDbUrl}`,
      });
    const applyFail = await applyMigrationsWithPrisma(validMockDbUrl, failRunner);
    assert.equal(applyFail.applied, false);
    const applyErr = applyFail.error ?? "";
    assert.equal(applyErr.includes("super_secret_pw"), false);
    assert.match(applyErr, /\[REDACTED\]/);
  });
  void it("17. Fails closed when migration count is invalid (negative, fractional, NaN, Infinity)", async () => {
    const invalidCounts = [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY];

    for (const count of invalidCounts) {
      let applyCalled = false;
      const deps = createValidDependencies({
        getMigrationCount: () => count,
        applyMigrations: () => {
          applyCalled = true;
          return Promise.resolve({ applied: true });
        },
      });
      const env = { SYNTHESIS_SECRET_DATABASE_URL: validMockDbUrl };

      const result = await runCleanInstall(env, deps);

      assert.equal(result.status, "FAILED");
      assert.equal(result.stage, "MIGRATIONS_APPLIED");
      assert.equal(
        applyCalled,
        false,
        `applyMigrations must not be called for invalid count: ${String(count)}`,
      );
      assert.match(
        result.error ?? "",
        /INVALID_MIGRATION_COUNT: Migration count must be a non-negative finite integer/,
      );
    }
  });

  void it("18. Finding 1 regression: migration discovery handles missing dirs and fails closed on unreadable/invalid paths", () => {
    // 18a. Missing directory => returns 0
    const nonExistentDir = path.join(
      os.tmpdir(),
      `non_existent_migrations_${String(Date.now())}_${String(Math.random())}`,
    );
    assert.equal(getFilesystemMigrationCount(nonExistentDir), 0);

    // 18b. Existing valid directory => returns exact migration count
    const validTmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "synthesis_valid_migrations_"));
    try {
      fs.mkdirSync(path.join(validTmpDir, "20261001_init"));
      fs.mkdirSync(path.join(validTmpDir, "20261002_add_table"));
      fs.writeFileSync(path.join(validTmpDir, "migration_lock.toml"), "lock file content");
      fs.mkdirSync(path.join(validTmpDir, ".hidden_dir"));

      const count = getFilesystemMigrationCount(validTmpDir);
      assert.equal(count, 2);
    } finally {
      fs.rmSync(validTmpDir, { recursive: true, force: true });
    }

    // 18c. Existing regular file => fails closed with MIGRATION_DISCOVERY_FAILED (ENOTDIR)
    const regularFilePath = new URL("../../package.json", import.meta.url).pathname;
    assert.throws(
      () => getFilesystemMigrationCount(regularFilePath),
      /MIGRATION_DISCOVERY_FAILED: Unable to read existing migrations directory/,
    );

    // 18d. Inaccessible parent / permission denied => fails closed with MIGRATION_DISCOVERY_FAILED (EACCES)
    // Deterministic simulation via readdirSyncFn injection so test does not depend on root UID
    const eaccesError = Object.assign(new Error("Permission denied"), { code: "EACCES" });
    assert.throws(
      () =>
        getFilesystemMigrationCount("/some/path", () => {
          throw eaccesError;
        }),
      /MIGRATION_DISCOVERY_FAILED: Unable to read existing migrations directory.*Permission denied/,
    );

    // 18e. Unexpected filesystem failure (e.g. ELOOP, EIO) => fails closed with MIGRATION_DISCOVERY_FAILED
    const eloopError = Object.assign(new Error("Too many symbolic links encountered"), {
      code: "ELOOP",
    });
    assert.throws(
      () =>
        getFilesystemMigrationCount("/some/path", () => {
          throw eloopError;
        }),
      /MIGRATION_DISCOVERY_FAILED: Unable to read existing migrations directory.*Too many symbolic links/,
    );
  });

  void it("19. Finding 2 regression: redacts full URL, encoded password, and decoded password across probe and apply", async () => {
    const rawEncodedPassword = "fixture_p%40ss";
    const decodedPassword = "fixture_p@ss";
    const sensitiveDbUrl = `postgresql://synthesis_user:${rawEncodedPassword}@127.0.0.1:5432/db`;

    // 19a. Full URL leakage in probe
    const probeFullUrlRunner = () =>
      Promise.resolve({
        exitCode: 1,
        stdout: "",
        stderr: `Connection refused for ${sensitiveDbUrl}`,
      });
    const probeRes1 = await probeDatabaseWithPrisma(sensitiveDbUrl, probeFullUrlRunner);
    assert.equal(probeRes1.ready, false);
    const err1 = probeRes1.error ?? "";
    assert.equal(err1.includes(sensitiveDbUrl), false);
    assert.equal(err1.includes(rawEncodedPassword), false);
    assert.equal(err1.includes(decodedPassword), false);
    assert.match(err1, /\[REDACTED\]/);

    // 19b. Encoded password only in probe
    const probeEncodedRunner = () =>
      Promise.resolve({
        exitCode: 1,
        stdout: "",
        stderr: `Auth failed for credentials with password: ${rawEncodedPassword}`,
      });
    const probeRes2 = await probeDatabaseWithPrisma(sensitiveDbUrl, probeEncodedRunner);
    assert.equal(probeRes2.ready, false);
    const err2 = probeRes2.error ?? "";
    assert.equal(err2.includes(rawEncodedPassword), false);
    assert.equal(err2.includes(decodedPassword), false);
    assert.match(err2, /\[REDACTED\]/);

    // 19c. Decoded password only in probe (Finding 2 exact bug scenario)
    const probeDecodedRunner = () =>
      Promise.resolve({
        exitCode: 1,
        stdout: "",
        stderr: `FATAL: password authentication failed for user synthesis_user with decoded password: ${decodedPassword}`,
      });
    const probeRes3 = await probeDatabaseWithPrisma(sensitiveDbUrl, probeDecodedRunner);
    assert.equal(probeRes3.ready, false);
    const err3 = probeRes3.error ?? "";
    assert.equal(err3.includes(decodedPassword), false);
    assert.equal(err3.includes(rawEncodedPassword), false);
    assert.match(err3, /\[REDACTED\]/);

    // 19d. Decoded password only in applyMigrations
    const applyDecodedRunner = () =>
      Promise.resolve({
        exitCode: 1,
        stdout: "",
        stderr: `P1000: Authentication failed against database using password: ${decodedPassword}`,
      });
    const applyRes = await applyMigrationsWithPrisma(sensitiveDbUrl, applyDecodedRunner);
    assert.equal(applyRes.applied, false);
    const applyErr = applyRes.error ?? "";
    assert.equal(applyErr.includes(decodedPassword), false);
    assert.equal(applyErr.includes(rawEncodedPassword), false);
    assert.match(applyErr, /\[REDACTED\]/);
  });

  void it("20. Finding 2 regression: fails closed with secret-free diagnostic when percent-encoding is malformed", async () => {
    const malformedPassword = "bad_pass%ZZ_sentinel";
    const malformedDbUrl = `postgresql://synthesis_user:${malformedPassword}@127.0.0.1:5432/db`;

    // 20a. extractSecretsFromDatabaseUrl fails closed
    const extraction = extractSecretsFromDatabaseUrl(malformedDbUrl);
    assert.equal(extraction.isSafe, false);

    // 20b. probeDatabaseWithPrisma returns safe generic diagnostic without raw CLI output
    const failRunner = () =>
      Promise.resolve({
        exitCode: 1,
        stdout: "",
        stderr: `Raw error leaking ${malformedPassword}`,
      });
    const probeRes = await probeDatabaseWithPrisma(malformedDbUrl, failRunner);
    assert.equal(probeRes.ready, false);
    const probeErr = probeRes.error ?? "";
    assert.equal(probeErr.includes(malformedPassword), false);
    assert.match(probeErr, /\[REDACTED_SECURE_DIAGNOSTIC: Secret redaction could not be verified/);

    // 20c. applyMigrationsWithPrisma returns safe generic diagnostic without raw CLI output
    const applyRes = await applyMigrationsWithPrisma(malformedDbUrl, failRunner);
    assert.equal(applyRes.applied, false);
    const applyErr = applyRes.error ?? "";
    assert.equal(applyErr.includes(malformedPassword), false);
    assert.match(applyErr, /\[REDACTED_SECURE_DIAGNOSTIC: Secret redaction could not be verified/);

    // 20d. runCleanInstall returns safe generic diagnostic when encoding is malformed
    const deps = createValidDependencies({
      validateConfig: () => ({ valid: true, databaseUrl: malformedDbUrl }),
      probeDatabase: () =>
        Promise.resolve({ ready: false, error: `Failed with ${malformedPassword}` }),
    });
    const runRes = await runCleanInstall({ SYNTHESIS_SECRET_DATABASE_URL: malformedDbUrl }, deps);
    assert.equal(runRes.status, "FAILED");
    const runErr = runRes.error ?? "";
    assert.equal(runErr.includes(malformedPassword), false);
    assert.match(runErr, /\[REDACTED_SECURE_DIAGNOSTIC: Secret redaction could not be verified/);
  });

  void it("21. Ensures bootstrap participant and selfCheck InstallContext does NOT expose raw databaseUrl", async () => {
    let capturedContext: Record<string, unknown> | null = null;
    let capturedSelfCheckContext: Record<string, unknown> | null = null;

    const participants: BootstrapParticipant[] = [
      {
        id: "privacy-audit-participant",
        name: "Privacy Auditor",
        order: 1,
        execute: (context) => {
          capturedContext = context as unknown as Record<string, unknown>;
          return Promise.resolve({ ok: true });
        },
      },
    ];

    const deps = createValidDependencies({
      bootstrapParticipants: participants,
      selfCheck: (context) => {
        capturedSelfCheckContext = context as unknown as Record<string, unknown>;
        return { ok: true };
      },
    });
    const env = { SYNTHESIS_SECRET_DATABASE_URL: validMockDbUrl };

    const result = await runCleanInstall(env, deps);

    assert.equal(result.status, "SUCCESS");
    assert.equal(result.stage, "COMPLETE");

    assert.ok(capturedContext);
    assert.equal("databaseUrl" in capturedContext, false);
    assert.equal(Reflect.get(capturedContext, "databaseUrl"), undefined);

    assert.ok(capturedSelfCheckContext);
    assert.equal("databaseUrl" in capturedSelfCheckContext, false);
    assert.equal(Reflect.get(capturedSelfCheckContext, "databaseUrl"), undefined);
  });
});
