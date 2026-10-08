/// <reference types="node" />
/**
 * Synthesis CMS mini — Clean-Install / Bootstrap Real Database Integration Test
 *
 * Verifies real end-to-end clean install against an isolated, live PostgreSQL service container:
 * - Real config validation of SYNTHESIS_SECRET_DATABASE_URL
 * - Real PostgreSQL connection & readiness check via `prisma db execute --stdin` (SELECT 1;)
 * - Truthful zero migration handling (NO_MIGRATIONS_TO_APPLY)
 * - Zero bootstrap participants execution
 * - Installer self-check validation
 * - Reaching terminal COMPLETE state
 *
 * Excluded from standard `npm test` by file extension naming. Invoked explicitly in CI.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { type InstallDependencies, runCleanInstall } from "../../core/src/install/installer.ts";
import {
  type CommandRunner,
  applyMigrationsWithPrisma,
  getFilesystemMigrationCount,
  probeDatabaseWithPrisma,
  validateDatabaseConfig,
} from "../../core/src/install/prisma-cli.ts";

const realCommandRunner: CommandRunner = (command, args, options) => {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args as string[], {
      env: {
        ...process.env,
        ...(options?.env ?? {}),
      },
      stdio: ["pipe", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    if (options?.stdin) {
      child.stdin.write(options.stdin);
      child.stdin.end();
    }

    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });

    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });

    child.on("close", (exitCode: number | null) => {
      resolve({
        exitCode: exitCode ?? 1,
        stdout,
        stderr,
      });
    });

    child.on("error", (err: Error) => {
      reject(err);
    });
  });
};

void describe("Clean-Install / Bootstrap Real PostgreSQL Integration Test", () => {
  void it("Verifies full clean installation against isolated PostgreSQL database service", async () => {
    const databaseUrl = process.env.SYNTHESIS_SECRET_DATABASE_URL;
    assert.ok(
      databaseUrl,
      "SYNTHESIS_SECRET_DATABASE_URL environment variable must be provided for integration test",
    );

    const deps: InstallDependencies = {
      validateConfig: validateDatabaseConfig,
      probeDatabase: (dbUrl) => probeDatabaseWithPrisma(dbUrl, realCommandRunner),
      getMigrationCount: () => getFilesystemMigrationCount(),
      applyMigrations: (dbUrl) => applyMigrationsWithPrisma(dbUrl, realCommandRunner),
      bootstrapParticipants: [],
      selfCheck: (ctx) => {
        assert.equal(ctx.stage, "SELF_CHECK_PASS");
        assert.deepEqual(ctx.migrationResult, {
          count: 0,
          result: "NO_MIGRATIONS_TO_APPLY",
        });
        return { ok: true };
      },
    };

    const minimalEnv = {
      SYNTHESIS_SECRET_DATABASE_URL: databaseUrl,
    };
    const result = await runCleanInstall(minimalEnv, deps);

    assert.equal(result.status, "SUCCESS");
    assert.equal(result.stage, "COMPLETE");
    assert.deepEqual(result.migrationResult, {
      count: 0,
      result: "NO_MIGRATIONS_TO_APPLY",
    });
    assert.equal(result.participantsExecuted, 0);
    assert.equal(result.error, undefined);
  });
});
