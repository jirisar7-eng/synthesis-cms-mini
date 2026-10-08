/// <reference types="node" />
/**
 * Synthesis CMS mini — Clean-Install / Bootstrap Prisma CLI Adapter
 *
 * Internal Foundation adapter interfacing with the Prisma CLI for:
 * - database readiness verification via `prisma db execute --stdin` (SELECT 1;)
 * - audited migration discovery and deployment via `prisma migrate deploy`
 *
 * Strictly decoupled from any runtime PostgreSQL or Prisma client packages.
 */

import fs from "node:fs";
import path from "node:path";
import {
  DATABASE_URL_VARIABLE_NAME,
  validateDatabaseEnvironment,
} from "../../../contracts/src/database/index.ts";
import { redactSensitiveText } from "./installer.ts";

export type CommandRunner = (
  command: string,
  args: ReadonlyArray<string>,
  options?: {
    stdin?: string;
    env?: Record<string, string>;
  },
) => Promise<{
  exitCode: number;
  stdout: string;
  stderr: string;
}>;

export function validateDatabaseConfig(env: Readonly<Record<string, string | undefined>>): {
  valid: boolean;
  databaseUrl?: string;
  error?: string;
} {
  try {
    validateDatabaseEnvironment(env);
    const dbUrl = env[DATABASE_URL_VARIABLE_NAME];
    if (!dbUrl) {
      return {
        valid: false,
        error: `Missing required environment variable: ${DATABASE_URL_VARIABLE_NAME}`,
      };
    }
    return {
      valid: true,
      databaseUrl: dbUrl,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      valid: false,
      error: message,
    };
  }
}

function extractSecrets(databaseUrl: string): string[] {
  const secrets = [databaseUrl];
  try {
    const parsedUri = new URL(databaseUrl);
    if (parsedUri.password) {
      secrets.push(parsedUri.password);
    }
  } catch {
    // Non-URL format or unparseable; databaseUrl is already in secrets
  }
  return secrets;
}

export async function probeDatabaseWithPrisma(
  databaseUrl: string,
  runner: CommandRunner,
): Promise<{ ready: boolean; error?: string }> {
  const secrets = extractSecrets(databaseUrl);
  try {
    const res = await runner("npx", ["--no-install", "prisma", "db", "execute", "--stdin"], {
      stdin: "SELECT 1;\n",
      env: {
        [DATABASE_URL_VARIABLE_NAME]: databaseUrl,
      },
    });

    if (res.exitCode === 0) {
      return { ready: true };
    }

    const rawError =
      res.stderr.trim() || res.stdout.trim() || `Command exited with code ${String(res.exitCode)}`;
    const safeError = redactSensitiveText(rawError, secrets);
    return {
      ready: false,
      error: `DATABASE_PROBE_FAILED (exit code ${String(res.exitCode)}): ${safeError}`,
    };
  } catch (err) {
    const rawError = err instanceof Error ? err.message : String(err);
    const safeError = redactSensitiveText(rawError, secrets);
    return {
      ready: false,
      error: `DATABASE_PROBE_EXECUTION_ERROR: ${safeError}`,
    };
  }
}

export function getFilesystemMigrationCount(migrationsDir?: string): number {
  const targetDir = migrationsDir ?? path.resolve(process.cwd(), "prisma", "migrations");

  if (!fs.existsSync(targetDir)) {
    return 0;
  }

  try {
    const entries = fs.readdirSync(targetDir, { withFileTypes: true });
    // Count directory entries that represent migration folders (ignore migration_lock.toml, hidden files, etc.)
    const migrationDirs = entries.filter(
      (entry) => entry.isDirectory() && !entry.name.startsWith("."),
    );
    return migrationDirs.length;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(
      `MIGRATION_DISCOVERY_FAILED: Unable to read existing migrations directory at "${targetDir}": ${message}`,
    );
  }
}

export async function applyMigrationsWithPrisma(
  databaseUrl: string,
  runner: CommandRunner,
): Promise<{ applied: boolean; error?: string }> {
  const secrets = extractSecrets(databaseUrl);
  try {
    const res = await runner("npx", ["--no-install", "prisma", "migrate", "deploy"], {
      env: {
        [DATABASE_URL_VARIABLE_NAME]: databaseUrl,
      },
    });

    if (res.exitCode === 0) {
      return { applied: true };
    }

    const rawError =
      res.stderr.trim() || res.stdout.trim() || `Command exited with code ${String(res.exitCode)}`;
    const safeError = redactSensitiveText(rawError, secrets);
    return {
      applied: false,
      error: `MIGRATE_DEPLOY_FAILED (exit code ${String(res.exitCode)}): ${safeError}`,
    };
  } catch (err) {
    const rawError = err instanceof Error ? err.message : String(err);
    const safeError = redactSensitiveText(rawError, secrets);
    return {
      applied: false,
      error: `MIGRATE_DEPLOY_EXECUTION_ERROR: ${safeError}`,
    };
  }
}
