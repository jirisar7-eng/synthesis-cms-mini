/// <reference types="node" />
/**
 * Synthesis CMS mini — Clean-Install / Bootstrap Framework Installer
 *
 * Internal Foundation state-machine orchestrating deterministic installation:
 * PREFLIGHT -> CONFIG_VALIDATED -> DATABASE_READY -> MIGRATIONS_APPLIED ->
 * BOOTSTRAP_PARTICIPANTS_COMPLETE -> SELF_CHECK_PASS -> COMPLETE.
 *
 * Implements strict fail-closed execution, dependency injection, and secret-safe diagnostics.
 */

export type InstallStage =
  | "PREFLIGHT"
  | "CONFIG_VALIDATED"
  | "DATABASE_READY"
  | "MIGRATIONS_APPLIED"
  | "BOOTSTRAP_PARTICIPANTS_COMPLETE"
  | "SELF_CHECK_PASS"
  | "COMPLETE";

export interface MigrationExecutionResult {
  readonly count: number;
  readonly result: "NO_MIGRATIONS_TO_APPLY" | "MIGRATIONS_APPLIED";
}

export interface BootstrapParticipantResult {
  readonly ok: boolean;
  readonly error?: string;
}

export interface InstallContext {
  readonly stage: InstallStage;
  readonly migrationResult: MigrationExecutionResult;
  readonly participantResults: ReadonlyArray<Readonly<{ id: string; name: string; ok: boolean }>>;
}

export interface BootstrapParticipant {
  readonly id: string;
  readonly name: string;
  readonly order: number;
  execute(context: InstallContext): Promise<BootstrapParticipantResult>;
}

export interface InstallDependencies {
  readonly validateConfig: (env: Readonly<Record<string, string | undefined>>) => {
    valid: boolean;
    databaseUrl?: string;
    error?: string;
  };
  readonly probeDatabase: (databaseUrl: string) => Promise<{ ready: boolean; error?: string }>;
  readonly getMigrationCount: () => Promise<number> | number;
  readonly applyMigrations: (databaseUrl: string) => Promise<{ applied: boolean; error?: string }>;
  readonly bootstrapParticipants?: ReadonlyArray<BootstrapParticipant>;
  readonly selfCheck: (
    context: InstallContext,
  ) => Promise<{ ok: boolean; error?: string }> | { ok: boolean; error?: string };
}

export interface InstallResult {
  readonly status: "SUCCESS" | "FAILED";
  readonly stage: InstallStage;
  readonly migrationResult?: MigrationExecutionResult;
  readonly participantsExecuted: number;
  readonly error?: string;
}

export interface SecretExtractionResult {
  readonly secrets: ReadonlyArray<string>;
  readonly isSafe: boolean;
}

/**
 * Safely extracts credentials (complete URL, encoded password, and decoded password)
 * from a database connection URI without ever logging or exposing the source password.
 * Fails closed (isSafe = false) if percent-encoding is malformed or invalid.
 */
export function extractSecretsFromDatabaseUrl(databaseUrl: string): SecretExtractionResult {
  const secrets: string[] = [];
  if (databaseUrl && databaseUrl.length > 0) {
    secrets.push(databaseUrl);
  }

  let isSafe = true;

  try {
    const parsedUri = new URL(databaseUrl);
    const rawPassword = parsedUri.password;
    if (rawPassword && rawPassword.length > 0) {
      secrets.push(rawPassword);
      try {
        const decodedPassword = decodeURIComponent(rawPassword);
        if (decodedPassword && decodedPassword.length > 0 && decodedPassword !== rawPassword) {
          secrets.push(decodedPassword);
        }
      } catch {
        // Malformed percent encoding in password - redaction safety cannot be established
        isSafe = false;
      }
    }
  } catch {
    // Non-standard URI format
    if (databaseUrl.includes("@") && databaseUrl.includes(":")) {
      isSafe = false;
    }
  }

  const uniqueSecrets = Array.from(new Set(secrets.filter((s) => s.length > 0))).sort(
    (a, b) => b.length - a.length,
  );

  return {
    secrets: uniqueSecrets,
    isSafe,
  };
}

export function redactSensitiveText(
  text: string,
  secrets: ReadonlyArray<string>,
  isSafe = true,
): string {
  if (!isSafe) {
    return "[REDACTED_SECURE_DIAGNOSTIC: Secret redaction could not be verified due to malformed credentials encoding]";
  }

  let sanitized = text;
  const sortedSecrets = [...secrets].sort((a, b) => b.length - a.length);
  for (const s of sortedSecrets) {
    if (s && s.length > 0) {
      sanitized = sanitized.split(s).join("[REDACTED]");
    }
  }
  return sanitized;
}

export async function runCleanInstall(
  env: Readonly<Record<string, string | undefined>>,
  deps: InstallDependencies,
): Promise<InstallResult> {
  let currentStage: InstallStage = "PREFLIGHT";
  let databaseUrl = "";
  let sensitiveSecrets: string[] = [];
  let isRedactionSafe = true;

  try {
    // 1. PREFLIGHT
    if (typeof deps.validateConfig !== "function" || typeof deps.probeDatabase !== "function") {
      return {
        status: "FAILED",
        stage: currentStage,
        participantsExecuted: 0,
        error: "PREFLIGHT_FAILURE: Invalid installer dependencies provided",
      };
    }

    // 2. CONFIG_VALIDATED
    currentStage = "CONFIG_VALIDATED";
    const configResult = deps.validateConfig(env);
    if (!configResult.valid || !configResult.databaseUrl) {
      return {
        status: "FAILED",
        stage: currentStage,
        participantsExecuted: 0,
        error: `CONFIG_VALIDATION_FAILURE: ${configResult.error ?? "Invalid configuration"}`,
      };
    }
    databaseUrl = configResult.databaseUrl;
    const extraction = extractSecretsFromDatabaseUrl(databaseUrl);
    sensitiveSecrets = [...extraction.secrets];
    isRedactionSafe = extraction.isSafe;

    // 3. DATABASE_READY
    currentStage = "DATABASE_READY";
    const dbProbe = await deps.probeDatabase(databaseUrl);
    if (!dbProbe.ready) {
      const err = redactSensitiveText(
        dbProbe.error ?? "Database probe failed",
        sensitiveSecrets,
        isRedactionSafe,
      );
      return {
        status: "FAILED",
        stage: currentStage,
        participantsExecuted: 0,
        error: `DATABASE_READY_FAILURE: ${err}`,
      };
    }

    // 4. MIGRATIONS_APPLIED
    currentStage = "MIGRATIONS_APPLIED";
    const migrationCount = await deps.getMigrationCount();

    if (
      typeof migrationCount !== "number" ||
      !Number.isFinite(migrationCount) ||
      !Number.isInteger(migrationCount) ||
      migrationCount < 0
    ) {
      return {
        status: "FAILED",
        stage: currentStage,
        participantsExecuted: 0,
        error: `INVALID_MIGRATION_COUNT: Migration count must be a non-negative finite integer, got ${String(migrationCount)}`,
      };
    }

    let migrationResult: MigrationExecutionResult;

    if (migrationCount === 0) {
      migrationResult = {
        count: 0,
        result: "NO_MIGRATIONS_TO_APPLY",
      };
    } else {
      const migrationRun = await deps.applyMigrations(databaseUrl);
      if (!migrationRun.applied) {
        const err = redactSensitiveText(
          migrationRun.error ?? "Migration execution failed",
          sensitiveSecrets,
          isRedactionSafe,
        );
        return {
          status: "FAILED",
          stage: currentStage,
          participantsExecuted: 0,
          error: `MIGRATION_EXECUTION_FAILURE: ${err}`,
        };
      }
      migrationResult = {
        count: migrationCount,
        result: "MIGRATIONS_APPLIED",
      };
    }

    // 5. BOOTSTRAP_PARTICIPANTS_COMPLETE
    currentStage = "BOOTSTRAP_PARTICIPANTS_COMPLETE";
    const rawParticipants = deps.bootstrapParticipants ?? [];
    const participantResults: Array<{ id: string; name: string; ok: boolean }> = [];

    // Validate participants uniqueness and order sanity
    const seenIds = new Set<string>();
    for (const p of rawParticipants) {
      if (!p.id || typeof p.id !== "string" || !p.name || typeof p.name !== "string") {
        return {
          status: "FAILED",
          stage: currentStage,
          migrationResult,
          participantsExecuted: 0,
          error: "BOOTSTRAP_PARTICIPANT_FAILURE: Malformed participant structure",
        };
      }
      if (!Number.isFinite(p.order)) {
        return {
          status: "FAILED",
          stage: currentStage,
          migrationResult,
          participantsExecuted: 0,
          error: `BOOTSTRAP_PARTICIPANT_FAILURE: Invalid non-finite order for participant ${p.id}`,
        };
      }
      if (seenIds.has(p.id)) {
        return {
          status: "FAILED",
          stage: currentStage,
          migrationResult,
          participantsExecuted: 0,
          error: `BOOTSTRAP_PARTICIPANT_FAILURE: Duplicate participant id "${p.id}"`,
        };
      }
      seenIds.add(p.id);
    }

    // Sort deterministically: order ascending, id ascending as tie-breaker
    const sortedParticipants = [...rawParticipants].sort((a, b) => {
      if (a.order !== b.order) {
        return a.order - b.order;
      }
      return a.id.localeCompare(b.id);
    });

    for (const participant of sortedParticipants) {
      const context: InstallContext = {
        stage: currentStage,
        migrationResult,
        participantResults: [...participantResults],
      };

      try {
        const runRes = await participant.execute(context);
        if (!runRes.ok) {
          const err = redactSensitiveText(
            runRes.error ?? `Participant ${participant.id} failed`,
            sensitiveSecrets,
            isRedactionSafe,
          );
          return {
            status: "FAILED",
            stage: currentStage,
            migrationResult,
            participantsExecuted: participantResults.length,
            error: `BOOTSTRAP_PARTICIPANT_FAILURE: ${err}`,
          };
        }
        participantResults.push({ id: participant.id, name: participant.name, ok: true });
      } catch (execErr) {
        const rawMsg = execErr instanceof Error ? execErr.message : String(execErr);
        const err = redactSensitiveText(rawMsg, sensitiveSecrets, isRedactionSafe);
        return {
          status: "FAILED",
          stage: currentStage,
          migrationResult,
          participantsExecuted: participantResults.length,
          error: `BOOTSTRAP_PARTICIPANT_FAILURE: ${err}`,
        };
      }
    }

    // 6. SELF_CHECK_PASS
    currentStage = "SELF_CHECK_PASS";
    const finalContext: InstallContext = {
      stage: currentStage,
      migrationResult,
      participantResults: [...participantResults],
    };

    const selfCheckResult = await deps.selfCheck(finalContext);
    if (!selfCheckResult.ok) {
      const err = redactSensitiveText(
        selfCheckResult.error ?? "Installer self-check failed",
        sensitiveSecrets,
        isRedactionSafe,
      );
      return {
        status: "FAILED",
        stage: currentStage,
        migrationResult,
        participantsExecuted: participantResults.length,
        error: `SELF_CHECK_FAILURE: ${err}`,
      };
    }

    // 7. COMPLETE
    currentStage = "COMPLETE";
    return {
      status: "SUCCESS",
      stage: "COMPLETE",
      migrationResult,
      participantsExecuted: participantResults.length,
    };
  } catch (unexpectedError) {
    const rawMsg =
      unexpectedError instanceof Error ? unexpectedError.message : String(unexpectedError);
    const err = redactSensitiveText(rawMsg, sensitiveSecrets, isRedactionSafe);
    return {
      status: "FAILED",
      stage: currentStage,
      participantsExecuted: 0,
      error: `UNEXPECTED_INSTALL_FAILURE: ${err}`,
    };
  }
}
