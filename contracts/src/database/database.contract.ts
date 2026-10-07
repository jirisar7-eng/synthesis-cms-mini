/**
 * Synthesis CMS mini — Framework-Neutral Database Environment Contract
 *
 * Provides database environment schema definition, validation, and secret-safe
 * connection URI format verification by composing the generic Step 9 Environment Contract.
 */

import {
  type EnvironmentSchema,
  type EnvSource,
  EnvironmentValidationError,
  validateEnvironment,
} from "../env/index.ts";

export const DATABASE_URL_VARIABLE_NAME = "SYNTHESIS_SECRET_DATABASE_URL" as const;

/**
 * Database environment schema defining server-only secret connection URL.
 */
export const databaseEnvironmentSchema: EnvironmentSchema = Object.freeze({
  [DATABASE_URL_VARIABLE_NAME]: {
    type: "string",
    category: "SECRET_SERVER_ONLY",
    required: true,
  },
});

export interface ValidatedDatabaseConfig {
  readonly SYNTHESIS_SECRET_DATABASE_URL: string;
}

/**
 * Validates database environment variables from the given environment source.
 *
 * Enforces:
 * 1. Step 9 fail-closed namespace validation and category-prefix matching.
 * 2. Presence of required server-only secret DATABASE_URL.
 * 3. Safe URI protocol verification (postgresql: or postgres:).
 * 4. Presence of valid hostname and database path.
 * 5. Zero secret credential leakage in error messages or diagnostic reasons.
 *
 * Returns a frozen, validated database configuration object.
 */
export function validateDatabaseEnvironment(source: EnvSource): ValidatedDatabaseConfig {
  // 1. Validate through the Step 9 Environment Contract validator
  const validated = validateEnvironment(databaseEnvironmentSchema, source);
  const rawUrl = validated[DATABASE_URL_VARIABLE_NAME];

  if (typeof rawUrl !== "string") {
    throw new EnvironmentValidationError(
      DATABASE_URL_VARIABLE_NAME,
      "MISSING_REQUIRED_VARIABLE",
      "Database URL is required and must be a string",
    );
  }

  // 2. Validate URI protocol and syntax safely without leaking credentials
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== "postgresql:" && parsed.protocol !== "postgres:") {
      throw new Error("Invalid protocol");
    }
    if (!parsed.hostname || parsed.hostname.trim() === "") {
      throw new Error("Missing database hostname");
    }
    if (parsed.pathname === "" || parsed.pathname === "/") {
      throw new Error("Missing database name");
    }
  } catch {
    throw new EnvironmentValidationError(
      DATABASE_URL_VARIABLE_NAME,
      "INVALID_DATABASE_URL_FORMAT" as unknown as "INVALID_ENUM_VALUE",
      "Database URL must be a valid postgresql:// or postgres:// connection URI",
    );
  }

  return validated as unknown as ValidatedDatabaseConfig;
}
