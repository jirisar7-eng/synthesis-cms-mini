/**
 * Synthesis CMS mini — Database Environment Contract Tests
 *
 * Scenarios:
 * - Valid postgresql connection URL acceptance
 * - Valid postgres connection URL acceptance
 * - Missing required database URL (EnvironmentValidationError)
 * - Malformed database URL format rejection (DatabaseValidationError)
 * - Insecure / foreign protocol rejection (DatabaseValidationError)
 * - Secret credential redaction in errors (passwords never leak in error messages/reasons/serialization)
 * - Unrelated host environment variables ignored
 * - Unknown SYNTHESIS_* variable fail-closed rejection (EnvironmentValidationError)
 * - Database configuration object frozen / immutable
 * - Public projection isolation (database secret is never public)
 * - Zero live database connection dependency
 */

import {
  DATABASE_URL_VARIABLE_NAME,
  DatabaseValidationError,
  type DatabaseValidationErrorCode,
  databaseEnvironmentSchema,
  validateDatabaseEnvironment,
} from "../../contracts/src/database/index.ts";
import {
  type EnvSource,
  EnvironmentValidationError,
  type ValidationErrorCode,
  projectPublicEnvironment,
  validateEnvironment,
} from "../../contracts/src/env/index.ts";

let passedScenarios = 0;

function runScenario(name: string, fn: () => void): void {
  try {
    fn();
    passedScenarios++;
  } catch (err) {
    console.error(`FAILED database scenario: ${name}`);
    throw err;
  }
}

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

function assertThrowsEnv(
  fn: () => void,
  expectedCode?: ValidationErrorCode,
): EnvironmentValidationError {
  try {
    fn();
  } catch (err) {
    if (err instanceof EnvironmentValidationError) {
      if (expectedCode !== undefined && err.code !== expectedCode) {
        throw new Error(
          `Expected EnvironmentValidationError code "${expectedCode}", but got "${err.code}" (${err.message})`,
        );
      }
      return err;
    }
    throw new Error(`Expected EnvironmentValidationError, but got: ${String(err)}`);
  }
  throw new Error(
    `Expected function to throw EnvironmentValidationError ${expectedCode ?? ""}, but it did not throw`,
  );
}

function assertThrowsDb(
  fn: () => void,
  expectedCode?: DatabaseValidationErrorCode,
): DatabaseValidationError {
  try {
    fn();
  } catch (err) {
    if (err instanceof DatabaseValidationError) {
      if (expectedCode !== undefined && !Object.is(err.code, expectedCode)) {
        throw new Error(
          `Expected DatabaseValidationError code "${expectedCode}", but got "${err.code}" (${err.message})`,
        );
      }
      return err;
    }
    throw new Error(`Expected DatabaseValidationError, but got: ${String(err)}`);
  }
  throw new Error(
    `Expected function to throw DatabaseValidationError ${expectedCode ?? ""}, but it did not throw`,
  );
}

// Scenario 1: Valid postgresql connection URL
runScenario("01 valid postgresql url", () => {
  const source: EnvSource = {
    [DATABASE_URL_VARIABLE_NAME]:
      "postgresql://synthesis_admin:secret_pass_123@localhost:5432/synthesis_mini?schema=public",
  };
  const config = validateDatabaseEnvironment(source);
  assert(
    config[DATABASE_URL_VARIABLE_NAME] === source[DATABASE_URL_VARIABLE_NAME],
    "Config should contain exact valid postgresql URL",
  );
});

// Scenario 2: Valid postgres connection URL
runScenario("02 valid postgres url", () => {
  const source: EnvSource = {
    [DATABASE_URL_VARIABLE_NAME]: "postgres://db_user:my_secret_token@db.internal:5432/synthesis",
  };
  const config = validateDatabaseEnvironment(source);
  assert(
    config[DATABASE_URL_VARIABLE_NAME] === source[DATABASE_URL_VARIABLE_NAME],
    "Config should accept postgres:// protocol",
  );
});

// Scenario 3: Missing required database URL throws EnvironmentValidationError
runScenario("03 missing required database url throws EnvironmentValidationError", () => {
  const source: EnvSource = {};
  const err = assertThrowsEnv(
    () => validateDatabaseEnvironment(source),
    "MISSING_REQUIRED_VARIABLE",
  );
  assert(
    err.variableName === DATABASE_URL_VARIABLE_NAME,
    "Error should identify database URL variable",
  );
});

// Scenario 4: Malformed database URL throws DatabaseValidationError
runScenario("04 malformed url throws DatabaseValidationError", () => {
  const malformedUrls = [
    "not-a-url",
    "postgresql://",
    "://localhost",
    "postgresql:/localhost",
    "",
    "   ",
  ];
  for (const url of malformedUrls) {
    const source: EnvSource = { [DATABASE_URL_VARIABLE_NAME]: url };
    const err = assertThrowsDb(
      () => validateDatabaseEnvironment(source),
      "INVALID_DATABASE_URL_FORMAT",
    );
    assert(Boolean(err.variableName), "Error should identify database URL variable");
  }
});

// Scenario 5: Insecure / foreign protocols throw DatabaseValidationError
runScenario("05 foreign protocols throw DatabaseValidationError", () => {
  const foreignUrls = [
    "http://localhost:5432/db",
    "https://localhost:5432/db",
    "mysql://user:pass@localhost:3306/db",
    "mongodb://localhost:27017/db",
    "sqlite:///data.db",
    "file:///data.db",
  ];
  for (const url of foreignUrls) {
    const source: EnvSource = { [DATABASE_URL_VARIABLE_NAME]: url };
    const err = assertThrowsDb(
      () => validateDatabaseEnvironment(source),
      "INVALID_DATABASE_URL_FORMAT",
    );
    assert(Boolean(err.variableName), "Error should identify database URL variable");
  }
});

// Scenario 6: Secret credentials redaction in errors
runScenario("06 secret credentials redaction in errors", () => {
  const sensitiveSentinel = "SUPER_SECRET_COMPLEX_PASSWORD_9988776655";
  const invalidUrlWithSecret = `http://user:${sensitiveSentinel}@localhost:5432/db`;
  const source: EnvSource = { [DATABASE_URL_VARIABLE_NAME]: invalidUrlWithSecret };
  const err = assertThrowsDb(
    () => validateDatabaseEnvironment(source),
    "INVALID_DATABASE_URL_FORMAT",
  );
  assert(Boolean(err.variableName), "Variable name must be preserved");
  assert(!err.message.includes(sensitiveSentinel), "Error message must NEVER include secret");
  assert(!err.reason.includes(sensitiveSentinel), "Error reason must NEVER include secret");
  assert(
    !JSON.stringify(err).includes(sensitiveSentinel),
    "Serialized error must NEVER include secret",
  );
});

// Scenario 7: Unrelated host environment variables ignored
runScenario("07 unrelated host environment variables ignored", () => {
  const source: EnvSource = {
    [DATABASE_URL_VARIABLE_NAME]: "postgresql://u:p@localhost:5432/db",
    PATH: "/usr/bin:/bin",
    HOME: "/home/user",
    USER: "root",
    NODE_ENV: "test",
    CI: "true",
  };
  const config = validateDatabaseEnvironment(source);
  assert(
    config[DATABASE_URL_VARIABLE_NAME] === "postgresql://u:p@localhost:5432/db",
    "Database URL must be present",
  );
  assert(!("PATH" in config), "PATH must be excluded");
  assert(!("HOME" in config), "HOME must be excluded");
});

// Scenario 8: Unknown SYNTHESIS_* variable fails closed with EnvironmentValidationError
runScenario("08 unknown SYNTHESIS_* variable fails closed", () => {
  const source: EnvSource = {
    [DATABASE_URL_VARIABLE_NAME]: "postgresql://u:p@localhost:5432/db",
    SYNTHESIS_UNKNOWN_CUSTOM_KEY: "unexpected_value",
  };
  const err = assertThrowsEnv(
    () => validateDatabaseEnvironment(source),
    "UNKNOWN_SYNTHESIS_VARIABLE",
  );
  assert(
    err.variableName === "SYNTHESIS_UNKNOWN_CUSTOM_KEY",
    "Error should identify unknown variable",
  );
});

// Scenario 9: Returned database configuration is frozen
runScenario("09 returned database configuration is frozen", () => {
  const source: EnvSource = {
    [DATABASE_URL_VARIABLE_NAME]: "postgresql://u:p@localhost:5432/db",
  };
  const config = validateDatabaseEnvironment(source);
  assert(
    typeof config[DATABASE_URL_VARIABLE_NAME] === "string" &&
      config[DATABASE_URL_VARIABLE_NAME] === "postgresql://u:p@localhost:5432/db",
    "Validated database config must contain valid database URL",
  );
  assert(Object.isFrozen(config), "Returned database configuration must be frozen");
});

// Scenario 10: Database secret is never projectable to public environment
runScenario("10 database secret is never public", () => {
  const source: EnvSource = {
    [DATABASE_URL_VARIABLE_NAME]: "postgresql://u:p@localhost:5432/db",
  };
  const validated = validateEnvironment(databaseEnvironmentSchema, source);
  const publicConfig = projectPublicEnvironment(databaseEnvironmentSchema, validated);
  assert(
    !(DATABASE_URL_VARIABLE_NAME in publicConfig),
    "DATABASE_URL must NEVER be included in public projection",
  );
  assert(Object.keys(publicConfig).length === 0, "Public config for database schema must be empty");
});

console.log(
  `PASS: All ${String(passedScenarios)} database contract test scenarios executed successfully.`,
);
