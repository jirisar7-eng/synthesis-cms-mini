/**
 * Synthesis CMS mini — Environment Contract Unit Tests
 *
 * Covers 22+ validation, category, projection, redaction and typing scenarios.
 * Executable directly via `node --test` with zero external dependencies.
 */

import {
  validateEnvironment,
  projectPublicEnvironment,
  EnvironmentValidationError,
  type EnvironmentSchema,
  type EnvSource,
  type ConfigCategory,
} from "../../contracts/src/env/index.ts";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

function assertThrows(fn: () => void, expectedCode: string): EnvironmentValidationError {
  try {
    fn();
    throw new Error(
      `Expected function to throw EnvironmentValidationError with code ${expectedCode}, but it did not throw.`,
    );
  } catch (err) {
    if (err instanceof EnvironmentValidationError) {
      if (err.code !== expectedCode) {
        throw new Error(
          `Expected error code "${expectedCode}", but got "${err.code}": ${err.message}`,
        );
      }
      return err;
    }
    throw err;
  }
}

let passedScenarios = 0;

function runScenario(name: string, fn: () => void): void {
  try {
    fn();
    passedScenarios++;
  } catch (error) {
    console.error(`FAILED SCENARIO: ${name}`);
    throw error;
  }
}

// Scenario 01: Valid required string
runScenario("01 valid required string", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_HOST: { type: "string", category: "SERVER_ONLY", required: true },
  };
  const source: EnvSource = { SYNTHESIS_HOST: "127.0.0.1" };
  const config = validateEnvironment(schema, source);
  assert(config["SYNTHESIS_HOST"] === "127.0.0.1", "Host should match submitted string");
});

// Scenario 02: Missing required variable
runScenario("02 missing required variable", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_HOST: { type: "string", category: "SERVER_ONLY", required: true },
  };
  const source: EnvSource = {};
  const err = assertThrows(() => validateEnvironment(schema, source), "MISSING_REQUIRED_VARIABLE");
  assert(err.variableName === "SYNTHESIS_HOST", "Error should name missing variable");
});

// Scenario 03: Optional absent variable
runScenario("03 optional absent variable", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_HOST: { type: "string", category: "SERVER_ONLY", required: false },
  };
  const source: EnvSource = {};
  const config = validateEnvironment(schema, source);
  assert(config["SYNTHESIS_HOST"] === undefined, "Optional absent variable should be undefined");
  assert(
    !("SYNTHESIS_HOST" in config),
    "Absent variable without default should not be set in result",
  );
});

// Scenario 04: Explicit safe default
runScenario("04 explicit safe default", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_PORT: { type: "integer", category: "SERVER_ONLY", default: 3000 },
  };
  const source: EnvSource = {};
  const config = validateEnvironment(schema, source);
  assert(config["SYNTHESIS_PORT"] === 3000, "Default port should be 3000");
});

// Scenario 05: Valid boolean 'true'
runScenario("05 valid boolean true", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_DEBUG: { type: "boolean", category: "SERVER_ONLY" },
  };
  const source: EnvSource = { SYNTHESIS_DEBUG: "true" };
  const config = validateEnvironment(schema, source);
  assert(config["SYNTHESIS_DEBUG"] === true, "Boolean should parse to true");
});

// Scenario 06: Valid boolean 'false'
runScenario("06 valid boolean false", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_DEBUG: { type: "boolean", category: "SERVER_ONLY" },
  };
  const source: EnvSource = { SYNTHESIS_DEBUG: "false" };
  const config = validateEnvironment(schema, source);
  assert(config["SYNTHESIS_DEBUG"] === false, "Boolean should parse to false");
});

// Scenario 07: Invalid boolean
runScenario("07 invalid boolean", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_DEBUG: { type: "boolean", category: "SERVER_ONLY" },
  };
  const invalidValues = ["1", "0", "yes", "no", "TRUE", "FALSE", "random"];
  for (const v of invalidValues) {
    const source: EnvSource = { SYNTHESIS_DEBUG: v };
    assertThrows(() => validateEnvironment(schema, source), "INVALID_BOOLEAN_VALUE");
  }
});

// Scenario 08: Valid integer
runScenario("08 valid integer", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_PORT: { type: "integer", category: "SERVER_ONLY" },
  };
  const source: EnvSource = { SYNTHESIS_PORT: "8080" };
  const config = validateEnvironment(schema, source);
  assert(config["SYNTHESIS_PORT"] === 8080, "Integer should parse to 8080");
});

// Scenario 09: Invalid integer syntax
runScenario("09 invalid integer syntax", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_PORT: { type: "integer", category: "SERVER_ONLY" },
  };
  const invalidSyntaxes = ["8080abc", "3.14", "", "--5", "0x10"];
  for (const v of invalidSyntaxes) {
    const source: EnvSource = { SYNTHESIS_PORT: v };
    assertThrows(() => validateEnvironment(schema, source), "INVALID_INTEGER_VALUE");
  }
});

// Scenario 10: Unsafe/non-valid integer
runScenario("10 unsafe/non-valid integer", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_BIG_NUM: { type: "integer", category: "SERVER_ONLY" },
  };
  const source: EnvSource = { SYNTHESIS_BIG_NUM: "90071992547409929999999999" };
  assertThrows(() => validateEnvironment(schema, source), "INVALID_INTEGER_VALUE");
});

// Scenario 11: Valid enum
runScenario("11 valid enum", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_LOG_LEVEL: {
      type: "enum",
      category: "SERVER_ONLY",
      enumValues: ["debug", "info", "warn", "error"],
    },
  };
  const source: EnvSource = { SYNTHESIS_LOG_LEVEL: "warn" };
  const config = validateEnvironment(schema, source);
  assert(config["SYNTHESIS_LOG_LEVEL"] === "warn", "Enum should match 'warn'");
});

// Scenario 12: Invalid enum
runScenario("12 invalid enum", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_LOG_LEVEL: {
      type: "enum",
      category: "SERVER_ONLY",
      enumValues: ["debug", "info", "warn", "error"],
    },
  };
  const source: EnvSource = { SYNTHESIS_LOG_LEVEL: "verbose" };
  assertThrows(() => validateEnvironment(schema, source), "INVALID_ENUM_VALUE");
});

// Scenario 13: Unknown SYNTHESIS_* variable rejected
runScenario("13 unknown SYNTHESIS_* variable rejected", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_HOST: { type: "string", category: "SERVER_ONLY" },
  };
  const source: EnvSource = {
    SYNTHESIS_HOST: "localhost",
    SYNTHESIS_UNKNOWN_KEY: "unexpected",
  };
  const err = assertThrows(() => validateEnvironment(schema, source), "UNKNOWN_SYNTHESIS_VARIABLE");
  assert(err.variableName === "SYNTHESIS_UNKNOWN_KEY", "Error should identify unknown variable");
});

// Scenario 14: Unrelated host variable ignored
runScenario("14 unrelated host variable ignored", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_HOST: { type: "string", category: "SERVER_ONLY" },
  };
  const source: EnvSource = {
    SYNTHESIS_HOST: "localhost",
    PATH: "/usr/bin:/bin",
    HOME: "/home/user",
    CI: "true",
    TERM: "xterm-256color",
  };
  const config = validateEnvironment(schema, source);
  assert(config["SYNTHESIS_HOST"] === "localhost", "Declared config should be present");
  assert(!("PATH" in config), "PATH must not be in validated config");
  assert(!("HOME" in config), "HOME must not be in validated config");
});

// Scenario 15: PUBLIC_SAFE included in public projection
runScenario("15 PUBLIC_SAFE included in public projection", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_PUBLIC_APP_NAME: { type: "string", category: "PUBLIC_SAFE" },
  };
  const source: EnvSource = { SYNTHESIS_PUBLIC_APP_NAME: "Mini CMS" };
  const config = validateEnvironment(schema, source);
  const publicConfig = projectPublicEnvironment(schema, config);
  assert(
    publicConfig["SYNTHESIS_PUBLIC_APP_NAME"] === "Mini CMS",
    "Public config should include PUBLIC_SAFE key",
  );
});

// Scenario 16: SERVER_ONLY excluded from public projection
runScenario("16 SERVER_ONLY excluded from public projection", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_HOST: { type: "string", category: "SERVER_ONLY" },
    SYNTHESIS_PUBLIC_NAME: { type: "string", category: "PUBLIC_SAFE" },
  };
  const source: EnvSource = { SYNTHESIS_HOST: "127.0.0.1", SYNTHESIS_PUBLIC_NAME: "App" };
  const config = validateEnvironment(schema, source);
  const publicConfig = projectPublicEnvironment(schema, config);
  assert(
    !("SYNTHESIS_HOST" in publicConfig),
    "SERVER_ONLY must be excluded from public projection",
  );
  assert(
    publicConfig["SYNTHESIS_PUBLIC_NAME"] === "App",
    "PUBLIC_SAFE must be present in public projection",
  );
});

// Scenario 17: SECRET_SERVER_ONLY excluded from public projection
runScenario("17 SECRET_SERVER_ONLY excluded from public projection", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_SECRET_TOKEN: { type: "string", category: "SECRET_SERVER_ONLY" },
    SYNTHESIS_PUBLIC_NAME: { type: "string", category: "PUBLIC_SAFE" },
  };
  const source: EnvSource = {
    SYNTHESIS_SECRET_TOKEN: "sensitive_value",
    SYNTHESIS_PUBLIC_NAME: "App",
  };
  const config = validateEnvironment(schema, source);
  const publicConfig = projectPublicEnvironment(schema, config);
  assert(
    !("SYNTHESIS_SECRET_TOKEN" in publicConfig),
    "SECRET_SERVER_ONLY must be excluded from public projection",
  );
});

// Scenario 18: INTERNAL_RUNTIME excluded from public projection
runScenario("18 INTERNAL_RUNTIME excluded from public projection", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_INTERNAL_WORKER_COUNT: { type: "integer", category: "INTERNAL_RUNTIME" },
  };
  const source: EnvSource = { SYNTHESIS_INTERNAL_WORKER_COUNT: "4" };
  const config = validateEnvironment(schema, source);
  const publicConfig = projectPublicEnvironment(schema, config);
  assert(
    !("SYNTHESIS_INTERNAL_WORKER_COUNT" in publicConfig),
    "INTERNAL_RUNTIME must be excluded from public projection",
  );
});

// Scenario 19: TEST_ONLY rejected in runtime mode
runScenario("19 TEST_ONLY rejected in runtime mode", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_TEST_MOCK_TIME: { type: "string", category: "TEST_ONLY" },
  };
  const source: EnvSource = { SYNTHESIS_TEST_MOCK_TIME: "2026-01-01" };
  assertThrows(
    () => validateEnvironment(schema, source, { mode: "runtime" }),
    "TEST_ONLY_DISALLOWED_IN_RUNTIME",
  );
});

// Scenario 20: TEST_ONLY accepted in explicit test mode
runScenario("20 TEST_ONLY accepted in test mode", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_TEST_MOCK_TIME: { type: "string", category: "TEST_ONLY" },
  };
  const source: EnvSource = { SYNTHESIS_TEST_MOCK_TIME: "2026-01-01" };
  const config = validateEnvironment(schema, source, { mode: "test" });
  assert(
    config["SYNTHESIS_TEST_MOCK_TIME"] === "2026-01-01",
    "TEST_ONLY should be allowed in test mode",
  );
});

// Scenario 21: Errors include variable name but never submitted raw value
runScenario("21 error secret redaction", () => {
  const syntheticSecretSentinel = "VERY_SENSITIVE_TEST_TOKEN_XYZ_987654321";
  const schema: EnvironmentSchema = {
    SYNTHESIS_SECRET_PORT: { type: "integer", category: "SECRET_SERVER_ONLY" },
  };
  const source: EnvSource = { SYNTHESIS_SECRET_PORT: syntheticSecretSentinel };
  const err = assertThrows(() => validateEnvironment(schema, source), "INVALID_INTEGER_VALUE");

  assert(err.variableName === "SYNTHESIS_SECRET_PORT", "Error must contain variable name");
  assert(
    !err.message.includes(syntheticSecretSentinel),
    "Error message must NEVER include raw secret value",
  );
  assert(
    !err.reason.includes(syntheticSecretSentinel),
    "Error reason must NEVER include raw secret value",
  );
  assert(
    !JSON.stringify(err).includes(syntheticSecretSentinel),
    "JSON serialization of error must NEVER include raw secret value",
  );
});

// Scenario 22: Returned configuration is frozen AND category/prefix mismatch is rejected
runScenario("22 frozen config and prefix/category mismatch", () => {
  // Test frozen config
  const schema: EnvironmentSchema = {
    SYNTHESIS_PORT: { type: "integer", category: "SERVER_ONLY", default: 3000 },
  };
  const config = validateEnvironment(schema, {});
  assert(Object.isFrozen(config), "Validated configuration object must be frozen");

  const publicConfig = projectPublicEnvironment(schema, config);
  assert(Object.isFrozen(publicConfig), "Public projection configuration object must be frozen");

  // Test prefix/category mismatches
  const invalidSchemas: Array<[string, ConfigCategory]> = [
    ["SYNTHESIS_PUBLIC_TOKEN", "SECRET_SERVER_ONLY"],
    ["SYNTHESIS_SECRET_NAME", "PUBLIC_SAFE"],
    ["SYNTHESIS_INTERNAL_NAME", "SERVER_ONLY"],
    ["SYNTHESIS_TEST_VAR", "SERVER_ONLY"],
    ["UNPREFIXED_NAME", "SERVER_ONLY"],
  ];

  for (const [key, category] of invalidSchemas) {
    const badSchema: EnvironmentSchema = {
      [key]: { type: "string", category },
    };
    assertThrows(() => validateEnvironment(badSchema, {}), "PREFIX_CATEGORY_MISMATCH");
  }
});

console.log(
  `PASS: All ${String(passedScenarios)} environment contract test scenarios executed successfully.`,
);
