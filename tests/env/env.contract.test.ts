/**
 * Synthesis CMS mini — Framework-Neutral Environment Contract Test Suite
 *
 * Covers:
 * - Missing required variable detection
 * - Variable default value application
 * - Boolean parsing strictness (reject 1/0/yes/no)
 * - Canonical integer parsing strictness (whitespace rejection, leading zero rejection, safe bounds, -0 rejection)
 * - Enum validation
 * - Unknown SYNTHESIS_* prefix fail-closed rejection
 * - Ignore unrelated environment variables (e.g. PATH, HOME)
 * - Public projection isolation (PUBLIC_SAFE only)
 * - Secret and internal exclusion from public projection
 * - TEST_ONLY mode enforcement (denied in runtime, accepted in test mode)
 * - Error message secret-safety / redaction
 * - Prefix-category consistency validation
 * - Module-private WeakMap projection binding enforcement (unvalidated rejection, schema instance mismatch rejection, post-validation mutation protection)
 */

import {
  type ConfigCategory,
  type EnvironmentSchema,
  type EnvSource,
  EnvironmentValidationError,
  projectPublicEnvironment,
  validateEnvironment,
} from "../../contracts/src/env/index.ts";

let passedScenarios = 0;

function runScenario(name: string, fn: () => void): void {
  try {
    fn();
    passedScenarios++;
  } catch (err) {
    console.error(`FAILED scenario: ${name}`);
    throw err;
  }
}

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

function assertThrows(fn: () => void, expectedCode: string): EnvironmentValidationError {
  try {
    fn();
  } catch (err) {
    if (err instanceof EnvironmentValidationError) {
      if (err.code !== expectedCode) {
        throw new Error(
          `Expected error code "${expectedCode}", but got "${err.code}" (${err.message})`,
        );
      }
      return err;
    }
    throw new Error(`Expected EnvironmentValidationError, but got: ${String(err)}`);
  }
  throw new Error(`Expected function to throw ${expectedCode}, but it did not throw`);
}

// Scenario 1: Valid required string
runScenario("01 valid required string", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_HOST: { type: "string", category: "SERVER_ONLY", required: true },
  };
  const source: EnvSource = { SYNTHESIS_HOST: "127.0.0.1" };
  const config = validateEnvironment(schema, source);
  assert(config["SYNTHESIS_HOST"] === "127.0.0.1", "Host should match input");
});

// Scenario 2: Missing required variable
runScenario("02 missing required variable", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_PORT: { type: "integer", category: "SERVER_ONLY", required: true },
  };
  const source: EnvSource = {};
  const err = assertThrows(() => validateEnvironment(schema, source), "MISSING_REQUIRED_VARIABLE");
  assert(err.variableName === "SYNTHESIS_PORT", "Error should identify missing variable");
});

// Scenario 3: Default value applied
runScenario("03 default value applied", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_PORT: { type: "integer", category: "SERVER_ONLY", default: 3000 },
  };
  const source: EnvSource = {};
  const config = validateEnvironment(schema, source);
  assert(config["SYNTHESIS_PORT"] === 3000, "Port should default to 3000");
});

// Scenario 4: Explicit value overrides default
runScenario("04 explicit value overrides default", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_PORT: { type: "integer", category: "SERVER_ONLY", default: 3000 },
  };
  const source: EnvSource = { SYNTHESIS_PORT: "8080" };
  const config = validateEnvironment(schema, source);
  assert(config["SYNTHESIS_PORT"] === 8080, "Port should be overridden to 8080");
});

// Scenario 5: Valid boolean "true" and "false"
runScenario("05 valid booleans", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_DEBUG: { type: "boolean", category: "SERVER_ONLY" },
    SYNTHESIS_PROFILING: { type: "boolean", category: "SERVER_ONLY" },
  };
  const source: EnvSource = {
    SYNTHESIS_DEBUG: "true",
    SYNTHESIS_PROFILING: "false",
  };
  const config = validateEnvironment(schema, source);
  assert(config["SYNTHESIS_DEBUG"] === true, "Debug should be true");
  assert(config["SYNTHESIS_PROFILING"] === false, "Profiling should be false");
});

// Scenario 6: Invalid boolean values rejected
runScenario("06 invalid booleans rejected", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_FLAG: { type: "boolean", category: "SERVER_ONLY" },
  };
  const invalidBooleans = ["1", "0", "yes", "no", "TRUE", "FALSE", "enabled", "on", " "];
  for (const v of invalidBooleans) {
    const source: EnvSource = { SYNTHESIS_FLAG: v };
    assertThrows(() => validateEnvironment(schema, source), "INVALID_BOOLEAN_VALUE");
  }
});

// Scenario 7: Valid canonical integers (positive, zero, negative, min/max safe)
runScenario("07 valid canonical integers", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_PORT: { type: "integer", category: "SERVER_ONLY" },
    SYNTHESIS_ZERO: { type: "integer", category: "SERVER_ONLY" },
    SYNTHESIS_NEGATIVE: { type: "integer", category: "SERVER_ONLY" },
    SYNTHESIS_MAX_SAFE: { type: "integer", category: "SERVER_ONLY" },
    SYNTHESIS_MIN_SAFE: { type: "integer", category: "SERVER_ONLY" },
  };
  const source: EnvSource = {
    SYNTHESIS_PORT: "3000",
    SYNTHESIS_ZERO: "0",
    SYNTHESIS_NEGATIVE: "-42",
    SYNTHESIS_MAX_SAFE: String(Number.MAX_SAFE_INTEGER),
    SYNTHESIS_MIN_SAFE: String(Number.MIN_SAFE_INTEGER),
  };
  const config = validateEnvironment(schema, source);
  assert(config["SYNTHESIS_PORT"] === 3000, "Port should be 3000");
  assert(config["SYNTHESIS_ZERO"] === 0, "Zero should be 0");
  assert(config["SYNTHESIS_NEGATIVE"] === -42, "Negative should be -42");
  assert(config["SYNTHESIS_MAX_SAFE"] === Number.MAX_SAFE_INTEGER, "Max safe int should match");
  assert(config["SYNTHESIS_MIN_SAFE"] === Number.MIN_SAFE_INTEGER, "Min safe int should match");
});

// Scenario 8: Non-canonical integers rejected (whitespace, leading zeros, + sign, -0)
runScenario("08 non-canonical integers rejected", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_PORT: { type: "integer", category: "SERVER_ONLY" },
  };
  const nonCanonicalIntegers = [
    " 3000",
    "3000 ",
    " 3000 ",
    "0123",
    "00",
    "-0",
    "-00",
    "+3000",
    "+0",
    "007",
  ];
  for (const v of nonCanonicalIntegers) {
    const source: EnvSource = { SYNTHESIS_PORT: v };
    assertThrows(() => validateEnvironment(schema, source), "INVALID_INTEGER_VALUE");
  }
});

// Scenario 9: Non-integer syntax rejected
runScenario("09 invalid integer syntax rejected", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_PORT: { type: "integer", category: "SERVER_ONLY" },
  };
  const invalidIntegers = [
    "abc",
    "3000a",
    "12.34",
    "NaN",
    "Infinity",
    "-Infinity",
    "",
    " ",
    "1e5",
    "0x1f",
  ];
  for (const v of invalidIntegers) {
    const source: EnvSource = { SYNTHESIS_PORT: v };
    assertThrows(() => validateEnvironment(schema, source), "INVALID_INTEGER_VALUE");
  }
});

// Scenario 10: Unsafe integer bounds rejected
runScenario("10 unsafe integer bounds rejected", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_BIG_NUM: { type: "integer", category: "SERVER_ONLY" },
  };
  const outOfBounds = [
    "9007199254740992", // MAX_SAFE_INTEGER + 1
    "-9007199254740992", // MIN_SAFE_INTEGER - 1
    "90071992547409929999999999",
  ];
  for (const v of outOfBounds) {
    const source: EnvSource = { SYNTHESIS_BIG_NUM: v };
    assertThrows(() => validateEnvironment(schema, source), "INVALID_INTEGER_VALUE");
  }
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

// Scenario 23: Arbitrary/manually-created object rejected by projectPublicEnvironment
runScenario("23 unvalidated object rejected by projectPublicEnvironment", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_PUBLIC_APP_NAME: { type: "string", category: "PUBLIC_SAFE" },
  };
  // Fake object created directly without validateEnvironment
  const fakeConfig = { SYNTHESIS_PUBLIC_APP_NAME: "Injected App" };
  assertThrows(
    () => projectPublicEnvironment(schema, fakeConfig),
    "INVALID_PUBLIC_PROJECTION_SOURCE",
  );
});

// Scenario 24: Schema instance mismatch rejected by projectPublicEnvironment
runScenario("24 schema instance mismatch rejected", () => {
  const schemaA: EnvironmentSchema = {
    SYNTHESIS_PUBLIC_APP_NAME: { type: "string", category: "PUBLIC_SAFE" },
  };
  const schemaB: EnvironmentSchema = {
    SYNTHESIS_PUBLIC_APP_NAME: { type: "string", category: "PUBLIC_SAFE" },
  };
  const configA = validateEnvironment(schemaA, { SYNTHESIS_PUBLIC_APP_NAME: "App A" });
  assertThrows(
    () => projectPublicEnvironment(schemaB, configA),
    "INVALID_PUBLIC_PROJECTION_SOURCE",
  );
});

// Scenario 25: Non-object, null, or undefined rejected by projectPublicEnvironment
runScenario("25 non-object/null inputs rejected by projectPublicEnvironment", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_PUBLIC_APP_NAME: { type: "string", category: "PUBLIC_SAFE" },
  };
  const invalidInputs: unknown[] = [null, undefined, "string", 123, true, [1, 2, 3]];
  for (const input of invalidInputs) {
    assertThrows(
      () => projectPublicEnvironment(schema, input as Readonly<Record<string, unknown>>),
      "INVALID_PUBLIC_PROJECTION_SOURCE",
    );
  }
});

// Scenario 26: Post-validation schema mutation does NOT expose secret key
runScenario("26 post-validation schema mutation cannot expose secret keys", () => {
  // Mutable schema object
  const mutableSchema: Record<string, { type: "string"; category: ConfigCategory }> = {
    SYNTHESIS_PUBLIC_TITLE: { type: "string", category: "PUBLIC_SAFE" },
    SYNTHESIS_SECRET_TOKEN: { type: "string", category: "SECRET_SERVER_ONLY" },
  };

  const config = validateEnvironment(mutableSchema, {
    SYNTHESIS_PUBLIC_TITLE: "My Title",
    SYNTHESIS_SECRET_TOKEN: "secret_12345",
  });

  // Maliciously attempt to mutate schema category after validation
  mutableSchema["SYNTHESIS_SECRET_TOKEN"] = { type: "string", category: "PUBLIC_SAFE" };

  const publicConfig = projectPublicEnvironment(mutableSchema, config);

  // Assert secret token is NEVER exposed in publicConfig because publicKeys were snapshotted at validation
  assert(publicConfig["SYNTHESIS_PUBLIC_TITLE"] === "My Title", "Public title must be present");
  assert(
    !("SYNTHESIS_SECRET_TOKEN" in publicConfig),
    "SECRET_SERVER_ONLY must NEVER leak via schema mutation",
  );
  assert(
    Object.keys(publicConfig).length === 1,
    "Only validation-time public keys must be present",
  );
});

// Scenario 27: Failed validation never creates a usable projection binding
runScenario("27 failed validation never creates usable binding", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_PORT: { type: "integer", category: "SERVER_ONLY", required: true },
    SYNTHESIS_PUBLIC_APP: { type: "string", category: "PUBLIC_SAFE" },
  };
  const invalidSource: EnvSource = {
    SYNTHESIS_PORT: "invalid_not_number",
    SYNTHESIS_PUBLIC_APP: "App",
  };

  // Validation fails
  assertThrows(() => validateEnvironment(schema, invalidSource), "INVALID_INTEGER_VALUE");

  // Attempting to project an unvalidated object with that schema fails closed
  const fakeConfig = { SYNTHESIS_PUBLIC_APP: "App" };
  assertThrows(
    () => projectPublicEnvironment(schema, fakeConfig),
    "INVALID_PUBLIC_PROJECTION_SOURCE",
  );
});

// Scenario 28: Multiple independent validations maintain separate isolated schema bindings
runScenario("28 multiple independent validations isolated", () => {
  const schema1: EnvironmentSchema = {
    SYNTHESIS_PUBLIC_NAME: { type: "string", category: "PUBLIC_SAFE" },
  };
  const schema2: EnvironmentSchema = {
    SYNTHESIS_PUBLIC_NAME: { type: "string", category: "PUBLIC_SAFE" },
  };

  const config1 = validateEnvironment(schema1, { SYNTHESIS_PUBLIC_NAME: "Instance 1" });
  const config2 = validateEnvironment(schema2, { SYNTHESIS_PUBLIC_NAME: "Instance 2" });

  const proj1 = projectPublicEnvironment(schema1, config1);
  const proj2 = projectPublicEnvironment(schema2, config2);

  assert(proj1["SYNTHESIS_PUBLIC_NAME"] === "Instance 1", "Proj 1 should match schema 1 config");
  assert(proj2["SYNTHESIS_PUBLIC_NAME"] === "Instance 2", "Proj 2 should match schema 2 config");

  // Cross-projection fails closed
  assertThrows(
    () => projectPublicEnvironment(schema1, config2),
    "INVALID_PUBLIC_PROJECTION_SOURCE",
  );
  assertThrows(
    () => projectPublicEnvironment(schema2, config1),
    "INVALID_PUBLIC_PROJECTION_SOURCE",
  );
});

// Scenario 29: Validated configuration with multiple PUBLIC_SAFE keys projects cleanly and is frozen
runScenario("29 multiple PUBLIC_SAFE keys project cleanly and frozen", () => {
  const schema: EnvironmentSchema = {
    SYNTHESIS_PUBLIC_SITE_NAME: { type: "string", category: "PUBLIC_SAFE", default: "Synthesis" },
    SYNTHESIS_PUBLIC_THEME: {
      type: "enum",
      category: "PUBLIC_SAFE",
      enumValues: ["light", "dark"],
      default: "light",
    },
    SYNTHESIS_PUBLIC_MAX_ITEMS: { type: "integer", category: "PUBLIC_SAFE", default: 20 },
    SYNTHESIS_SECRET_API_KEY: { type: "string", category: "SECRET_SERVER_ONLY" },
  };
  const source: EnvSource = {
    SYNTHESIS_SECRET_API_KEY: "super_secret",
  };
  const config = validateEnvironment(schema, source);
  const publicConfig = projectPublicEnvironment(schema, config);

  assert(publicConfig["SYNTHESIS_PUBLIC_SITE_NAME"] === "Synthesis", "Site name projected");
  assert(publicConfig["SYNTHESIS_PUBLIC_THEME"] === "light", "Theme projected");
  assert(publicConfig["SYNTHESIS_PUBLIC_MAX_ITEMS"] === 20, "Max items projected");
  assert(!("SYNTHESIS_SECRET_API_KEY" in publicConfig), "API key excluded");
  assert(Object.keys(publicConfig).length === 3, "Exactly 3 public keys projected");
  assert(Object.isFrozen(publicConfig), "Projected config is frozen");
});

console.log(
  `PASS: All ${String(passedScenarios)} environment contract test scenarios executed successfully.`,
);
