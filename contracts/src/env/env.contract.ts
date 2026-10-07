/**
 * Synthesis CMS mini — Framework-Neutral Environment Contract
 *
 * Provides schema definition, strict validation, fail-closed project namespace enforcement,
 * public projection with module-private schema binding, and secret-safe error diagnostics
 * without external runtime dependencies.
 */

export type EnvSource = Readonly<Record<string, string | undefined>>;

export type ConfigCategory =
  "SERVER_ONLY" | "PUBLIC_SAFE" | "SECRET_SERVER_ONLY" | "INTERNAL_RUNTIME" | "TEST_ONLY";

export type ConfigFieldType = "string" | "boolean" | "integer" | "enum";

export type ValidationMode = "runtime" | "test";

export interface BaseFieldDescriptor {
  readonly category: ConfigCategory;
  readonly required?: boolean;
  readonly default?: unknown;
}

export interface StringFieldDescriptor extends BaseFieldDescriptor {
  readonly type: "string";
  readonly default?: string;
}

export interface BooleanFieldDescriptor extends BaseFieldDescriptor {
  readonly type: "boolean";
  readonly default?: boolean;
}

export interface IntegerFieldDescriptor extends BaseFieldDescriptor {
  readonly type: "integer";
  readonly default?: number;
}

export interface EnumFieldDescriptor<T extends string = string> extends BaseFieldDescriptor {
  readonly type: "enum";
  readonly enumValues: readonly T[];
  readonly default?: T;
}

export type EnvironmentFieldDescriptor =
  StringFieldDescriptor | BooleanFieldDescriptor | IntegerFieldDescriptor | EnumFieldDescriptor;

export type EnvironmentSchema = Readonly<Record<string, EnvironmentFieldDescriptor>>;

export const SERVER_CONFIG_PREFIX = "SYNTHESIS_";
export const PUBLIC_CONFIG_PREFIX = "SYNTHESIS_PUBLIC_";
export const SECRET_CONFIG_PREFIX = "SYNTHESIS_SECRET_";
export const INTERNAL_CONFIG_PREFIX = "SYNTHESIS_INTERNAL_";
export const TEST_CONFIG_PREFIX = "SYNTHESIS_TEST_";

export type ValidationErrorCode =
  | "MISSING_REQUIRED_VARIABLE"
  | "INVALID_BOOLEAN_VALUE"
  | "INVALID_INTEGER_VALUE"
  | "INVALID_ENUM_VALUE"
  | "UNKNOWN_SYNTHESIS_VARIABLE"
  | "PREFIX_CATEGORY_MISMATCH"
  | "TEST_ONLY_DISALLOWED_IN_RUNTIME"
  | "INVALID_PUBLIC_PROJECTION_SOURCE";

export class EnvironmentValidationError extends Error {
  public readonly variableName: string;
  public readonly code: ValidationErrorCode;
  public readonly reason: string;

  constructor(variableName: string, code: ValidationErrorCode, reason: string) {
    super(`Environment validation error [${code}] for variable "${variableName}": ${reason}`);
    this.name = "EnvironmentValidationError";
    this.variableName = variableName;
    this.code = code;
    this.reason = reason;
  }
}

/**
 * Module-private WeakMap binding validated configuration objects to their authoritative schema
 * and validation-time captured PUBLIC_SAFE key set.
 *
 * This WeakMap is never exported and guarantees that unvalidated, foreign, or mutated objects
 * cannot be projected.
 */
const validatedConfigBindings = new WeakMap<
  object,
  {
    readonly schema: EnvironmentSchema;
    readonly publicKeys: ReadonlySet<string>;
  }
>();

/**
 * Validates that the variable key prefix matches the declared configuration category.
 */
export function validateCategoryPrefixMatch(key: string, category: ConfigCategory): void {
  switch (category) {
    case "PUBLIC_SAFE": {
      if (!key.startsWith(PUBLIC_CONFIG_PREFIX)) {
        throw new EnvironmentValidationError(
          key,
          "PREFIX_CATEGORY_MISMATCH",
          `PUBLIC_SAFE variables must start with prefix "${PUBLIC_CONFIG_PREFIX}"`,
        );
      }
      break;
    }
    case "SECRET_SERVER_ONLY": {
      if (!key.startsWith(SECRET_CONFIG_PREFIX)) {
        throw new EnvironmentValidationError(
          key,
          "PREFIX_CATEGORY_MISMATCH",
          `SECRET_SERVER_ONLY variables must start with prefix "${SECRET_CONFIG_PREFIX}"`,
        );
      }
      break;
    }
    case "INTERNAL_RUNTIME": {
      if (!key.startsWith(INTERNAL_CONFIG_PREFIX)) {
        throw new EnvironmentValidationError(
          key,
          "PREFIX_CATEGORY_MISMATCH",
          `INTERNAL_RUNTIME variables must start with prefix "${INTERNAL_CONFIG_PREFIX}"`,
        );
      }
      break;
    }
    case "TEST_ONLY": {
      if (!key.startsWith(TEST_CONFIG_PREFIX)) {
        throw new EnvironmentValidationError(
          key,
          "PREFIX_CATEGORY_MISMATCH",
          `TEST_ONLY variables must start with prefix "${TEST_CONFIG_PREFIX}"`,
        );
      }
      break;
    }
    case "SERVER_ONLY": {
      if (!key.startsWith(SERVER_CONFIG_PREFIX)) {
        throw new EnvironmentValidationError(
          key,
          "PREFIX_CATEGORY_MISMATCH",
          `SERVER_ONLY variables must start with prefix "${SERVER_CONFIG_PREFIX}"`,
        );
      }
      // Cannot collide with reserved more-specific prefixes
      if (
        key.startsWith(PUBLIC_CONFIG_PREFIX) ||
        key.startsWith(SECRET_CONFIG_PREFIX) ||
        key.startsWith(INTERNAL_CONFIG_PREFIX) ||
        key.startsWith(TEST_CONFIG_PREFIX)
      ) {
        throw new EnvironmentValidationError(
          key,
          "PREFIX_CATEGORY_MISMATCH",
          `SERVER_ONLY variable "${key}" collides with a reserved specific prefix`,
        );
      }
      break;
    }
  }
}

/**
 * Validates an environment source against an environment schema.
 * Returns a frozen, authoritative configuration object bound to the provided schema.
 */
export function validateEnvironment(
  schema: EnvironmentSchema,
  source: EnvSource,
  options: { mode?: ValidationMode } = {},
): Readonly<Record<string, unknown>> {
  const mode = options.mode ?? "runtime";
  const result: Record<string, unknown> = {};

  // 1. Verify all declared fields in schema
  for (const [key, descriptor] of Object.entries(schema)) {
    validateCategoryPrefixMatch(key, descriptor.category);

    if (descriptor.category === "TEST_ONLY" && mode === "runtime") {
      throw new EnvironmentValidationError(
        key,
        "TEST_ONLY_DISALLOWED_IN_RUNTIME",
        "TEST_ONLY variables are forbidden in runtime validation mode",
      );
    }

    const rawValue = source[key];

    if (rawValue === undefined) {
      if (descriptor.default !== undefined) {
        result[key] = descriptor.default;
      } else if (descriptor.required) {
        throw new EnvironmentValidationError(
          key,
          "MISSING_REQUIRED_VARIABLE",
          "Required environment variable is missing or undefined",
        );
      }
      continue;
    }

    // Parse and validate type
    switch (descriptor.type) {
      case "string": {
        result[key] = rawValue;
        break;
      }
      case "boolean": {
        if (rawValue === "true") {
          result[key] = true;
        } else if (rawValue === "false") {
          result[key] = false;
        } else {
          throw new EnvironmentValidationError(
            key,
            "INVALID_BOOLEAN_VALUE",
            'Boolean environment variables must be strictly "true" or "false"',
          );
        }
        break;
      }
      case "integer": {
        // Strict canonical decimal integer: "0" or non-zero integer with optional leading minus.
        // No leading/trailing whitespace, no explicit "+", no leading zeros, no "-0".
        if (!/^(0|-?[1-9]\d*)$/.test(rawValue)) {
          throw new EnvironmentValidationError(
            key,
            "INVALID_INTEGER_VALUE",
            "Integer environment variable contains invalid syntax or non-canonical representation",
          );
        }
        const parsed = Number(rawValue);
        if (!Number.isFinite(parsed) || !Number.isSafeInteger(parsed) || Object.is(parsed, -0)) {
          throw new EnvironmentValidationError(
            key,
            "INVALID_INTEGER_VALUE",
            "Integer environment variable must be a safe finite integer",
          );
        }
        result[key] = parsed;
        break;
      }
      case "enum": {
        const enumDescriptor = descriptor;
        if (!enumDescriptor.enumValues.includes(rawValue)) {
          throw new EnvironmentValidationError(
            key,
            "INVALID_ENUM_VALUE",
            `Enum variable must be one of declared allowed values: [${enumDescriptor.enumValues.join(", ")}]`,
          );
        }
        result[key] = rawValue;
        break;
      }
    }
  }

  // 2. Fail closed for unknown SYNTHESIS_ prefixed variables in source
  for (const key of Object.keys(source)) {
    if (key.startsWith(SERVER_CONFIG_PREFIX)) {
      if (!Object.prototype.hasOwnProperty.call(schema, key)) {
        throw new EnvironmentValidationError(
          key,
          "UNKNOWN_SYNTHESIS_VARIABLE",
          "Unknown variable starting with SYNTHESIS_ namespace is not declared in schema",
        );
      }
    }
  }

  // 3. Freeze result object
  const frozenResult = Object.freeze(result);

  // 4. Capture PUBLIC_SAFE keys at validation time
  const publicKeys = new Set<string>();
  for (const [key, descriptor] of Object.entries(schema)) {
    if (
      descriptor.category === "PUBLIC_SAFE" &&
      Object.prototype.hasOwnProperty.call(frozenResult, key)
    ) {
      publicKeys.add(key);
    }
  }

  // 5. Bind the frozen result to the schema and captured PUBLIC_SAFE key set
  validatedConfigBindings.set(frozenResult, {
    schema,
    publicKeys: Object.freeze(publicKeys),
  });

  // 6. Return the frozen bound result
  return frozenResult;
}

/**
 * Projects only PUBLIC_SAFE properties from a validated configuration bound to the declared schema.
 * Fail-closed if the input is not a validated configuration object or if the schema instance differs.
 */
export function projectPublicEnvironment(
  schema: EnvironmentSchema,
  validatedConfig: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
  // 1. Look up validatedConfig in module-private binding
  const candidate: unknown = validatedConfig;
  if (!candidate || typeof candidate !== "object" || !validatedConfigBindings.has(candidate)) {
    throw new EnvironmentValidationError(
      "",
      "INVALID_PUBLIC_PROJECTION_SOURCE",
      "Configuration object is not a validated configuration bound to an environment schema",
    );
  }

  const binding = validatedConfigBindings.get(candidate);
  if (!binding) {
    throw new EnvironmentValidationError(
      "",
      "INVALID_PUBLIC_PROJECTION_SOURCE",
      "Configuration object has no valid schema binding",
    );
  }

  // 2. Verify schema instance identity match
  if (binding.schema !== schema) {
    throw new EnvironmentValidationError(
      "",
      "INVALID_PUBLIC_PROJECTION_SOURCE",
      "Validated configuration schema instance does not match the provided schema",
    );
  }

  // 3. Project ONLY keys snapshotted at validation time in binding.publicKeys
  const publicConfig: Record<string, unknown> = {};
  for (const key of binding.publicKeys) {
    if (Object.prototype.hasOwnProperty.call(validatedConfig, key)) {
      publicConfig[key] = validatedConfig[key];
    }
  }

  // 4. Return frozen projection
  return Object.freeze(publicConfig);
}
