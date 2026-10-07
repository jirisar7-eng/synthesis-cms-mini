/**
 * Synthesis CMS mini — Environment Contract Entrypoint
 */

export type {
  EnvSource,
  ConfigCategory,
  ConfigFieldType,
  ValidationMode,
  BaseFieldDescriptor,
  StringFieldDescriptor,
  BooleanFieldDescriptor,
  IntegerFieldDescriptor,
  EnumFieldDescriptor,
  EnvironmentFieldDescriptor,
  EnvironmentSchema,
  ValidationErrorCode,
} from "./env.contract.ts";

export {
  SERVER_CONFIG_PREFIX,
  PUBLIC_CONFIG_PREFIX,
  SECRET_CONFIG_PREFIX,
  INTERNAL_CONFIG_PREFIX,
  TEST_CONFIG_PREFIX,
  EnvironmentValidationError,
  validateCategoryPrefixMatch,
  validateEnvironment,
  projectPublicEnvironment,
} from "./env.contract.ts";
