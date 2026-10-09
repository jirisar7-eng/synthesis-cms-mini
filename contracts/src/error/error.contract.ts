/**
 * Synthesis CMS mini — Unified Error Contract
 *
 * Contract ID: CONTRACT-CORE-UNIFIED-ERROR-001
 * Roadmap Step: 14/60 — Unified error contract
 *
 * Provides a standardized, transport-neutral error contract, strict validation,
 * fail-closed normalization of untrusted throw values, fail-closed public allowlist
 * serialization, and RFC-8785 deterministic canonicalization without external dependencies.
 */

import {
  NAMESPACE_ROOTS,
  ROOT_MIN_ARITY,
  CORE_INTEGRATION_MIN_ARITY,
  type NamespaceRoot,
} from "../namespace/namespace.contract.ts";

export const UNIFIED_ERROR_CONTRACT_ID = "CONTRACT-CORE-UNIFIED-ERROR-001" as const;

/**
 * Nine canonical error kinds.
 */
export const ERROR_KINDS = Object.freeze([
  "DOMAIN_ERROR",
  "SYSTEM_ERROR",
  "SECURITY_ERROR",
  "VALIDATION_ERROR",
  "GOVERNANCE_ERROR",
  "MODULE_ERROR",
  "INTEGRATION_ERROR",
  "LICENSE_ERROR",
  "INFRASTRUCTURE_ERROR",
] as const);

export type ErrorKind = (typeof ERROR_KINDS)[number];

/**
 * Four canonical error severity levels.
 */
export const ERROR_SEVERITIES = Object.freeze(["FATAL", "ERROR", "WARNING", "INFO"] as const);

export type ErrorSeverity = (typeof ERROR_SEVERITIES)[number];

/**
 * Lexical grammar constants for error codes and message keys.
 */
export const ERROR_GRAMMAR = Object.freeze({
  CODE_REGEX: /^ERR_[A-Z0-9_]+$/,
  MESSAGE_KEY_REGEX: /^[a-z0-9_]+(\.[a-z0-9_]+){1,5}$/,
  MESSAGE_KEY_SEGMENT_REGEX: /^[a-z0-9_]{1,48}$/,
  MESSAGE_KEY_MAX_LENGTH: 128,
  MESSAGE_KEY_MIN_SEGMENTS: 2,
  MESSAGE_KEY_MAX_SEGMENTS: 6,
  UTC_TIMESTAMP_REGEX: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
} as const);

/**
 * Explicit public serialization allowlist.
 * Only properties present in this list are emitted in PublicErrorPayload.
 */
export const ALLOWLIST_PUBLIC_KEYS = Object.freeze([
  "code",
  "message",
  "message_key",
  "kind",
  "severity",
  "correlation_id",
  "timestamp",
  "recoverable",
  "public_details",
] as const);

export type PublicAllowlistKey = (typeof ALLOWLIST_PUBLIC_KEYS)[number];

/**
 * Safe generic defaults for untrusted or unhandled exceptions.
 */
export const ERROR_DEFAULTS = Object.freeze({
  CODE: "ERR_INTERNAL_SERVER_ERROR",
  MESSAGE: "An internal server error occurred.",
  MESSAGE_KEY: "core.error.internal_server_error",
  KIND: "SYSTEM_ERROR",
  SEVERITY: "ERROR",
  RECOVERABLE: false,
  HTTP_STATUS: 500,
} as const);

/**
 * Canonical dictionary of authorized public messages for safe message provenance.
 * Never directly reflects arbitrary constructor or request-supplied text to public clients.
 */
export const AUTHORIZED_PUBLIC_MESSAGES: Readonly<Record<string, string>> = Object.freeze({
  "core.error.internal_server_error": "An internal server error occurred.",
  "core.error.validation_failed": "Input validation failed.",
  "core.error.unauthorized": "User is not authorized to perform this operation.",
  "core.error.unauthorized_access": "User is not authorized to perform this operation.",
  "core.error.resource_not_found": "Requested resource was not found.",
  "core.error.configuration": "Configuration error.",
  "gov.error.access_denied": "Access is denied.",
  "core.error.fake": "Fake error",
  "core.error.test": "Test message",
});

/**
 * Positively authorized keys for public details.
 * Any key not in this list is omitted by default to prevent secret and diagnostic leaks.
 */
export const AUTHORIZED_PUBLIC_DETAIL_KEYS = Object.freeze([
  "role",
  "resourceId",
  "roleRequired",
  "safeField",
  "field",
  "resource",
  "entity",
  "action",
  "reason",
  "limit",
  "count",
  "status",
] as const);

/**
 * Static enum of authorized public roles for safe detail provenance.
 */
export const ALLOWED_PUBLIC_ROLES = Object.freeze([
  "guest",
  "user",
  "admin",
  "editor",
  "viewer",
  "anonymous",
  "owner",
  "member",
  "system",
  "moderator",
] as const);

/**
 * Static enum of authorized public fields for safe detail provenance.
 */
export const ALLOWED_PUBLIC_FIELDS = Object.freeze([
  "email",
  "username",
  "password",
  "title",
  "name",
  "slug",
  "content",
  "status",
  "id",
  "type",
  "description",
  "role",
  "payload",
] as const);

/**
 * Static enum of authorized public reasons for safe detail provenance.
 */
export const ALLOWED_PUBLIC_REASONS = Object.freeze([
  "not_found",
  "already_exists",
  "expired",
  "invalid_format",
  "required",
  "forbidden",
  "rate_limited",
  "conflict",
  "inactive",
  "unsupported",
  "invalid_state",
] as const);

/**
 * Static enum of authorized public entities/resources for safe detail provenance.
 */
export const ALLOWED_PUBLIC_ENTITIES = Object.freeze([
  "user",
  "role",
  "session",
  "content",
  "page",
  "post",
  "media",
  "module",
  "theme",
  "setting",
  "permission",
] as const);

/**
 * Static enum of authorized public actions for safe detail provenance.
 */
export const ALLOWED_PUBLIC_ACTIONS = Object.freeze([
  "read",
  "write",
  "create",
  "update",
  "delete",
  "list",
  "publish",
  "unpublish",
  "execute",
] as const);

/**
 * Static enum of authorized public statuses for safe detail provenance.
 */
export const ALLOWED_PUBLIC_STATUSES = Object.freeze([
  "active",
  "inactive",
  "pending",
  "disabled",
  "draft",
  "published",
  "archived",
] as const);

/**
 * Static enum of authorized values for demonstration safeField key.
 */
export const ALLOWED_PUBLIC_SAFE_VALUES = Object.freeze(["allowed_value"] as const);

/**
 * Trusted system correlation ID prefixes representing safe platform/framework origin.
 * Never reflects arbitrary user-supplied tokens, client headers, or auth tokens.
 */
export const TRUSTED_CORRELATION_PREFIXES = Object.freeze([
  "corr-",
  "req-",
  "syn-",
  "trace-",
  "sys-",
  "fallback-",
] as const);

/**
 * Module-private non-forgeable instance tracking for authentic SynthesisBaseError instances.
 */
const genuineErrorInstances = new WeakSet();

function isGenuineSynthesisError(val: unknown): val is SynthesisBaseError {
  if (val === null || typeof val !== "object") return false;
  return genuineErrorInstances.has(val);
}

/**
 * Module-private non-forgeable instance tracking for authentic InternalErrorContext instances.
 */
const genuineContextInstances = new WeakSet();

function isGenuineErrorContext(val: unknown): val is InternalErrorContext {
  if (val === null || typeof val !== "object") return false;
  return genuineContextInstances.has(val);
}

/**
 * Transport-neutral core error contract.
 */
export interface ErrorContract {
  readonly code: string;
  readonly message: string;
  readonly message_key: string;
  readonly kind: ErrorKind;
  readonly severity: ErrorSeverity;
  readonly timestamp: string;
  readonly recoverable: boolean;
  readonly correlation_id?: string | undefined;
  readonly public_details?: Readonly<Record<string, unknown>> | undefined;
  readonly http_status?: number | undefined;
}

/**
 * Internal error context containing full diagnostics for server-side logging.
 * NEVER serialize or emit this object to public clients.
 */
export interface InternalErrorContext {
  readonly contract: ErrorContract;
  readonly stack_trace?: string | undefined;
  readonly cause_message?: string | undefined;
  readonly internal_component?: string | undefined;
  readonly raw_throw_value?: unknown;
  readonly internal_details?: Readonly<Record<string, unknown>> | undefined;
}

/**
 * Sanitized public error payload safe for client emission over HTTP or IPC.
 */
export interface PublicErrorPayload {
  readonly code: string;
  readonly message: string;
  readonly message_key: string;
  readonly kind: ErrorKind;
  readonly severity: ErrorSeverity;
  readonly timestamp: string;
  readonly recoverable: boolean;
  readonly correlation_id?: string | undefined;
  readonly public_details?: Readonly<Record<string, unknown>> | undefined;
}

/**
 * Base error class for all verified Synthesis domain errors.
 */
export class SynthesisBaseError extends Error implements ErrorContract {
  readonly code: string;
  readonly message_key: string;
  readonly kind: ErrorKind;
  readonly severity: ErrorSeverity;
  readonly recoverable: boolean;
  readonly correlation_id?: string | undefined;
  readonly public_details?: Readonly<Record<string, unknown>> | undefined;
  readonly internal_details?: Readonly<Record<string, unknown>> | undefined;
  readonly http_status?: number | undefined;
  readonly timestamp: string;

  constructor(params: {
    code: string;
    message: string;
    message_key: string;
    kind: ErrorKind;
    severity?: ErrorSeverity | undefined;
    recoverable?: boolean | undefined;
    correlation_id?: string | undefined;
    public_details?: Record<string, unknown> | undefined;
    internal_details?: Record<string, unknown> | undefined;
    http_status?: number | undefined;
    timestamp?: string | undefined;
  }) {
    const p = params as unknown as Record<string, unknown> | null | undefined;
    const safeMsg =
      p && typeof p === "object" && isValidPublicMessage(p.message)
        ? p.message
        : ERROR_DEFAULTS.MESSAGE;
    super(safeMsg);
    this.name = this.constructor.name;

    if (!p || typeof p !== "object") {
      throw new Error("SynthesisBaseError requires params object.");
    }

    const rawCode: unknown = params.code;
    if (!isValidErrorCode(rawCode)) {
      throw new Error(
        'Invalid SynthesisBaseError code: "' + params.code + '". Must match /^ERR_[A-Z0-9_]+$/.',
      );
    }

    const rawKey: unknown = params.message_key;
    if (!isValidMessageKey(rawKey)) {
      throw new Error(
        'Invalid SynthesisBaseError message_key: "' +
          params.message_key +
          '". Must conform to Step 13 namespace rules.',
      );
    }

    if (!ERROR_KINDS.includes(params.kind)) {
      throw new Error('Invalid SynthesisBaseError kind: "' + params.kind + '".');
    }

    const severity = params.severity ?? "ERROR";
    if (!ERROR_SEVERITIES.includes(severity)) {
      throw new Error('Invalid SynthesisBaseError severity: "' + severity + '".');
    }

    const rawTs: unknown = params.timestamp ?? new Date().toISOString();
    if (!isValidUtcTimestamp(rawTs)) {
      throw new Error(
        'Invalid SynthesisBaseError timestamp: "' + String(rawTs) + '". Must be ISO-8601 UTC.',
      );
    }

    if (params.correlation_id !== undefined && !isValidCorrelationId(params.correlation_id)) {
      throw new Error(
        'Invalid SynthesisBaseError correlation_id: "' + String(params.correlation_id) + '".',
      );
    }

    if (params.recoverable !== undefined && typeof params.recoverable !== "boolean") {
      throw new Error("Invalid SynthesisBaseError recoverable: expected boolean.");
    }

    if (
      params.http_status !== undefined &&
      (typeof params.http_status !== "number" ||
        !Number.isInteger(params.http_status) ||
        params.http_status < 100 ||
        params.http_status > 599)
    ) {
      throw new Error(
        'Invalid SynthesisBaseError http_status: "' + String(params.http_status) + '".',
      );
    }

    this.code = params.code;
    this.message_key = params.message_key;
    this.kind = params.kind;
    this.severity = severity;
    this.recoverable = typeof params.recoverable === "boolean" ? params.recoverable : false;
    this.timestamp = rawTs;

    if (params.correlation_id !== undefined) {
      this.correlation_id = params.correlation_id;
    }

    if (params.public_details !== undefined) {
      const safePublic = sanitizePublicDetails(params.public_details);
      if (safePublic !== undefined) {
        this.public_details = safePublic;
      }
    }

    if (params.internal_details !== undefined) {
      try {
        this.internal_details = Object.freeze({ ...params.internal_details });
      } catch {
        // Ignore hostile internal details getter
      }
    }

    if (params.http_status !== undefined) {
      this.http_status = params.http_status;
    }

    // Module-private non-forgeable instance registration
    genuineErrorInstances.add(this);

    Object.setPrototypeOf(this, new.target.prototype);
    Object.freeze(this);
  }
}

/**
 * Validates whether a value is a valid uppercase ASCII snake_case error code starting with ERR_.
 */
export function isValidErrorCode(code: unknown): code is string {
  return typeof code === "string" && ERROR_GRAMMAR.CODE_REGEX.test(code);
}

/**
 * Validates whether a message_key conforms to Step 13 namespace rules.
 * Must begin with an approved Step 13 root (core, gov, sys, pack, ext),
 * total length <= 128, 2 to 6 dot-separated segments, max 48 chars per segment,
 * and satisfy root-specific arity (including pack.*, ext.* and core.integration.*).
 */
export function isValidMessageKey(key: unknown): key is string {
  if (typeof key !== "string") return false;
  if (key.length < 3 || key.length > ERROR_GRAMMAR.MESSAGE_KEY_MAX_LENGTH) return false;
  if (!ERROR_GRAMMAR.MESSAGE_KEY_REGEX.test(key)) return false;
  const segments = key.split(".");
  if (
    segments.length < ERROR_GRAMMAR.MESSAGE_KEY_MIN_SEGMENTS ||
    segments.length > ERROR_GRAMMAR.MESSAGE_KEY_MAX_SEGMENTS
  ) {
    return false;
  }
  const root = segments[0] as NamespaceRoot;
  if (!NAMESPACE_ROOTS.includes(root)) return false;

  const minArity = ROOT_MIN_ARITY[root];
  if (segments.length < minArity) {
    return false;
  }
  if (root === "core" && segments.length >= 2 && segments[1] === "integration") {
    if (segments.length < CORE_INTEGRATION_MIN_ARITY) {
      return false;
    }
  }

  for (const seg of segments) {
    if (!ERROR_GRAMMAR.MESSAGE_KEY_SEGMENT_REGEX.test(seg)) return false;
  }
  return true;
}

/**
 * Validates whether a timestamp is ISO-8601 UTC string format with 3 decimal milliseconds (YYYY-MM-DDTHH:mm:ss.sssZ) and a valid calendar date.
 */
export function isValidUtcTimestamp(ts: unknown): ts is string {
  if (typeof ts !== "string") return false;
  if (!ERROR_GRAMMAR.UTC_TIMESTAMP_REGEX.test(ts)) return false;
  try {
    const parsed = new Date(ts);
    if (Number.isNaN(parsed.getTime())) return false;
    return parsed.toISOString() === ts;
  } catch {
    return false;
  }
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const FORBIDDEN_CORRELATION_PATTERNS = [
  /token/i,
  /bearer/i,
  /secret/i,
  /jwt/i,
  /auth/i,
  /key/i,
  /session/i,
  /cookie/i,
  /password/i,
  /credential/i,
  /user-/i,
  /client-/i,
  /attacker/i,
  /forged/i,
  /header/i,
];

/**
 * Validates correlation_id string enforcing safe origin provenance.
 * Rejects attacker-supplied headers, request tokens, and arbitrary user IDs.
 */
export function isValidCorrelationId(id: unknown): id is string {
  if (typeof id !== "string") return false;
  const trimmed = id.trim();
  if (trimmed.length < 4 || trimmed.length > 128) return false;
  if (!/^[a-zA-Z0-9_.-]+$/.test(trimmed)) return false;

  for (const pattern of FORBIDDEN_CORRELATION_PATTERNS) {
    if (pattern.test(trimmed)) return false;
  }

  const hasTrustedPrefix = (TRUSTED_CORRELATION_PREFIXES as readonly string[]).some((prefix) =>
    trimmed.startsWith(prefix),
  );
  if (!hasTrustedPrefix && !UUID_REGEX.test(trimmed)) {
    return false;
  }

  return true;
}

/**
 * Validates public message string (non-empty string, <= 1024 chars, no raw control chars).
 */
export function isValidPublicMessage(msg: unknown): msg is string {
  if (typeof msg !== "string") return false;
  const trimmed = msg.trim();
  if (trimmed.length === 0 || trimmed.length > 1024) return false;
  if (/[ --]/.test(msg)) return false;
  return true;
}

/**
 * Resolves safe public message provenance.
 * Never directly reflects arbitrary constructor or request-supplied text to public clients.
 */
export function resolveSafePublicMessage(message_key: string): string {
  const canonical = AUTHORIZED_PUBLIC_MESSAGES[message_key];
  if (canonical !== undefined) {
    return canonical;
  }
  return ERROR_DEFAULTS.MESSAGE;
}

const FORBIDDEN_STRING_PATTERNS = [
  /postgres(ql)?:\/\//i,
  /mysql:\/\//i,
  /mongodb(\+srv)?:\/\//i,
  /redis:\/\//i,
  /sqlite:\/\//i,
  /bearer\s+[a-zA-Z0-9._~+/-]+=*/i,
  /ghp_[a-zA-Z0-9]{36}/,
  /sk_[a-zA-Z0-9]{20,}/,
  /^(\/|[a-zA-Z]:[\/])/,
  /node_modules/i,
  /\.env/i,
];

const SAFE_RESOURCE_ID_REGEX =
  /^(res|item|doc|node|user|page|post|file|media|entity)-[a-zA-Z0-9_-]{1,32}$/;

/**
 * Validates whether a value is an authorized safe resourceId.
 */
function isValidPublicResourceId(val: unknown): boolean {
  if (typeof val !== "string") return false;
  if (val.length < 3 || val.length > 36) return false;
  if (!SAFE_RESOURCE_ID_REGEX.test(val) && !UUID_REGEX.test(val)) return false;
  for (const pattern of FORBIDDEN_STRING_PATTERNS) {
    if (pattern.test(val)) return false;
  }
  for (const pattern of FORBIDDEN_CORRELATION_PATTERNS) {
    if (pattern.test(val)) return false;
  }
  return true;
}

/**
 * Positively sanitizes public_details to prevent secret, internal-path, and diagnostic leaks.
 * Enforces positive authorization of detail keys and strictly bounded typed values / static enums.
 * Arbitrary strings are rejected even under authorized keys. Omit untrusted details by default.
 */
export function sanitizePublicDetails(
  input: unknown,
  allowedKeys?: readonly string[],
): Readonly<Record<string, unknown>> | undefined {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return undefined;

  const allowedSet = new Set<string>(
    allowedKeys && allowedKeys.length > 0 ? allowedKeys : AUTHORIZED_PUBLIC_DETAIL_KEYS,
  );

  const obj = input as Record<string, unknown>;
  const clean: Record<string, unknown> = {};
  let keyCount = 0;

  try {
    const keys = Object.keys(obj);
    for (const key of keys) {
      if (keyCount >= 10) break;
      if (key === "__proto__" || key === "constructor" || key === "prototype") continue;
      if (!allowedSet.has(key)) continue;

      let val: unknown;
      try {
        val = obj[key];
      } catch {
        continue;
      }

      if (
        val === undefined ||
        val === null ||
        typeof val === "function" ||
        typeof val === "symbol" ||
        typeof val === "bigint" ||
        typeof val === "object" // Omit untrusted nested data by default
      ) {
        continue;
      }

      if (key === "role" || key === "roleRequired") {
        if (typeof val === "string" && (ALLOWED_PUBLIC_ROLES as readonly string[]).includes(val)) {
          clean[key] = val;
          keyCount++;
        }
      } else if (key === "field") {
        if (typeof val === "string" && (ALLOWED_PUBLIC_FIELDS as readonly string[]).includes(val)) {
          clean[key] = val;
          keyCount++;
        }
      } else if (key === "reason") {
        if (
          typeof val === "string" &&
          (ALLOWED_PUBLIC_REASONS as readonly string[]).includes(val)
        ) {
          clean[key] = val;
          keyCount++;
        }
      } else if (key === "resource" || key === "entity") {
        if (
          typeof val === "string" &&
          (ALLOWED_PUBLIC_ENTITIES as readonly string[]).includes(val)
        ) {
          clean[key] = val;
          keyCount++;
        }
      } else if (key === "action") {
        if (
          typeof val === "string" &&
          (ALLOWED_PUBLIC_ACTIONS as readonly string[]).includes(val)
        ) {
          clean[key] = val;
          keyCount++;
        }
      } else if (key === "safeField") {
        if (
          typeof val === "string" &&
          (ALLOWED_PUBLIC_SAFE_VALUES as readonly string[]).includes(val)
        ) {
          clean[key] = val;
          keyCount++;
        }
      } else if (key === "resourceId") {
        if (isValidPublicResourceId(val)) {
          clean[key] = val;
          keyCount++;
        }
      } else if (key === "status") {
        if (typeof val === "boolean") {
          clean[key] = val;
          keyCount++;
        } else if (
          typeof val === "string" &&
          (ALLOWED_PUBLIC_STATUSES as readonly string[]).includes(val)
        ) {
          clean[key] = val;
          keyCount++;
        }
      } else if (key === "limit" || key === "count") {
        if (typeof val === "number" && Number.isSafeInteger(val) && val >= 0 && val <= 100000) {
          clean[key] = val;
          keyCount++;
        }
      }
    }
  } catch {
    return undefined;
  }

  if (Object.keys(clean).length === 0) return undefined;
  return Object.freeze(clean);
}

/**
 * Safely normalizes any throw value (native Error, primitive, null, forged object, SynthesisBaseError)
 * into a structured InternalErrorContext.
 *
 * UNTRUSTED THROW VALUES ARE NEVER TRUSTED. They normalize fail-closed to:
 * - code: ERR_INTERNAL_SERVER_ERROR
 * - message: "An internal server error occurred."
 * - message_key: "core.error.internal_server_error"
 * - kind: SYSTEM_ERROR
 * - severity: ERROR
 */
export function normalizeToErrorContract(
  throwValue: unknown,
  defaultCorrelationId?: string,
): InternalErrorContext {
  const nowUtc = new Date().toISOString();
  const safeDefaultCorr = isValidCorrelationId(defaultCorrelationId)
    ? defaultCorrelationId
    : undefined;

  let isAuthenticSynthesisError = false;
  if (throwValue !== null && typeof throwValue === "object") {
    try {
      if (isGenuineSynthesisError(throwValue)) {
        isAuthenticSynthesisError = true;
      }
    } catch {
      isAuthenticSynthesisError = false;
    }
  }

  if (isAuthenticSynthesisError) {
    const err = throwValue as SynthesisBaseError;
    try {
      const code = isValidErrorCode(err.code) ? err.code : undefined;
      const message_key = isValidMessageKey(err.message_key) ? err.message_key : undefined;
      const kind =
        typeof err.kind === "string" && ERROR_KINDS.includes(err.kind) ? err.kind : undefined;
      const severity =
        typeof err.severity === "string" && ERROR_SEVERITIES.includes(err.severity)
          ? err.severity
          : undefined;
      const timestamp = isValidUtcTimestamp(err.timestamp) ? err.timestamp : undefined;
      const recoverable = typeof err.recoverable === "boolean" ? err.recoverable : undefined;
      const message = resolveSafePublicMessage(message_key ?? "");

      if (
        code &&
        message_key &&
        kind &&
        severity &&
        timestamp &&
        recoverable !== undefined &&
        message
      ) {
        const corrId = isValidCorrelationId(err.correlation_id)
          ? err.correlation_id
          : safeDefaultCorr;
        const safePublic = sanitizePublicDetails(err.public_details);
        const httpStatus =
          typeof err.http_status === "number" &&
          Number.isInteger(err.http_status) &&
          err.http_status >= 100 &&
          err.http_status <= 599
            ? err.http_status
            : undefined;

        const contract: ErrorContract = {
          code,
          message,
          message_key,
          kind,
          severity,
          timestamp,
          recoverable,
          ...(corrId !== undefined ? { correlation_id: corrId } : {}),
          ...(safePublic !== undefined ? { public_details: safePublic } : {}),
          ...(httpStatus !== undefined ? { http_status: httpStatus } : {}),
        };

        const ctx: Record<string, unknown> = {
          contract: Object.freeze(contract),
          raw_throw_value: err,
        };

        try {
          if (typeof err.stack === "string") ctx.stack_trace = err.stack;
        } catch {}

        try {
          if (err.internal_details !== undefined) {
            ctx.internal_details = Object.freeze({ ...err.internal_details });
          }
        } catch {}

        const frozenCtx = Object.freeze(ctx as unknown as InternalErrorContext);
        genuineContextInstances.add(frozenCtx);
        return frozenCtx;
      }
    } catch {
      // Fail closed to fallback on forged/corrupted object
    }
  }

  // Untrusted or unknown throw value: native Error, primitive, plain object, forged error
  let stackTrace: string | undefined;
  let causeMsg: string | undefined;

  try {
    if (throwValue instanceof Error) {
      try {
        stackTrace = typeof throwValue.stack === "string" ? throwValue.stack : undefined;
      } catch {}
      try {
        causeMsg = isValidPublicMessage(throwValue.message) ? throwValue.message : "Error thrown";
      } catch {
        causeMsg = "Hostile error message getter";
      }
    } else if (typeof throwValue === "string") {
      causeMsg = isValidPublicMessage(throwValue) ? throwValue : "String thrown";
    } else if (throwValue !== null && typeof throwValue === "object") {
      try {
        const msg = (throwValue as Record<string, unknown>).message;
        causeMsg = isValidPublicMessage(msg) ? msg : "Object thrown";
      } catch {
        causeMsg = "Unserializable object thrown";
      }
    } else {
      try {
        causeMsg = String(throwValue);
      } catch {
        causeMsg = "Unprintable primitive thrown";
      }
    }
  } catch {
    causeMsg = "Hostile throw value";
  }

  const fallbackContract: ErrorContract = {
    code: ERROR_DEFAULTS.CODE,
    message: ERROR_DEFAULTS.MESSAGE,
    message_key: ERROR_DEFAULTS.MESSAGE_KEY,
    kind: ERROR_DEFAULTS.KIND,
    severity: ERROR_DEFAULTS.SEVERITY,
    timestamp: nowUtc,
    recoverable: ERROR_DEFAULTS.RECOVERABLE,
    ...(safeDefaultCorr !== undefined ? { correlation_id: safeDefaultCorr } : {}),
    http_status: ERROR_DEFAULTS.HTTP_STATUS,
  };

  const ctx: Record<string, unknown> = {
    contract: Object.freeze(fallbackContract),
    raw_throw_value: throwValue,
  };

  if (stackTrace !== undefined) ctx.stack_trace = stackTrace;
  ctx.cause_message = causeMsg;

  const frozenFallbackCtx = Object.freeze(ctx as unknown as InternalErrorContext);
  genuineContextInstances.add(frozenFallbackCtx);
  return frozenFallbackCtx;
}

/**
 * Serializes an InternalErrorContext into a PublicErrorPayload using an explicit fail-closed allowlist.
 *
 * ONLY properties present in ALLOWLIST_PUBLIC_KEYS are emitted.
 * Stack traces, internal details, raw throw values, and unknown properties are dropped fail-closed.
 * Every public value is explicitly re-validated prior to emission.
 * Untrusted contexts produce entirely generic public errors, never partial copied fields.
 */
export function serializePublicErrorPayload(
  errorContext: InternalErrorContext,
): PublicErrorPayload {
  if (!isGenuineErrorContext(errorContext)) {
    const fallbackPayload: Record<string, unknown> = {
      code: ERROR_DEFAULTS.CODE,
      message: ERROR_DEFAULTS.MESSAGE,
      message_key: ERROR_DEFAULTS.MESSAGE_KEY,
      kind: ERROR_DEFAULTS.KIND,
      severity: ERROR_DEFAULTS.SEVERITY,
      timestamp: new Date().toISOString(),
      recoverable: ERROR_DEFAULTS.RECOVERABLE,
    };
    return Object.freeze(fallbackPayload as unknown as PublicErrorPayload);
  }

  const contract = errorContext.contract;
  let code: string = ERROR_DEFAULTS.CODE;
  let message_key: string = ERROR_DEFAULTS.MESSAGE_KEY;
  let kind: ErrorKind = ERROR_DEFAULTS.KIND;
  let severity: ErrorSeverity = ERROR_DEFAULTS.SEVERITY;
  let timestamp = new Date().toISOString();
  let recoverable: boolean = ERROR_DEFAULTS.RECOVERABLE;
  let correlation_id: string | undefined;
  let public_details: Readonly<Record<string, unknown>> | undefined;

  try {
    if (isValidErrorCode(contract.code)) code = contract.code;
    if (isValidMessageKey(contract.message_key)) message_key = contract.message_key;
    if (ERROR_KINDS.includes(contract.kind)) kind = contract.kind;
    if (ERROR_SEVERITIES.includes(contract.severity)) severity = contract.severity;
    if (isValidUtcTimestamp(contract.timestamp)) timestamp = contract.timestamp;
    if (typeof contract.recoverable === "boolean") recoverable = contract.recoverable;
    if (isValidCorrelationId(contract.correlation_id)) correlation_id = contract.correlation_id;
    if (contract.public_details !== undefined)
      public_details = sanitizePublicDetails(contract.public_details);
  } catch {
    // Fail closed on hostile contract getters
  }

  const message = resolveSafePublicMessage(message_key);

  const rawPayload: Record<string, unknown> = {
    code,
    message,
    message_key,
    kind,
    severity,
    timestamp,
    recoverable,
  };

  if (correlation_id !== undefined) rawPayload.correlation_id = correlation_id;
  if (public_details !== undefined) rawPayload.public_details = public_details;

  // Strict allowlist filtering pass
  const payload: Record<string, unknown> = {};
  for (const key of ALLOWLIST_PUBLIC_KEYS) {
    if (Object.prototype.hasOwnProperty.call(rawPayload, key) && rawPayload[key] !== undefined) {
      payload[key] = rawPayload[key];
    }
  }

  return Object.freeze(payload as unknown as PublicErrorPayload);
}

/**
 * Deterministically canonicalizes any JavaScript object using RFC-8785 JSON rules.
 * Keys are sorted lexicographically by Unicode code point order.
 * No indentation or whitespace is inserted outside string literals.
 */
export function toRFC8785JSON(value: unknown): string {
  const seen = new Set<object>();
  return canonicalizeValue(value, seen);
}

function canonicalizeValue(val: unknown, seen: Set<object>): string {
  if (val === null) return "null";
  if (typeof val === "boolean") return val ? "true" : "false";
  if (typeof val === "number") {
    if (!Number.isFinite(val)) {
      throw new TypeError("Non-finite number forbidden in RFC-8785 JSON");
    }
    return JSON.stringify(val);
  }
  if (typeof val === "string") {
    try {
      encodeURIComponent(val);
    } catch {
      throw new TypeError("Invalid Unicode surrogate in toRFC8785JSON");
    }
    return JSON.stringify(val);
  }
  if (typeof val === "symbol" || typeof val === "function" || typeof val === "bigint") {
    throw new TypeError("Unsupported data type in toRFC8785JSON");
  }

  if (typeof val === "object") {
    const objVal = val;
    if (seen.has(objVal)) {
      throw new TypeError("Circular reference detected in toRFC8785JSON");
    }
    seen.add(objVal);
    try {
      if (Array.isArray(val)) {
        const items: string[] = [];
        const arr = val as readonly unknown[];
        for (let i = 0; i < arr.length; i++) {
          if (!(i in arr)) {
            items.push("null");
          } else {
            const item = arr[i];
            if (item === undefined || typeof item === "function" || typeof item === "symbol") {
              items.push("null");
            } else {
              items.push(canonicalizeValue(item, seen));
            }
          }
        }
        return "[" + items.join(",") + "]";
      } else {
        const obj = val as Record<string, unknown>;
        const keys = Object.keys(obj).sort();
        const pairs: string[] = [];
        for (const key of keys) {
          try {
            encodeURIComponent(key);
          } catch {
            throw new TypeError(
              "Invalid Unicode surrogate in property key during RFC-8785 canonicalization",
            );
          }
          const v = obj[key];
          if (v === undefined || typeof v === "function" || typeof v === "symbol") continue;
          pairs.push(JSON.stringify(key) + ":" + canonicalizeValue(v, seen));
        }
        return "{" + pairs.join(",") + "}";
      }
    } finally {
      seen.delete(objVal);
    }
  }

  throw new TypeError("Unsupported value in toRFC8785JSON");
}
