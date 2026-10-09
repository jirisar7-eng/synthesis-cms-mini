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

import { NAMESPACE_ROOTS, type NamespaceRoot } from "../namespace/namespace.contract.ts";

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
  UTC_TIMESTAMP_REGEX: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/,
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
    super(params.message);
    this.name = this.constructor.name;

    const rawCode: unknown = params.code;
    if (!isValidErrorCode(rawCode)) {
      throw new Error(
        'Invalid SynthesisBaseError code: "' +
          String(rawCode) +
          '". Must match /^ERR_[A-Z0-9_]+$/.',
      );
    }

    const rawKey: unknown = params.message_key;
    if (!isValidMessageKey(rawKey)) {
      throw new Error(
        'Invalid SynthesisBaseError message_key: "' +
          String(rawKey) +
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
    const timestampStr = rawTs;

    this.code = params.code;
    this.message_key = params.message_key;
    this.kind = params.kind;
    this.severity = severity;
    this.recoverable = params.recoverable ?? false;
    if (params.correlation_id !== undefined) this.correlation_id = params.correlation_id;
    if (params.public_details !== undefined)
      this.public_details = Object.freeze({ ...params.public_details });
    if (params.internal_details !== undefined)
      this.internal_details = Object.freeze({ ...params.internal_details });
    if (params.http_status !== undefined) this.http_status = params.http_status;
    this.timestamp = timestampStr;

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
 * total length <= 128, 2 to 6 dot-separated segments, max 48 chars per segment.
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

  for (const seg of segments) {
    if (!ERROR_GRAMMAR.MESSAGE_KEY_SEGMENT_REGEX.test(seg)) return false;
  }

  return true;
}

/**
 * Validates whether a timestamp is ISO-8601 UTC string format (YYYY-MM-DDTHH:mm:ss.sssZ).
 */
export function isValidUtcTimestamp(ts: unknown): ts is string {
  if (typeof ts !== "string") return false;
  if (!ERROR_GRAMMAR.UTC_TIMESTAMP_REGEX.test(ts)) return false;
  const parsed = Date.parse(ts);
  return !Number.isNaN(parsed);
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

  if (
    throwValue !== null &&
    typeof throwValue === "object" &&
    throwValue instanceof SynthesisBaseError
  ) {
    const err = throwValue;
    const contract: ErrorContract = {
      code: err.code,
      message: err.message,
      message_key: err.message_key,
      kind: err.kind,
      severity: err.severity,
      timestamp: isValidUtcTimestamp(err.timestamp) ? err.timestamp : nowUtc,
      recoverable: err.recoverable,
      ...(err.correlation_id !== undefined
        ? { correlation_id: err.correlation_id }
        : defaultCorrelationId !== undefined
          ? { correlation_id: defaultCorrelationId }
          : {}),
      ...(err.public_details !== undefined ? { public_details: err.public_details } : {}),
      ...(err.http_status !== undefined ? { http_status: err.http_status } : {}),
    };

    const ctx: Record<string, unknown> = {
      contract: Object.freeze(contract),
      raw_throw_value: err,
    };
    if (err.stack !== undefined) ctx.stack_trace = err.stack;
    if (err.internal_details !== undefined) ctx.internal_details = err.internal_details;

    return Object.freeze(ctx as unknown as InternalErrorContext);
  }

  // Untrusted or unknown throw value: native Error, primitive, plain object, forged error
  let stackTrace: string | undefined;
  let causeMsg: string | undefined;

  if (throwValue instanceof Error) {
    stackTrace = throwValue.stack;
    causeMsg = throwValue.message;
  } else if (typeof throwValue === "string") {
    causeMsg = throwValue;
  } else if (throwValue !== null && typeof throwValue === "object") {
    try {
      const msg = (throwValue as { message?: unknown }).message;
      causeMsg = typeof msg === "string" ? msg : "Object thrown";
    } catch {
      causeMsg = "Unserializable object thrown";
    }
  } else {
    causeMsg = String(throwValue);
  }

  const fallbackContract: ErrorContract = {
    code: ERROR_DEFAULTS.CODE,
    message: ERROR_DEFAULTS.MESSAGE,
    message_key: ERROR_DEFAULTS.MESSAGE_KEY,
    kind: ERROR_DEFAULTS.KIND,
    severity: ERROR_DEFAULTS.SEVERITY,
    timestamp: nowUtc,
    recoverable: ERROR_DEFAULTS.RECOVERABLE,
    ...(defaultCorrelationId !== undefined ? { correlation_id: defaultCorrelationId } : {}),
    http_status: ERROR_DEFAULTS.HTTP_STATUS,
  };

  const ctx: Record<string, unknown> = {
    contract: Object.freeze(fallbackContract),
    raw_throw_value: throwValue,
  };
  if (stackTrace !== undefined) ctx.stack_trace = stackTrace;
  ctx.cause_message = causeMsg;

  return Object.freeze(ctx as unknown as InternalErrorContext);
}

/**
 * Serializes an InternalErrorContext into a PublicErrorPayload using an explicit fail-closed allowlist.
 *
 * ONLY properties present in ALLOWLIST_PUBLIC_KEYS are emitted.
 * Stack traces, internal details, raw throw values, and unknown properties are dropped fail-closed.
 * Every public value is explicitly re-validated prior to emission.
 */
export function serializePublicErrorPayload(
  errorContext: InternalErrorContext,
): PublicErrorPayload {
  const contract = errorContext.contract;

  // Validate or fallback code
  const code = isValidErrorCode(contract.code) ? contract.code : ERROR_DEFAULTS.CODE;

  // Validate or fallback message_key
  const message_key = isValidMessageKey(contract.message_key)
    ? contract.message_key
    : ERROR_DEFAULTS.MESSAGE_KEY;

  // Validate or fallback message
  const message =
    typeof contract.message === "string" && contract.message.trim().length > 0
      ? contract.message
      : ERROR_DEFAULTS.MESSAGE;

  // Validate or fallback kind
  const kind = ERROR_KINDS.includes(contract.kind) ? contract.kind : ERROR_DEFAULTS.KIND;

  // Validate or fallback severity
  const severity = ERROR_SEVERITIES.includes(contract.severity)
    ? contract.severity
    : ERROR_DEFAULTS.SEVERITY;

  // Validate or fallback timestamp
  const timestamp = isValidUtcTimestamp(contract.timestamp)
    ? contract.timestamp
    : new Date().toISOString();

  // Validate recoverable
  const recoverable = contract.recoverable;

  // Validate correlation_id
  const correlation_id =
    typeof contract.correlation_id === "string" && contract.correlation_id.trim().length > 0
      ? contract.correlation_id
      : undefined;

  // Validate public_details
  let public_details: Readonly<Record<string, unknown>> | undefined;
  if (
    contract.public_details !== undefined &&
    typeof contract.public_details === "object" &&
    !Array.isArray(contract.public_details)
  ) {
    const cleanDetails: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(contract.public_details)) {
      // Reject prototype pollution / internal keys
      if (key === "__proto__" || key === "constructor" || key === "prototype") continue;
      cleanDetails[key] = val;
    }
    if (Object.keys(cleanDetails).length > 0) {
      public_details = Object.freeze(cleanDetails);
    }
  }

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
  return canonicalizeValue(value);
}

function canonicalizeValue(val: unknown): string {
  if (val === null) return "null";
  if (typeof val === "boolean") return val ? "true" : "false";
  if (typeof val === "number") {
    if (!Number.isFinite(val)) {
      throw new TypeError();
    }
    return JSON.stringify(val);
  }
  if (typeof val === "string") return JSON.stringify(val);

  if (Array.isArray(val)) {
    const items = val.map((item) => canonicalizeValue(item));
    return "[" + items.join(",") + "]";
  }

  if (typeof val === "object") {
    const obj = val as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const pairs: string[] = [];

    for (const key of keys) {
      const v = obj[key];
      if (v === undefined) continue; // undefined properties are omitted
      pairs.push(JSON.stringify(key) + ":" + canonicalizeValue(v));
    }

    return "{" + pairs.join(",") + "}";
  }

  throw new TypeError();
}
