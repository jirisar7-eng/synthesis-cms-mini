/**
 * Synthesis CMS mini — Request, Actor & Provenance Context Contract
 *
 * Immutable, transport-neutral context contract for tracing, request lifecycle,
 * actor execution modality, and causality provenance across Synthesis CMS mini.
 *
 * ARCHITECTURAL INVARIANTS:
 * 1. ActorKind represents execution modality ONLY, never authenticated identity or authorization.
 * 2. Default authorization is server-side DENY.
 * 3. request_id and correlation_id are platform-minted using cryptographic randomness (req-<UUIDv4>, corr-<UUIDv4>).
 * 4. Contexts are deeply immutable; instances are verified for authenticity before causal derivation.
 * 5. Maximum causal depth is strictly bounded (MAX_HOP_COUNT = 32).
 * 6. Public contracts export interfaces, constants, and pure validators ONLY.
 *    Privileged root context issuance is restricted to core runtime internals.
 */

/**
 * Valid execution modality kinds for actors operating within the system.
 * ActorKind classifies HOW execution is triggered, NOT who or what permissions exist.
 */
export const ACTOR_KINDS = Object.freeze([
  "HUMAN",
  "AI",
  "SYSTEM",
  "MODULE",
  "INTEGRATION",
  "JOB",
] as const);

export type ActorKind = (typeof ACTOR_KINDS)[number];

/**
 * Maximum causal depth limit for child context derivation to prevent unbounded recursion.
 */
export const MAX_HOP_COUNT = 32;

/**
 * Anchored regular expression for RFC 4122 UUIDv4 validation:
 * - 8 hex chars
 * - 4 hex chars
 * - '4' + 3 hex chars (version 4)
 * - [89ab] + 3 hex chars (variant 1 / RFC 4122)
 * - 12 hex chars
 */
export const UUID_V4_PATTERN =
  "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";

/**
 * Platform request identifier pattern: req-<UUIDv4> (lowercase hexadecimal only).
 */
export const REQUEST_ID_REGEX =
  /^req-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/**
 * Platform correlation identifier pattern: corr-<UUIDv4> (lowercase hexadecimal only).
 * Compatible with Step 14 TRUSTED_CORRELATION_PREFIXES ("corr-").
 */
export const CORRELATION_ID_REGEX =
  /^corr-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/**
 * Permitted character set and length boundaries for safe identifiers.
 */
export const SAFE_IDENTIFIER_REGEX = /^[a-zA-Z0-9_.-]+$/;
export const MAX_ACTOR_ID_LENGTH = 128;
export const MAX_TENANT_ID_LENGTH = 64;
export const MAX_ORIGIN_LENGTH = 256;
export const MAX_ISSUER_LENGTH = 128;
export const MAX_EXTERNAL_TRACE_ID_LENGTH = 128;

/**
 * Strict UTC ISO 8601 timestamp regular expression (millisecond precision optional).
 */
export const UTC_TIMESTAMP_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;

/**
 * Immutable Actor Context interface.
 * Captures execution modality and sanitized identifier.
 */
export interface ActorContext {
  readonly kind: ActorKind;
  readonly actor_id: string;
  readonly tenant_id?: string | undefined;
}

/**
 * Immutable Provenance Context interface.
 * Captures request origin, issuer authority, causal ancestry, and telemetry.
 */
export interface ProvenanceContext {
  readonly origin: string;
  readonly issuer: string;
  readonly hop_count: number;
  readonly causal_parent_id?: string | undefined;
  readonly external_trace_id?: string | undefined;
}

/**
 * Immutable Request Context interface.
 * Root context carrier for request lifecycle, correlation, actor, and provenance.
 */
export interface RequestContext {
  readonly request_id: string;
  readonly correlation_id: string;
  readonly timestamp: string;
  readonly actor: ActorContext;
  readonly provenance: ProvenanceContext;
}

/**
 * Validates whether a value is a valid ActorKind.
 */
export function isValidActorKind(val: unknown): val is ActorKind {
  return typeof val === "string" && (ACTOR_KINDS as readonly string[]).includes(val);
}

/**
 * Validates whether a value is a valid platform-minted request ID (req-<UUIDv4>).
 */
export function isValidRequestId(val: unknown): val is string {
  if (typeof val !== "string") return false;
  return REQUEST_ID_REGEX.test(val);
}

/**
 * Validates whether a value is a valid platform-minted correlation ID (corr-<UUIDv4>).
 * Compatible with Step 14 correlation validation.
 */
export function isValidCorrelationId(val: unknown): val is string {
  if (typeof val !== "string") return false;
  return CORRELATION_ID_REGEX.test(val);
}

/**
 * Validates an actor identifier string.
 */
export function isValidActorId(val: unknown): val is string {
  if (typeof val !== "string") return false;
  if (val.length === 0 || val.length > MAX_ACTOR_ID_LENGTH) return false;
  return SAFE_IDENTIFIER_REGEX.test(val);
}

/**
 * Validates a tenant identifier string.
 */
export function isValidTenantId(val: unknown): val is string {
  if (typeof val !== "string") return false;
  if (val.length === 0 || val.length > MAX_TENANT_ID_LENGTH) return false;
  return SAFE_IDENTIFIER_REGEX.test(val);
}

/**
 * Validates an origin descriptor string.
 */
export function isValidOrigin(val: unknown): val is string {
  if (typeof val !== "string") return false;
  if (val.length === 0 || val.length > MAX_ORIGIN_LENGTH) return false;
  return SAFE_IDENTIFIER_REGEX.test(val);
}

/**
 * Validates an issuer descriptor string.
 */
export function isValidIssuer(val: unknown): val is string {
  if (typeof val !== "string") return false;
  if (val.length === 0 || val.length > MAX_ISSUER_LENGTH) return false;
  return SAFE_IDENTIFIER_REGEX.test(val);
}

/**
 * Validates an external trace identifier string (telemetry only).
 */
export function isValidExternalTraceId(val: unknown): val is string {
  if (typeof val !== "string") return false;
  if (val.length === 0 || val.length > MAX_EXTERNAL_TRACE_ID_LENGTH) return false;
  return SAFE_IDENTIFIER_REGEX.test(val);
}

/**
 * Validates a strict UTC ISO 8601 timestamp string.
 */
export function isValidUtcTimestamp(val: unknown): val is string {
  if (typeof val !== "string") return false;
  if (!UTC_TIMESTAMP_REGEX.test(val)) return false;
  const d = new Date(val);
  return !Number.isNaN(d.getTime());
}
