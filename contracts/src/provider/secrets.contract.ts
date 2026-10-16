/**
 * =============================================================================
 * SYNTHESIS CMS MINI — SECRETS PROVIDER CONTRACT
 * =============================================================================
 *
 * @module @synthesis-cms/contracts/provider/secrets
 * @version 1.0.0
 * @task SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001
 * @command CMD-SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001-20261016-049-IMPLEMENT-SECRETS-V1
 * @phase IMPLEMENT
 *
 * ARCHITECTURAL CONTEXT & INVARIANTS:
 * -----------------------------------------------------------------------------
 * 1. Vendor-Neutral Core:
 *    - Core engine abstractions remain 100% vendor-neutral. No AWS Secrets
 *      Manager, HashiCorp Vault, GCP Secret Manager, or platform-specific types
 *      leak into the Core contract boundary.
 *
 * 2. V1 Read-Only Scope:
 *    - V1 specifies read-only retrieval via `get(key, options?)` only.
 *    - Mutation (set, rotate, delete), batch listing, versioning, and presigned
 *      access are deferred to future revisions.
 *
 * 3. Secret Value Protection & Memory Hygiene:
 *    - Secrets are returned exclusively as caller-owned independent `Uint8Array`
 *      byte buffers to prevent internal state tampering or aliasing.
 *    - Secret bytes, keys, and tenant credentials must NEVER be logged,
 *      traced, or disclosed in public error payloads.
 *
 * 4. Provenance vs Authorization Boundary:
 *    - `RequestContext` provides correlation and audit provenance ONLY.
 *    - Default authorization is server-side DENY. Production authorization
 *      MUST be enforced by a trusted pre-provider gateway before invoking
 *      provider methods. Provider interfaces do NOT perform RBAC.
 *
 * 5. Runtime Immutability:
 *    - TypeScript `readonly` provides compile-time protection only.
 *    - Runtime constants and validation results are frozen via `Object.freeze()`.
 *    - `getCapabilities()` returns a fresh frozen array snapshot.
 */

import type { RequestContext } from "../context/index.ts";
import type { ProviderResult } from "./shared.contract.ts";

/**
 * Unique identifier for the Secrets Provider Contract.
 */
export const PROVIDER_SECRETS_CONTRACT_ID = "CONTRACT-CORE-PROVIDER-SECRETS-001" as const;

/**
 * Alias identifier for the Secrets Provider Contract matching architectural specification sketch.
 */
export const SECRETS_PROVIDER_CONTRACT_ID = PROVIDER_SECRETS_CONTRACT_ID;

/**
 * Fundamental immutable limits for secrets provider operations.
 */
export const SECRETS_LIMITS = Object.freeze({
  /** Minimum key length in ASCII bytes (inclusive). */
  KEY_MIN_BYTES: 1,
  /** Maximum key length in ASCII bytes (inclusive). */
  KEY_MAX_BYTES: 128,
  /** Maximum secret value length in bytes (inclusive, 64 KiB). */
  VALUE_MAX_BYTES: 65536,
} as const);

/**
 * Standard capability identifiers for Secrets Provider implementations.
 */
export const SECRETS_CAPABILITY_KEYS = Object.freeze(["read"] as const);

/**
 * Valid capability key for Secrets Provider.
 */
export type SecretsCapabilityKey = (typeof SECRETS_CAPABILITY_KEYS)[number];

/**
 * Validated, safe secret key identifier.
 * Note: Untrusted strings must be passed through `validateSecretKey()` first.
 */
export type SecretKey = string;

/**
 * Successful validation outcome for a secret key.
 */
export interface ValidSecretKey {
  readonly valid: true;
  readonly key: string;
}

/**
 * Failed validation outcome for a secret key with a static safe reason.
 */
export interface InvalidSecretKey {
  readonly valid: false;
  readonly reason: string;
}

/**
 * Discriminated result of secret key validation.
 */
export type SecretKeyValidationResult = ValidSecretKey | InvalidSecretKey;

/**
 * Static failure reasons for secret key validation.
 * Guaranteed never to echo untrusted input or leak sensitive markers.
 */
const REASON_NOT_STRING = "Secret key must be a primitive string";
const REASON_EMPTY = "Secret key must not be empty";
const REASON_TOO_LONG = "Secret key exceeds maximum length of 128 characters";
const REASON_INVALID_FIRST_CHAR = "Secret key must start with an ASCII letter [A-Za-z]";
const REASON_INVALID_CHAR =
  "Secret key contains invalid characters (allowed: ASCII alphanumeric, _, -)";
const REASON_RESERVED_NAME = "Secret key uses a reserved identifier";

/**
 * Pure, defensive validator for secret keys.
 *
 * Invariants:
 *  - Accepts only primitive string (rejects non-strings, null, undefined, boxed String, objects, proxies).
 *  - Length bounds: 1 to 128 ASCII characters inclusive.
 *  - First character must be ASCII letter: a-z, A-Z.
 *  - Remaining characters must be ASCII alphanumeric, underscore, or hyphen: a-z, A-Z, 0-9, _, -.
 *  - Exact reserved names forbidden: "constructor", "prototype", "__proto__".
 *  - Explicit character-by-character validation (avoids multiline or regex parsing vulnerabilities).
 *  - Returns a frozen discriminated result with static reason (no reflection of untrusted input).
 *
 * @param input - Untrusted input to validate as a SecretKey.
 * @returns Frozen SecretKeyValidationResult indicating validity and reason.
 */
export function validateSecretKey(input: unknown): SecretKeyValidationResult {
  if (typeof input !== "string") {
    return Object.freeze({ valid: false, reason: REASON_NOT_STRING });
  }

  const len = input.length;
  if (len < SECRETS_LIMITS.KEY_MIN_BYTES) {
    return Object.freeze({ valid: false, reason: REASON_EMPTY });
  }
  if (len > SECRETS_LIMITS.KEY_MAX_BYTES) {
    return Object.freeze({ valid: false, reason: REASON_TOO_LONG });
  }

  // First character must be ASCII letter: a-z (97-122) or A-Z (65-90)
  const firstCode = input.charCodeAt(0);
  const isFirstLetter =
    (firstCode >= 65 && firstCode <= 90) || (firstCode >= 97 && firstCode <= 122);

  if (!isFirstLetter) {
    return Object.freeze({ valid: false, reason: REASON_INVALID_FIRST_CHAR });
  }

  // Remaining characters: a-z, A-Z, 0-9 (48-57), _ (95), - (45)
  for (let i = 1; i < len; i++) {
    const code = input.charCodeAt(i);
    const isUpper = code >= 65 && code <= 90;
    const isLower = code >= 97 && code <= 122;
    const isDigit = code >= 48 && code <= 57;
    const isUnderscore = code === 95;
    const isHyphen = code === 45;

    if (!isUpper && !isLower && !isDigit && !isUnderscore && !isHyphen) {
      return Object.freeze({ valid: false, reason: REASON_INVALID_CHAR });
    }
  }

  // Reserved identifier check
  if (input === "constructor" || input === "prototype" || input === "__proto__") {
    return Object.freeze({ valid: false, reason: REASON_RESERVED_NAME });
  }

  return Object.freeze({ valid: true, key: input });
}

/**
 * Result payload delivered by a successful secret read operation.
 * Guaranteed to be an independent, caller-owned Uint8Array byte buffer.
 */
export interface SecretReadResult {
  /**
   * Independent, unaliased raw secret bytes (0 to 65,536 bytes).
   * Note: An existing empty secret has length 0 and is distinct from NOT_FOUND.
   */
  readonly bytes: Uint8Array;
}

/**
 * Options for secrets retrieval operations.
 */
export interface SecretsGetOptions {
  /**
   * Optional AbortSignal for early cancellation and timeout signaling.
   */
  readonly signal?: AbortSignal | undefined;

  /**
   * Optional RequestContext providing correlation and audit provenance.
   * Note: RequestContext identifies provenance ONLY; it never grants permission.
   */
  readonly context?: RequestContext | undefined;
}

/**
 * Public runtime contract interface for pluggable Secrets Providers.
 *
 * Implements vendor-neutral retrieval of encrypted application secrets,
 * API tokens, and credentials.
 */
export interface SecretsProvider {
  /**
   * Unique, vendor-neutral identifier of this secrets provider instance.
   */
  readonly id: string;

  /**
   * Queries whether this provider instance supports a specific capability.
   * In V1, "read" is the mandatory capability and returns true.
   *
   * @param capability - The capability identifier to query.
   * @returns True if supported, false otherwise.
   */
  hasCapability(capability: SecretsCapabilityKey): boolean;

  /**
   * Returns an immutable snapshot array of capabilities supported by this provider.
   * Returns a frozen copy `["read"]` to ensure runtime immutability.
   *
   * @returns Frozen array of supported capability keys.
   */
  getCapabilities(): readonly SecretsCapabilityKey[];

  /**
   * Retrieves a secret by its validated key.
   *
   * Operational semantics:
   *  - Key validation failure: returns `VALIDATION_FAILED`.
   *  - Secret does not exist: returns `NOT_FOUND`.
   *  - Secret exists but is empty (0 bytes): returns `ProviderSuccess` with 0-byte `bytes`.
   *  - Secret value exceeds 65,536 bytes: returns `BYTE_LIMIT_EXCEEDED`.
   *  - Pre-aborted or canceled signal: returns `CANCELED`.
   *  - Enforced adapter deadline: returns `TIMEOUT`.
   *  - Provider internal error: returns `INTERNAL`.
   *
   * @param key - The secret key identifier.
   * @param options - Optional cancellation signal and provenance context.
   * @returns Promise resolving to a discriminated ProviderResult with SecretReadResult.
   */
  get(key: SecretKey, options?: SecretsGetOptions): Promise<ProviderResult<SecretReadResult>>;
}
