/**
 * SYNTHESIS CMS MINI — SHARED PROVIDER CONTRACTS
 *
 * Universal contracts, types, interfaces, and guards shared across all provider interfaces.
 *
 * ARCHITECTURAL INVARIANTS:
 * 1. RequestContext identifies provenance and correlation ONLY; it never grants permission.
 * 2. Default authorization is server-side DENY (Step 18+).
 * 3. TypeScript 'readonly' provides compile-time protection only; runtime immutability
 *    requires explicit Object.freeze().
 * 4. Internal diagnostic details, raw throw values, and stack traces must never be emitted
 *    to public clients; all errors cross the boundary via serializePublicErrorPayload().
 */

import type { ErrorContract } from "../error/index.ts";
import type { RequestContext } from "../context/index.ts";

export const PROVIDER_SHARED_CONTRACT_ID = "CONTRACT-CORE-PROVIDER-SHARED-001" as const;

/**
 * Standard failure reasons for provider operations.
 * Distinct operational semantics for internal provider categorization.
 * These are strictly internal categories, distinct from approved public error codes.
 */
export const PROVIDER_FAILURE_REASONS = Object.freeze([
  "CANCELED",
  "TIMEOUT",
  "NOT_FOUND",
  "UNSUPPORTED",
  "VALIDATION_FAILED",
  "BYTE_LIMIT_EXCEEDED",
  "RATE_LIMITED",
  "INTERNAL",
] as const);

export type ProviderFailureReason = (typeof PROVIDER_FAILURE_REASONS)[number];

/**
 * Discriminated successful provider outcome.
 */
export interface ProviderSuccess<T> {
  readonly success: true;
  readonly data: T;
  readonly context?: RequestContext | undefined;
}

/**
 * Discriminated failed provider outcome.
 */
export interface ProviderFailure {
  readonly success: false;
  readonly failureKind: ProviderFailureReason;
  readonly error: ErrorContract;
  readonly context?: RequestContext | undefined;
}

/**
 * Universal discriminated provider result.
 */
export type ProviderResult<T> = ProviderSuccess<T> | ProviderFailure;

/**
 * Type guard narrowing an already typed ProviderResult to ProviderSuccess.
 */
export function isProviderSuccess<T>(result: ProviderResult<T>): result is ProviderSuccess<T> {
  return result.success;
}

/**
 * Type guard narrowing an already typed ProviderResult to ProviderFailure.
 */
export function isProviderFailure<T>(result: ProviderResult<T>): result is ProviderFailure {
  return !result.success;
}

// ============================================================
// BOUNDED STREAM SPECIFICATION & INTERFACES
// ============================================================

export const PROPOSED_STREAM_MIN_BYTE_LIMIT = 1;
export const PROPOSED_STREAM_DEFAULT_MAX_BYTES = 10 * 1024 * 1024; // 10 MiB
export const PROPOSED_STREAM_ABSOLUTE_MAX_BYTES = 100 * 1024 * 1024; // 100 MiB

/**
 * Options configuring bounded stream consumption.
 */
export interface BoundedStreamOptions {
  /**
   * Maximum permitted total bytes allowed from the stream.
   * Must be a finite safe integer: PROPOSED_STREAM_MIN_BYTE_LIMIT <= maxBytes <= PROPOSED_STREAM_ABSOLUTE_MAX_BYTES.
   */
  readonly maxBytes: number;
  /**
   * Optional standard AbortSignal for early cancellation.
   */
  readonly signal?: AbortSignal | undefined;
}

/**
 * Iterator contract for BoundedByteStream requiring an explicit return() method.
 * Guarantees that break/return during for-await-of invokes deterministic cleanup.
 */
export interface BoundedByteStreamIterator extends AsyncIterator<Uint8Array, void, undefined> {
  next(): Promise<IteratorResult<Uint8Array, void>>;
  return(value?: void | PromiseLike<void>): Promise<IteratorResult<Uint8Array, void>>;
}

/**
 * Portable, bounded byte stream interface.
 * Represents a single-reader asynchronous sequence of binary chunks (Uint8Array).
 * Enforces:
 *  - Finite safe integer byte ceiling (maxBytes)
 *  - Overflow before delivering an excess chunk
 *  - Clean EOF termination
 *  - Cancellation via cancel() or AbortSignal
 *  - Early return cleanup
 *  - Single active reader policy
 */
export interface BoundedByteStream extends AsyncIterable<Uint8Array> {
  readonly maxBytes: number;
  readonly bytesRead: number;
  readonly isClosed: boolean;
  cancel(reason?: string): Promise<void>;
  [Symbol.asyncIterator](): BoundedByteStreamIterator;
}

// ============================================================
// BOUNDED PAGINATION SPECIFICATION & VALIDATOR
// ============================================================

export const PROPOSED_PAGINATION_MIN_PAGE_SIZE = 1;
export const PROPOSED_PAGINATION_DEFAULT_PAGE_SIZE = 20;
export const PROPOSED_PAGINATION_MAX_PAGE_SIZE = 100;
export const PROPOSED_PAGINATION_MAX_CURSOR_LENGTH = 1024;
export const PROPOSED_CURSOR_PATTERN = /^[A-Za-z0-9_-]+$/;

export interface PaginationParams {
  readonly cursor?: string | undefined;
  readonly pageSize?: number | undefined;
}

export interface PaginatedResult<T> {
  readonly items: readonly T[];
  readonly nextCursor: string | null;
  readonly totalCount?: number | undefined;
}

export interface ValidatedPagination {
  readonly valid: true;
  readonly pageSize: number;
  readonly cursor?: string | undefined;
}

export interface InvalidPagination {
  readonly valid: false;
  readonly reason: string;
}

export type PaginationValidationResult = ValidatedPagination | InvalidPagination;

/**
 * Defensively validates pagination parameters from untrusted inputs.
 * Enforces:
 *  - Accepts unknown input safely
 *  - Validates plain record boundary (Object.prototype or null prototype only)
 *  - Rejects arrays, Date, RegExp, and class instances
 *  - All reflection and property reads are isolated inside a try/catch boundary
 *  - Revoked Proxies and throwing accessors return controlled static failure
 *  - Reads pageSize and cursor exactly once into local snapshots
 *  - Never reflects caught thrown values or exception messages
 *  - Returns a frozen validation result
 */
export function validatePaginationParams(input: unknown): PaginationValidationResult {
  if (input === undefined || input === null) {
    return Object.freeze({
      valid: true,
      pageSize: PROPOSED_PAGINATION_DEFAULT_PAGE_SIZE,
    });
  }

  let rawPageSize: unknown;
  let rawCursor: unknown;

  try {
    if (typeof input !== "object") {
      return Object.freeze({
        valid: false,
        reason: "Pagination parameters must be a plain object",
      });
    }

    if (Array.isArray(input)) {
      return Object.freeze({
        valid: false,
        reason: "Pagination parameters must not be an array",
      });
    }

    if (input instanceof Date || input instanceof RegExp) {
      return Object.freeze({
        valid: false,
        reason: "Pagination parameters must not be a specialized object instance",
      });
    }

    const proto: unknown = Object.getPrototypeOf(input);
    if (proto !== null && proto !== Object.prototype) {
      return Object.freeze({
        valid: false,
        reason:
          "Pagination parameters must be a plain object with Object.prototype or null prototype",
      });
    }

    const record = input as Record<string, unknown>;
    rawPageSize = record["pageSize"];
    rawCursor = record["cursor"];
  } catch {
    return Object.freeze({
      valid: false,
      reason: "Failed to safely read properties from untrusted pagination input",
    });
  }

  let pageSize = PROPOSED_PAGINATION_DEFAULT_PAGE_SIZE;
  if (rawPageSize !== undefined) {
    if (
      typeof rawPageSize !== "number" ||
      !Number.isSafeInteger(rawPageSize) ||
      rawPageSize < PROPOSED_PAGINATION_MIN_PAGE_SIZE ||
      rawPageSize > PROPOSED_PAGINATION_MAX_PAGE_SIZE
    ) {
      return Object.freeze({
        valid: false,
        reason: `pageSize must be a safe integer between ${String(PROPOSED_PAGINATION_MIN_PAGE_SIZE)} and ${String(PROPOSED_PAGINATION_MAX_PAGE_SIZE)}`,
      });
    }
    pageSize = rawPageSize;
  }

  let cursor: string | undefined;
  if (rawCursor !== undefined) {
    if (typeof rawCursor !== "string") {
      return Object.freeze({
        valid: false,
        reason: "cursor must be a string",
      });
    }

    if (rawCursor.length > PROPOSED_PAGINATION_MAX_CURSOR_LENGTH) {
      return Object.freeze({
        valid: false,
        reason: `cursor exceeds maximum length of ${String(PROPOSED_PAGINATION_MAX_CURSOR_LENGTH)}`,
      });
    }

    if (rawCursor.length > 0 && !PROPOSED_CURSOR_PATTERN.test(rawCursor)) {
      return Object.freeze({
        valid: false,
        reason: "cursor contains invalid characters",
      });
    }

    if (rawCursor.length > 0) {
      cursor = rawCursor;
    }
  }

  return Object.freeze({
    valid: true,
    pageSize,
    ...(cursor !== undefined ? { cursor } : {}),
  });
}
