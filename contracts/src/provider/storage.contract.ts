/**
 * =============================================================================
 * SYNTHESIS CMS MINI — FOUNDATION PROVIDER CONTRACTS
 * =============================================================================
 *
 * @module @synthesis-cms/contracts/provider/storage
 * @version 1.0.0-draft.r03
 * @task SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001
 * @command CMD-SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001-20261015-009-RESTORE-AND-IMPLEMENT-R03
 * @checkpoint STORAGE_R03_CONTRACT
 *
 * ARCHITECTURAL CONTEXT & BOUNDARIES:
 * -----------------------------------------------------------------------------
 * 1. Vendor-Neutral Core Layer (contracts/):
 *    - Defines pure TypeScript interfaces, frozen validation constraints, and
 *      defensive parameter validators for pluggable storage providers.
 *    - Zero runtime dependency on AWS S3, Google Cloud Storage, Azure Blob,
 *      or specific local filesystem paths.
 *    - Standard web binary primitives (Uint8Array, BoundedByteStream, AbortSignal)
 *      are used across all contract boundaries.
 *
 * 2. Error Model & Serialization:
 *    - All operational failures are mapped into the standard ProviderResult
 *      discriminated union (ProviderSuccess<T> | ProviderFailure).
 *    - Failures use standard ErrorContract instances and ProviderFailureReason
 *      without registering new public error codes or mutating shared registries.
 *
 * 3. Write Integrity & Create-Only Semantics:
 *    - Overwrite defaults to false (atomic create-only).
 *    - Create-only conflict is represented as a discriminated outcome
 *      `StoragePutOutcome` (stored | already-exists).
 *    - Callers MUST inspect `data.outcome === "stored"` to verify data write.
 *
 * 4. Bounded Streams:
 *    - Reuses BoundedByteStream from shared.contract.ts.
 *    - Stream default maximum: 10 MiB; absolute maximum ceiling: 100 MiB.
 *    - Future backend adapters are required to enforce true byte ceilings,
 *      cancellation, and deterministic cleanup via Symbol.asyncIterator return().
 * =============================================================================
 */

import type { ErrorContract } from "../error/index.ts";
import type { RequestContext } from "../context/index.ts";
import type { BoundedByteStream, PaginationParams, ProviderResult } from "./shared.contract.ts";
import {
  PROPOSED_PAGINATION_DEFAULT_PAGE_SIZE,
  PROPOSED_PAGINATION_MAX_CURSOR_LENGTH,
  PROPOSED_PAGINATION_MAX_PAGE_SIZE,
  PROPOSED_PAGINATION_MIN_PAGE_SIZE,
  PROPOSED_STREAM_ABSOLUTE_MAX_BYTES,
  PROPOSED_STREAM_DEFAULT_MAX_BYTES,
  PROPOSED_STREAM_MIN_BYTE_LIMIT,
} from "./shared.contract.ts";

export const PROVIDER_STORAGE_CONTRACT_ID = "CONTRACT-CORE-PROVIDER-STORAGE-001" as const;

// =============================================================================
// STORAGE INVARIANT LIMITS (FROZEN RUNTIME CONSTANTS)
// =============================================================================

export const STORAGE_LIMITS = Object.freeze({
  KEY_MIN_BYTES: 1,
  KEY_MAX_BYTES: 1024,
  PREFIX_MAX_BYTES: 1024,
  STREAM_MIN_BYTES: PROPOSED_STREAM_MIN_BYTE_LIMIT,
  STREAM_DEFAULT_MAX_BYTES: PROPOSED_STREAM_DEFAULT_MAX_BYTES, // 10 MiB
  STREAM_ABSOLUTE_MAX_BYTES: PROPOSED_STREAM_ABSOLUTE_MAX_BYTES, // 100 MiB
  PAGINATION_MIN_PAGE_SIZE: PROPOSED_PAGINATION_MIN_PAGE_SIZE, // 1
  PAGINATION_DEFAULT_PAGE_SIZE: PROPOSED_PAGINATION_DEFAULT_PAGE_SIZE, // 20
  PAGINATION_MAX_PAGE_SIZE: PROPOSED_PAGINATION_MAX_PAGE_SIZE, // 100
  PAGINATION_MAX_CURSOR_LENGTH: PROPOSED_PAGINATION_MAX_CURSOR_LENGTH, // 1024
  BATCH_DELETE_MIN_KEYS: 1,
  BATCH_DELETE_MAX_KEYS: 100,
  SIGNED_URL_MIN_TTL_SECONDS: 1,
  SIGNED_URL_MAX_TTL_SECONDS: 900, // 15 minutes
} as const);

// =============================================================================
// STORAGE KEY & PREFIX VALIDATION
// =============================================================================

export interface ValidStorageKey {
  readonly valid: true;
  readonly key: string;
}

export interface InvalidStorageKey {
  readonly valid: false;
  readonly reason: string;
}

export type StorageKeyValidationResult = ValidStorageKey | InvalidStorageKey;

export interface ValidStoragePrefix {
  readonly valid: true;
  readonly prefix: string;
}

export interface InvalidStoragePrefix {
  readonly valid: false;
  readonly reason: string;
}

export type StoragePrefixValidationResult = ValidStoragePrefix | InvalidStoragePrefix;

export interface ValidContentType {
  readonly valid: true;
  readonly contentType: string;
}

export interface InvalidContentType {
  readonly valid: false;
  readonly reason: string;
}

export type ContentTypeValidationResult = ValidContentType | InvalidContentType;

/**
 * Validates a storage key according to strict security and portability invariants.
 *
 * Rules:
 *  - Must be a non-empty string.
 *  - Length must be between 1 and 1024 ASCII bytes.
 *  - Allowed characters: ASCII alphanumeric [A-Za-z0-9], period [.], hyphen [-], underscore [_], slash [/].
 *  - Must NOT start with a slash `/`.
 *  - Must NOT end with a slash `/`.
 *  - Must NOT contain consecutive slashes `//`.
 *  - Segments between slashes must NOT be empty.
 *  - Each segment must begin with an alphanumeric character [A-Za-z0-9] (rejects dot-prefixed hidden files).
 *  - Every period `.` in a segment must immediately follow an alphanumeric character (rejects `..`, `a..b`, `a-.b`).
 *  - Rejects spaces, non-ASCII, percent encodings, backslashes, control characters.
 *  - Evaluated purely and defensively; never reflects raw input values in error reasons.
 */
export function validateStorageKey(input: unknown): StorageKeyValidationResult {
  if (typeof input !== "string") {
    return Object.freeze({
      valid: false,
      reason: "Storage key must be a string",
    });
  }

  const len = input.length;
  if (len < STORAGE_LIMITS.KEY_MIN_BYTES) {
    return Object.freeze({
      valid: false,
      reason: "Storage key must not be empty",
    });
  }

  if (len > STORAGE_LIMITS.KEY_MAX_BYTES) {
    return Object.freeze({
      valid: false,
      reason: `Storage key exceeds maximum length of ${String(STORAGE_LIMITS.KEY_MAX_BYTES)} characters`,
    });
  }

  if (input.charCodeAt(0) === 0x2f) {
    return Object.freeze({
      valid: false,
      reason: "Storage key must not begin with a slash",
    });
  }

  if (input.charCodeAt(len - 1) === 0x2f) {
    return Object.freeze({
      valid: false,
      reason: "Storage key must not end with a slash",
    });
  }

  // Iterate over segments
  const segments = input.split("/");
  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i];
    if (segment === undefined || segment.length === 0) {
      return Object.freeze({
        valid: false,
        reason: "Storage key must not contain empty path segments",
      });
    }

    const firstCode = segment.charCodeAt(0);
    const isFirstAlphaNum =
      (firstCode >= 0x30 && firstCode <= 0x39) || // 0-9
      (firstCode >= 0x41 && firstCode <= 0x5a) || // A-Z
      (firstCode >= 0x61 && firstCode <= 0x7a); // a-z

    if (!isFirstAlphaNum) {
      return Object.freeze({
        valid: false,
        reason: "Storage key segment must begin with an ASCII alphanumeric character",
      });
    }

    for (let j = 1; j < segment.length; j++) {
      const code = segment.charCodeAt(j);
      const isAlphaNum =
        (code >= 0x30 && code <= 0x39) ||
        (code >= 0x41 && code <= 0x5a) ||
        (code >= 0x61 && code <= 0x7a);
      const isAllowedPunct = code === 0x5f || code === 0x2d; // _ or -
      const isDot = code === 0x2e; // .

      if (!isAlphaNum && !isAllowedPunct && !isDot) {
        return Object.freeze({
          valid: false,
          reason: "Storage key contains invalid characters",
        });
      }

      if (isDot) {
        const prevCode = segment.charCodeAt(j - 1);
        const prevIsAlphaNum =
          (prevCode >= 0x30 && prevCode <= 0x39) ||
          (prevCode >= 0x41 && prevCode <= 0x5a) ||
          (prevCode >= 0x61 && prevCode <= 0x7a);
        if (!prevIsAlphaNum) {
          return Object.freeze({
            valid: false,
            reason:
              "Period in storage key segment must immediately follow an alphanumeric character",
          });
        }
      }
    }
  }

  return Object.freeze({
    valid: true,
    key: input,
  });
}

/**
 * Validates a storage listing prefix.
 *
 * Rules:
 *  - Empty string is valid (matches entire authorized namespace).
 *  - Maximum length 1024 characters.
 *  - May end with a single `/`.
 *  - Segments follow same character rules as keys, except the final segment may be partial.
 */
export function validateStoragePrefix(input: unknown): StoragePrefixValidationResult {
  if (input === undefined || input === null) {
    return Object.freeze({
      valid: true,
      prefix: "",
    });
  }

  if (typeof input !== "string") {
    return Object.freeze({
      valid: false,
      reason: "Storage prefix must be a string",
    });
  }

  if (input.length === 0) {
    return Object.freeze({
      valid: true,
      prefix: "",
    });
  }

  if (input.length > STORAGE_LIMITS.PREFIX_MAX_BYTES) {
    return Object.freeze({
      valid: false,
      reason: `Storage prefix exceeds maximum length of ${String(STORAGE_LIMITS.PREFIX_MAX_BYTES)} characters`,
    });
  }

  if (input.charCodeAt(0) === 0x2f) {
    return Object.freeze({
      valid: false,
      reason: "Storage prefix must not begin with a slash",
    });
  }

  if (input.includes("//")) {
    return Object.freeze({
      valid: false,
      reason: "Storage prefix must not contain consecutive slashes",
    });
  }

  // Split and validate segments
  const hasTrailingSlash = input.endsWith("/");
  const normalized = hasTrailingSlash ? input.slice(0, -1) : input;
  const segments = normalized.split("/");

  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i];
    if (segment === undefined || segment.length === 0) {
      return Object.freeze({
        valid: false,
        reason: "Storage prefix must not contain empty path segments",
      });
    }

    const firstCode = segment.charCodeAt(0);
    const isFirstAlphaNum =
      (firstCode >= 0x30 && firstCode <= 0x39) ||
      (firstCode >= 0x41 && firstCode <= 0x5a) ||
      (firstCode >= 0x61 && firstCode <= 0x7a);

    if (!isFirstAlphaNum) {
      return Object.freeze({
        valid: false,
        reason: "Storage prefix segment must begin with an ASCII alphanumeric character",
      });
    }

    for (let j = 1; j < segment.length; j++) {
      const code = segment.charCodeAt(j);
      const isAlphaNum =
        (code >= 0x30 && code <= 0x39) ||
        (code >= 0x41 && code <= 0x5a) ||
        (code >= 0x61 && code <= 0x7a);
      const isAllowedPunct = code === 0x5f || code === 0x2d;
      const isDot = code === 0x2e;

      if (!isAlphaNum && !isAllowedPunct && !isDot) {
        return Object.freeze({
          valid: false,
          reason: "Storage prefix contains invalid characters",
        });
      }

      if (isDot) {
        const prevCode = segment.charCodeAt(j - 1);
        const prevIsAlphaNum =
          (prevCode >= 0x30 && prevCode <= 0x39) ||
          (prevCode >= 0x41 && prevCode <= 0x5a) ||
          (prevCode >= 0x61 && prevCode <= 0x7a);
        if (!prevIsAlphaNum) {
          return Object.freeze({
            valid: false,
            reason:
              "Period in storage prefix segment must immediately follow an alphanumeric character",
          });
        }
      }
    }
  }

  return Object.freeze({
    valid: true,
    prefix: input,
  });
}

/**
 * Defensively validates a declared contentType string.
 *
 * Rules:
 *  - Must be a non-empty string.
 *  - Must NOT contain CR (\r), LF (\n), or any ASCII control characters (0x00–0x1F, 0x7F).
 *  - Maximum length 256 characters.
 *  - Evaluated cleanly without side effects.
 */
export function validateContentType(input: unknown): ContentTypeValidationResult {
  if (typeof input !== "string") {
    return Object.freeze({
      valid: false,
      reason: "Content-Type must be a string",
    });
  }

  if (input.length === 0) {
    return Object.freeze({
      valid: false,
      reason: "Content-Type must not be empty",
    });
  }

  if (input.length > 256) {
    return Object.freeze({
      valid: false,
      reason: "Content-Type exceeds maximum length of 256 characters",
    });
  }

  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f) {
      return Object.freeze({
        valid: false,
        reason: "Content-Type contains forbidden ASCII control characters",
      });
    }
  }

  return Object.freeze({
    valid: true,
    contentType: input,
  });
}

// =============================================================================
// STORAGE METADATA, CAPABILITIES & RESULT TYPES
// =============================================================================

export interface StorageObjectMetadata {
  readonly key: string;
  readonly size: number; // safe integer >= 0
  readonly lastModified: Date;
  readonly eTag?: string | undefined;
  readonly contentType?: string | undefined;
}

/**
 * Discriminated outcome for storage put/copy/move operations.
 *
 * IMPORTANT CONTRACT REQUIREMENT:
 * `ProviderSuccess<StoragePutOutcome>` indicates only that the operation completed evaluation.
 * Data write is confirmed ONLY when `data.outcome === "stored"`.
 * When `data.outcome === "already-exists"`, the key already existed and overwrite was false;
 * no data was written.
 */
export type StoragePutOutcome =
  | { readonly outcome: "stored"; readonly metadata: StorageObjectMetadata }
  | { readonly outcome: "already-exists" };

export interface StorageByteRange {
  readonly start: number; // non-negative safe integer
  readonly end: number; // inclusive non-negative safe integer >= start
}

export interface StorageRangeMetadata {
  readonly start: number;
  readonly end: number;
  readonly length: number;
}

export interface StoragePutOptions {
  readonly overwrite?: boolean | undefined; // default: false (atomic create-only)
  readonly contentType?: string | undefined;
  readonly signal?: AbortSignal | undefined;
  readonly context?: RequestContext | undefined;
}

export interface StorageGetOptions {
  readonly range?: StorageByteRange | undefined;
  readonly maxBytes?: number | undefined;
  readonly signal?: AbortSignal | undefined;
  readonly context?: RequestContext | undefined;
}

export interface StorageGetResult {
  readonly metadata: StorageObjectMetadata;
  readonly stream: BoundedByteStream;
  readonly range?: StorageRangeMetadata | undefined;
}

/**
 * Option B getBytes result shape: returns full object metadata alongside delivered bytes
 * and explicit delivered range metadata when range retrieval was requested.
 */
export interface StorageGetBytesResult {
  readonly metadata: StorageObjectMetadata;
  readonly bytes: Uint8Array;
  readonly range?: StorageRangeMetadata | undefined;
}

export interface StorageHeadOptions {
  readonly signal?: AbortSignal | undefined;
  readonly context?: RequestContext | undefined;
}

export interface StorageDeleteOptions {
  readonly signal?: AbortSignal | undefined;
  readonly context?: RequestContext | undefined;
}

export interface StorageListOptions extends PaginationParams {
  readonly prefix?: string | undefined;
  readonly delimiter?: string | undefined; // only "/" or undefined
  readonly signal?: AbortSignal | undefined;
  readonly context?: RequestContext | undefined;
}

export type StorageListEntry =
  | { readonly type: "object"; readonly metadata: StorageObjectMetadata }
  | { readonly type: "prefix"; readonly prefix: string };

export interface StorageListResult {
  readonly items: readonly StorageListEntry[];
  readonly nextCursor: string | null;
}

export interface StorageCopyOptions {
  readonly overwrite?: boolean | undefined;
  readonly signal?: AbortSignal | undefined;
  readonly context?: RequestContext | undefined;
}

export interface StorageMoveOptions {
  readonly overwrite?: boolean | undefined;
  readonly signal?: AbortSignal | undefined;
  readonly context?: RequestContext | undefined;
}

export type StorageSignedUrlAction = "read" | "write";

export interface StorageSignedUrlOptions {
  readonly action: StorageSignedUrlAction;
  readonly ttlSeconds: number; // safe integer: 1 <= ttlSeconds <= 900
  readonly maxBytes?: number | undefined;
  readonly signal?: AbortSignal | undefined;
  readonly context?: RequestContext | undefined;
}

export interface StorageSignedUrlResult {
  readonly url: string;
  readonly action: StorageSignedUrlAction;
  readonly expiresAt: Date;
}

export interface StorageDeleteManyOptions {
  readonly signal?: AbortSignal | undefined;
  readonly context?: RequestContext | undefined;
}

export type StorageDeleteBatchItemOutcome = "deleted" | "absent" | "failed";

export interface StorageDeleteBatchItemResult {
  readonly key: string;
  readonly outcome: StorageDeleteBatchItemOutcome;
  readonly error?: ErrorContract | undefined;
}

// =============================================================================
// STORAGE CAPABILITIES SPECIFICATION
// =============================================================================

export const STORAGE_CAPABILITY_KEYS = Object.freeze([
  "read",
  "write",
  "delete",
  "list",
  "stat",
  "stream",
  "copy",
  "move",
  "signedUrl",
  "batchDelete",
] as const);

export type StorageCapabilityKey = (typeof STORAGE_CAPABILITY_KEYS)[number];

// =============================================================================
// STORAGE PROVIDER INTERFACE
// =============================================================================

/**
 * Universal Storage Provider Interface.
 *
 * Defines the public, vendor-neutral contract for all Synthesis CMS Mini storage adapters.
 */
export interface StorageProvider {
  readonly id: string;

  /**
   * Checks whether this provider instance supports a specific storage capability.
   */
  hasCapability(capability: StorageCapabilityKey): boolean;

  /**
   * Returns a frozen snapshot of capabilities supported by this provider instance.
   */
  getCapabilities(): ReadonlySet<StorageCapabilityKey>;

  /**
   * Stores an object at the specified key.
   * Default `overwrite: false` requires the adapter to guarantee atomic create-only semantics.
   * If the adapter cannot enforce atomic create-only, it MUST fail with UNSUPPORTED before I/O.
   */
  put(
    key: string,
    data: Uint8Array | BoundedByteStream,
    options?: StoragePutOptions,
  ): Promise<ProviderResult<StoragePutOutcome>>;

  /**
   * Retrieves an object stream and metadata at the specified key.
   */
  get(key: string, options?: StorageGetOptions): Promise<ProviderResult<StorageGetResult>>;

  /**
   * Convenience bounded retrieval delivering full byte payload and metadata in-memory.
   */
  getBytes(
    key: string,
    options?: StorageGetOptions,
  ): Promise<ProviderResult<StorageGetBytesResult>>;

  /**
   * Checks metadata for an object without retrieving body payload.
   * Returns metadata if found, or null if absent.
   */
  head(
    key: string,
    options?: StorageHeadOptions,
  ): Promise<ProviderResult<StorageObjectMetadata | null>>;

  /**
   * Deletes an object at the specified key.
   * Returns true if deleted, false if the object did not exist.
   */
  delete(key: string, options?: StorageDeleteOptions): Promise<ProviderResult<boolean>>;

  /**
   * Lists objects and prefixes under the configured namespace and optional prefix.
   */
  list(options?: StorageListOptions): Promise<ProviderResult<StorageListResult>>;

  /**
   * Optional copy: copies source object to destination key.
   * Preserves source object; destination obeys overwrite policy.
   */
  copy?(
    sourceKey: string,
    destinationKey: string,
    options?: StorageCopyOptions,
  ): Promise<ProviderResult<StoragePutOutcome>>;

  /**
   * Optional move: moves source object to destination key atomically in provider namespace.
   * Copy-then-delete without atomic primitive is forbidden and must return UNSUPPORTED.
   */
  move?(
    sourceKey: string,
    destinationKey: string,
    options?: StorageMoveOptions,
  ): Promise<ProviderResult<StoragePutOutcome>>;

  /**
   * Optional presigned URL generation for client-side direct transfer.
   */
  getSignedUrl?(
    key: string,
    options: StorageSignedUrlOptions,
  ): Promise<ProviderResult<StorageSignedUrlResult>>;

  /**
   * Optional batch delete: atomically validates all keys before any mutation.
   * Maximum 100 items per batch.
   */
  deleteMany?(
    keys: readonly string[],
    options?: StorageDeleteManyOptions,
  ): Promise<ProviderResult<readonly StorageDeleteBatchItemResult[]>>;
}
