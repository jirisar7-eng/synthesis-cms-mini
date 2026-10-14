/**
 * SYNTHESIS CMS MINI — SHARED PROVIDER CONTRACT TESTS
 *
 * Verifies shared provider contract definitions, result discriminated unions,
 * pagination parameter defensive boundary, and stream interface constraints.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  PROVIDER_SHARED_CONTRACT_ID,
  PROVIDER_FAILURE_REASONS,
  type ProviderResult,
  isProviderSuccess,
  isProviderFailure,
  PROPOSED_STREAM_MIN_BYTE_LIMIT,
  PROPOSED_STREAM_ABSOLUTE_MAX_BYTES,
  type BoundedStreamOptions,
  type BoundedByteStream,
  type BoundedByteStreamIterator,
  PROPOSED_PAGINATION_MIN_PAGE_SIZE,
  PROPOSED_PAGINATION_DEFAULT_PAGE_SIZE,
  PROPOSED_PAGINATION_MAX_PAGE_SIZE,
  PROPOSED_PAGINATION_MAX_CURSOR_LENGTH,
  validatePaginationParams,
} from "../../contracts/src/provider/index.ts";

import {
  SynthesisBaseError,
  normalizeToErrorContract,
  serializePublicErrorPayload,
  type ErrorContract,
  type InternalErrorContext,
  type PublicErrorPayload,
} from "../../contracts/src/error/index.ts";

void describe("Shared Provider Contracts", () => {
  void describe("Result Types & Failure Categories", () => {
    void it("1. Verifies contract ID and frozen failure reasons", () => {
      assert.equal(PROVIDER_SHARED_CONTRACT_ID, "CONTRACT-CORE-PROVIDER-SHARED-001");
      assert.ok(Object.isFrozen(PROVIDER_FAILURE_REASONS));
      assert.deepEqual(Array.from(PROVIDER_FAILURE_REASONS), [
        "CANCELED",
        "TIMEOUT",
        "NOT_FOUND",
        "UNSUPPORTED",
        "VALIDATION_FAILED",
        "BYTE_LIMIT_EXCEEDED",
        "RATE_LIMITED",
        "INTERNAL",
      ]);
    });

    void it("2. Narrows ProviderSuccess and ProviderFailure via type guards", () => {
      const successResult: ProviderResult<string> = {
        success: true,
        data: "payload_data",
      };

      const mockError: ErrorContract = {
        code: "ERR_VALIDATION_FAILED",
        message: "Input validation failed.",
        message_key: "core.error.validation_failed",
        kind: "VALIDATION_ERROR",
        severity: "ERROR",
        timestamp: "2026-10-14T09:20:00.000Z",
        recoverable: false,
      };

      const failureResult: ProviderResult<string> = {
        success: false,
        failureKind: "VALIDATION_FAILED",
        error: mockError,
      };

      assert.ok(isProviderSuccess(successResult));
      assert.ok(!isProviderFailure(successResult));
      if (isProviderSuccess(successResult)) {
        assert.equal(successResult.data, "payload_data");
      }

      assert.ok(isProviderFailure(failureResult));
      assert.ok(!isProviderSuccess(failureResult));
      if (isProviderFailure(failureResult)) {
        assert.equal(failureResult.failureKind, "VALIDATION_FAILED");
        assert.equal(failureResult.error.code, "ERR_VALIDATION_FAILED");
      }
    });

    void it("3. Confirms provider failure categories are distinct from public error codes", () => {
      // ProviderFailureReason are operational failure states, NOT transport codes
      for (const reason of PROVIDER_FAILURE_REASONS) {
        assert.ok(!reason.startsWith("ERR_"));
      }
    });
  });

  void describe("Pagination Validation (Untrusted Input Boundary)", () => {
    void it("4. Returns frozen defaults on undefined or null input", () => {
      const resUndefined = validatePaginationParams(undefined);
      assert.ok(resUndefined.valid);
      assert.equal(resUndefined.pageSize, PROPOSED_PAGINATION_DEFAULT_PAGE_SIZE);
      assert.equal(resUndefined.cursor, undefined);
      assert.ok(Object.isFrozen(resUndefined));

      const resNull = validatePaginationParams(null);
      assert.ok(resNull.valid);
      assert.equal(resNull.pageSize, PROPOSED_PAGINATION_DEFAULT_PAGE_SIZE);
      assert.equal(resNull.cursor, undefined);
      assert.ok(Object.isFrozen(resNull));
    });

    void it("5. Accepts valid pageSize and cursor within bounds", () => {
      const res = validatePaginationParams({
        pageSize: 50,
        cursor: "cursor_token_123",
      });
      assert.ok(res.valid);
      assert.equal(res.pageSize, 50);
      assert.equal(res.cursor, "cursor_token_123");

      // Boundary values
      const minRes = validatePaginationParams({ pageSize: PROPOSED_PAGINATION_MIN_PAGE_SIZE });
      assert.ok(minRes.valid);
      assert.equal(minRes.pageSize, 1);

      const maxRes = validatePaginationParams({ pageSize: PROPOSED_PAGINATION_MAX_PAGE_SIZE });
      assert.ok(maxRes.valid);
      assert.equal(maxRes.pageSize, 100);
    });

    void it("6. Rejects NaN, Infinity, fractional, negative, and out-of-range pageSize", () => {
      const invalidSizes = [NaN, Infinity, -Infinity, 20.5, 0, -1, -50, 101, 1000];
      for (const size of invalidSizes) {
        const res = validatePaginationParams({ pageSize: size });
        assert.ok(!res.valid);
        assert.ok(res.reason.includes("pageSize must be a safe integer"));
        assert.ok(Object.isFrozen(res));
      }
    });

    void it("7. Validates cursor length limits and character grammar", () => {
      // Empty string is treated as undefined (start of list)
      const emptyRes = validatePaginationParams({ cursor: "" });
      assert.ok(emptyRes.valid);
      assert.equal(emptyRes.cursor, undefined);

      // Max permitted cursor length
      const maxCursor = "a".repeat(PROPOSED_PAGINATION_MAX_CURSOR_LENGTH);
      const maxRes = validatePaginationParams({ cursor: maxCursor });
      assert.ok(maxRes.valid);
      assert.equal(maxRes.cursor, maxCursor);

      // Oversized cursor rejected
      const oversized = "a".repeat(PROPOSED_PAGINATION_MAX_CURSOR_LENGTH + 1);
      const overRes = validatePaginationParams({ cursor: oversized });
      assert.ok(!overRes.valid);
      assert.ok(overRes.reason.includes("cursor exceeds maximum length"));

      // Invalid character rejected
      const badCharRes = validatePaginationParams({ cursor: "cursor with space!" });
      assert.ok(!badCharRes.valid);
      assert.ok(badCharRes.reason.includes("cursor contains invalid characters"));

      // Non-string cursor rejected
      const nonStringRes = validatePaginationParams({ cursor: 12345 as unknown as string });
      assert.ok(!nonStringRes.valid);
      assert.ok(nonStringRes.reason.includes("cursor must be a string"));
    });

    void it("8. Rejects non-plain objects: arrays, Date, and class instances", () => {
      const arrayRes = validatePaginationParams([1, 2, 3]);
      assert.ok(!arrayRes.valid);
      assert.equal(arrayRes.reason, "Pagination parameters must not be an array");

      const dateRes = validatePaginationParams(new Date());
      assert.ok(!dateRes.valid);
      assert.equal(
        dateRes.reason,
        "Pagination parameters must not be a specialized object instance",
      );

      class CustomClass {
        pageSize = 10;
      }
      const classRes = validatePaginationParams(new CustomClass());
      assert.ok(!classRes.valid);
      assert.equal(
        classRes.reason,
        "Pagination parameters must be a plain object with Object.prototype or null prototype",
      );
    });

    void it("9. Accepts plain records with null prototype", () => {
      const nullProto = Object.create(null) as Record<string, unknown>;
      nullProto["pageSize"] = 25;
      nullProto["cursor"] = "opaque_cursor";

      const res = validatePaginationParams(nullProto);
      assert.ok(res.valid);
      assert.equal(res.pageSize, 25);
      assert.equal(res.cursor, "opaque_cursor");
    });

    void it("10. Fails closed on revoked Proxy and throwing accessors without unhandled exceptions", () => {
      // Revoked Proxy test
      const { proxy, revoke } = Proxy.revocable({}, {});
      revoke();

      const revokedRes = validatePaginationParams(proxy);
      assert.ok(!revokedRes.valid);
      assert.equal(
        revokedRes.reason,
        "Failed to safely read properties from untrusted pagination input",
      );

      // Throwing getter test
      const hostileObj = {
        get pageSize() {
          throw new Error("Hostile getter exception");
        },
      };

      const hostileRes = validatePaginationParams(hostileObj);
      assert.ok(!hostileRes.valid);
      assert.equal(
        hostileRes.reason,
        "Failed to safely read properties from untrusted pagination input",
      );
    });

    void it("11. Reads accessor properties exactly once into snapshots", () => {
      let pageSizeReads = 0;
      let cursorReads = 0;

      const tracked = {
        get pageSize() {
          pageSizeReads++;
          return 30;
        },
        get cursor() {
          cursorReads++;
          return "cursor_snap";
        },
      };

      const res = validatePaginationParams(tracked);
      assert.ok(res.valid);
      assert.equal(pageSizeReads, 1);
      assert.equal(cursorReads, 1);
    });
  });

  void describe("Bounded Stream Interface & Behavioral Contract", () => {
    /**
     * Minimal compliant test double enforcing BoundedByteStream invariants.
     */
    class MockBoundedByteStream implements BoundedByteStream {
      readonly maxBytes: number;
      private _bytesRead = 0;
      private _isClosed = false;
      private _hasActiveReader = false;
      private readonly _chunks: readonly Uint8Array[];
      private readonly _signal?: AbortSignal | undefined;

      public returnCalled = false;
      public cancelCalled = false;

      constructor(options: BoundedStreamOptions, chunks: readonly Uint8Array[] = []) {
        if (
          !Number.isSafeInteger(options.maxBytes) ||
          options.maxBytes < PROPOSED_STREAM_MIN_BYTE_LIMIT ||
          options.maxBytes > PROPOSED_STREAM_ABSOLUTE_MAX_BYTES
        ) {
          throw new RangeError(
            `maxBytes must be between ${String(PROPOSED_STREAM_MIN_BYTE_LIMIT)} and ${String(PROPOSED_STREAM_ABSOLUTE_MAX_BYTES)}`,
          );
        }

        this.maxBytes = options.maxBytes;
        this._chunks = chunks;
        this._signal = options.signal;
      }

      get bytesRead(): number {
        return this._bytesRead;
      }

      get isClosed(): boolean {
        return this._isClosed;
      }

      cancel(reason?: string): Promise<void> {
        assert.ok(reason === undefined || typeof reason === "string");
        this.cancelCalled = true;
        this._isClosed = true;
        return Promise.resolve();
      }

      [Symbol.asyncIterator](): BoundedByteStreamIterator {
        if (this._hasActiveReader) {
          throw new Error("STREAM_ALREADY_CONSUMED: Single-reader policy violation");
        }
        this._hasActiveReader = true;
        let chunkIndex = 0;

        return {
          next: async (): Promise<IteratorResult<Uint8Array, void>> => {
            if (this._isClosed) {
              return { done: true, value: undefined };
            }

            if (this._signal?.aborted) {
              await this.cancel("AbortSignal triggered");
              throw new Error("STREAM_CANCELED");
            }

            if (chunkIndex >= this._chunks.length) {
              this._isClosed = true;
              return { done: true, value: undefined };
            }

            const nextChunk = this._chunks[chunkIndex];
            if (!nextChunk) {
              this._isClosed = true;
              return { done: true, value: undefined };
            }

            if (this._bytesRead + nextChunk.byteLength > this.maxBytes) {
              // Overflow: do NOT deliver excess chunk, close immediately
              await this.cancel("Byte limit exceeded");
              throw new Error("STREAM_OVERFLOW");
            }

            this._bytesRead += nextChunk.byteLength;
            chunkIndex++;
            return { done: false, value: nextChunk };
          },
          return: async (
            value?: void | PromiseLike<void>,
          ): Promise<IteratorResult<Uint8Array, void>> => {
            if (value) {
              await value;
            }
            this.returnCalled = true;
            await this.cancel("Early iterator return");
            return { done: true, value: undefined };
          },
        };
      }
    }

    void it("12. Reads chunks until clean EOF and handles read-after-EOF idempotently", async () => {
      const chunk1 = new Uint8Array([1, 2, 3]);
      const chunk2 = new Uint8Array([4, 5]);
      const stream = new MockBoundedByteStream({ maxBytes: 100 }, [chunk1, chunk2]);

      const iterator = stream[Symbol.asyncIterator]();
      const r1 = await iterator.next();
      assert.equal(r1.done, false);
      assert.deepEqual(r1.value, chunk1);

      const r2 = await iterator.next();
      assert.equal(r2.done, false);
      assert.deepEqual(r2.value, chunk2);

      const r3 = await iterator.next();
      assert.equal(r3.done, true);
      assert.equal(r3.value, undefined);

      // Read after EOF must idempotently return done without errors
      const r4 = await iterator.next();
      assert.equal(r4.done, true);
      assert.equal(r4.value, undefined);

      assert.equal(stream.bytesRead, 5);
      assert.ok(stream.isClosed);
    });

    void it("13. Enforces single-reader policy against repeated iterator creation", () => {
      const stream = new MockBoundedByteStream({ maxBytes: 100 }, []);
      const iter1 = stream[Symbol.asyncIterator]();
      assert.ok(iter1);

      assert.throws(() => stream[Symbol.asyncIterator](), {
        name: "Error",
        message: "STREAM_ALREADY_CONSUMED: Single-reader policy violation",
      });
    });

    void it("14. Halts on overflow before delivering excess chunk", async () => {
      const chunk1 = new Uint8Array(6); // 6 bytes
      const chunk2 = new Uint8Array(6); // 6 bytes -> total 12 > max 10
      const stream = new MockBoundedByteStream({ maxBytes: 10 }, [chunk1, chunk2]);

      const received: Uint8Array[] = [];
      let caughtError: Error | undefined;

      try {
        for await (const chunk of stream) {
          received.push(chunk);
        }
      } catch (err) {
        caughtError = err as Error;
      }

      assert.ok(caughtError);
      assert.equal(caughtError.message, "STREAM_OVERFLOW");
      // Only first chunk was delivered; excess chunk was blocked
      assert.equal(received.length, 1);
      assert.equal(stream.bytesRead, 6);
      assert.ok(stream.isClosed);
      assert.ok(stream.cancelCalled);
    });

    void it("15. Triggers early return cleanup when break occurs during iteration", async () => {
      const chunk1 = new Uint8Array([1, 2]);
      const chunk2 = new Uint8Array([3, 4]);
      const stream = new MockBoundedByteStream({ maxBytes: 100 }, [chunk1, chunk2]);

      for await (const chunk of stream) {
        assert.equal(chunk.byteLength, 2);
        break; // Triggers iterator.return()
      }

      assert.ok(stream.returnCalled);
      assert.ok(stream.cancelCalled);
      assert.ok(stream.isClosed);
    });

    void it("16. Rejects reading when AbortSignal triggers cancellation", async () => {
      const controller = new AbortController();
      controller.abort();

      const stream = new MockBoundedByteStream({ maxBytes: 100, signal: controller.signal }, [
        new Uint8Array([1, 2, 3]),
      ]);

      await assert.rejects(
        async () => {
          for await (const chunk of stream) {
            assert.ok(chunk.byteLength > 0);
          }
        },
        {
          name: "Error",
          message: "STREAM_CANCELED",
        },
      );

      assert.ok(stream.isClosed);
      assert.ok(stream.cancelCalled);
    });
  });

  void describe("Error Boundary & Synthetic Secret Marker Exclusion", () => {
    void it("17. Ensures synthetic secret marker is absent from entire serialized public JSON", () => {
      const syntheticSecret = "sk_live_super_secret_token_never_leak_xyz_999";

      // 1. Construct authentic domain error with synthetic secret in internal details
      const err = new SynthesisBaseError({
        code: "ERR_VALIDATION_FAILED",
        message: "Input validation failed.",
        message_key: "core.error.validation_failed",
        kind: "VALIDATION_ERROR",
        public_details: { safeField: "allowed_value" },
        internal_details: {
          tokenSecret: syntheticSecret,
          dbPassword: "secret_db_password_123",
        },
      });

      // 2. Normalize to InternalErrorContext
      const internalCtx: InternalErrorContext = normalizeToErrorContract(err);
      assert.ok(internalCtx.contract);
      // Internal details are preserved in memory for authorized logging
      assert.equal(internalCtx.internal_details?.tokenSecret, syntheticSecret);

      // 3. Serialize to PublicErrorPayload at public runtime boundary
      const publicPayload: PublicErrorPayload = serializePublicErrorPayload(internalCtx);

      // 4. Assert direct property omission
      const rawPayload = publicPayload as unknown as Record<string, unknown>;
      assert.equal(rawPayload["tokenSecret"], undefined);
      assert.equal(rawPayload["internal_details"], undefined);

      // 5. Assert synthetic secret marker is ABSENT from the entire serialized JSON string
      const serializedJson = JSON.stringify(publicPayload);
      assert.ok(!serializedJson.includes(syntheticSecret));
      assert.ok(!serializedJson.includes("tokenSecret"));
      assert.ok(!serializedJson.includes("dbPassword"));
      assert.ok(!serializedJson.includes("secret_db_password"));

      // 6. Confirms public payload only emits approved public triplet and allowed details
      assert.equal(publicPayload.code, "ERR_VALIDATION_FAILED");
      assert.equal(publicPayload.message_key, "core.error.validation_failed");
      assert.equal(publicPayload.kind, "VALIDATION_ERROR");
      assert.deepEqual(publicPayload.public_details, { safeField: "allowed_value" });
    });
  });
});
