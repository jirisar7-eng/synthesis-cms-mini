/**
 * SYNTHESIS CMS MINI — STORAGE PROVIDER CONTRACT TESTS
 *
 * Conformance test matrix and compile-time type verification for Storage Provider R03.
 * Uses in-memory conformance models to verify specification invariants without network I/O.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  PROVIDER_STORAGE_CONTRACT_ID,
  STORAGE_CAPABILITY_KEYS,
  STORAGE_LIMITS,
  validateContentType,
  validateStorageKey,
  validateStoragePrefix,
} from "../../contracts/src/provider/storage.contract.ts";
import type {
  BoundedByteStream,
  BoundedByteStreamIterator,
  StorageByteRange,
  StorageCapabilityKey,
  StorageDeleteBatchItemResult,
  StorageGetOptions,
  StorageGetResult,
  StorageGetBytesResult,
  StorageListOptions,
  StorageListResult,
  StorageObjectMetadata,
  StorageProvider,
  StoragePutOptions,
  StoragePutOutcome,
  StorageSignedUrlOptions,
  StorageSignedUrlResult,
} from "../../contracts/src/provider/index.ts";
import {
  isProviderFailure,
  isProviderSuccess,
  type ProviderResult,
} from "../../contracts/src/provider/shared.contract.ts";
import type { ErrorContract } from "../../contracts/src/error/index.ts";

function createMockError(code: string, message: string, http_status = 400): ErrorContract {
  return {
    code,
    message,
    message_key: `core.error.${code.toLowerCase()}`,
    kind: "VALIDATION_ERROR",
    severity: "ERROR",
    timestamp: "2026-10-15T18:00:00.000Z",
    recoverable: false,
    http_status,
  };
}

// =============================================================================
// TEST IN-MEMORY FIXTURES (CONFORMANCE MODELS)
// =============================================================================

function createMockStream(
  chunks: Uint8Array[],
  totalMaxBytes = 100 * 1024 * 1024,
): BoundedByteStream {
  let isClosed = false;
  let bytesRead = 0;
  let chunkIdx = 0;

  const iterator: BoundedByteStreamIterator = {
    async next(): Promise<IteratorResult<Uint8Array, void>> {
      await Promise.resolve();
      if (isClosed || chunkIdx >= chunks.length) {
        return { done: true, value: undefined };
      }
      const chunk = chunks[chunkIdx];
      chunkIdx += 1;
      if (chunk === undefined) {
        return { done: true, value: undefined };
      }
      if (bytesRead + chunk.byteLength > totalMaxBytes) {
        isClosed = true;
        throw new Error("STREAM_BYTE_LIMIT_EXCEEDED");
      }
      bytesRead += chunk.byteLength;
      return { done: false, value: chunk };
    },
    async return(): Promise<IteratorResult<Uint8Array, void>> {
      await Promise.resolve();
      isClosed = true;
      return { done: true, value: undefined };
    },
  };

  return {
    maxBytes: totalMaxBytes,
    get bytesRead() {
      return bytesRead;
    },
    get isClosed() {
      return isClosed;
    },
    async cancel(): Promise<void> {
      await Promise.resolve();
      isClosed = true;
    },
    [Symbol.asyncIterator]() {
      return iterator;
    },
  };
}

class InMemoryStorageConformanceProvider implements StorageProvider {
  public readonly id = "in-memory-conformance";
  private readonly store = new Map<string, { metadata: StorageObjectMetadata; data: Uint8Array }>();
  private readonly capabilities: ReadonlySet<StorageCapabilityKey>;

  public constructor(customCapabilities?: StorageCapabilityKey[]) {
    this.capabilities = new Set(
      customCapabilities ?? [
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
      ],
    );
  }

  public hasCapability(cap: StorageCapabilityKey): boolean {
    return this.capabilities.has(cap);
  }

  public getCapabilities(): ReadonlySet<StorageCapabilityKey> {
    return this.capabilities;
  }

  public async put(
    key: string,
    data: Uint8Array | BoundedByteStream,
    options?: StoragePutOptions,
  ): Promise<ProviderResult<StoragePutOutcome>> {
    const keyVal = validateStorageKey(key);
    if (!keyVal.valid) {
      return {
        success: false,
        failureKind: "VALIDATION_FAILED",
        error: createMockError("VALIDATION_ERROR", keyVal.reason, 400),
      };
    }

    if (options?.contentType !== undefined) {
      const ctVal = validateContentType(options.contentType);
      if (!ctVal.valid) {
        return {
          success: false,
          failureKind: "VALIDATION_FAILED",
          error: createMockError("VALIDATION_ERROR", ctVal.reason, 400),
        };
      }
    }

    const overwrite = options?.overwrite ?? false;
    const existing = this.store.get(key);

    if (existing !== undefined && !overwrite) {
      return {
        success: true,
        data: Object.freeze({ outcome: "already-exists" as const }),
      };
    }

    let bytes: Uint8Array;
    if (data instanceof Uint8Array) {
      bytes = new Uint8Array(data);
    } else {
      const chunks: Uint8Array[] = [];
      let total = 0;
      for await (const chunk of data) {
        chunks.push(chunk);
        total += chunk.byteLength;
        if (total > STORAGE_LIMITS.STREAM_ABSOLUTE_MAX_BYTES) {
          return {
            success: false,
            failureKind: "BYTE_LIMIT_EXCEEDED",
            error: createMockError(
              "BAD_REQUEST",
              "Stream exceeded absolute maximum byte limit",
              413,
            ),
          };
        }
      }
      bytes = new Uint8Array(total);
      let offset = 0;
      for (const c of chunks) {
        bytes.set(c, offset);
        offset += c.byteLength;
      }
    }

    const metadata: StorageObjectMetadata = Object.freeze({
      key,
      size: bytes.byteLength,
      lastModified: new Date(),
      eTag: `"etag-${String(Date.now())}"`,
      contentType: options?.contentType ?? "application/octet-stream",
    });

    this.store.set(key, { metadata, data: bytes });

    return {
      success: true,
      data: Object.freeze({ outcome: "stored" as const, metadata }),
    };
  }

  public async get(
    key: string,
    options?: StorageGetOptions,
  ): Promise<ProviderResult<StorageGetResult>> {
    await Promise.resolve();
    const keyVal = validateStorageKey(key);
    if (!keyVal.valid) {
      return {
        success: false,
        failureKind: "VALIDATION_FAILED",
        error: createMockError("VALIDATION_ERROR", keyVal.reason, 400),
      };
    }

    const item = this.store.get(key);
    if (!item) {
      return {
        success: false,
        failureKind: "NOT_FOUND",
        error: createMockError("NOT_FOUND", "Storage object not found", 404),
      };
    }

    let bytesToDeliver = item.data;
    let rangeMeta: { start: number; end: number; length: number } | undefined;

    if (options?.range !== undefined) {
      const { start, end } = options.range;
      if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < start) {
        return {
          success: false,
          failureKind: "VALIDATION_FAILED",
          error: createMockError("VALIDATION_ERROR", "Invalid byte range parameters", 400),
        };
      }
      if (item.metadata.size === 0 || start >= item.metadata.size) {
        return {
          success: false,
          failureKind: "VALIDATION_FAILED",
          error: createMockError("VALIDATION_ERROR", "Range start exceeds object size", 416),
        };
      }
      const clampedEnd = Math.min(end, item.metadata.size - 1);
      bytesToDeliver = item.data.slice(start, clampedEnd + 1);
      rangeMeta = { start, end: clampedEnd, length: bytesToDeliver.byteLength };
    }

    const stream = createMockStream([bytesToDeliver]);

    return {
      success: true,
      data: {
        metadata: item.metadata,
        stream,
        ...(rangeMeta ? { range: rangeMeta } : {}),
      },
    };
  }

  public async getBytes(
    key: string,
    options?: StorageGetOptions,
  ): Promise<ProviderResult<StorageGetBytesResult>> {
    const res = await this.get(key, options);
    if (!res.success) {
      return res;
    }
    const chunks: Uint8Array[] = [];
    for await (const chunk of res.data.stream) {
      chunks.push(chunk);
    }
    const totalLen = chunks.reduce((acc, c) => acc + c.byteLength, 0);
    const combined = new Uint8Array(totalLen);
    let offset = 0;
    for (const c of chunks) {
      combined.set(c, offset);
      offset += c.byteLength;
    }

    return {
      success: true,
      data: {
        metadata: res.data.metadata,
        bytes: combined,
        ...(res.data.range ? { range: res.data.range } : {}),
      },
    };
  }

  public async head(key: string): Promise<ProviderResult<StorageObjectMetadata | null>> {
    await Promise.resolve();
    const keyVal = validateStorageKey(key);
    if (!keyVal.valid) {
      return {
        success: false,
        failureKind: "VALIDATION_FAILED",
        error: createMockError("VALIDATION_ERROR", keyVal.reason, 400),
      };
    }
    const item = this.store.get(key);
    return {
      success: true,
      data: item ? item.metadata : null,
    };
  }

  public async delete(key: string): Promise<ProviderResult<boolean>> {
    await Promise.resolve();
    const keyVal = validateStorageKey(key);
    if (!keyVal.valid) {
      return {
        success: false,
        failureKind: "VALIDATION_FAILED",
        error: createMockError("VALIDATION_ERROR", keyVal.reason, 400),
      };
    }
    const had = this.store.delete(key);
    return {
      success: true,
      data: had,
    };
  }

  public async list(options?: StorageListOptions): Promise<ProviderResult<StorageListResult>> {
    await Promise.resolve();
    const prefix = options?.prefix ?? "";
    const prefixVal = validateStoragePrefix(prefix);
    if (!prefixVal.valid) {
      return {
        success: false,
        failureKind: "VALIDATION_FAILED",
        error: createMockError("VALIDATION_ERROR", prefixVal.reason, 400),
      };
    }

    const items: Array<
      { type: "object"; metadata: StorageObjectMetadata } | { type: "prefix"; prefix: string }
    > = [];
    const delimiter = options?.delimiter;

    for (const [k, v] of this.store.entries()) {
      if (k.startsWith(prefix)) {
        if (delimiter === "/") {
          const rest = k.slice(prefix.length);
          const slashIdx = rest.indexOf("/");
          if (slashIdx >= 0) {
            const commonPrefix = prefix + rest.slice(0, slashIdx + 1);
            if (!items.some((it) => it.type === "prefix" && it.prefix === commonPrefix)) {
              items.push({ type: "prefix", prefix: commonPrefix });
            }
            continue;
          }
        }
        items.push({ type: "object", metadata: v.metadata });
      }
    }

    return {
      success: true,
      data: {
        items,
        nextCursor: null,
      },
    };
  }

  public async copy(
    sourceKey: string,
    destinationKey: string,
    options?: StoragePutOptions,
  ): Promise<ProviderResult<StoragePutOutcome>> {
    const srcVal = validateStorageKey(sourceKey);
    const dstVal = validateStorageKey(destinationKey);
    if (!srcVal.valid || !dstVal.valid) {
      return {
        success: false,
        failureKind: "VALIDATION_FAILED",
        error: createMockError("VALIDATION_ERROR", "Invalid source or destination key", 400),
      };
    }

    const src = this.store.get(sourceKey);
    if (!src) {
      return {
        success: false,
        failureKind: "NOT_FOUND",
        error: createMockError("NOT_FOUND", "Source object not found", 404),
      };
    }

    return this.put(destinationKey, src.data, options);
  }

  public async move(
    sourceKey: string,
    destinationKey: string,
    options?: StoragePutOptions,
  ): Promise<ProviderResult<StoragePutOutcome>> {
    if (!this.hasCapability("move")) {
      return {
        success: false,
        failureKind: "UNSUPPORTED",
        error: createMockError("NOT_IMPLEMENTED", "Atomic move capability not supported", 501),
      };
    }

    if (sourceKey === destinationKey) {
      return {
        success: false,
        failureKind: "VALIDATION_FAILED",
        error: createMockError("VALIDATION_ERROR", "Source and destination keys must differ", 400),
      };
    }

    const copyRes = await this.copy(sourceKey, destinationKey, options);
    if (copyRes.success && copyRes.data.outcome === "stored") {
      this.store.delete(sourceKey);
    }
    return copyRes;
  }

  public async getSignedUrl(
    key: string,
    options: StorageSignedUrlOptions,
  ): Promise<ProviderResult<StorageSignedUrlResult>> {
    await Promise.resolve();
    if (!this.hasCapability("signedUrl")) {
      return {
        success: false,
        failureKind: "UNSUPPORTED",
        error: createMockError("NOT_IMPLEMENTED", "Signed URLs not supported", 501),
      };
    }

    const keyVal = validateStorageKey(key);
    if (!keyVal.valid) {
      return {
        success: false,
        failureKind: "VALIDATION_FAILED",
        error: createMockError("VALIDATION_ERROR", keyVal.reason, 400),
      };
    }

    if (
      !Number.isSafeInteger(options.ttlSeconds) ||
      options.ttlSeconds < STORAGE_LIMITS.SIGNED_URL_MIN_TTL_SECONDS ||
      options.ttlSeconds > STORAGE_LIMITS.SIGNED_URL_MAX_TTL_SECONDS
    ) {
      return {
        success: false,
        failureKind: "VALIDATION_FAILED",
        error: createMockError("VALIDATION_ERROR", "Invalid TTL seconds for signed URL", 400),
      };
    }

    const expiresAt = new Date(Date.now() + options.ttlSeconds * 1000);
    return {
      success: true,
      data: {
        url: `https://mock.storage.local/signed/${encodeURIComponent(key)}?exp=${String(expiresAt.getTime())}`,
        action: options.action,
        expiresAt,
      },
    };
  }

  public async deleteMany(
    keys: readonly string[],
  ): Promise<ProviderResult<readonly StorageDeleteBatchItemResult[]>> {
    await Promise.resolve();
    if (!this.hasCapability("batchDelete")) {
      return {
        success: false,
        failureKind: "UNSUPPORTED",
        error: createMockError("NOT_IMPLEMENTED", "Batch delete not supported", 501),
      };
    }

    if (keys.length < 1 || keys.length > STORAGE_LIMITS.BATCH_DELETE_MAX_KEYS) {
      return {
        success: false,
        failureKind: "VALIDATION_FAILED",
        error: createMockError("VALIDATION_ERROR", "Batch size must be between 1 and 100", 400),
      };
    }

    const seen = new Set<string>();
    for (const k of keys) {
      const val = validateStorageKey(k);
      if (!val.valid) {
        return {
          success: false,
          failureKind: "VALIDATION_FAILED",
          error: createMockError("VALIDATION_ERROR", "All keys in batch must be valid", 400),
        };
      }
      if (seen.has(k)) {
        return {
          success: false,
          failureKind: "VALIDATION_FAILED",
          error: createMockError("VALIDATION_ERROR", "Duplicate keys in batch are forbidden", 400),
        };
      }
      seen.add(k);
    }

    const results: StorageDeleteBatchItemResult[] = [];
    for (const k of keys) {
      const had = this.store.delete(k);
      results.push({
        key: k,
        outcome: had ? "deleted" : "absent",
      });
    }

    return {
      success: true,
      data: Object.freeze(results),
    };
  }
}

class BrokenOverwriteProvider extends InMemoryStorageConformanceProvider {
  public override async put(
    key: string,
    data: Uint8Array | BoundedByteStream,
    options?: StoragePutOptions,
  ): Promise<ProviderResult<StoragePutOutcome>> {
    return super.put(key, data, { ...options, overwrite: true });
  }
}

// =============================================================================
// TEST SUITE: STEP 17 STORAGE PROVIDER CONTRACT
// =============================================================================

void describe("Step 17: Storage Provider Contract", () => {
  void it("exports correct contract identity", () => {
    assert.equal(PROVIDER_STORAGE_CONTRACT_ID, "CONTRACT-CORE-PROVIDER-STORAGE-001");
    assert.equal(STORAGE_CAPABILITY_KEYS.includes("read"), true);
  });

  void describe("K01: Storage Key Validation Grammar", () => {
    void it("accepts valid keys including hierarchical paths and file extensions", () => {
      const validCases = [
        "file.txt",
        "document.v2.tar.gz",
        "media/2026/04/hero-image.webp",
        "users/profile_123/avatar.png",
        "a",
        "a/b/c/d/e",
        "folder.v1/sub_folder.v2/file-name_v3.pdf",
      ];
      for (const k of validCases) {
        const res = validateStorageKey(k);
        assert.equal(res.valid, true, `Key should be valid: ${k}`);
        assert.equal(res.key, k);
      }
    });

    void it("verifies length boundaries (0, 1, 1024, 1025)", () => {
      assert.equal(validateStorageKey("").valid, false);
      assert.equal(validateStorageKey("a").valid, true);

      const max1024 = "a".repeat(1024);
      assert.equal(validateStorageKey(max1024).valid, true);

      const over1025 = "a".repeat(1025);
      const resOver = validateStorageKey(over1025);
      assert.equal(resOver.valid, false);
      assert.match(resOver.reason, /exceeds maximum length/);
    });

    void it("rejects leading slash, trailing slash, and consecutive slashes", () => {
      assert.equal(validateStorageKey("/file.txt").valid, false);
      assert.equal(validateStorageKey("file.txt/").valid, false);
      assert.equal(validateStorageKey("media//image.png").valid, false);
      assert.equal(validateStorageKey("media///image.png").valid, false);
    });

    void it("rejects dot-prefixed segments and path traversal", () => {
      assert.equal(validateStorageKey(".hidden").valid, false);
      assert.equal(validateStorageKey("media/.secret/file.txt").valid, false);
      assert.equal(validateStorageKey("..").valid, false);
      assert.equal(validateStorageKey("media/../file.txt").valid, false);
      assert.equal(validateStorageKey("media/./file.txt").valid, false);
    });

    void it("rejects consecutive dots (a..b) and dots after punctuation (a-.b)", () => {
      assert.equal(validateStorageKey("a..b").valid, false);
      assert.equal(validateStorageKey("a-.b").valid, false);
      assert.equal(validateStorageKey("a_.b").valid, false);
    });

    void it("rejects non-ASCII, spaces, percent-encodings, and backslashes", () => {
      assert.equal(validateStorageKey("file name.txt").valid, false);
      assert.equal(validateStorageKey("file%20name.txt").valid, false);
      assert.equal(validateStorageKey("c:\\path\\file.txt").valid, false);
      assert.equal(validateStorageKey("český_soubor.txt").valid, false);
      assert.equal(validateStorageKey("file\x00.txt").valid, false);
      assert.equal(validateStorageKey("file\x1f.txt").valid, false);
    });
  });

  void describe("K02: Defensive Validation Against Hostile Inputs", () => {
    void it("handles non-string, null, undefined, objects, arrays, dates, regExps safely", () => {
      const nonStrings = [null, undefined, 123, true, {}, [], new Date(), /test/];
      for (const val of nonStrings) {
        const res = validateStorageKey(val);
        assert.equal(res.valid, false);
        assert.equal(res.reason, "Storage key must be a string");
      }
    });

    void it("does not invoke hostile toString() or crash on throwing getters", () => {
      let toStringCalled = false;
      const hostileObj = {
        toString() {
          toStringCalled = true;
          throw new Error("HOSTILE_TO_STRING");
        },
      };
      const res = validateStorageKey(hostileObj);
      assert.equal(toStringCalled, false);
      assert.equal(res.valid, false);
    });
  });

  void describe("K03: Frozen Invariant Limits & Pure Guards", () => {
    void it("verifies STORAGE_LIMITS is frozen and immutable", () => {
      assert.equal(Object.isFrozen(STORAGE_LIMITS), true);
      assert.throws(() => {
        // @ts-expect-error mutation attempt
        STORAGE_LIMITS.KEY_MAX_BYTES = 2048;
      }, TypeError);
    });

    void it("returns frozen validation result objects", () => {
      const valid = validateStorageKey("valid-key.txt");
      assert.equal(Object.isFrozen(valid), true);

      const invalid = validateStorageKey("");
      assert.equal(Object.isFrozen(invalid), true);
    });
  });

  void describe("P01: Storage Prefix Validation", () => {
    void it("accepts empty string, undefined, and valid prefix paths", () => {
      assert.equal(validateStoragePrefix("").valid, true);
      assert.equal(validateStoragePrefix(undefined).valid, true);
      assert.equal(validateStoragePrefix("media/").valid, true);
      assert.equal(validateStoragePrefix("media/2026/").valid, true);
      assert.equal(validateStoragePrefix("media/hero").valid, true);
    });

    void it("rejects leading slash, consecutive slashes, and dot violations in prefix", () => {
      assert.equal(validateStoragePrefix("/media/").valid, false);
      assert.equal(validateStoragePrefix("media//2026").valid, false);
      assert.equal(validateStoragePrefix("media/.secret/").valid, false);
      assert.equal(validateStoragePrefix("media/a..b/").valid, false);
    });
  });

  void describe("E01: Content-Type Validation and Secret Redaction", () => {
    void it("validates safe Content-Type values", () => {
      assert.equal(validateContentType("text/plain").valid, true);
      assert.equal(validateContentType("application/json").valid, true);
      assert.equal(validateContentType("image/webp").valid, true);
    });

    void it("rejects CR, LF, and control characters in Content-Type", () => {
      assert.equal(validateContentType("text/plain\r\nInjected-Header: evil").valid, false);
      assert.equal(validateContentType("text/plain\nInjected: evil").valid, false);
      assert.equal(validateContentType("text/plain\x00").valid, false);
      assert.equal(validateContentType("text/plain\x7f").valid, false);
    });

    void it("does not leak synthetic secrets into validation reasons", () => {
      const secretKey = "SECRET_PASSWORD_123456_INVALID_%";
      const res = validateStorageKey(secretKey);
      assert.equal(res.valid, false);
      assert.equal(res.reason.includes("SECRET_PASSWORD_123456"), false);
    });
  });

  void describe("T01: Compile-Time Type Narrowing & Outcome Distinction", () => {
    void it("verifies StoragePutOutcome discriminated union narrowing", async () => {
      const provider = new InMemoryStorageConformanceProvider();
      const res = await provider.put("file1.txt", new Uint8Array([1, 2, 3]), { overwrite: false });

      assert.equal(isProviderSuccess(res), true);
      if (isProviderSuccess(res)) {
        if (res.data.outcome === "stored") {
          assert.equal(res.data.metadata.key, "file1.txt");
          assert.equal(res.data.metadata.size, 3);
        } else {
          assert.fail("Expected outcome stored on initial put");
        }
      }

      const res2 = await provider.put("file1.txt", new Uint8Array([4, 5]), { overwrite: false });
      assert.equal(isProviderSuccess(res2), true);
      if (isProviderSuccess(res2)) {
        assert.equal(res2.data.outcome, "already-exists");
      }
    });

    void it("verifies Option B getBytes shape", async () => {
      const provider = new InMemoryStorageConformanceProvider();
      await provider.put("test.bin", new Uint8Array([10, 20, 30]));

      const getRes = await provider.getBytes("test.bin");
      assert.equal(isProviderSuccess(getRes), true);
      if (isProviderSuccess(getRes)) {
        assert.equal(getRes.data.metadata.key, "test.bin");
        assert.equal(getRes.data.bytes.byteLength, 3);
        assert.equal(getRes.data.bytes[0], 10);
      }
    });
  });

  void describe("W01 & W02: Overwrite Invariants & Byte Readback Verification", () => {
    void it("preserves original data byte-for-byte when overwrite is false", async () => {
      const provider = new InMemoryStorageConformanceProvider();
      const originalBytes = new Uint8Array([1, 2, 3, 4, 5]);
      await provider.put("immutable.dat", originalBytes, { overwrite: false });

      const hostileBytes = new Uint8Array([99, 99, 99]);
      const rejectPut = await provider.put("immutable.dat", hostileBytes, { overwrite: false });

      assert.equal(isProviderSuccess(rejectPut), true);
      if (isProviderSuccess(rejectPut)) {
        assert.equal(rejectPut.data.outcome, "already-exists");
      }

      const readback = await provider.getBytes("immutable.dat");
      assert.equal(isProviderSuccess(readback), true);
      if (isProviderSuccess(readback)) {
        assert.deepEqual(readback.data.bytes, originalBytes);
      }
    });

    void it("broken provider that overwrites on overwrite:false is caught by invariant test", async () => {
      const broken = new BrokenOverwriteProvider();
      const originalBytes = new Uint8Array([1, 2, 3]);
      await broken.put("test.txt", originalBytes, { overwrite: false });

      const secondBytes = new Uint8Array([9, 9]);
      await broken.put("test.txt", secondBytes, { overwrite: false });

      const readback = await broken.getBytes("test.txt");
      assert.equal(isProviderSuccess(readback), true);
      if (isProviderSuccess(readback)) {
        const bytesWereMutated = !readback.data.bytes.every((v, i) => v === originalBytes[i]);
        assert.equal(
          bytesWereMutated,
          true,
          "Broken fixture successfully captured invariant violation",
        );
      }
    });

    void it("W02: simultaneous writers result in exactly one winner", async () => {
      const provider = new InMemoryStorageConformanceProvider();
      const writerA = provider.put("race.txt", new Uint8Array([1]), { overwrite: false });
      const writerB = provider.put("race.txt", new Uint8Array([2]), { overwrite: false });

      const [resA, resB] = await Promise.all([writerA, writerB]);
      assert.equal(isProviderSuccess(resA), true);
      assert.equal(isProviderSuccess(resB), true);

      if (isProviderSuccess(resA) && isProviderSuccess(resB)) {
        const outcomes = [resA.data.outcome, resB.data.outcome];
        assert.equal(outcomes.filter((o) => o === "stored").length, 1);
        assert.equal(outcomes.filter((o) => o === "already-exists").length, 1);
      }
    });
  });

  void describe("S01: Bounded Byte Stream Handling", () => {
    void it("delivers stream chunks cleanly under ceiling", async () => {
      const provider = new InMemoryStorageConformanceProvider();
      const stream = createMockStream([new Uint8Array([1, 2]), new Uint8Array([3, 4])]);
      const res = await provider.put("streamed.bin", stream);

      assert.equal(isProviderSuccess(res), true);
      if (isProviderSuccess(res)) {
        assert.equal(res.data.outcome, "stored");
        assert.equal(res.data.metadata.size, 4);
      }
    });

    void it("early break invokes return() cleanup", async () => {
      const stream = createMockStream([
        new Uint8Array([1]),
        new Uint8Array([2]),
        new Uint8Array([3]),
      ]);
      for await (const chunk of stream) {
        assert.equal(chunk[0], 1);
        break;
      }
      assert.equal(stream.isClosed, true);
    });
  });

  void describe("R01, C01, B01, U01: Range, Capabilities, Batch & Signed URLs", () => {
    void it("R01: returns bounded byte slice and range metadata", async () => {
      const provider = new InMemoryStorageConformanceProvider();
      await provider.put("range.txt", new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]));

      const range: StorageByteRange = { start: 2, end: 5 };
      const res = await provider.getBytes("range.txt", { range });
      assert.equal(isProviderSuccess(res), true);
      if (isProviderSuccess(res)) {
        assert.deepEqual(res.data.bytes, new Uint8Array([2, 3, 4, 5]));
        assert.deepEqual(res.data.range, { start: 2, end: 5, length: 4 });
      }
    });

    void it("C01: handles atomic move and unsupported capability", async () => {
      const provider = new InMemoryStorageConformanceProvider();
      await provider.put("source.txt", new Uint8Array([42]));

      const moveRes = await provider.move("source.txt", "dest.txt");
      assert.equal(isProviderSuccess(moveRes), true);

      const srcHead = await provider.head("source.txt");
      assert.equal(isProviderSuccess(srcHead) && srcHead.data, null);

      const dstGet = await provider.getBytes("dest.txt");
      assert.equal(isProviderSuccess(dstGet) && dstGet.data.bytes[0], 42);

      const noMoveProvider = new InMemoryStorageConformanceProvider(["read", "write"]);
      const unsupportedRes = await noMoveProvider.move("a.txt", "b.txt");
      assert.equal(isProviderFailure(unsupportedRes), true);
      if (isProviderFailure(unsupportedRes)) {
        assert.equal(unsupportedRes.failureKind, "UNSUPPORTED");
      }
    });

    void it("B01: deleteMany validates all keys first and rejects duplicates", async () => {
      const provider = new InMemoryStorageConformanceProvider();
      await provider.put("k1.txt", new Uint8Array([1]));
      await provider.put("k2.txt", new Uint8Array([2]));

      const batchRes = await provider.deleteMany(["k1.txt", "k2.txt", "k3_nonexistent.txt"]);
      assert.equal(isProviderSuccess(batchRes), true);
      if (isProviderSuccess(batchRes)) {
        assert.equal(batchRes.data.length, 3);
        assert.equal(batchRes.data[0]?.outcome, "deleted");
        assert.equal(batchRes.data[1]?.outcome, "deleted");
        assert.equal(batchRes.data[2]?.outcome, "absent");
      }

      const dupRes = await provider.deleteMany(["a.txt", "a.txt"]);
      assert.equal(isProviderFailure(dupRes), true);
      if (isProviderFailure(dupRes)) {
        assert.equal(dupRes.failureKind, "VALIDATION_FAILED");
      }
    });

    void it("U01: validates signed URL TTL bounds (1 to 900)", async () => {
      const provider = new InMemoryStorageConformanceProvider();
      const validUrl = await provider.getSignedUrl("file.txt", { action: "read", ttlSeconds: 300 });
      assert.equal(isProviderSuccess(validUrl), true);

      const invalidTtl = await provider.getSignedUrl("file.txt", {
        action: "read",
        ttlSeconds: 1000,
      });
      assert.equal(isProviderFailure(invalidTtl), true);
      if (isProviderFailure(invalidTtl)) {
        assert.equal(invalidTtl.failureKind, "VALIDATION_FAILED");
      }
    });
  });
});
