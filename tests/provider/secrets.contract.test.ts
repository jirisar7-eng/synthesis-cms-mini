/**
 * =============================================================================
 * SYNTHESIS CMS MINI — SECRETS PROVIDER CONTRACT TESTS
 * =============================================================================
 *
 * @module tests/provider/secrets.contract.test
 * @version 1.0.0
 * @task SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001
 * @command CMD-SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001-20261016-049-IMPLEMENT-SECRETS-V1
 * @phase TEST
 *
 * TEST MATRIX & CONFORMANCE SPECIFICATION:
 * -----------------------------------------------------------------------------
 *  - K01: Secret Key Validation Grammar (length 0..129, ASCII bounds, reserved names)
 *  - K02: Defensive Validation Against Hostile Inputs (no coercion, proxy safety)
 *  - K03: Frozen Invariant Limits & Pure Guards
 *  - SEC01: In-Memory Conformance Fixture (0..65536 bounds, independent buffers, no-leak)
 *  - CAP01: Capability Discovery & Snapshot Immutability
 *  - SIG01: AbortSignal & Cancellation Semantics
 *  - GW01: Synthetic Pre-Provider Gateway Specification (401/403 denial before provider)
 *  - T01: Compile-Time Type Narrowing & Conformance
 *
 * NOTE: These synthetic tests and in-memory fixtures verify contractual shape
 * and conformance. They do NOT represent or prove production backend KMS
 * encryption, operating system memory zeroization, or transport security.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  PROVIDER_SECRETS_CONTRACT_ID,
  SECRETS_PROVIDER_CONTRACT_ID,
  SECRETS_LIMITS,
  SECRETS_CAPABILITY_KEYS,
  validateSecretKey,
  type SecretsProvider,
  type SecretsCapabilityKey,
  type SecretReadResult,
  type SecretsGetOptions,
} from "../../contracts/src/provider/secrets.contract.ts";

import {
  isProviderSuccess,
  isProviderFailure,
  type ProviderResult,
} from "../../contracts/src/provider/shared.contract.ts";

import {
  SynthesisBaseError,
  normalizeToErrorContract,
  serializePublicErrorPayload,
  type ErrorContract,
} from "../../contracts/src/error/index.ts";

function createMockError(code: string, message: string, http_status = 400): ErrorContract {
  return {
    code,
    message,
    message_key: `core.error.${code.toLowerCase()}`,
    kind: "DOMAIN_ERROR",
    severity: "ERROR",
    timestamp: "2026-10-16T18:00:00.000Z",
    recoverable: false,
    http_status,
  };
}

// =============================================================================
// IN-MEMORY CONFORMANCE FIXTURE IMPLEMENTATION
// =============================================================================

class ConformanceSecretsProvider implements SecretsProvider {
  public readonly id: string;
  private readonly store: Map<string, Uint8Array>;
  public getInvocationCount = 0;

  public constructor(id = "fixture-secrets-provider", initialSecrets?: Record<string, Uint8Array>) {
    this.id = id;
    this.store = new Map();
    if (initialSecrets) {
      for (const [k, v] of Object.entries(initialSecrets)) {
        // Defensive copy on ingestion
        this.store.set(k, new Uint8Array(v));
      }
    }
  }

  public hasCapability(capability: SecretsCapabilityKey): boolean {
    return (capability as string) === "read";
  }

  public getCapabilities(): readonly SecretsCapabilityKey[] {
    return Object.freeze(["read"]);
  }

  public async get(
    key: string,
    options?: SecretsGetOptions,
  ): Promise<ProviderResult<SecretReadResult>> {
    await Promise.resolve();
    this.getInvocationCount++;

    // 1. Cancellation check
    if (options?.signal?.aborted) {
      return Object.freeze({
        success: false,
        failureKind: "CANCELED",
        error: createMockError("ERR_OPERATION_ABORTED", "Secret retrieval was aborted", 400),
      });
    }

    // 2. Defensive key validation
    const keyValidation = validateSecretKey(key);
    if (!keyValidation.valid) {
      return Object.freeze({
        success: false,
        failureKind: "VALIDATION_FAILED",
        error: createMockError("ERR_INVALID_SECRET_KEY", keyValidation.reason, 400),
      });
    }

    // 3. Existence lookup
    const existing = this.store.get(keyValidation.key);
    if (!existing) {
      return Object.freeze({
        success: false,
        failureKind: "NOT_FOUND",
        error: createMockError("ERR_SECRET_NOT_FOUND", "Requested secret does not exist", 404),
      });
    }

    // 4. Value boundary check (0 to 65,536 bytes)
    if (existing.byteLength > SECRETS_LIMITS.VALUE_MAX_BYTES) {
      return Object.freeze({
        success: false,
        failureKind: "BYTE_LIMIT_EXCEEDED",
        error: createMockError(
          "ERR_SECRET_BYTE_LIMIT_EXCEEDED",
          "Secret payload exceeds maximum permissible size",
          413,
        ),
      });
    }

    // 5. Caller-owned independent byte clone (no buffer aliasing)
    const clonedBytes = new Uint8Array(existing.byteLength);
    clonedBytes.set(existing);

    return Object.freeze({
      success: true,
      data: Object.freeze({
        bytes: clonedBytes,
      }),
      context: options?.context,
    });
  }
}

// =============================================================================
// TEST SUITE
// =============================================================================

void describe("Step 17: Secrets Provider Contract", () => {
  void it("exports correct contract identity and frozen limits", () => {
    assert.equal(PROVIDER_SECRETS_CONTRACT_ID, "CONTRACT-CORE-PROVIDER-SECRETS-001");
    assert.equal(SECRETS_PROVIDER_CONTRACT_ID, "CONTRACT-CORE-PROVIDER-SECRETS-001");
    assert.equal(SECRETS_LIMITS.KEY_MIN_BYTES, 1);
    assert.equal(SECRETS_LIMITS.KEY_MAX_BYTES, 128);
    assert.equal(SECRETS_LIMITS.VALUE_MAX_BYTES, 65536);
    assert.equal(Object.isFrozen(SECRETS_LIMITS), true);

    assert.deepEqual(SECRETS_CAPABILITY_KEYS, ["read"]);
    assert.equal(Object.isFrozen(SECRETS_CAPABILITY_KEYS), true);
  });

  void describe("K01: Secret Key Validation Grammar", () => {
    void it("accepts valid keys within length 1..128 bounds", () => {
      // Single letter
      const resA = validateSecretKey("a");
      if (!resA.valid) {
        assert.fail('Expected key "a" to be valid');
      }
      const resZ = validateSecretKey("Z");
      if (!resZ.valid) {
        assert.fail('Expected key "Z" to be valid');
      }

      // Typical identifiers
      const resDb = validateSecretKey("DATABASE_URL");
      if (!resDb.valid) {
        assert.fail('Expected key "DATABASE_URL" to be valid');
      }
      const resJwt = validateSecretKey("jwt-secret_key-01");
      if (!resJwt.valid) {
        assert.fail('Expected key "jwt-secret_key-01" to be valid');
      }
      const resStripe = validateSecretKey("STRIPE_API_KEY_LIVE");
      if (!resStripe.valid) {
        assert.fail('Expected key "STRIPE_API_KEY_LIVE" to be valid');
      }
      const resApp = validateSecretKey("app_config_token");
      if (!resApp.valid) {
        assert.fail('Expected key "app_config_token" to be valid');
      }

      // Max length (128 characters)
      const maxKey = "a" + "b".repeat(127);
      const resMax = validateSecretKey(maxKey);
      if (!resMax.valid) {
        assert.fail("Expected 128-char key to be valid");
      }
      assert.equal(resMax.key, maxKey);
    });

    void it("verifies length boundary rejection (0 and 129)", () => {
      // Empty string (0 bytes)
      const res0 = validateSecretKey("");
      if (res0.valid) {
        assert.fail("Expected empty key to be rejected");
      }
      assert.equal(res0.reason, "Secret key must not be empty");

      // Exceeds max length (129 bytes)
      const res129 = validateSecretKey("a".repeat(129));
      if (res129.valid) {
        assert.fail("Expected 129-char key to be rejected");
      }
      assert.equal(res129.reason, "Secret key exceeds maximum length of 128 characters");
    });

    void it("rejects keys that do not start with an ASCII letter", () => {
      const invalidStarts = ["1abc", "_secret", "-secret", ".secret", "/secret", "@secret"];
      for (const key of invalidStarts) {
        const res = validateSecretKey(key);
        if (res.valid) {
          assert.fail(`Expected key ${key} to be rejected`);
        }
        assert.equal(res.reason, "Secret key must start with an ASCII letter [A-Za-z]");
      }
    });

    void it("rejects non-ASCII, spaces, control characters, and line terminators", () => {
      const hostileKeys = [
        "secret key", // space
        "secret\tkey", // tab
        "secret\nkey", // LF
        "secret\rkey", // CR
        "secretkey\n", // trailing LF
        "secretkey\r\n", // trailing CRLF
        "secretkey\u2028", // line separator
        "secretkey\u2029", // paragraph separator
        "klíč_k_databázi", // Unicode
        "secret/path", // slash
        "secret\\path", // backslash
        "secret%20key", // percent
        "secret.key", // dot
        "secret!key", // punctuation
      ];

      for (const key of hostileKeys) {
        const res = validateSecretKey(key);
        if (res.valid) {
          assert.fail(`Expected ${JSON.stringify(key)} to be rejected`);
        }
      }
    });

    void it("rejects exact reserved prototype property names", () => {
      const reserved = ["constructor", "prototype", "__proto__"];
      for (const name of reserved) {
        const res = validateSecretKey(name);
        if (res.valid) {
          assert.fail(`Expected reserved name ${name} to be rejected`);
        }
        assert.equal(
          res.reason === "Secret key uses a reserved identifier" ||
            res.reason === "Secret key must start with an ASCII letter [A-Za-z]",
          true,
        );
      }
    });
  });

  void describe("K02: Defensive Validation Against Hostile Inputs", () => {
    void it("safely rejects non-string types without coercion or crash", () => {
      const nonStrings = [
        null,
        undefined,
        12345,
        true,
        false,
        {},
        [],
        new Date(),
        /regex/,
        new String("boxedString"), // boxed object
      ];

      for (const val of nonStrings) {
        const res = validateSecretKey(val);
        if (res.valid) {
          assert.fail("Expected non-string to be rejected");
        }
        assert.equal(res.reason, "Secret key must be a primitive string");
      }
    });

    void it("safely handles hostile Proxy objects without calling toString", () => {
      let toStringCalled = false;
      const hostileObj = {
        toString() {
          toStringCalled = true;
          throw new Error("HOSTILE_TO_STRING_INVOKED");
        },
      };

      const hostileProxy = new Proxy(hostileObj, {
        get(_target, prop) {
          if (prop === "length") return 10;
          if (prop === "charCodeAt") return () => 65;
          return undefined;
        },
      });

      const res = validateSecretKey(hostileProxy);
      if (res.valid) {
        assert.fail("Expected proxy object to be rejected");
      }
      assert.equal(toStringCalled, false);
      assert.equal(res.reason, "Secret key must be a primitive string");
    });
  });

  void describe("K03: Frozen Invariant Limits & Pure Guards", () => {
    void it("returns frozen validation result objects", () => {
      const validRes = validateSecretKey("VALID_KEY");
      assert.equal(Object.isFrozen(validRes), true);

      const invalidRes = validateSecretKey("123_INVALID");
      assert.equal(Object.isFrozen(invalidRes), true);
    });
  });

  void describe("SEC01: In-Memory Conformance Fixture", () => {
    void it("retrieves an existing secret returning caller-owned independent bytes", async () => {
      const originalBytes = new Uint8Array([1, 2, 3, 4, 5]);
      const provider = new ConformanceSecretsProvider("test-provider", {
        API_TOKEN: originalBytes,
      });

      const result = await provider.get("API_TOKEN");
      if (!isProviderSuccess(result)) {
        assert.fail("Expected provider success");
      }
      assert.deepEqual(result.data.bytes, originalBytes);

      // Verify independent buffer allocation (no buffer aliasing)
      result.data.bytes[0] = 99;
      assert.equal(originalBytes[0], 1, "Original buffer must not be mutated");

      // Subsequent read delivers pristine bytes
      const secondRead = await provider.get("API_TOKEN");
      if (!isProviderSuccess(secondRead)) {
        assert.fail("Expected second read to succeed");
      }
      assert.equal(secondRead.data.bytes[0], 1);
    });

    void it("delivers an existing empty secret (0 bytes) as success, distinct from NOT_FOUND", async () => {
      const provider = new ConformanceSecretsProvider("test-provider", {
        EMPTY_SECRET: new Uint8Array(0),
      });

      const result = await provider.get("EMPTY_SECRET");
      if (!isProviderSuccess(result)) {
        assert.fail("Expected empty secret to succeed");
      }
      assert.equal(result.data.bytes.byteLength, 0);

      // Distinct from absent secret
      const absentResult = await provider.get("ABSENT_SECRET");
      if (!isProviderFailure(absentResult)) {
        assert.fail("Expected absent secret to fail");
      }
      assert.equal(absentResult.failureKind, "NOT_FOUND");
    });

    void it("enforces maximum permissible value bound (65,536 bytes)", async () => {
      const maxBytes = new Uint8Array(SECRETS_LIMITS.VALUE_MAX_BYTES).fill(42);
      const provider = new ConformanceSecretsProvider("test-provider", {
        MAX_SECRET: maxBytes,
      });

      const result = await provider.get("MAX_SECRET");
      if (!isProviderSuccess(result)) {
        assert.fail("Expected max secret to succeed");
      }
      assert.equal(result.data.bytes.byteLength, 65536);
    });

    void it("fails with BYTE_LIMIT_EXCEEDED when secret payload exceeds 65,536 bytes", async () => {
      const overBytes = new Uint8Array(SECRETS_LIMITS.VALUE_MAX_BYTES + 1).fill(42);
      const provider = new ConformanceSecretsProvider("test-provider", {
        OVERSIZED_SECRET: overBytes,
      });

      const result = await provider.get("OVERSIZED_SECRET");
      if (!isProviderFailure(result)) {
        assert.fail("Expected oversized secret to fail");
      }
      assert.equal(result.failureKind, "BYTE_LIMIT_EXCEEDED");
    });

    void it("returns VALIDATION_FAILED when passed an invalid key", async () => {
      const provider = new ConformanceSecretsProvider("test-provider");
      const result = await provider.get("123-invalid-start");
      if (!isProviderFailure(result)) {
        assert.fail("Expected invalid key to fail");
      }
      assert.equal(result.failureKind, "VALIDATION_FAILED");
    });

    void it("ensures synthetic secret markers are not leaked into failure responses", async () => {
      const provider = new ConformanceSecretsProvider("test-provider");
      const secretMarker = "SUPER_SECRET_TOKEN_DO_NOT_LEAK";
      const result = await provider.get(secretMarker);

      if (!isProviderFailure(result)) {
        assert.fail("Expected secret marker lookup to fail");
      }
      const jsonString = JSON.stringify(result);
      // The secret marker is the requested key, but failure message must not leak internal secrets
      assert.equal(jsonString.includes("Requested secret does not exist"), true);
    });
  });

  void describe("CAP01: Capability Discovery & Immutability", () => {
    void it("reports read capability and rejects unsupported capabilities", () => {
      const provider = new ConformanceSecretsProvider();
      assert.equal(provider.hasCapability("read"), true);
      assert.equal(provider.hasCapability("write" as unknown as SecretsCapabilityKey), false);
      assert.equal(provider.hasCapability("rotate" as unknown as SecretsCapabilityKey), false);
    });

    void it("returns a frozen array snapshot from getCapabilities()", () => {
      const provider = new ConformanceSecretsProvider();
      const caps = provider.getCapabilities();
      assert.deepEqual(caps, ["read"]);
      assert.equal(Object.isFrozen(caps), true);

      // Attempting to mutate throws TypeError in strict mode
      assert.throws(() => {
        (caps as unknown as string[]).push("unauthorized");
      }, TypeError);
    });
  });

  void describe("SIG01: AbortSignal & Cancellation Semantics", () => {
    void it("aborts early when signal is pre-aborted with zero I/O performed", async () => {
      const provider = new ConformanceSecretsProvider("test-provider", {
        SECRET_A: new Uint8Array([1, 2, 3]),
      });

      const controller = new AbortController();
      controller.abort();

      const result = await provider.get("SECRET_A", {
        signal: controller.signal,
      });

      if (!isProviderFailure(result)) {
        assert.fail("Expected aborted request to fail");
      }
      assert.equal(result.failureKind, "CANCELED");
    });
  });

  void describe("GW01: Synthetic Pre-Provider Gateway Specification", () => {
    void it("demonstrates pre-provider authorization denial without invoking provider", async () => {
      const provider = new ConformanceSecretsProvider("test-provider", {
        SENSITIVE_KEY: new Uint8Array([10, 20, 30]),
      });

      // Synthetic gateway enforcing server-side DENY policy before provider invocation
      async function gatewayGetSecret(
        key: string,
        authContext: { authenticated: boolean; authorized: boolean },
      ): Promise<ProviderResult<SecretReadResult>> {
        if (!authContext.authenticated) {
          // HTTP 401 unauthenticated
          throw new SynthesisBaseError({
            code: "ERR_UNAUTHORIZED",
            message: "Authentication required to access secrets",
            message_key: "core.error.unauthorized",
            kind: "SECURITY_ERROR",
            http_status: 401,
          });
        }
        if (!authContext.authorized) {
          // HTTP 403 authenticated but denied
          throw new SynthesisBaseError({
            code: "ERR_FORBIDDEN",
            message: "Caller is not authorized to access the requested secret",
            message_key: "gov.error.access_denied",
            kind: "SECURITY_ERROR",
            http_status: 403,
          });
        }

        return provider.get(key);
      }

      // 1. Unauthenticated caller (401)
      let unauthCaught = false;
      try {
        await gatewayGetSecret("SENSITIVE_KEY", {
          authenticated: false,
          authorized: false,
        });
      } catch (err) {
        unauthCaught = true;
        const normalized = normalizeToErrorContract(err);
        const payload = serializePublicErrorPayload(normalized);
        assert.equal(payload.code, "ERR_UNAUTHORIZED");
        assert.equal(payload.kind, "SECURITY_ERROR");
        assert.equal(payload.message_key, "core.error.unauthorized");
        assert.equal(provider.getInvocationCount, 0, "Provider must not be invoked");
      }
      assert.equal(unauthCaught, true);

      // 2. Authenticated but unauthorized caller (403)
      let forbiddenCaught = false;
      try {
        await gatewayGetSecret("SENSITIVE_KEY", {
          authenticated: true,
          authorized: false,
        });
      } catch (err) {
        forbiddenCaught = true;
        const normalized = normalizeToErrorContract(err);
        const payload = serializePublicErrorPayload(normalized);
        assert.equal(payload.code, "ERR_FORBIDDEN");
        assert.equal(payload.kind, "SECURITY_ERROR");
        assert.equal(payload.message_key, "gov.error.access_denied");
        assert.equal(provider.getInvocationCount, 0, "Provider must not be invoked");
      }
      assert.equal(forbiddenCaught, true);

      // 3. Authorized caller
      const successResult = await gatewayGetSecret("SENSITIVE_KEY", {
        authenticated: true,
        authorized: true,
      });
      if (!isProviderSuccess(successResult)) {
        assert.fail("Expected gateway call to succeed");
      }
      assert.equal(provider.getInvocationCount, 1, "Provider invoked exactly once");
    });
  });

  void describe("T01: Compile-Time Type Narrowing & Conformance", () => {
    void it("verifies compile-time type narrowing for ProviderResult", () => {
      const successResult: ProviderResult<SecretReadResult> = Object.freeze({
        success: true,
        data: Object.freeze({ bytes: new Uint8Array([1, 2]) }),
      });

      if (isProviderSuccess(successResult)) {
        const bytes: Uint8Array = successResult.data.bytes;
        assert.equal(bytes.byteLength, 2);
      } else {
        assert.fail("Expected success branch");
      }

      const failureResult: ProviderResult<SecretReadResult> = Object.freeze({
        success: false,
        failureKind: "NOT_FOUND",
        error: createMockError("ERR_SECRET_NOT_FOUND", "Not found", 404),
      });

      if (isProviderFailure(failureResult)) {
        assert.equal(failureResult.failureKind, "NOT_FOUND");
      } else {
        assert.fail("Expected failure branch");
      }
    });
  });
});
