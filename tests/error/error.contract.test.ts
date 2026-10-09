import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  ALLOWLIST_PUBLIC_KEYS,
  ERROR_DEFAULTS,
  SynthesisBaseError,
  isValidErrorCode,
  isValidMessageKey,
  isValidUtcTimestamp,
  normalizeToErrorContract,
  serializePublicErrorPayload,
  toRFC8785JSON,
} from "../../contracts/src/error/index.ts";

void describe("Unified Error Contract", () => {
  void it("1. Constructs verified SynthesisBaseError with exact contract properties", () => {
    const err = new SynthesisBaseError({
      code: "ERR_UNAUTHORIZED",
      message: "User is not authorized to perform this operation.",
      message_key: "core.error.unauthorized",
      kind: "SECURITY_ERROR",
      severity: "ERROR",
      recoverable: false,
      correlation_id: "corr-test-123",
      public_details: { role: "guest" },
      internal_details: { userId: "u-101" },
      http_status: 401,
      timestamp: "2026-10-09T04:47:00.000Z",
    });

    assert.equal(err.code, "ERR_UNAUTHORIZED");
    assert.equal(err.message, "User is not authorized to perform this operation.");
    assert.equal(err.message_key, "core.error.unauthorized");
    assert.equal(err.kind, "SECURITY_ERROR");
    assert.equal(err.severity, "ERROR");
    assert.equal(err.recoverable, false);
    assert.equal(err.correlation_id, "corr-test-123");
    assert.deepEqual(err.public_details, { role: "guest" });
    assert.deepEqual(err.internal_details, { userId: "u-101" });
    assert.equal(err.http_status, 401);
    assert.equal(err.timestamp, "2026-10-09T04:47:00.000Z");
  });

  void it("2. Enforces strict immutability (Object.freeze) on SynthesisBaseError", () => {
    const err = new SynthesisBaseError({
      code: "ERR_INVALID_INPUT",
      message: "Input validation failed.",
      message_key: "core.error.validation_failed",
      kind: "VALIDATION_ERROR",
    });

    assert.ok(Object.isFrozen(err));
  });

  void it("3. Validates error code grammar (ERR_[A-Z0-9_]+)", () => {
    assert.ok(isValidErrorCode("ERR_UNAUTHORIZED"));
    assert.ok(isValidErrorCode("ERR_INVALID_INPUT_123"));
    assert.ok(isValidErrorCode("ERR_SYSTEM_FAILURE"));
    assert.equal(isValidErrorCode("err_unauthorized"), false);
    assert.equal(isValidErrorCode("ERR-UNAUTHORIZED"), false);
    assert.equal(isValidErrorCode("INVALID_CODE"), false);
    assert.equal(isValidErrorCode(""), false);
    assert.equal(isValidErrorCode(123), false);
    assert.equal(isValidErrorCode(null), false);
  });

  void it("4. Validates message_key Step 13 namespace grammar alignment", () => {
    assert.ok(isValidMessageKey("core.error.validation_failed"));
    assert.ok(isValidMessageKey("core.error.unauthorized_access"));
    assert.ok(isValidMessageKey("gov.error.access_denied"));
    assert.ok(isValidMessageKey("sys.error.database_offline"));
    assert.ok(isValidMessageKey("pack.ecommerce.order_failed"));
    assert.ok(isValidMessageKey("ext.acme.blog.error.not_found"));

    assert.equal(isValidMessageKey("error.validation.failed"), false, "Missing Step 13 root");
    assert.equal(isValidMessageKey("invalid.root.error"), false, "Invalid root");
    assert.equal(isValidMessageKey("core.error.Validation_Failed"), false, "Uppercase forbidden");
    assert.equal(isValidMessageKey("core.error.space in key"), false, "Spaces forbidden");
    assert.equal(isValidMessageKey("core.error.hyphen-key"), false, "Hyphens forbidden");
    assert.equal(isValidMessageKey("core"), false, "Fewer than 2 segments");
    assert.equal(isValidMessageKey("core.1.2.3.4.5.6.7"), false, "More than 6 segments");
    assert.equal(isValidMessageKey("core." + "a".repeat(50)), false, "Segment length > 48");
  });

  void it("5. Validates UTC ISO-8601 timestamp format", () => {
    assert.ok(isValidUtcTimestamp("2026-10-09T04:47:00.000Z"));
    assert.ok(isValidUtcTimestamp(new Date().toISOString()));
    assert.equal(isValidUtcTimestamp("2026-10-09 04:47:00"), false);
    assert.equal(isValidUtcTimestamp("2026-10-09T04:47:00Z"), false, "Missing milliseconds");
    assert.equal(isValidUtcTimestamp("invalid-date"), false);
    assert.equal(isValidUtcTimestamp(1728449220000), false);
    assert.equal(isValidUtcTimestamp(null), false);
  });

  void it("6. Normalizes verified SynthesisBaseError instances accurately", () => {
    const err = new SynthesisBaseError({
      code: "ERR_NOT_FOUND",
      message: "Requested resource was not found.",
      message_key: "core.error.resource_not_found",
      kind: "DOMAIN_ERROR",
      severity: "INFO",
      recoverable: true,
      correlation_id: "corr-001",
      public_details: { resourceId: "res-99" },
      internal_details: { sqlQuery: "SELECT * FROM res WHERE id = 99" },
      http_status: 404,
      timestamp: "2026-10-09T04:47:00.000Z",
    });

    const ctx = normalizeToErrorContract(err);
    assert.equal(ctx.contract.code, "ERR_NOT_FOUND");
    assert.equal(ctx.contract.message_key, "core.error.resource_not_found");
    assert.equal(ctx.contract.kind, "DOMAIN_ERROR");
    assert.equal(ctx.contract.recoverable, true);
    assert.equal(ctx.contract.http_status, 404);
    assert.equal(ctx.raw_throw_value, err);
    assert.deepEqual(ctx.internal_details, { sqlQuery: "SELECT * FROM res WHERE id = 99" });
  });

  void it("7. Fails closed on untrusted throw values", () => {
    const testCases: unknown[] = [
      null,
      undefined,
      "Raw string error message",
      404,
      false,
      new Error("Native JavaScript exception"),
      { code: "ERR_FAKE", message: "Fake error", message_key: "core.error.fake" },
      Object.create({ code: "ERR_INJECTED", message_key: "core.error.injected" }),
    ];

    for (const item of testCases) {
      const ctx = normalizeToErrorContract(item, "corr-fallback-123");
      assert.equal(ctx.contract.code, ERROR_DEFAULTS.CODE);
      assert.equal(ctx.contract.message, ERROR_DEFAULTS.MESSAGE);
      assert.equal(ctx.contract.message_key, ERROR_DEFAULTS.MESSAGE_KEY);
      assert.equal(ctx.contract.kind, ERROR_DEFAULTS.KIND);
      assert.equal(ctx.contract.severity, ERROR_DEFAULTS.SEVERITY);
      assert.equal(ctx.contract.recoverable, false);
      assert.equal(ctx.contract.http_status, 500);
      assert.equal(ctx.contract.correlation_id, "corr-fallback-123");
      assert.ok(isValidUtcTimestamp(ctx.contract.timestamp));
    }
  });

  void it("8. Serializes PublicErrorPayload using explicit fail-closed allowlist filtering", () => {
    const err = new SynthesisBaseError({
      code: "ERR_FORBIDDEN",
      message: "Access is denied.",
      message_key: "gov.error.access_denied",
      kind: "SECURITY_ERROR",
      severity: "ERROR",
      recoverable: false,
      correlation_id: "corr-sec-99",
      public_details: { roleRequired: "admin" },
      internal_details: { tokenSecret: "secret_jwt_key_xyz" },
      http_status: 403,
      timestamp: "2026-10-09T04:47:00.000Z",
    });

    const internalCtx = normalizeToErrorContract(err);
    const publicPayload = serializePublicErrorPayload(internalCtx);

    assert.equal(publicPayload.code, "ERR_FORBIDDEN");
    assert.equal(publicPayload.message, "Access is denied.");
    assert.equal(publicPayload.message_key, "gov.error.access_denied");
    assert.equal(publicPayload.kind, "SECURITY_ERROR");
    assert.equal(publicPayload.severity, "ERROR");
    assert.equal(publicPayload.recoverable, false);
    assert.equal(publicPayload.correlation_id, "corr-sec-99");
    assert.deepEqual(publicPayload.public_details, { roleRequired: "admin" });

    const keys = Object.keys(publicPayload);
    for (const k of keys) {
      assert.ok((ALLOWLIST_PUBLIC_KEYS as readonly string[]).includes(k));
    }

    const rawObj = publicPayload as unknown as Record<string, unknown>;
    assert.equal(rawObj.stack_trace, undefined);
    assert.equal(rawObj.internal_details, undefined);
    assert.equal(rawObj.http_status, undefined);
    assert.equal(rawObj.raw_throw_value, undefined);
  });

  void it("9. Prevents prototype pollution and unknown field injection during public serialization", () => {
    const malformedCtx = {
      contract: {
        code: "ERR_VALIDATION_FAILED",
        message: "Invalid payload",
        message_key: "core.error.validation_failed",
        kind: "VALIDATION_ERROR" as const,
        severity: "WARNING" as const,
        timestamp: new Date().toISOString(),
        recoverable: true,
        public_details: JSON.parse('{"field":"email","__proto__":{"polluted":true}}') as Record<
          string,
          unknown
        >,
        injectedSecretField: "secret_token_123",
      } as unknown,
    };

    const publicPayload = serializePublicErrorPayload(
      malformedCtx as unknown as Parameters<typeof serializePublicErrorPayload>[0],
    );

    const rawObj = publicPayload as unknown as Record<string, unknown>;
    assert.equal(rawObj.injectedSecretField, undefined);
    assert.equal(
      (publicPayload.public_details as unknown as Record<string, unknown>).__proto__,
      Object.prototype,
    );
    assert.equal(
      (Object.prototype as unknown as Record<string, unknown>).polluted,
      undefined,
      "Global prototype must not be polluted.",
    );
  });

  void it("10. Tests RFC-8785 deterministic canonical JSON serialization", () => {
    const objA = {
      z: 1,
      a: "hello",
      kind: "SECURITY_ERROR",
      details: { b: 2, a: 1 },
    };

    const objB = {
      a: "hello",
      kind: "SECURITY_ERROR",
      details: { a: 1, b: 2 },
      z: 1,
    };

    const canonicalA = toRFC8785JSON(objA);
    const canonicalB = toRFC8785JSON(objB);

    assert.equal(
      canonicalA,
      canonicalB,
      "Canonicalized JSON strings must be identical regardless of property insertion order.",
    );
    assert.equal(canonicalA, '{"a":"hello","details":{"a":1,"b":2},"kind":"SECURITY_ERROR","z":1}');
  });

  void it("11. Tests RFC-8785 canonicalization error handling on non-finite numbers", () => {
    assert.throws(() => toRFC8785JSON({ badNum: NaN }), TypeError);
    assert.throws(() => toRFC8785JSON({ badNum: Infinity }), TypeError);
  });

  void it("12. Regression: no nested token/credential/DB URI leaks", () => {
    const err = new SynthesisBaseError({
      code: "ERR_INVALID_CONFIG",
      message: "Configuration error.",
      message_key: "core.error.configuration",
      kind: "SYSTEM_ERROR",
      public_details: {
        safeField: "allowed_value",
        auth: { token: "secret_bearer_token_123" },
        db_uri: "postgres://user:password@localhost:5432/db",
        nestedSecret: "sk_live_12345678901234567890",
        filePath: "/tmp/synthesis-cms-mini-task/secret.txt",
      },
    });

    const ctx = normalizeToErrorContract(err);
    const payload = serializePublicErrorPayload(ctx);

    assert.deepEqual(payload.public_details, { safeField: "allowed_value" });
  });

  void it("12b. Regression: forged SynthesisBaseError prototype rejected", () => {
    const forged = Object.create(SynthesisBaseError.prototype) as Record<string, unknown>;
    forged.code = "ERR_FORGED";
    forged.message = "Forged message";
    forged.message_key = "core.error.forged";
    forged.kind = "SYSTEM_ERROR";
    forged.severity = "FATAL";
    forged.timestamp = "2026-10-09T04:47:00.000Z";
    forged.recoverable = true;

    const ctx = normalizeToErrorContract(forged);
    assert.equal(ctx.contract.code, ERROR_DEFAULTS.CODE);
    assert.equal(ctx.contract.message, ERROR_DEFAULTS.MESSAGE);
  });

  void it("12c. Regression: forged public context cannot bypass safety", () => {
    const malformedCtx = {
      contract: {
        code: "<script>alert(1)</script>",
        message_key: "invalid.message.key",
        kind: "HACKED_KIND",
        severity: "SUPER_FATAL",
        timestamp: "not-a-timestamp",
        correlation_id: "bad id with spaces!",
        recoverable: "true",
      },
    };

    const payload = serializePublicErrorPayload(
      malformedCtx as unknown as Parameters<typeof serializePublicErrorPayload>[0],
    );

    assert.equal(payload.code, ERROR_DEFAULTS.CODE);
    assert.equal(payload.message_key, ERROR_DEFAULTS.MESSAGE_KEY);
    assert.equal(payload.kind, ERROR_DEFAULTS.KIND);
    assert.equal(payload.severity, ERROR_DEFAULTS.SEVERITY);
    assert.equal(payload.recoverable, false);
    assert.equal(payload.correlation_id, undefined);
  });

  void it("12d. Regression: hostile getters and Proxy cannot escape fallback", () => {
    const hostileProxy = new Proxy(
      {},
      {
        get() {
          throw new Error("Hostile getter triggered!");
        },
      },
    );

    const ctx = normalizeToErrorContract(hostileProxy);
    assert.equal(ctx.contract.code, ERROR_DEFAULTS.CODE);
    assert.equal(ctx.cause_message, "Unserializable object thrown");

    const hostileCtx = {
      contract: new Proxy(
        {},
        {
          get() {
            throw new Error("Hostile contract getter");
          },
        },
      ),
    };

    const payload = serializePublicErrorPayload(
      hostileCtx as unknown as Parameters<typeof serializePublicErrorPayload>[0],
    );
    assert.equal(payload.code, ERROR_DEFAULTS.CODE);
    assert.equal(payload.message, ERROR_DEFAULTS.MESSAGE);
  });

  void it("12e. Regression: invalid recoverable/correlation_id rejected", () => {
    assert.throws(
      () =>
        new SynthesisBaseError({
          code: "ERR_TEST",
          message: "Test message",
          message_key: "core.error.test",
          kind: "SYSTEM_ERROR",
          correlation_id: "invalid id containing spaces & symbols!",
        }),
    );

    assert.throws(
      () =>
        new SynthesisBaseError({
          code: "ERR_TEST",
          message: "Test message",
          message_key: "core.error.test",
          kind: "SYSTEM_ERROR",
          recoverable: "true" as unknown as boolean,
        }),
    );
  });

  void it("12f. Regression: invalid Step13 namespace arity rejected", () => {
    assert.equal(isValidMessageKey("pack.ecommerce"), false, "pack root requires min 3 segments");
    assert.equal(isValidMessageKey("ext.acme"), false, "ext root requires min 3 segments");
    assert.equal(
      isValidMessageKey("core.integration.stripe"),
      false,
      "core.integration requires min 4 segments",
    );

    assert.equal(isValidMessageKey("pack.ecommerce.order_failed"), true);
    assert.equal(isValidMessageKey("ext.acme.blog.error"), true);
    assert.equal(isValidMessageKey("core.integration.stripe.payment_failed"), true);
  });

  void it("12g. Regression: invalid calendar dates rejected", () => {
    assert.equal(
      isValidUtcTimestamp("2026-02-31T12:00:00.000Z"),
      false,
      "Feb 31 is invalid calendar date",
    );
    assert.equal(
      isValidUtcTimestamp("2026-11-31T12:00:00.000Z"),
      false,
      "Nov 31 is invalid calendar date",
    );
    assert.equal(isValidUtcTimestamp("2026-10-09T04:47:00.000Z"), true);
  });

  void it("12h. Regression: unsafe canonical JSON inputs rejected", () => {
    const circularObj: Record<string, unknown> = {};
    circularObj.self = circularObj;

    assert.throws(() => toRFC8785JSON(circularObj), TypeError);
    assert.throws(() => toRFC8785JSON(String.fromCharCode(0xd800)), TypeError);
  });
});
