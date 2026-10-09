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
  type InternalErrorContext,
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
      internal_details: { auth_provider: "jwt" },
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
    assert.deepEqual(err.internal_details, { auth_provider: "jwt" });
    assert.equal(err.http_status, 401);
    assert.equal(err.timestamp, "2026-10-09T04:47:00.000Z");
    assert.ok(Object.isFrozen(err));
  });

  void it("2. Validates error codes with strict lexical grammar", () => {
    assert.ok(isValidErrorCode("ERR_VALIDATION_FAILED"));
    assert.ok(isValidErrorCode("ERR_NOT_FOUND_404"));
    assert.ok(isValidErrorCode("ERR_A"));

    assert.equal(isValidErrorCode(""), false);
    assert.equal(isValidErrorCode("err_lowercase"), false);
    assert.equal(isValidErrorCode("ERR-DASHES"), false);
    assert.equal(isValidErrorCode("ERR_SPACES NOT_ALLOWED"), false);
    assert.equal(isValidErrorCode(123), false);
    assert.equal(isValidErrorCode(null), false);
    assert.equal(isValidErrorCode(undefined), false);

    assert.throws(
      () =>
        new SynthesisBaseError({
          code: "invalid-code",
          message: "Input validation failed.",
          message_key: "core.error.validation_failed",
          kind: "VALIDATION_ERROR",
        }),
      /Invalid SynthesisBaseError code/,
    );
  });

  void it("3. Validates message_key against Step 13 namespace rules and roots", () => {
    assert.ok(isValidMessageKey("core.error.validation_failed"));
    assert.ok(isValidMessageKey("gov.access.denied"));
    assert.ok(isValidMessageKey("sys.health.check"));
    assert.ok(isValidMessageKey("pack.ecommerce.order"));
    assert.ok(isValidMessageKey("ext.analytics.event"));
    assert.ok(isValidMessageKey("core.integration.stripe.charge"));

    assert.equal(isValidMessageKey("invalid_no_root.error"), false);
    assert.equal(isValidMessageKey("core"), false);
    assert.equal(isValidMessageKey("pack.order"), false); // pack requires min arity 3
    assert.equal(isValidMessageKey("ext.event"), false); // ext requires min arity 3
    assert.equal(isValidMessageKey("core.integration.stripe"), false); // core.integration requires min arity 4
    assert.equal(isValidMessageKey("core..empty_segment"), false);
    assert.equal(isValidMessageKey("core.UPPERCASE.not_allowed"), false);
    assert.equal(isValidMessageKey(null), false);
    assert.equal(isValidMessageKey(12345), false);

    assert.throws(
      () =>
        new SynthesisBaseError({
          code: "ERR_CONFIG_INVALID",
          message: "Configuration error.",
          message_key: "invalid_no_root_key",
          kind: "SYSTEM_ERROR",
        }),
      /Invalid SynthesisBaseError message_key/,
    );
  });

  void it("4. Validates timestamp ISO-8601 UTC with milliseconds and calendar date", () => {
    assert.ok(isValidUtcTimestamp("2026-10-09T04:47:00.000Z"));
    assert.ok(isValidUtcTimestamp("2024-02-29T12:00:00.000Z")); // leap year

    assert.equal(isValidUtcTimestamp("2023-02-29T12:00:00.000Z"), false); // invalid leap year date
    assert.equal(isValidUtcTimestamp("2026-10-09T04:47:00Z"), false); // missing millis
    assert.equal(isValidUtcTimestamp("2026-10-09"), false);
    assert.equal(isValidUtcTimestamp("invalid-date"), false);
    assert.equal(isValidUtcTimestamp(123456789), false);
  });

  void it("5. Validates correlation_id constraints", () => {
    const valid = new SynthesisBaseError({
      code: "ERR_RESOURCE_NOT_FOUND",
      message: "Requested resource was not found.",
      message_key: "core.error.resource_not_found",
      kind: "DOMAIN_ERROR",
      correlation_id: "req-abc_123.xyz",
    });
    assert.equal(valid.correlation_id, "req-abc_123.xyz");

    assert.throws(
      () =>
        new SynthesisBaseError({
          code: "ERR_RESOURCE_NOT_FOUND",
          message: "Requested resource was not found.",
          message_key: "core.error.resource_not_found",
          kind: "DOMAIN_ERROR",
          correlation_id: "invalid id with spaces",
        }),
      /Invalid SynthesisBaseError correlation_id/,
    );
  });

  void it("6. Normalizes authentic SynthesisBaseError into InternalErrorContext", () => {
    const err = new SynthesisBaseError({
      code: "ERR_RESOURCE_NOT_FOUND",
      message: "Requested resource was not found.",
      message_key: "core.error.resource_not_found",
      kind: "DOMAIN_ERROR",
      severity: "WARNING",
      recoverable: true,
      correlation_id: "corr-456",
      public_details: { resourceId: "res-99" },
      internal_details: { queryTimeMs: 14 },
      http_status: 404,
      timestamp: "2026-10-09T04:47:00.000Z",
    });

    const ctx = normalizeToErrorContract(err);

    assert.equal(ctx.contract.code, "ERR_RESOURCE_NOT_FOUND");
    assert.equal(ctx.contract.message, "Requested resource was not found.");
    assert.equal(ctx.contract.message_key, "core.error.resource_not_found");
    assert.equal(ctx.contract.kind, "DOMAIN_ERROR");
    assert.equal(ctx.contract.severity, "WARNING");
    assert.equal(ctx.contract.recoverable, true);
    assert.equal(ctx.contract.correlation_id, "corr-456");
    assert.equal(ctx.contract.public_details, undefined); // Security R04: dynamic resourceId is deliberately omitted to prevent request-derived reflection
    assert.equal(ctx.contract.http_status, 404);
    assert.equal(ctx.raw_throw_value, err);
    assert.deepEqual(ctx.internal_details, { queryTimeMs: 14 });
    assert.ok(typeof ctx.stack_trace === "string");
    assert.ok(Object.isFrozen(ctx));
    assert.ok(Object.isFrozen(ctx.contract));
  });

  void it("7. Normalizes untrusted Error and hostile throw values fail-closed into generic defaults", () => {
    const nativeErr = new TypeError("Database connection lost: password123");
    const ctxNative = normalizeToErrorContract(nativeErr, "fallback-corr");

    assert.equal(ctxNative.contract.code, ERROR_DEFAULTS.CODE);
    assert.equal(ctxNative.contract.message, ERROR_DEFAULTS.MESSAGE);
    assert.equal(ctxNative.contract.message_key, ERROR_DEFAULTS.MESSAGE_KEY);
    assert.equal(ctxNative.contract.kind, ERROR_DEFAULTS.KIND);
    assert.equal(ctxNative.contract.severity, ERROR_DEFAULTS.SEVERITY);
    assert.equal(ctxNative.contract.recoverable, ERROR_DEFAULTS.RECOVERABLE);
    assert.equal(ctxNative.contract.correlation_id, "fallback-corr");
    assert.equal(ctxNative.contract.http_status, ERROR_DEFAULTS.HTTP_STATUS);
    assert.equal(ctxNative.raw_throw_value, nativeErr);
    assert.equal(ctxNative.cause_message, "Database connection lost: password123");
    assert.ok(typeof ctxNative.stack_trace === "string");

    const ctxString = normalizeToErrorContract("plain string failure");
    assert.equal(ctxString.contract.code, ERROR_DEFAULTS.CODE);
    assert.equal(ctxString.cause_message, "plain string failure");

    const ctxNull = normalizeToErrorContract(null);
    assert.equal(ctxNull.contract.code, ERROR_DEFAULTS.CODE);
    assert.equal(ctxNull.cause_message, "null");
  });

  void it("8. Serializes InternalErrorContext to PublicErrorPayload with strict allowlist", () => {
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
    assert.equal(publicPayload.correlation_id, undefined); // Security R04: public correlation_id is deliberately omitted when origin is uncertain until Step 15 trusted issuer exists
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
    const err = new SynthesisBaseError({
      code: "ERR_VALIDATION_FAILED",
      message: "Input validation failed.",
      message_key: "core.error.validation_failed",
      kind: "VALIDATION_ERROR",
      severity: "WARNING",
      recoverable: true,
      public_details: JSON.parse('{"field":"email","__proto__":{"polluted":true}}') as Record<
        string,
        unknown
      >,
    });

    const internalCtx = normalizeToErrorContract(err);
    const publicPayload = serializePublicErrorPayload(internalCtx);

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
    const objA = { z: 1, a: 2, m: { y: 3, x: 4 } };
    const objB = { m: { x: 4, y: 3 }, a: 2, z: 1 };

    const canonicalA = toRFC8785JSON(objA);
    const canonicalB = toRFC8785JSON(objB);

    assert.equal(canonicalA, '{"a":2,"m":{"x":4,"y":3},"z":1}');
    assert.equal(canonicalA, canonicalB);
  });

  void it("11. Tests RFC-8785 canonicalization error handling on non-finite numbers", () => {
    assert.throws(() => toRFC8785JSON({ invalid: Number.NaN }), {
      name: "TypeError",
    });
    assert.throws(() => toRFC8785JSON({ invalid: Number.POSITIVE_INFINITY }), {
      name: "TypeError",
    });
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
          recoverable: "yes" as unknown as boolean,
        }),
      /expected boolean/,
    );

    assert.throws(
      () =>
        new SynthesisBaseError({
          code: "ERR_TEST",
          message: "Test message",
          message_key: "core.error.test",
          kind: "SYSTEM_ERROR",
          correlation_id: "bad id with spaces!",
        }),
      /Invalid SynthesisBaseError correlation_id/,
    );
  });

  void it("12f. Regression: invalid Step13 namespace arity rejected", () => {
    assert.equal(isValidMessageKey("pack.one"), false);
    assert.equal(isValidMessageKey("ext.one"), false);
    assert.equal(isValidMessageKey("core.integration.service"), false);
    assert.ok(isValidMessageKey("pack.one.two"));
    assert.ok(isValidMessageKey("ext.one.two"));
    assert.ok(isValidMessageKey("core.integration.service.action"));
  });

  void it("12g. Regression: invalid calendar dates rejected", () => {
    assert.equal(isValidUtcTimestamp("2026-02-29T12:00:00.000Z"), false);
    assert.equal(isValidUtcTimestamp("2026-04-31T12:00:00.000Z"), false);
    assert.ok(isValidUtcTimestamp("2026-04-30T12:00:00.000Z"));
  });

  void it("12h. Regression: unsafe canonical JSON inputs rejected", () => {
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    assert.throws(() => toRFC8785JSON(circular), {
      name: "TypeError",
    });

    const sparseArr = new Array(3);
    assert.equal(toRFC8785JSON(sparseArr), "[null,null,null]");

    const badSurrogateObj = { bad: "\uD800" };
    assert.throws(() => toRFC8785JSON(badSurrogateObj), {
      name: "TypeError",
    });
  });

  void it("13. Demonstration: Forged prototype with exported brand is rejected", () => {
    const forged = Object.create(SynthesisBaseError.prototype) as Record<string | symbol, unknown>;
    forged.code = "ERR_FORGED";
    forged.message = "Forged error message";
    forged.message_key = "core.error.forged";
    forged.kind = "SYSTEM_ERROR";
    forged.severity = "FATAL";
    forged.timestamp = "2026-10-09T04:47:00.000Z";
    forged.recoverable = true;
    forged[Symbol.for("synthesis.core.error.brand")] = true;

    const ctx = normalizeToErrorContract(forged);
    assert.equal(ctx.contract.code, ERROR_DEFAULTS.CODE);
    assert.equal(ctx.contract.message, ERROR_DEFAULTS.MESSAGE);
    assert.equal(ctx.contract.message_key, ERROR_DEFAULTS.MESSAGE_KEY);
    assert.equal(ctx.contract.kind, ERROR_DEFAULTS.KIND);
  });

  void it("14. Demonstration: Valid-looking forged public context produces generic error", () => {
    const validLookingForgedCtx: InternalErrorContext = {
      contract: {
        code: "ERR_VALID_LOOKING",
        message: "Valid looking public message",
        message_key: "core.error.validation_failed",
        kind: "VALIDATION_ERROR" as const,
        severity: "ERROR" as const,
        timestamp: "2026-10-09T04:47:00.000Z",
        recoverable: true,
        correlation_id: "corr-forged-valid",
        public_details: { field: "email" },
      },
    };

    const payload = serializePublicErrorPayload(validLookingForgedCtx);

    assert.equal(payload.code, ERROR_DEFAULTS.CODE);
    assert.equal(payload.message, ERROR_DEFAULTS.MESSAGE);
    assert.equal(payload.message_key, ERROR_DEFAULTS.MESSAGE_KEY);
    assert.equal(payload.kind, ERROR_DEFAULTS.KIND);
    assert.equal(payload.severity, ERROR_DEFAULTS.SEVERITY);
    assert.equal(payload.recoverable, ERROR_DEFAULTS.RECOVERABLE);
    assert.equal(payload.correlation_id, undefined);
    assert.equal(payload.public_details, undefined);
  });

  void it("15. Demonstration: Secret in innocuous detail field is omitted by positive authorization", () => {
    const err = new SynthesisBaseError({
      code: "ERR_VALIDATION_FAILED",
      message: "Input validation failed.",
      message_key: "core.error.validation_failed",
      kind: "VALIDATION_ERROR",
      public_details: {
        safeField: "allowed_value",
        innocuousField: "super_secret_api_key_value",
        debugInfo: "db_password_123",
      },
    });

    const ctx = normalizeToErrorContract(err);
    const payload = serializePublicErrorPayload(ctx);

    assert.deepEqual(payload.public_details, { safeField: "allowed_value" });
    const rawDetails = payload.public_details as unknown as Record<string, unknown>;
    assert.equal(rawDetails.innocuousField, undefined);
    assert.equal(rawDetails.debugInfo, undefined);
  });

  void it("16. Demonstration: Arbitrary untrusted public message is not reflected to clients", () => {
    const errWithUntrustedMsg = new SynthesisBaseError({
      code: "ERR_UNAUTHORIZED",
      message: "Sensitive SQL error in query: select * from admin_users where secret=1",
      message_key: "core.error.unauthorized",
      kind: "SECURITY_ERROR",
    });

    const ctx = normalizeToErrorContract(errWithUntrustedMsg);
    const payload = serializePublicErrorPayload(ctx);

    assert.equal(payload.message, "User is not authorized to perform this operation.");
    assert.notEqual(
      payload.message,
      "Sensitive SQL error in query: select * from admin_users where secret=1",
    );
  });

  void it("17. Demonstration: Malformed Unicode property key is rejected by toRFC8785JSON", () => {
    const badKeyObj: unknown = JSON.parse('{"\uD800": "bad_key_value"}');
    assert.throws(() => toRFC8785JSON(badKeyObj), {
      name: "TypeError",
    });
  });

  void it("18. Demonstration: Secret values under ALLOWED detail keys are omitted", () => {
    const err = new SynthesisBaseError({
      code: "ERR_VALIDATION_FAILED",
      message: "Input validation failed.",
      message_key: "core.error.validation_failed",
      kind: "VALIDATION_ERROR",
      public_details: {
        role: "sk_live_secret_role_token_12345",
        field: "sk_live_api_key_secret_leak",
        reason: "database connection failed with password postgresql://admin:secret@host/db",
        resourceId: "secret_token_key_12345",
        safeField: "unauthorized_secret_string",
      },
    });

    const ctx = normalizeToErrorContract(err);
    const payload = serializePublicErrorPayload(ctx);

    // All secret or unauthorized values under allowed detail keys must be omitted
    assert.equal(payload.public_details, undefined);

    // Mixed case: valid static enum alongside unauthorized string
    const mixedErr = new SynthesisBaseError({
      code: "ERR_VALIDATION_FAILED",
      message: "Input validation failed.",
      message_key: "core.error.validation_failed",
      kind: "VALIDATION_ERROR",
      public_details: {
        role: "guest",
        field: "arbitrary_untrusted_field_value_with_secrets",
      },
    });
    const mixedCtx = normalizeToErrorContract(mixedErr);
    const mixedPayload = serializePublicErrorPayload(mixedCtx);
    assert.deepEqual(mixedPayload.public_details, { role: "guest" });
  });

  void it("19. Demonstration: Forged user-sourced correlation_id is rejected", () => {
    // Arbitrary user-supplied correlation IDs must be rejected at construction
    const forgedIds = [
      "user-supplied-trace-id",
      "client-request-token-999",
      "bearer-token-secret-123",
      "req-with-secret-jwt-token",
      "forged-correlation-id",
      "header-x-request-id-attacker",
    ];

    for (const forgedId of forgedIds) {
      assert.throws(
        () =>
          new SynthesisBaseError({
            code: "ERR_UNAUTHORIZED",
            message: "User is not authorized to perform this operation.",
            message_key: "core.error.unauthorized",
            kind: "SECURITY_ERROR",
            correlation_id: forgedId,
          }),
        /Invalid SynthesisBaseError correlation_id/,
      );
    }

    // Untrusted object with forged correlation_id normalized fail-closed
    const rawHostile = {
      name: "Error",
      message: "Hostile throw",
      correlation_id: "user-supplied-trace-id",
    };
    const ctx = normalizeToErrorContract(rawHostile);
    assert.equal(ctx.contract.correlation_id, undefined);
    const payload = serializePublicErrorPayload(ctx);
    assert.equal(payload.correlation_id, undefined);
  });

  void it("20. Demonstration: Normal safe use cases with trusted enums and platform correlation_id", () => {
    const safeErr = new SynthesisBaseError({
      code: "ERR_VALIDATION_FAILED",
      message: "Input validation failed.",
      message_key: "core.error.validation_failed",
      kind: "VALIDATION_ERROR",
      severity: "ERROR",
      recoverable: false,
      correlation_id: "corr-test-123",
      public_details: {
        role: "guest",
        roleRequired: "admin",
        field: "email",
        safeField: "allowed_value",
        status: "active",
        count: 5,
        limit: 100,
      },
    });

    const ctx = normalizeToErrorContract(safeErr);
    const payload = serializePublicErrorPayload(ctx);

    assert.equal(payload.correlation_id, undefined); // Security R04: public correlation_id omitted when origin is uncertain
    assert.deepEqual(payload.public_details, {
      role: "guest",
      roleRequired: "admin",
      field: "email",
      safeField: "allowed_value",
      status: "active",
      count: 5,
      limit: 100,
    }); // Security R04: dynamic resourceId is deliberately omitted

    // UUID correlation_id is internal; public correlation_id is omitted when origin is uncertain
    const uuidErr = new SynthesisBaseError({
      code: "ERR_UNAUTHORIZED",
      message: "User is not authorized to perform this operation.",
      message_key: "core.error.unauthorized",
      kind: "SECURITY_ERROR",
      correlation_id: "550e8400-e29b-41d4-a716-446655440000",
    });
    const uuidCtx = normalizeToErrorContract(uuidErr);
    assert.equal(uuidCtx.contract.correlation_id, "550e8400-e29b-41d4-a716-446655440000");
    const uuidPayload = serializePublicErrorPayload(uuidCtx);
    assert.equal(uuidPayload.correlation_id, undefined); // Security R04: UUID correlation_id is omitted when origin is uncertain
  });

  void it("21. Demonstration: Syntactically valid, attacker-controlled code and message_key fail closed to safe defaults", () => {
    const err = new SynthesisBaseError({
      code: "ERR_ATTACKER_CONTROLLED_PROBE",
      message: "Attacker message probe",
      message_key: "core.error.attacker_crafted_key",
      kind: "SECURITY_ERROR",
    });

    const ctx = normalizeToErrorContract(err);
    // Internally, error context preserves original diagnostic info
    assert.equal(ctx.contract.code, "ERR_ATTACKER_CONTROLLED_PROBE");
    assert.equal(ctx.contract.message_key, "core.error.attacker_crafted_key");

    // Public serialization fails closed: prevents arbitrary public echo of codes and message keys
    const publicPayload = serializePublicErrorPayload(ctx);
    assert.equal(publicPayload.code, ERROR_DEFAULTS.CODE);
    assert.equal(publicPayload.message_key, ERROR_DEFAULTS.MESSAGE_KEY);
    assert.equal(publicPayload.message, ERROR_DEFAULTS.MESSAGE);
  });

  void it("22. Demonstration: Uncertain correlation_id and dynamic resourceId are omitted from public payload", () => {
    const err = new SynthesisBaseError({
      code: "ERR_RESOURCE_NOT_FOUND",
      message: "Requested resource was not found.",
      message_key: "core.error.resource_not_found",
      kind: "DOMAIN_ERROR",
      correlation_id: "corr-untrusted-dynamic-id",
      public_details: {
        resourceId: "res-attacker-probe-99",
        role: "guest",
      },
    });

    const ctx = normalizeToErrorContract(err);
    // Internal context preserves correlation_id for server diagnostics
    assert.equal(ctx.contract.correlation_id, "corr-untrusted-dynamic-id");

    // Public payload strictly omits uncertain correlation_id and request-derived resourceId
    const payload = serializePublicErrorPayload(ctx);
    assert.equal(payload.correlation_id, undefined);
    assert.deepEqual(payload.public_details, { role: "guest" });
    const rawDetails = payload.public_details as unknown as Record<string, unknown>;
    assert.equal(rawDetails.resourceId, undefined);
  });

  void it("23. Regression: Enforces atomic public error code, message_key, and kind consistency", () => {
    // 23a. Known code with wrong known message_key fails closed atomically
    const wrongKeyErr = new SynthesisBaseError({
      code: "ERR_UNAUTHORIZED",
      message: "Input validation failed.",
      message_key: "core.error.validation_failed", // Mismatched key for ERR_UNAUTHORIZED
      kind: "SECURITY_ERROR",
      public_details: { role: "guest" },
    });
    const wrongKeyCtx = normalizeToErrorContract(wrongKeyErr);
    const wrongKeyPayload = serializePublicErrorPayload(wrongKeyCtx);
    assert.equal(wrongKeyPayload.code, ERROR_DEFAULTS.CODE);
    assert.equal(wrongKeyPayload.message_key, ERROR_DEFAULTS.MESSAGE_KEY);
    assert.equal(wrongKeyPayload.message, ERROR_DEFAULTS.MESSAGE);
    assert.equal(wrongKeyPayload.kind, ERROR_DEFAULTS.KIND);
    assert.equal(wrongKeyPayload.public_details, undefined); // Cannot retain public details

    // 23b. Known code and message_key with mismatched kind fails closed atomically
    const wrongKindErr = new SynthesisBaseError({
      code: "ERR_VALIDATION_FAILED",
      message: "Input validation failed.",
      message_key: "core.error.validation_failed",
      kind: "SECURITY_ERROR", // Mismatched kind for validation failed (expected VALIDATION_ERROR)
      public_details: { role: "guest" },
    });
    const wrongKindCtx = normalizeToErrorContract(wrongKindErr);
    const wrongKindPayload = serializePublicErrorPayload(wrongKindCtx);
    assert.equal(wrongKindPayload.code, ERROR_DEFAULTS.CODE);
    assert.equal(wrongKindPayload.message_key, ERROR_DEFAULTS.MESSAGE_KEY);
    assert.equal(wrongKindPayload.message, ERROR_DEFAULTS.MESSAGE);
    assert.equal(wrongKindPayload.kind, ERROR_DEFAULTS.KIND);
    assert.equal(wrongKindPayload.public_details, undefined);

    // 23c. Unknown code with known message_key fails closed atomically
    const unknownCodeErr = new SynthesisBaseError({
      code: "ERR_UNKNOWN_CODE_PROBE",
      message: "Input validation failed.",
      message_key: "core.error.validation_failed",
      kind: "VALIDATION_ERROR",
      public_details: { role: "guest" },
    });
    const unknownCodeCtx = normalizeToErrorContract(unknownCodeErr);
    const unknownCodePayload = serializePublicErrorPayload(unknownCodeCtx);
    assert.equal(unknownCodePayload.code, ERROR_DEFAULTS.CODE);
    assert.equal(unknownCodePayload.message_key, ERROR_DEFAULTS.MESSAGE_KEY);
    assert.equal(unknownCodePayload.message, ERROR_DEFAULTS.MESSAGE);
    assert.equal(unknownCodePayload.kind, ERROR_DEFAULTS.KIND);
    assert.equal(unknownCodePayload.public_details, undefined);

    // 23d. Known code with unknown message_key fails closed atomically
    const unknownKeyErr = new SynthesisBaseError({
      code: "ERR_VALIDATION_FAILED",
      message: "An internal server error occurred.",
      message_key: "core.error.unregistered_custom_key",
      kind: "VALIDATION_ERROR",
      public_details: { role: "guest" },
    });
    const unknownKeyCtx = normalizeToErrorContract(unknownKeyErr);
    const unknownKeyPayload = serializePublicErrorPayload(unknownKeyCtx);
    assert.equal(unknownKeyPayload.code, ERROR_DEFAULTS.CODE);
    assert.equal(unknownKeyPayload.message_key, ERROR_DEFAULTS.MESSAGE_KEY);
    assert.equal(unknownKeyPayload.message, ERROR_DEFAULTS.MESSAGE);
    assert.equal(unknownKeyPayload.kind, ERROR_DEFAULTS.KIND);
    assert.equal(unknownKeyPayload.public_details, undefined);

    // 23e. Valid approved tuple retains correct output and authorized details without secret reflection
    const validErr = new SynthesisBaseError({
      code: "ERR_VALIDATION_FAILED",
      message: "Input validation failed.",
      message_key: "core.error.validation_failed",
      kind: "VALIDATION_ERROR",
      public_details: {
        role: "guest",
        field: "email",
        secret_leak: "sk_test_secret_key_never_emitted",
      },
    });
    const validCtx = normalizeToErrorContract(validErr);
    const validPayload = serializePublicErrorPayload(validCtx);
    assert.equal(validPayload.code, "ERR_VALIDATION_FAILED");
    assert.equal(validPayload.message_key, "core.error.validation_failed");
    assert.equal(validPayload.message, "Input validation failed.");
    assert.equal(validPayload.kind, "VALIDATION_ERROR");
    assert.deepEqual(validPayload.public_details, { role: "guest", field: "email" });
  });
});
