/**
 * Synthesis CMS mini — Unified Error Contract Security & Integration Test Suite
 *
 * Roadmap Step: 14/60 — Unified error contract
 * Contract ID: CONTRACT-CORE-UNIFIED-ERROR-001
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {
  UNIFIED_ERROR_CONTRACT_ID,
  ERROR_KINDS,
  ERROR_SEVERITIES,
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

void describe("Unified Error Contract — Unit & Security Test Suite", () => {
  void it("1. Verifies contract identity, snapshot fixture and taxonomy constants", () => {
    assert.equal(UNIFIED_ERROR_CONTRACT_ID, "CONTRACT-CORE-UNIFIED-ERROR-001");
    assert.equal(ERROR_KINDS.length, 9);
    assert.equal(ERROR_SEVERITIES.length, 4);

    const snapshotPath = path.join(
      process.cwd(),
      "tests/error/fixtures/error.contract.snapshot.json",
    );
    assert.ok(fs.existsSync(snapshotPath), "Snapshot fixture must exist.");

    const snapshot = JSON.parse(fs.readFileSync(snapshotPath, "utf-8")) as {
      contract_id: string;
      error_kinds: string[];
      error_severities: string[];
      public_allowlist_keys: string[];
    };
    assert.equal(snapshot.contract_id, UNIFIED_ERROR_CONTRACT_ID);
    assert.deepEqual(Array.from(snapshot.error_kinds), Array.from(ERROR_KINDS));
    assert.deepEqual(Array.from(snapshot.error_severities), Array.from(ERROR_SEVERITIES));
    assert.deepEqual(Array.from(snapshot.public_allowlist_keys), Array.from(ALLOWLIST_PUBLIC_KEYS));
  });

  void it("2. Tests SynthesisBaseError instantiation with valid parameters", () => {
    const err = new SynthesisBaseError({
      code: "ERR_INVALID_CREDENTIALS",
      message: "Invalid username or password.",
      message_key: "core.error.unauthorized_access",
      kind: "SECURITY_ERROR",
      severity: "WARNING",
      recoverable: false,
      correlation_id: "corr-test-123",
      public_details: { attemptCount: 3 },
      internal_details: { dbQueryTimeMs: 12 },
      http_status: 401,
    });

    assert.equal(err.code, "ERR_INVALID_CREDENTIALS");
    assert.equal(err.message, "Invalid username or password.");
    assert.equal(err.message_key, "core.error.unauthorized_access");
    assert.equal(err.kind, "SECURITY_ERROR");
    assert.equal(err.severity, "WARNING");
    assert.equal(err.recoverable, false);
    assert.equal(err.correlation_id, "corr-test-123");
    assert.deepEqual(err.public_details, { attemptCount: 3 });
    assert.deepEqual(err.internal_details, { dbQueryTimeMs: 12 });
    assert.equal(err.http_status, 401);
    assert.ok(isValidUtcTimestamp(err.timestamp));
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
    // Valid Step 13 root examples
    assert.ok(isValidMessageKey("core.error.validation_failed"));
    assert.ok(isValidMessageKey("core.error.unauthorized_access"));
    assert.ok(isValidMessageKey("gov.error.access_denied"));
    assert.ok(isValidMessageKey("sys.error.database_offline"));
    assert.ok(isValidMessageKey("pack.ecommerce.order_failed"));
    assert.ok(isValidMessageKey("ext.acme.blog.error.not_found"));

    // Invalid examples (missing root, bad chars, uppercase, spaces, oversized)
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

  void it("7. Fails closed on untrusted throw values (null, undefined, primitive, native Error, forged objects)", () => {
    const testCases: unknown[] = [
      null,
      undefined,
      "Raw string error message",
      404,
      false,
      new Error("Native JavaScript exception"),
      { code: "ERR_FAKE", message: "Fake error", message_key: "core.error.fake" }, // plain object spoofing
      Object.create({ code: "ERR_INJECTED", message_key: "core.error.injected" }), // prototype spoofing
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
    });

    const internalCtx = normalizeToErrorContract(err);
    const publicPayload = serializePublicErrorPayload(internalCtx);

    // Verify allowed fields exist
    assert.equal(publicPayload.code, "ERR_FORBIDDEN");
    assert.equal(publicPayload.message, "Access is denied.");
    assert.equal(publicPayload.message_key, "gov.error.access_denied");
    assert.equal(publicPayload.kind, "SECURITY_ERROR");
    assert.equal(publicPayload.severity, "ERROR");
    assert.equal(publicPayload.recoverable, false);
    assert.equal(publicPayload.correlation_id, "corr-sec-99");
    assert.deepEqual(publicPayload.public_details, { roleRequired: "admin" });

    // Verify secret / internal / prototype fields are strictly excluded
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
});
