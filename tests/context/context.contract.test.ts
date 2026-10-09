import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { describe, it } from "node:test";
import {
  ACTOR_KINDS,
  type ActorKind,
  CORRELATION_ID_REGEX,
  MAX_HOP_COUNT,
  REQUEST_ID_REGEX,
  type RequestContext,
  isValidActorId,
  isValidActorKind,
  isValidCorrelationId,
  isValidExternalTraceId,
  isValidIssuer,
  isValidOrigin,
  isValidRequestId,
  isValidTenantId,
  isValidUtcTimestamp,
} from "../../contracts/src/context/index.ts";
import {
  createRootContext,
  deriveChildContext,
  isGenuineRequestContext,
} from "../../core/src/context/context.issuer.ts";
import {
  SynthesisBaseError,
  normalizeToErrorContract,
  serializePublicErrorPayload,
} from "../../contracts/src/error/index.ts";

void describe("Step 15: Request, Actor & Provenance Context Contract", () => {
  // =========================================================================
  // POSITIVE TEST SUITE
  // =========================================================================

  void describe("Positive Cases (P1 - P8)", () => {
    void it("P1: Supports all six ActorKinds defined in specification", () => {
      assert.strictEqual(ACTOR_KINDS.length, 6);
      const expectedKinds: readonly ActorKind[] = [
        "HUMAN",
        "AI",
        "SYSTEM",
        "MODULE",
        "INTEGRATION",
        "JOB",
      ];
      for (const kind of expectedKinds) {
        assert.ok(isValidActorKind(kind), `Kind ${kind} must be valid`);
        const ctx = createRootContext({
          actor: { kind, actor_id: `actor-${kind.toLowerCase()}` },
          provenance: { origin: "test.origin", issuer: "test.issuer" },
        });
        assert.strictEqual(ctx.actor.kind, kind);
      }
    });

    void it("P2: request_id has anchored req-<UUIDv4> format with valid version 4 and variant bits", () => {
      const ctx = createRootContext({
        actor: { kind: "SYSTEM", actor_id: "sys-01" },
        provenance: { origin: "kernel.init", issuer: "kernel" },
      });
      assert.ok(isValidRequestId(ctx.request_id));
      assert.ok(REQUEST_ID_REGEX.test(ctx.request_id));

      const uuidPart = ctx.request_id.slice(4);
      const parts = uuidPart.split("-");
      assert.strictEqual(parts.length, 5);
      // Version 4 check: 3rd component starts with '4'
      assert.strictEqual(parts[2]?.charAt(0), "4");
      // RFC 4122 variant check: 4th component starts with 8, 9, a, or b
      assert.ok(["8", "9", "a", "b"].includes(parts[3]?.charAt(0) ?? ""));
    });

    void it("P3: correlation_id has anchored corr-<UUIDv4> format with valid version 4 and variant bits", () => {
      const ctx = createRootContext({
        actor: { kind: "HUMAN", actor_id: "user-123" },
        provenance: { origin: "web.http", issuer: "ingress" },
      });
      assert.ok(isValidCorrelationId(ctx.correlation_id));
      assert.ok(CORRELATION_ID_REGEX.test(ctx.correlation_id));

      const uuidPart = ctx.correlation_id.slice(5);
      const parts = uuidPart.split("-");
      assert.strictEqual(parts.length, 5);
      assert.strictEqual(parts[2]?.charAt(0), "4");
      assert.ok(["8", "9", "a", "b"].includes(parts[3]?.charAt(0) ?? ""));
    });

    void it("P4: Root context creation produces deeply frozen structures with hop_count=0", () => {
      const ctx = createRootContext({
        actor: { kind: "JOB", actor_id: "cron-cleanup", tenant_id: "tenant-primary" },
        provenance: {
          origin: "scheduler.daemon",
          issuer: "scheduler",
          external_trace_id: "trace-999",
        },
      });

      assert.ok(isGenuineRequestContext(ctx));
      assert.ok(Object.isFrozen(ctx));
      assert.ok(Object.isFrozen(ctx.actor));
      assert.ok(Object.isFrozen(ctx.provenance));
      assert.strictEqual(ctx.provenance.hop_count, 0);
      assert.strictEqual(ctx.provenance.causal_parent_id, undefined);
      assert.strictEqual(ctx.actor.tenant_id, "tenant-primary");
      assert.strictEqual(ctx.provenance.external_trace_id, "trace-999");
      assert.ok(isValidUtcTimestamp(ctx.timestamp));
    });

    void it("P5: Child context derivation increments hop_count and links causal_parent_id", () => {
      const root = createRootContext({
        actor: { kind: "INTEGRATION", actor_id: "stripe-webhook" },
        provenance: { origin: "ingress.webhook", issuer: "ingress" },
      });

      const child = deriveChildContext(root, { origin: "handler.invoice" });
      assert.ok(isGenuineRequestContext(child));
      assert.strictEqual(child.correlation_id, root.correlation_id);
      assert.notStrictEqual(child.request_id, root.request_id);
      assert.ok(isValidRequestId(child.request_id));
      assert.strictEqual(child.provenance.hop_count, 1);
      assert.strictEqual(child.provenance.causal_parent_id, root.request_id);
      assert.strictEqual(child.provenance.origin, "handler.invoice");
      assert.strictEqual(child.provenance.issuer, root.provenance.issuer);
      assert.strictEqual(child.actor.kind, root.actor.kind);
      assert.strictEqual(child.actor.actor_id, root.actor.actor_id);
    });

    void it("P6: Multi-hop causal chain succeeds up to MAX_HOP_COUNT (32)", () => {
      let current = createRootContext({
        actor: { kind: "SYSTEM", actor_id: "core-pipeline" },
        provenance: { origin: "pipeline.root", issuer: "core" },
      });

      for (let hop = 1; hop <= MAX_HOP_COUNT; hop++) {
        const next = deriveChildContext(current, { origin: `step-${String(hop)}` });
        assert.strictEqual(next.provenance.hop_count, hop);
        assert.strictEqual(next.provenance.causal_parent_id, current.request_id);
        assert.strictEqual(next.correlation_id, current.correlation_id);
        current = next;
      }

      assert.strictEqual(current.provenance.hop_count, 32);
    });

    void it("P7: Sibling child derivations produce isolated contexts with identical root correlation", () => {
      const parent = createRootContext({
        actor: { kind: "MODULE", actor_id: "mod-auth" },
        provenance: { origin: "module.init", issuer: "module-loader" },
      });

      const siblingA = deriveChildContext(parent, { origin: "branch.a" });
      const siblingB = deriveChildContext(parent, { origin: "branch.b" });

      assert.strictEqual(siblingA.correlation_id, parent.correlation_id);
      assert.strictEqual(siblingB.correlation_id, parent.correlation_id);
      assert.strictEqual(siblingA.provenance.causal_parent_id, parent.request_id);
      assert.strictEqual(siblingB.provenance.causal_parent_id, parent.request_id);
      assert.notStrictEqual(siblingA.request_id, siblingB.request_id);
      assert.strictEqual(siblingA.provenance.origin, "branch.a");
      assert.strictEqual(siblingB.provenance.origin, "branch.b");
    });

    void it("P8: Seamless interoperability with Step 14 Unified Error Contract", () => {
      const ctx = createRootContext({
        actor: { kind: "SYSTEM", actor_id: "kernel" },
        provenance: { origin: "kernel.exec", issuer: "kernel" },
      });

      // Pass platform-minted correlation_id to Step 14 SynthesisBaseError
      const err = new SynthesisBaseError({
        code: "ERR_UNAUTHORIZED",
        message: "User is not authorized to perform this operation.",
        message_key: "core.error.unauthorized",
        kind: "SECURITY_ERROR",
        correlation_id: ctx.correlation_id,
      });

      assert.strictEqual(err.correlation_id, ctx.correlation_id);

      // Verify internal context accepts it and preserves it
      const errorCtx = normalizeToErrorContract(err);
      assert.strictEqual(errorCtx.contract.correlation_id, ctx.correlation_id);

      // Verify Step 14 public serializer omits correlation_id
      const publicPayload = serializePublicErrorPayload(errorCtx);
      assert.strictEqual(publicPayload.correlation_id, undefined);
    });
  });

  // =========================================================================
  // NEGATIVE TEST SUITE
  // =========================================================================

  void describe("Negative & Security Cases (N1 - N14)", () => {
    void it("N1: Unknown or malformed ActorKind is rejected (fail-closed)", () => {
      assert.strictEqual(isValidActorKind("ROOT"), false);
      assert.strictEqual(isValidActorKind("ADMIN"), false);
      assert.strictEqual(isValidActorKind("system"), false);
      assert.strictEqual(isValidActorKind(""), false);
      assert.strictEqual(isValidActorKind(123), false);

      assert.throws(
        () =>
          createRootContext({
            // @ts-expect-error Testing invalid runtime kind
            actor: { kind: "SUPERUSER", actor_id: "user-1" },
            provenance: { origin: "web", issuer: "ingress" },
          }),
        /INVALID_ACTOR_KIND/,
      );
    });

    void it("N2: Invalid UUID version or variant bits are rejected", () => {
      // Version 5 UUID instead of version 4
      const v5RequestId = "req-00000000-0000-5000-8000-000000000000";
      assert.strictEqual(isValidRequestId(v5RequestId), false);

      // Variant 0 UUID instead of variant 1 (8,9,a,b)
      const var0CorrelationId = "corr-00000000-0000-4000-0000-000000000000";
      assert.strictEqual(isValidCorrelationId(var0CorrelationId), false);

      // Uppercase UUID rejected
      const upperCorrelationId = "corr-A0B1C2D3-E4F5-4A6B-8C7D-9E0F1A2B3C4D";
      assert.strictEqual(isValidCorrelationId(upperCorrelationId), false);

      // Missing prefix
      const noPrefix = "00000000-0000-4000-8000-000000000000";
      assert.strictEqual(isValidRequestId(noPrefix), false);
      assert.strictEqual(isValidCorrelationId(noPrefix), false);
    });

    void it("N3: Forged RequestContext object is detected and rejected by WeakSet guard", () => {
      const forgedContext: unknown = {
        request_id: "req-00000000-0000-4000-8000-000000000000",
        correlation_id: "corr-00000000-0000-4000-8000-000000000000",
        timestamp: new Date().toISOString(),
        actor: { kind: "SYSTEM" as const, actor_id: "forged-system" },
        provenance: { origin: "attacker", issuer: "forged", hop_count: 0 },
      };

      assert.strictEqual(isGenuineRequestContext(forgedContext), false);
      assert.throws(
        () => deriveChildContext(forgedContext as RequestContext),
        /UNAUTHENTIC_PARENT_CONTEXT/,
      );
    });

    void it("N4: Exceeding MAX_HOP_COUNT (32) fails closed with MAX_HOP_COUNT_EXCEEDED", () => {
      let current = createRootContext({
        actor: { kind: "JOB", actor_id: "worker" },
        provenance: { origin: "job.runner", issuer: "worker-pool" },
      });

      for (let hop = 1; hop <= MAX_HOP_COUNT; hop++) {
        current = deriveChildContext(current);
      }

      assert.strictEqual(current.provenance.hop_count, 32);

      // 33rd hop must fail closed
      assert.throws(() => deriveChildContext(current), /MAX_HOP_COUNT_EXCEEDED/);
    });

    void it("N5: Cross-tenant derivation is forbidden", () => {
      const root = createRootContext({
        actor: { kind: "HUMAN", actor_id: "tenant-user", tenant_id: "tenant-alpha" },
        provenance: { origin: "web", issuer: "ingress" },
      });

      assert.throws(
        () => deriveChildContext(root, { tenant_id: "tenant-beta" }),
        /CROSS_TENANT_DERIVATION_FORBIDDEN/,
      );
    });

    void it("N6: Mutation attempts on frozen context throw TypeError", () => {
      const ctx = createRootContext({
        actor: { kind: "SYSTEM", actor_id: "sys" },
        provenance: { origin: "kernel", issuer: "kernel" },
      });

      assert.throws(() => {
        // @ts-expect-error Intentionally testing immutable runtime freeze
        ctx.request_id = "req-tampered";
      }, TypeError);

      assert.throws(() => {
        // @ts-expect-error Intentionally testing immutable runtime freeze
        ctx.actor.kind = "AI";
      }, TypeError);

      assert.throws(() => {
        // @ts-expect-error Intentionally testing immutable runtime freeze
        ctx.provenance.hop_count = 99;
      }, TypeError);
    });

    void it("N7: Prototype pollution attempts are detected and rejected", () => {
      const pollutedActor = JSON.parse(
        '{"__proto__":{"polluted":true},"kind":"AI","actor_id":"ai-bot"}',
      ) as { kind: ActorKind; actor_id: string };
      assert.throws(
        () =>
          createRootContext({
            actor: pollutedActor,
            provenance: { origin: "chat", issuer: "ai-runtime" },
          }),
        /PROTOTYPE_POLLUTION_DETECTED/,
      );
    });

    void it("N8: Hostile proxy with throwing getters is rejected safely", () => {
      const hostileActor = new Proxy(
        { kind: "HUMAN" as const, actor_id: "user-1" },
        {
          get(target, prop, receiver) {
            if (prop === "tenant_id") {
              throw new Error("HOSTILE_GETTER_TRAP");
            }
            return Reflect.get(target, prop, receiver) as unknown;
          },
        },
      );

      assert.throws(() => {
        createRootContext({
          actor: hostileActor,
          provenance: { origin: "web", issuer: "ingress" },
        });
      }, /HOSTILE_GETTER_TRAP/);
    });

    void it("N9: Excessive identifier string lengths are rejected", () => {
      const oversizedActorId = "a".repeat(129);
      assert.strictEqual(isValidActorId(oversizedActorId), false);
      assert.throws(
        () =>
          createRootContext({
            actor: { kind: "AI", actor_id: oversizedActorId },
            provenance: { origin: "origin", issuer: "issuer" },
          }),
        /INVALID_ACTOR_ID/,
      );

      const oversizedTenantId = "t".repeat(65);
      assert.strictEqual(isValidTenantId(oversizedTenantId), false);

      const oversizedOrigin = "o".repeat(257);
      assert.strictEqual(isValidOrigin(oversizedOrigin), false);

      const oversizedIssuer = "i".repeat(129);
      assert.strictEqual(isValidIssuer(oversizedIssuer), false);

      const oversizedTraceId = "tr".repeat(65);
      assert.strictEqual(isValidExternalTraceId(oversizedTraceId), false);
    });

    void it("N10: Malformed or non-UTC timestamps are rejected", () => {
      assert.strictEqual(isValidUtcTimestamp("2026-10-09"), false);
      assert.strictEqual(isValidUtcTimestamp("2026-10-09 12:00:00"), false);
      assert.strictEqual(isValidUtcTimestamp("2026-10-09T12:00:00+02:00"), false); // Non-UTC offset
      assert.strictEqual(isValidUtcTimestamp("invalid-date"), false);
      assert.strictEqual(isValidUtcTimestamp(123456789), false);
    });

    void it("N11: Shell metacharacters and control characters in identifiers are rejected", () => {
      assert.strictEqual(isValidActorId("actor;rm -rf /"), false);
      assert.strictEqual(isValidActorId("actor$(whoami)"), false);
      assert.strictEqual(isValidActorId("actor`id`"), false);
      assert.strictEqual(isValidActorId("actor\nid"), false);
      assert.strictEqual(isValidActorId("actor id"), false);
    });

    void it("N12: Public contract index does NOT export internal context issuer functions", async () => {
      const publicExports = (await import("../../contracts/src/context/index.ts")) as Record<
        string,
        unknown
      >;
      assert.strictEqual("createRootContext" in publicExports, false);
      assert.strictEqual("deriveChildContext" in publicExports, false);
      assert.strictEqual("isGenuineRequestContext" in publicExports, false);
    });

    void it("N13: External headers cannot override internal issuer correlation ID", () => {
      // Caller attempts to pass an untrusted client header as correlation_id
      const clientHeader = "trace-client-spoof-12345";
      assert.throws(
        () =>
          createRootContext({
            actor: { kind: "HUMAN", actor_id: "user-1" },
            provenance: { origin: "web", issuer: "ingress" },
            correlation_id: clientHeader,
          }),
        /INVALID_CORRELATION_ID/,
      );
    });

    void it("N14: Snapshot fixture verifies frozen shape consistency", () => {
      const snapshotPath = path.resolve(
        import.meta.dirname,
        "fixtures/context.contract.snapshot.json",
      );
      const snapshotContent = fs.readFileSync(snapshotPath, "utf8");
      const snapshotData = JSON.parse(snapshotContent) as {
        contract_id: string;
        invariants: { max_hop_count: number };
        actor_kinds: readonly string[];
      };
      assert.strictEqual(snapshotData.contract_id, "CONTRACT-CONTEXT-REQUEST-ACTOR-PROVENANCE-001");
      assert.strictEqual(snapshotData.invariants.max_hop_count, 32);
      assert.deepStrictEqual(snapshotData.actor_kinds, [
        "HUMAN",
        "AI",
        "SYSTEM",
        "MODULE",
        "INTEGRATION",
        "JOB",
      ]);
    });
  });
});
