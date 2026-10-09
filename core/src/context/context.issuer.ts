/**
 * Synthesis CMS mini — Internal Core Context Issuer
 *
 * Implements internal trusted-core context issuance, minting, and causal derivation.
 *
 * SECURITY LIMITATIONS & ARCHITECTURAL INVARIANTS:
 * 1. Source-module separation and WeakSet do NOT prevent arbitrary malicious same-process
 *    code from importing internal modules. WeakSet is an authenticity guard against object
 *    spoofing, NOT caller authorization or an OS-level sandbox.
 * 2. The trusted-core boundary is an explicit trusted-computing-base assumption.
 * 3. ActorKind is NEVER a permission grant. Default authorization is server-side DENY.
 * 4. No caller input is automatically treated as authenticated identity.
 * 5. Child context derivation enforces strict causal lineage, increments hop_count,
 *    and forbids privilege escalation (AI or MODULE cannot become SYSTEM or HUMAN).
 * 6. Maximum causal depth is strictly enforced: MAX_HOP_COUNT = 32 (fail-closed).
 */

import { randomUUID } from "node:crypto";
import {
  type ActorContext,
  type ActorKind,
  type ProvenanceContext,
  type RequestContext,
  isValidActorId,
  isValidActorKind,
  isValidCorrelationId,
  isValidExternalTraceId,
  isValidIssuer,
  isValidOrigin,
  isValidTenantId,
  MAX_HOP_COUNT,
} from "../../../contracts/src/context/index.ts";

/**
 * Module-private WeakSet tracking authentic RequestContext instances
 * constructed exclusively by this trusted issuer.
 */
const genuineContextInstances = new WeakSet();

/**
 * Parameters for creating a platform root RequestContext.
 */
export interface CreateRootContextParams {
  readonly actor: {
    readonly kind: ActorKind;
    readonly actor_id: string;
    readonly tenant_id?: string | undefined;
  };
  readonly provenance: {
    readonly origin: string;
    readonly issuer: string;
    readonly external_trace_id?: string | undefined;
  };
  /**
   * Optional platform-verified correlation_id.
   * If not provided, a fresh platform correlation ID (corr-<UUIDv4>) is minted.
   */
  readonly correlation_id?: string | undefined;
}

/**
 * Parameters for deriving a child RequestContext.
 */
export interface DeriveChildContextParams {
  /**
   * Sub-origin or operation descriptor for the child context.
   * If omitted, inherits parent origin.
   */
  readonly origin?: string | undefined;
  /**
   * Optional tenant scope refinement (must match parent if parent has tenant_id).
   */
  readonly tenant_id?: string | undefined;
  /**
   * Optional external trace ID update (telemetry only).
   */
  readonly external_trace_id?: string | undefined;
}

/**
 * Verifies whether an object is a genuine, non-forged RequestContext instance
 * minted by this trusted issuer.
 */
export function isGenuineRequestContext(val: unknown): val is RequestContext {
  if (val === null || typeof val !== "object") return false;
  return genuineContextInstances.has(val);
}

/**
 * Asserts that an input object is plain and does not contain dangerous prototype tampering.
 */
function assertSafeObject(obj: unknown, label: string): asserts obj is Record<string, unknown> {
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
    throw new TypeError(`INVALID_${label.toUpperCase()}: Expected non-null object for ${label}`);
  }
  if (Object.prototype.hasOwnProperty.call(obj, "__proto__")) {
    throw new Error(`PROTOTYPE_POLLUTION_DETECTED: Forbidden property '__proto__' in ${label}`);
  }
  if (Object.prototype.hasOwnProperty.call(obj, "constructor")) {
    throw new Error(`PROTOTYPE_POLLUTION_DETECTED: Forbidden property 'constructor' in ${label}`);
  }
  if (Object.prototype.hasOwnProperty.call(obj, "prototype")) {
    throw new Error(`PROTOTYPE_POLLUTION_DETECTED: Forbidden property 'prototype' in ${label}`);
  }
}

/**
 * Creates a platform root RequestContext.
 *
 * This function is an internal kernel/runtime API. Ingress controllers must
 * sanitize all external inputs prior to invocation.
 */
export function createRootContext(params: CreateRootContextParams): RequestContext {
  assertSafeObject(params, "CreateRootContextParams");
  assertSafeObject(params.actor, "ActorContextParams");
  assertSafeObject(params.provenance, "ProvenanceContextParams");

  // 1. Validate Actor
  const { kind, actor_id, tenant_id } = params.actor;
  if (!isValidActorKind(kind)) {
    throw new Error(`INVALID_ACTOR_KIND: Unrecognized or invalid ActorKind: ${String(kind)}`);
  }
  if (!isValidActorId(actor_id)) {
    throw new Error(`INVALID_ACTOR_ID: Invalid actor_id format or length: ${String(actor_id)}`);
  }
  if (tenant_id !== undefined && !isValidTenantId(tenant_id)) {
    throw new Error(`INVALID_TENANT_ID: Invalid tenant_id format or length: ${String(tenant_id)}`);
  }

  // 2. Validate Provenance
  const { origin, issuer, external_trace_id } = params.provenance;
  if (!isValidOrigin(origin)) {
    throw new Error(`INVALID_ORIGIN: Invalid origin format or length: ${String(origin)}`);
  }
  if (!isValidIssuer(issuer)) {
    throw new Error(`INVALID_ISSUER: Invalid issuer format or length: ${String(issuer)}`);
  }
  if (external_trace_id !== undefined && !isValidExternalTraceId(external_trace_id)) {
    throw new Error(
      `INVALID_EXTERNAL_TRACE_ID: Invalid external_trace_id format: ${String(external_trace_id)}`,
    );
  }

  // 3. Determine Correlation ID (platform-minted or platform-verified)
  let correlationId: string;
  if (params.correlation_id !== undefined) {
    if (!isValidCorrelationId(params.correlation_id)) {
      throw new Error(
        `INVALID_CORRELATION_ID: Provided correlation_id is not valid platform corr-<UUIDv4>: ${String(params.correlation_id)}`,
      );
    }
    correlationId = params.correlation_id;
  } else {
    correlationId = `corr-${randomUUID()}`;
  }

  // 4. Mint Request ID & Timestamp
  const requestId = `req-${randomUUID()}`;
  const timestamp = new Date().toISOString();

  // 5. Construct defensive immutable objects
  const actorContext: ActorContext = Object.freeze({
    kind,
    actor_id,
    ...(tenant_id !== undefined ? { tenant_id } : {}),
  });

  const provenanceContext: ProvenanceContext = Object.freeze({
    origin,
    issuer,
    hop_count: 0,
    ...(external_trace_id !== undefined ? { external_trace_id } : {}),
  });

  const requestContext: RequestContext = Object.freeze({
    request_id: requestId,
    correlation_id: correlationId,
    timestamp,
    actor: actorContext,
    provenance: provenanceContext,
  });

  // 6. Register authentic instance in WeakSet
  genuineContextInstances.add(requestContext);

  return requestContext;
}

/**
 * Derives a child RequestContext from a verified genuine parent RequestContext.
 *
 * Invariants:
 * - Parent must be a verified genuine RequestContext instance.
 * - Mints a fresh request_id for each hop.
 * - Preserves root correlation_id without modification.
 * - Preserves actor modality and actor_id (no privilege escalation or actor mutation).
 * - Records causal_parent_id = parent.request_id.
 * - Increments hop_count by 1.
 * - Enforces MAX_HOP_COUNT = 32 limit (fails closed with error if exceeded).
 */
export function deriveChildContext(
  parent: RequestContext,
  params?: DeriveChildContextParams,
): RequestContext {
  if (!isGenuineRequestContext(parent)) {
    throw new Error(
      "UNAUTHENTIC_PARENT_CONTEXT: deriveChildContext requires a genuine platform-issued RequestContext",
    );
  }

  if (params !== undefined) {
    assertSafeObject(params, "DeriveChildContextParams");
  }

  // Enforce causal depth boundary
  const nextHopCount = parent.provenance.hop_count + 1;
  if (nextHopCount > MAX_HOP_COUNT) {
    throw new Error(
      `MAX_HOP_COUNT_EXCEEDED: Causal depth ${String(nextHopCount)} exceeds maximum limit of ${String(MAX_HOP_COUNT)}`,
    );
  }

  // Resolve origin
  let childOrigin = parent.provenance.origin;
  if (params?.origin !== undefined) {
    if (!isValidOrigin(params.origin)) {
      throw new Error("INVALID_ORIGIN: Invalid child origin");
    }
    childOrigin = params.origin;
  }

  // Resolve tenant scope (may narrow or inherit, but cannot cross tenants)
  let childTenantId = parent.actor.tenant_id;
  if (params?.tenant_id !== undefined) {
    if (!isValidTenantId(params.tenant_id)) {
      throw new Error("INVALID_TENANT_ID: Invalid child tenant_id");
    }
    if (parent.actor.tenant_id !== undefined && parent.actor.tenant_id !== params.tenant_id) {
      throw new Error("CROSS_TENANT_DERIVATION_FORBIDDEN: Child tenant does not match parent");
    }
    childTenantId = params.tenant_id;
  }

  // Resolve external trace ID
  let childExternalTraceId = parent.provenance.external_trace_id;
  if (params?.external_trace_id !== undefined) {
    if (!isValidExternalTraceId(params.external_trace_id)) {
      throw new Error("INVALID_EXTERNAL_TRACE_ID: Invalid child external_trace_id");
    }
    childExternalTraceId = params.external_trace_id;
  }

  // Mint fresh child request ID and capture current timestamp
  const childRequestId = `req-${randomUUID()}`;
  const timestamp = new Date().toISOString();

  // Construct defensive immutable child structures
  const childActor: ActorContext = Object.freeze({
    kind: parent.actor.kind,
    actor_id: parent.actor.actor_id,
    ...(childTenantId !== undefined ? { tenant_id: childTenantId } : {}),
  });

  const childProvenance: ProvenanceContext = Object.freeze({
    origin: childOrigin,
    issuer: parent.provenance.issuer,
    hop_count: nextHopCount,
    causal_parent_id: parent.request_id,
    ...(childExternalTraceId !== undefined ? { external_trace_id: childExternalTraceId } : {}),
  });

  const childContext: RequestContext = Object.freeze({
    request_id: childRequestId,
    correlation_id: parent.correlation_id,
    timestamp,
    actor: childActor,
    provenance: childProvenance,
  });

  // Register in WeakSet
  genuineContextInstances.add(childContext);

  return childContext;
}
