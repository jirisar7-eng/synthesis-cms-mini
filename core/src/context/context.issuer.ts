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
 * 5. A root context ALWAYS mints its own fresh correlation_id (corr-<UUIDv4>);
 *    external or caller-supplied correlation_id values are strictly forbidden.
 * 6. Child context derivation preserves parent actor, tenant scope, issuer, and root correlation_id;
 *    tenant_id overrides in child derivation are strictly forbidden.
 * 7. Error messages NEVER reflect raw untrusted user input or values.
 * 8. Maximum causal depth is strictly enforced: MAX_HOP_COUNT = 32 (fail-closed).
 */

import { randomUUID } from "node:crypto";
import {
  type ActorContext,
  type ActorKind,
  type ProvenanceContext,
  type RequestContext,
  isValidActorId,
  isValidActorKind,
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
 * Callers cannot provide or override correlation_id; it is always platform-minted.
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
}

/**
 * Parameters for deriving a child RequestContext.
 * Tenant scope is strictly immutable and cannot be overridden.
 */
export interface DeriveChildContextParams {
  /**
   * Sub-origin or operation descriptor for the child context.
   * If omitted, inherits parent origin.
   */
  readonly origin?: string | undefined;
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
 * Asserts that an input object is a plain data object matching exact allowlisted properties.
 * Rejects accessor properties (getters/setters), unknown/forbidden keys, prototype tampering,
 * and symbol keys without reflecting input values in error messages.
 */
function assertStrictPlainObject(
  obj: unknown,
  allowedKeys: readonly string[],
  label: string,
): asserts obj is Record<string, unknown> {
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
    throw new TypeError(
      `INVALID_${label.toUpperCase()}: Expected plain non-null object for ${label}`,
    );
  }

  // Reject objects with non-standard prototypes
  const proto: unknown = Object.getPrototypeOf(obj);
  if (proto !== Object.prototype && proto !== null) {
    throw new Error(`HOSTILE_OBJECT_DETECTED: Object for ${label} must have plain prototype`);
  }

  // Reject symbol properties
  if (Object.getOwnPropertySymbols(obj).length > 0) {
    throw new Error(`FORBIDDEN_PROPERTY_DETECTED: Symbol properties forbidden in ${label}`);
  }

  const ownKeys = Object.getOwnPropertyNames(obj);
  const allowedSet = new Set(allowedKeys);

  for (const key of ownKeys) {
    if (!allowedSet.has(key)) {
      throw new Error(`UNKNOWN_PROPERTY_DETECTED: Forbidden or unexpected property in ${label}`);
    }

    const desc = Object.getOwnPropertyDescriptor(obj, key);
    if (!desc || desc.get !== undefined || desc.set !== undefined) {
      throw new Error(`HOSTILE_PROPERTY_DETECTED: Accessor properties forbidden in ${label}`);
    }
  }
}

/**
 * Creates a platform root RequestContext.
 *
 * Invariants:
 * - correlation_id is ALWAYS platform-minted using fresh cryptographic entropy (corr-<UUIDv4>).
 * - Caller-supplied correlation_id is forbidden and rejected.
 * - Error messages never reflect untrusted user values.
 */
export function createRootContext(params: CreateRootContextParams): RequestContext {
  assertStrictPlainObject(params, ["actor", "provenance"], "CreateRootContextParams");
  assertStrictPlainObject(params.actor, ["kind", "actor_id", "tenant_id"], "ActorContextParams");
  assertStrictPlainObject(
    params.provenance,
    ["origin", "issuer", "external_trace_id"],
    "ProvenanceContextParams",
  );

  // 1. Validate Actor
  const { kind, actor_id, tenant_id } = params.actor;
  if (!isValidActorKind(kind)) {
    throw new Error("INVALID_ACTOR_KIND: Unrecognized or invalid ActorKind");
  }
  if (!isValidActorId(actor_id)) {
    throw new Error("INVALID_ACTOR_ID: Invalid actor_id format or length");
  }
  if (tenant_id !== undefined && !isValidTenantId(tenant_id)) {
    throw new Error("INVALID_TENANT_ID: Invalid tenant_id format or length");
  }

  // 2. Validate Provenance
  const { origin, issuer, external_trace_id } = params.provenance;
  if (!isValidOrigin(origin)) {
    throw new Error("INVALID_ORIGIN: Invalid origin format or length");
  }
  if (!isValidIssuer(issuer)) {
    throw new Error("INVALID_ISSUER: Invalid issuer format or length");
  }
  if (external_trace_id !== undefined && !isValidExternalTraceId(external_trace_id)) {
    throw new Error("INVALID_EXTERNAL_TRACE_ID: Invalid external_trace_id format or length");
  }

  // 3. Always platform-mint fresh correlation_id and request_id
  const correlationId = `corr-${randomUUID()}`;
  const requestId = `req-${randomUUID()}`;
  const timestamp = new Date().toISOString();

  // 4. Construct defensive immutable objects with copied primitives only
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

  // 5. Register authentic instance in WeakSet
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
 * - Preserves actor modality, actor_id, and tenant_id strictly (no tenant scope changes or acquisition).
 * - Records causal_parent_id = parent.request_id.
 * - Increments hop_count by 1.
 * - Enforces MAX_HOP_COUNT = 32 limit (fails closed with error if exceeded).
 * - Reject unknown options or tenant overrides.
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
    assertStrictPlainObject(params, ["origin", "external_trace_id"], "DeriveChildContextParams");
  }

  // Enforce causal depth boundary
  const nextHopCount = parent.provenance.hop_count + 1;
  if (nextHopCount > MAX_HOP_COUNT) {
    throw new Error("MAX_HOP_COUNT_EXCEEDED: Causal depth exceeds maximum allowed limit");
  }

  // Resolve origin
  let childOrigin = parent.provenance.origin;
  if (params?.origin !== undefined) {
    if (!isValidOrigin(params.origin)) {
      throw new Error("INVALID_ORIGIN: Invalid child origin format or length");
    }
    childOrigin = params.origin;
  }

  // Resolve external trace ID
  let childExternalTraceId = parent.provenance.external_trace_id;
  if (params?.external_trace_id !== undefined) {
    if (!isValidExternalTraceId(params.external_trace_id)) {
      throw new Error(
        "INVALID_EXTERNAL_TRACE_ID: Invalid child external_trace_id format or length",
      );
    }
    childExternalTraceId = params.external_trace_id;
  }

  // Mint fresh child request ID and capture current timestamp
  const childRequestId = `req-${randomUUID()}`;
  const timestamp = new Date().toISOString();

  // Child strictly retains parent's tenant_id (cannot acquire, alter, or drop tenant scope)
  const childActor: ActorContext = Object.freeze({
    kind: parent.actor.kind,
    actor_id: parent.actor.actor_id,
    ...(parent.actor.tenant_id !== undefined ? { tenant_id: parent.actor.tenant_id } : {}),
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
