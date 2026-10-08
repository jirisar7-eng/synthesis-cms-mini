/**
 * Synthesis CMS mini — Stable Namespace Registry Contract
 *
 * Contract ID: CONTRACT-CORE-STABLE-NAMESPACE-001
 * Roadmap Step: 13/60 — Stable namespace registry
 *
 * Provides canonical namespace grammar, closed root ownership taxonomy,
 * root-specific arity enforcement, 7-kind taxonomy with composite identity {kind, id},
 * strict module-prefix ownership binding, and lifecycle state management
 * without external runtime dependencies.
 */

export const NAMESPACE_CONTRACT_ID = "CONTRACT-CORE-STABLE-NAMESPACE-001" as const;

/**
 * Closed root ownership taxonomy governing prefix authority.
 * Every canonical identifier must begin with one of these approved roots.
 */
export const NAMESPACE_ROOTS = Object.freeze(["core", "gov", "sys", "pack", "ext"] as const);

export type NamespaceRoot = (typeof NAMESPACE_ROOTS)[number];

/**
 * Canonical 7 entity kinds supported by the namespace registry.
 */
export const NAMESPACE_KINDS = Object.freeze([
  "capability",
  "permission",
  "event",
  "settings",
  "module",
  "entitlement",
  "integration",
] as const);

export type NamespaceKind = (typeof NAMESPACE_KINDS)[number];

/**
 * Namespace lifecycle states.
 * Lifecycle transitions strictly follow: ACTIVE -> DEPRECATED -> RETIRED.
 * Reverse transitions are forbidden.
 * Once RETIRED, an identifier is permanently tombstoned and cannot be reused under any status.
 */
export const NAMESPACE_STATUSES = Object.freeze(["ACTIVE", "DEPRECATED", "RETIRED"] as const);

export type NamespaceStatus = (typeof NAMESPACE_STATUSES)[number];

/**
 * Grammar constants enforcing canonical dot-separated ASCII tokens.
 */
export const GRAMMAR_LIMITS = Object.freeze({
  TOTAL_LENGTH_MIN: 3,
  TOTAL_LENGTH_MAX: 128,
  SEGMENT_COUNT_MIN: 2,
  SEGMENT_COUNT_MAX: 6,
  SEGMENT_LENGTH_MIN: 1,
  SEGMENT_LENGTH_MAX: 48,
  CANONICAL_REGEX: /^[a-z0-9_]+(\.[a-z0-9_]+)+$/,
  SEGMENT_REGEX: /^[a-z0-9_]{1,48}$/,
} as const);

/**
 * Root-specific minimum arity constraints.
 */
export const ROOT_MIN_ARITY: Readonly<Record<NamespaceRoot, number>> = Object.freeze({
  core: 2,
  gov: 2,
  sys: 2,
  pack: 3,
  ext: 3,
});

export const CORE_INTEGRATION_MIN_ARITY = 4 as const;

export type NamespaceValidationErrorCode =
  | "INVALID_PRIMITIVE"
  | "INVALID_LENGTH"
  | "INVALID_CHARACTERS"
  | "MALFORMED_STRUCTURE"
  | "INVALID_SEGMENT_COUNT"
  | "INVALID_SEGMENT_LENGTH"
  | "INVALID_ROOT"
  | "INVALID_ARITY"
  | "INVALID_KIND"
  | "INVALID_STATUS"
  | "MODULE_PREFIX_MISMATCH"
  | "MODULE_OWNERSHIP_REQUIRED"
  | "THIRD_PARTY_ESCAPE"
  | "TOMBSTONE_REUSE"
  | "INVALID_SUPERSEDED_BY"
  | "INVALID_LIFECYCLE_TRANSITION"
  | "DUPLICATE_IDENTIFIER";

export class NamespaceValidationError extends Error {
  public readonly identifier: string;
  public readonly code: NamespaceValidationErrorCode;
  public readonly reason: string;

  constructor(identifier: string, code: NamespaceValidationErrorCode, reason: string) {
    super(`Namespace validation error [${code}] for identifier "${identifier}": ${reason}`);
    this.name = "NamespaceValidationError";
    this.identifier = identifier;
    this.code = code;
    this.reason = reason;
  }
}

/**
 * Input definition for a namespace entry.
 */
export interface NamespaceEntryInput {
  readonly kind: NamespaceKind;
  readonly id: string;
  readonly status: NamespaceStatus;
  readonly description: string;
  readonly ownerModuleId?: string | undefined;
  readonly version?: string | undefined;
  readonly superseded_by?: string | undefined;
}

/**
 * Validated, immutable namespace entry.
 */
export interface ValidatedNamespaceEntry {
  readonly kind: NamespaceKind;
  readonly id: string;
  readonly root: NamespaceRoot;
  readonly segments: readonly string[];
  readonly status: NamespaceStatus;
  readonly description: string;
  readonly ownerModuleId?: string | undefined;
  readonly version?: string | undefined;
  readonly superseded_by?: string | undefined;
}

/**
 * Validates raw string identifier against canonical lexical grammar in exact approved order:
 * primitive -> character screening -> total length -> dot structure -> segment extraction -> segment count -> segment length -> segment lexical validation.
 *
 * Throws NamespaceValidationError on any violation.
 */
export function validateNamespaceIdentifier(id: unknown): string {
  // 1. Primitive check
  if (typeof id !== "string") {
    throw new NamespaceValidationError(
      String(id),
      "INVALID_PRIMITIVE",
      `Expected non-null string primitive, received ${typeof id}`,
    );
  }

  // 2. Character screening (rejects uppercase, hyphens, whitespace, symbols, Unicode)
  for (let i = 0; i < id.length; i++) {
    const ch = id.charCodeAt(i);
    const isLower = ch >= 97 && ch <= 122; // a-z
    const isDigit = ch >= 48 && ch <= 57; // 0-9
    const isUnderscore = ch === 95; // _
    const isDot = ch === 46; // .

    if (!isLower && !isDigit && !isUnderscore && !isDot) {
      if (ch >= 65 && ch <= 90) {
        throw new NamespaceValidationError(
          id,
          "INVALID_CHARACTERS",
          "Uppercase characters are strictly forbidden; fail-closed rejection without silent normalization",
        );
      }
      if (ch === 45) {
        throw new NamespaceValidationError(
          id,
          "INVALID_CHARACTERS",
          "Hyphens are strictly forbidden in canonical namespace identifiers; use underscores",
        );
      }
      throw new NamespaceValidationError(
        id,
        "INVALID_CHARACTERS",
        `Disallowed character "${id.charAt(i)}" (char code ${String(ch)})`,
      );
    }
  }

  // 3. Total length check
  if (id.length < GRAMMAR_LIMITS.TOTAL_LENGTH_MIN || id.length > GRAMMAR_LIMITS.TOTAL_LENGTH_MAX) {
    throw new NamespaceValidationError(
      id,
      "INVALID_LENGTH",
      `Identifier length ${String(id.length)} out of bounds [${String(GRAMMAR_LIMITS.TOTAL_LENGTH_MIN)}, ${String(GRAMMAR_LIMITS.TOTAL_LENGTH_MAX)}]`,
    );
  }

  // 4. Dot structure check
  if (id.startsWith(".")) {
    throw new NamespaceValidationError(id, "MALFORMED_STRUCTURE", "Leading dot is forbidden");
  }
  if (id.endsWith(".")) {
    throw new NamespaceValidationError(id, "MALFORMED_STRUCTURE", "Trailing dot is forbidden");
  }
  if (id.includes("..")) {
    throw new NamespaceValidationError(id, "MALFORMED_STRUCTURE", "Consecutive dots are forbidden");
  }

  // 5. Segment extraction
  const segments = id.split(".");

  // 6. Segment count check
  if (
    segments.length < GRAMMAR_LIMITS.SEGMENT_COUNT_MIN ||
    segments.length > GRAMMAR_LIMITS.SEGMENT_COUNT_MAX
  ) {
    throw new NamespaceValidationError(
      id,
      "INVALID_SEGMENT_COUNT",
      `Segment count ${String(segments.length)} out of bounds [${String(GRAMMAR_LIMITS.SEGMENT_COUNT_MIN)}, ${String(GRAMMAR_LIMITS.SEGMENT_COUNT_MAX)}]`,
    );
  }

  // 7. Segment length check
  for (let idx = 0; idx < segments.length; idx++) {
    const seg = segments[idx];
    const segLen = seg === undefined ? 0 : seg.length;
    if (
      seg === undefined ||
      segLen < GRAMMAR_LIMITS.SEGMENT_LENGTH_MIN ||
      segLen > GRAMMAR_LIMITS.SEGMENT_LENGTH_MAX
    ) {
      throw new NamespaceValidationError(
        id,
        "INVALID_SEGMENT_LENGTH",
        `Segment ${String(idx + 1)} ("${seg ?? ""}") length ${String(segLen)} out of bounds [${String(GRAMMAR_LIMITS.SEGMENT_LENGTH_MIN)}, ${String(GRAMMAR_LIMITS.SEGMENT_LENGTH_MAX)}]`,
      );
    }
  }

  // 8. Segment lexical validation
  for (let idx = 0; idx < segments.length; idx++) {
    const seg = segments[idx];
    if (seg === undefined || !GRAMMAR_LIMITS.SEGMENT_REGEX.test(seg)) {
      throw new NamespaceValidationError(
        id,
        "INVALID_CHARACTERS",
        `Segment ${String(idx + 1)} ("${seg ?? ""}") does not match segment regex`,
      );
    }
  }

  return id;
}

/**
 * Boolean predicate checking whether an unknown input is a canonical namespace identifier.
 */
export function isCanonicalNamespaceIdentifier(id: unknown): id is string {
  try {
    validateNamespaceIdentifier(id);
    return true;
  } catch {
    return false;
  }
}

/**
 * Validates identifier grammar, checks root segment against closed root taxonomy,
 * and enforces root-specific arity constraints.
 */
export function validateNamespaceRoot(id: string): {
  readonly root: NamespaceRoot;
  readonly segments: readonly string[];
} {
  validateNamespaceIdentifier(id);

  const segments = Object.freeze(id.split("."));
  const rawRoot = segments[0];

  if (rawRoot === undefined || !NAMESPACE_ROOTS.includes(rawRoot as NamespaceRoot)) {
    throw new NamespaceValidationError(
      id,
      "INVALID_ROOT",
      `Root segment "${rawRoot ?? ""}" is not an authorized namespace root [${NAMESPACE_ROOTS.join(", ")}]`,
    );
  }

  const root = rawRoot as NamespaceRoot;
  const minArity = ROOT_MIN_ARITY[root];

  if (segments.length < minArity) {
    throw new NamespaceValidationError(
      id,
      "INVALID_ARITY",
      `Root "${root}" requires at least ${String(minArity)} segments; found ${String(segments.length)}`,
    );
  }

  // Special arity rule for first-party integrations: core.integration.* requires >= 4 segments
  if (root === "core" && segments.length > 1 && segments[1] === "integration") {
    if (segments.length < CORE_INTEGRATION_MIN_ARITY) {
      throw new NamespaceValidationError(
        id,
        "INVALID_ARITY",
        `First-party integration namespace "core.integration.*" requires at least ${String(CORE_INTEGRATION_MIN_ARITY)} segments (core.integration.<category>.<provider>); found ${String(segments.length)}`,
      );
    }
  }

  return { root, segments };
}

/**
 * Validates module ownership prefix rule.
 * An owned identifier must be equal to module_id (if kind is 'module')
 * OR must strictly start with module_id + '.'.
 */
export function validateModuleOwnership(
  identifier: string,
  kind: NamespaceKind,
  ownerModuleId: string,
): void {
  validateNamespaceIdentifier(ownerModuleId);
  validateNamespaceIdentifier(identifier);

  const { root: ownerRoot, segments: ownerSegments } = validateNamespaceRoot(ownerModuleId);

  if (ownerRoot === "ext" && ownerSegments.length !== 3) {
    throw new NamespaceValidationError(
      ownerModuleId,
      "INVALID_ARITY",
      `Third-party owner module ID "${ownerModuleId}" must have exactly 3 segments: ext.<publisher>.<module>`,
    );
  }

  if (kind === "module") {
    if (identifier !== ownerModuleId) {
      throw new NamespaceValidationError(
        identifier,
        "MODULE_PREFIX_MISMATCH",
        `Module declaration identifier "${identifier}" must match its owner module ID "${ownerModuleId}"`,
      );
    }
    return;
  }

  const requiredPrefix = ownerModuleId + ".";
  if (!identifier.startsWith(requiredPrefix)) {
    throw new NamespaceValidationError(
      identifier,
      "MODULE_PREFIX_MISMATCH",
      `Identifier "${identifier}" must start with owner module prefix "${requiredPrefix}"`,
    );
  }

  // Third-party escape check: ext modules cannot declare non-ext identifiers
  if (ownerModuleId.startsWith("ext.")) {
    if (!identifier.startsWith("ext.")) {
      throw new NamespaceValidationError(
        identifier,
        "THIRD_PARTY_ESCAPE",
        `Third-party module "${ownerModuleId}" cannot declare identifiers outside the "ext.*" namespace`,
      );
    }
  }
}

/**
 * Validates lifecycle transition rules.
 * Allowed transitions: ACTIVE -> DEPRECATED -> RETIRED.
 * Reverse transitions are forbidden.
 * RETIRED is a permanent terminal state and cannot transition.
 */
export function validateLifecycleTransition(
  currentStatus: NamespaceStatus,
  targetStatus: NamespaceStatus,
): void {
  if (!NAMESPACE_STATUSES.includes(currentStatus)) {
    throw new NamespaceValidationError(
      "lifecycle",
      "INVALID_STATUS",
      `Invalid current status: "${currentStatus}"`,
    );
  }
  if (!NAMESPACE_STATUSES.includes(targetStatus)) {
    throw new NamespaceValidationError(
      "lifecycle",
      "INVALID_STATUS",
      `Invalid target status: "${targetStatus}"`,
    );
  }
  if (currentStatus === targetStatus) {
    return;
  }
  if (currentStatus === "ACTIVE" && targetStatus === "DEPRECATED") {
    return;
  }
  if (currentStatus === "DEPRECATED" && targetStatus === "RETIRED") {
    return;
  }
  throw new NamespaceValidationError(
    "lifecycle",
    "INVALID_LIFECYCLE_TRANSITION",
    `Invalid lifecycle transition from ${currentStatus} to ${targetStatus}; allowed transitions are ACTIVE -> DEPRECATED -> RETIRED`,
  );
}

/**
 * Validates a single namespace entry against grammar, root taxonomy,
 * kind taxonomy, status, module prefix binding, and supersession integrity.
 * Fails closed on malformed runtime objects without leaking raw TypeErrors.
 */
export function validateNamespaceEntry(entry: unknown): ValidatedNamespaceEntry {
  if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
    throw new NamespaceValidationError(
      "entry",
      "INVALID_PRIMITIVE",
      "Entry must be a non-null object",
    );
  }

  const raw = entry as Record<string, unknown>;

  if (typeof raw.id !== "string") {
    throw new NamespaceValidationError(
      "entry.id",
      "INVALID_PRIMITIVE",
      "Entry id must be a string primitive",
    );
  }
  const id = raw.id;

  if (typeof raw.kind !== "string") {
    throw new NamespaceValidationError(
      id,
      "INVALID_PRIMITIVE",
      "Entry kind must be a string primitive",
    );
  }
  const kindStr = raw.kind;
  if (!NAMESPACE_KINDS.includes(kindStr as NamespaceKind)) {
    throw new NamespaceValidationError(
      id,
      "INVALID_KIND",
      `Kind "${kindStr}" is not an authorized namespace kind [${NAMESPACE_KINDS.join(", ")}]`,
    );
  }
  const kind = kindStr as NamespaceKind;

  if (typeof raw.status !== "string") {
    throw new NamespaceValidationError(
      id,
      "INVALID_PRIMITIVE",
      "Entry status must be a string primitive",
    );
  }
  const statusStr = raw.status;
  if (!NAMESPACE_STATUSES.includes(statusStr as NamespaceStatus)) {
    throw new NamespaceValidationError(
      id,
      "INVALID_STATUS",
      `Status "${statusStr}" is not an authorized lifecycle status [${NAMESPACE_STATUSES.join(", ")}]`,
    );
  }
  const status = statusStr as NamespaceStatus;

  if (typeof raw.description !== "string" || raw.description.trim().length === 0) {
    throw new NamespaceValidationError(
      id,
      "INVALID_PRIMITIVE",
      "Description must be a non-empty string primitive",
    );
  }
  const description = raw.description;

  if (raw.ownerModuleId !== undefined && typeof raw.ownerModuleId !== "string") {
    throw new NamespaceValidationError(
      id,
      "INVALID_PRIMITIVE",
      "ownerModuleId must be a string primitive if defined",
    );
  }
  const ownerModuleId = raw.ownerModuleId;

  if (raw.version !== undefined && typeof raw.version !== "string") {
    throw new NamespaceValidationError(
      id,
      "INVALID_PRIMITIVE",
      "version must be a string primitive if defined",
    );
  }
  const version = raw.version;

  if (raw.superseded_by !== undefined && typeof raw.superseded_by !== "string") {
    throw new NamespaceValidationError(
      id,
      "INVALID_PRIMITIVE",
      "superseded_by must be a string primitive if defined",
    );
  }
  const superseded_by = raw.superseded_by;

  const { root, segments } = validateNamespaceRoot(id);

  // Third-party ext.* ownership enforcement
  if (root === "ext") {
    if (kind === "module") {
      if (segments.length !== 3) {
        throw new NamespaceValidationError(
          id,
          "INVALID_ARITY",
          `Third-party module identifier "${id}" must have exactly 3 segments: ext.<publisher>.<module>`,
        );
      }
      if (ownerModuleId !== undefined && ownerModuleId !== id) {
        throw new NamespaceValidationError(
          id,
          "MODULE_PREFIX_MISMATCH",
          `Third-party module ownerModuleId "${ownerModuleId}" must match module ID "${id}"`,
        );
      }
    } else {
      if (segments.length < 4) {
        throw new NamespaceValidationError(
          id,
          "INVALID_ARITY",
          `Non-module ext identifier "${id}" must belong to exact "ext.<publisher>.<module>.*" (at least 4 segments)`,
        );
      }
      if (ownerModuleId === undefined) {
        throw new NamespaceValidationError(
          id,
          "MODULE_OWNERSHIP_REQUIRED",
          `Third-party extension identifier "${id}" requires explicit ownerModuleId`,
        );
      }
      validateModuleOwnership(id, kind, ownerModuleId);
    }
  } else {
    // Non-ext roots: if ownerModuleId is provided, validate prefix binding
    if (ownerModuleId !== undefined) {
      validateModuleOwnership(id, kind, ownerModuleId);
    }
  }

  // Superseded_by semantic validation
  if (superseded_by !== undefined) {
    validateNamespaceRoot(superseded_by);
    if (superseded_by === id) {
      throw new NamespaceValidationError(
        id,
        "INVALID_SUPERSEDED_BY",
        `Identifier "${id}" cannot supersede itself`,
      );
    }
    if (status === "ACTIVE") {
      throw new NamespaceValidationError(
        id,
        "INVALID_SUPERSEDED_BY",
        `ACTIVE identifier "${id}" cannot have a superseded_by reference; superseded_by is only permitted on DEPRECATED or RETIRED entries`,
      );
    }
  }

  return Object.freeze({
    kind,
    id,
    root,
    segments,
    status,
    description,
    ownerModuleId,
    version,
    superseded_by,
  });
}

/**
 * Validates a complete registry of entries.
 * Enforces uniqueness of composite identity (kind, id) and
 * prevents re-registration of tombstoned RETIRED identifiers under any status.
 */
export function validateNamespaceRegistry(
  entries: readonly NamespaceEntryInput[],
  existingTombstones?: ReadonlySet<string>,
): readonly ValidatedNamespaceEntry[] {
  if (!Array.isArray(entries)) {
    throw new NamespaceValidationError(
      "registry",
      "INVALID_PRIMITIVE",
      "Registry entries must be an array",
    );
  }
  if (existingTombstones !== undefined && !(existingTombstones instanceof Set)) {
    throw new NamespaceValidationError(
      "registry",
      "INVALID_PRIMITIVE",
      "existingTombstones must be a Set instance if defined",
    );
  }

  const seenCompositeKeys = new Set<string>();
  const validatedEntries: ValidatedNamespaceEntry[] = [];

  for (const entry of entries) {
    const validated = validateNamespaceEntry(entry);
    const compositeKey = `${validated.kind}::${validated.id}`;

    if (seenCompositeKeys.has(compositeKey)) {
      throw new NamespaceValidationError(
        validated.id,
        "DUPLICATE_IDENTIFIER",
        `Duplicate identifier for kind "${validated.kind}": "${validated.id}"`,
      );
    }
    seenCompositeKeys.add(compositeKey);

    // If an external tombstone set is provided, verify no tombstone reuse under ANY status
    if (existingTombstones && existingTombstones.has(compositeKey)) {
      throw new NamespaceValidationError(
        validated.id,
        "TOMBSTONE_REUSE",
        `Cannot re-register permanently retired tombstone "${validated.id}" for kind "${validated.kind}" under any status (attempted: ${validated.status})`,
      );
    }

    validatedEntries.push(validated);
  }

  return Object.freeze(validatedEntries);
}
