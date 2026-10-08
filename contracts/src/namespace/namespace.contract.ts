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
 * Once RETIRED, an identifier is permanently tombstoned and cannot be reused.
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
  | "THIRD_PARTY_ESCAPE"
  | "TOMBSTONE_REUSE"
  | "INVALID_SUPERSEDED_BY"
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
 * Step 1–8: Validates raw string identifier against canonical lexical grammar.
 * Throws NamespaceValidationError on any violation.
 */
export function validateNamespaceIdentifier(id: unknown): string {
  // 1. Primitive type check
  if (typeof id !== "string") {
    throw new NamespaceValidationError(
      String(id),
      "INVALID_PRIMITIVE",
      `Expected non-null string primitive, received ${typeof id}`,
    );
  }

  // 2. Total length check
  if (id.length < GRAMMAR_LIMITS.TOTAL_LENGTH_MIN || id.length > GRAMMAR_LIMITS.TOTAL_LENGTH_MAX) {
    throw new NamespaceValidationError(
      id,
      "INVALID_LENGTH",
      `Identifier length ${String(id.length)} out of bounds [${String(GRAMMAR_LIMITS.TOTAL_LENGTH_MIN)}, ${String(GRAMMAR_LIMITS.TOTAL_LENGTH_MAX)}]`,
    );
  }

  // 3. Character set screening (rejects uppercase, hyphens, whitespace, symbols, Unicode)
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

  // 4. Structural dot check
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

  // 7. Individual segment constraints
  for (let idx = 0; idx < segments.length; idx++) {
    const seg = segments[idx];
    if (
      seg === undefined ||
      seg.length < GRAMMAR_LIMITS.SEGMENT_LENGTH_MIN ||
      seg.length > GRAMMAR_LIMITS.SEGMENT_LENGTH_MAX
    ) {
      const segLen = seg === undefined ? 0 : seg.length;
      throw new NamespaceValidationError(
        id,
        "INVALID_SEGMENT_LENGTH",
        `Segment ${String(idx + 1)} ("${seg ?? ""}") length ${String(segLen)} out of bounds [${String(GRAMMAR_LIMITS.SEGMENT_LENGTH_MIN)}, ${String(GRAMMAR_LIMITS.SEGMENT_LENGTH_MAX)}]`,
      );
    }
    if (!GRAMMAR_LIMITS.SEGMENT_REGEX.test(seg)) {
      throw new NamespaceValidationError(
        id,
        "INVALID_CHARACTERS",
        `Segment ${String(idx + 1)} ("${seg}") does not match segment regex`,
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
 * Validates a single namespace entry against grammar, root taxonomy,
 * kind taxonomy, status, module prefix binding, and supersession integrity.
 */
export function validateNamespaceEntry(entry: NamespaceEntryInput): ValidatedNamespaceEntry {
  const rawEntry: unknown = entry;
  if (typeof rawEntry !== "object" || rawEntry === null) {
    throw new NamespaceValidationError(
      "entry",
      "INVALID_PRIMITIVE",
      "Entry must be a non-null object",
    );
  }

  const kindStr = entry.kind as string;
  if (!NAMESPACE_KINDS.includes(kindStr as NamespaceKind)) {
    throw new NamespaceValidationError(
      entry.id,
      "INVALID_KIND",
      `Kind "${kindStr}" is not an authorized namespace kind [${NAMESPACE_KINDS.join(", ")}]`,
    );
  }

  const statusStr = entry.status as string;
  if (!NAMESPACE_STATUSES.includes(statusStr as NamespaceStatus)) {
    throw new NamespaceValidationError(
      entry.id,
      "INVALID_STATUS",
      `Status "${statusStr}" is not an authorized lifecycle status [${NAMESPACE_STATUSES.join(", ")}]`,
    );
  }

  if (entry.description.trim().length === 0) {
    throw new NamespaceValidationError(
      entry.id,
      "INVALID_PRIMITIVE",
      "Description must be a non-empty string",
    );
  }

  const { root, segments } = validateNamespaceRoot(entry.id);

  if (entry.ownerModuleId !== undefined) {
    validateModuleOwnership(entry.id, entry.kind, entry.ownerModuleId);
  }

  if (entry.superseded_by !== undefined) {
    validateNamespaceIdentifier(entry.superseded_by);
    if (entry.status === "ACTIVE") {
      throw new NamespaceValidationError(
        entry.id,
        "INVALID_SUPERSEDED_BY",
        "ACTIVE identifier cannot have a superseded_by reference",
      );
    }
  }

  return Object.freeze({
    kind: entry.kind,
    id: entry.id,
    root,
    segments,
    status: entry.status,
    description: entry.description,
    ownerModuleId: entry.ownerModuleId,
    version: entry.version,
    superseded_by: entry.superseded_by,
  });
}

/**
 * Validates a complete registry of entries.
 * Enforces uniqueness of composite identity (kind, id) and
 * prevents re-registration of tombstoned RETIRED identifiers.
 */
export function validateNamespaceRegistry(
  entries: readonly NamespaceEntryInput[],
  existingTombstones?: ReadonlySet<string>,
): readonly ValidatedNamespaceEntry[] {
  const seenCompositeKeys = new Set<string>();
  const validatedEntries: ValidatedNamespaceEntry[] = [];

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    if (entry === undefined) {
      continue;
    }
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

    // If an external tombstone set is provided, verify active entries don't reuse retired IDs
    if (
      existingTombstones &&
      existingTombstones.has(compositeKey) &&
      validated.status === "ACTIVE"
    ) {
      throw new NamespaceValidationError(
        validated.id,
        "TOMBSTONE_REUSE",
        `Cannot re-activate permanently retired tombstone "${validated.id}" for kind "${validated.kind}"`,
      );
    }

    validatedEntries.push(validated);
  }

  return Object.freeze(validatedEntries);
}

/**
 * Exact-match permission evaluation.
 * Invariant: No wildcards (*), no prefix matching, fail-closed deny on missing match.
 * Invariant: Namespace ownership never conveys runtime authorization.
 */
export function checkPermission(
  requestedPermission: string,
  grantedPermissions: readonly string[],
): boolean {
  if (!isCanonicalNamespaceIdentifier(requestedPermission)) {
    return false;
  }
  const rawGranted: unknown = grantedPermissions;
  if (!Array.isArray(rawGranted)) {
    return false;
  }
  for (const granted of grantedPermissions) {
    if (granted === requestedPermission) {
      return true;
    }
  }
  return false;
}
