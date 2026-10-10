/**
 * Synthesis CMS mini — Internal Core Registry Framework Implementation
 *
 * Implements deterministic copy-on-write immutable registry snapshot management,
 * entry registration, listing, lookup, and lifecycle transitions.
 *
 * SECURITY LIMITATIONS & ARCHITECTURAL INVARIANTS:
 * 1. Registry snapshots are deeply frozen, versioned, copy-on-write structures.
 * 2. Authenticity is tracked via module-private WeakSet (isGenuineRegistrySnapshot).
 * 3. Entries are pure data descriptors (no functions, callbacks, or executable code).
 * 4. Composite key is {category, id}. Identifiers are canonical Step 13 namespaces.
 * 5. Third-party modules (ext.<publisher>.<module>) cannot escape their namespace.
 * 6. RETIRED entries are permanent tombstones; their IDs cannot be re-registered or reused.
 * 7. Error messages do not disclose untrusted input values or secret tokens.
 */

import { randomUUID } from "node:crypto";
import {
  type RegistryCategory,
  type RegistryEntry,
  type RegistryEntryInput,
  type RegistryEntryStatus,
  type RegistrySnapshot,
  isValidRegistryCategory,
  isValidRegistryDescription,
  isValidRegistryStatus,
  validateRegistryLifecycleTransition,
  validateRegistryOwnership,
} from "../../../contracts/src/registry/index.ts";
import { isCanonicalNamespaceIdentifier } from "../../../contracts/src/namespace/index.ts";

/**
 * Module-private WeakSet tracking authentic RegistrySnapshot instances
 * constructed exclusively by this framework.
 */
const genuineRegistrySnapshots = new WeakSet();

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
  let proto: unknown;
  try {
    proto = Object.getPrototypeOf(obj);
  } catch {
    throw new Error(`HOSTILE_OBJECT_DETECTED: Object for ${label} must have plain prototype`);
  }
  if (proto !== Object.prototype && proto !== null) {
    throw new Error(`HOSTILE_OBJECT_DETECTED: Object for ${label} must have plain prototype`);
  }

  // Reject symbol properties
  let symbols: (string | symbol)[];
  try {
    symbols = Object.getOwnPropertySymbols(obj);
  } catch {
    throw new Error(
      `HOSTILE_INPUT_ERROR: Malformed or hostile object descriptor detected in ${label}`,
    );
  }
  if (symbols.length > 0) {
    throw new Error(`FORBIDDEN_PROPERTY_DETECTED: Symbol properties forbidden in ${label}`);
  }

  let ownKeys: string[];
  try {
    ownKeys = Object.getOwnPropertyNames(obj);
  } catch {
    throw new Error(
      `HOSTILE_INPUT_ERROR: Malformed or hostile object descriptor detected in ${label}`,
    );
  }

  const allowedSet = new Set(allowedKeys);

  for (const key of ownKeys) {
    if (!allowedSet.has(key)) {
      throw new Error(`UNKNOWN_PROPERTY_DETECTED: Forbidden or unexpected property in ${label}`);
    }

    let desc: PropertyDescriptor | undefined;
    try {
      desc = Object.getOwnPropertyDescriptor(obj, key);
    } catch {
      throw new Error(
        `HOSTILE_INPUT_ERROR: Malformed or hostile object descriptor detected in ${label}`,
      );
    }

    if (!desc || desc.get !== undefined || desc.set !== undefined) {
      throw new Error(`HOSTILE_PROPERTY_DETECTED: Accessor properties forbidden in ${label}`);
    }
  }
}

/**
 * Verifies whether an object is a genuine RegistrySnapshot instance
 * created by this framework.
 */
export function isGenuineRegistrySnapshot(val: unknown): val is RegistrySnapshot {
  if (val === null || typeof val !== "object") return false;
  return genuineRegistrySnapshots.has(val);
}

/**
 * Validates an individual RegistryEntryInput descriptor.
 */
function validateEntryInput(rawInput: RegistryEntryInput): RegistryEntryInput {
  assertStrictPlainObject(
    rawInput,
    ["category", "id", "description", "owner_module_id"],
    "RegistryEntryInput",
  );

  let category: unknown;
  let id: unknown;
  let description: unknown;
  let owner_module_id: unknown;

  try {
    category = rawInput.category;
    id = rawInput.id;
    description = rawInput.description;
    owner_module_id = rawInput.owner_module_id;
  } catch {
    throw new Error("MALFORMED_ENTRY: Malformed or hostile entry properties detected");
  }

  if (!isValidRegistryCategory(category)) {
    throw new Error("INVALID_REGISTRY_CATEGORY: Unrecognized or invalid registry category");
  }

  if (typeof id !== "string" || !isCanonicalNamespaceIdentifier(id)) {
    throw new Error("INVALID_REGISTRY_ID: Registry ID must be a canonical namespace identifier");
  }

  if (!isValidRegistryDescription(description)) {
    throw new Error("INVALID_REGISTRY_DESCRIPTION: Invalid or oversized description");
  }

  if (owner_module_id !== undefined) {
    if (typeof owner_module_id !== "string" || !isCanonicalNamespaceIdentifier(owner_module_id)) {
      throw new Error(
        "INVALID_OWNER_MODULE_ID: owner_module_id must be a canonical namespace identifier",
      );
    }
  }

  validateRegistryOwnership(id, category, owner_module_id);

  return {
    category,
    id,
    description,
    ...(owner_module_id !== undefined ? { owner_module_id } : {}),
  };
}

/**
 * Compares two RegistryEntry objects deterministically by composite key {category, id}.
 */
function compareEntries(a: RegistryEntry, b: RegistryEntry): number {
  if (a.category !== b.category) {
    return a.category < b.category ? -1 : 1;
  }
  if (a.id !== b.id) {
    return a.id < b.id ? -1 : 1;
  }
  return 0;
}

/**
 * Helper to construct and freeze a brand-new RegistrySnapshot.
 */
function makeSnapshot(revision: number, entries: readonly RegistryEntry[]): RegistrySnapshot {
  if (!Number.isSafeInteger(revision) || revision < 0) {
    throw new Error("REVISION_OVERFLOW: Registry snapshot revision overflow or out of safe range");
  }

  const sorted = [...entries].sort(compareEntries);
  const frozenEntries = Object.freeze(sorted.map((e) => Object.freeze({ ...e })));

  const snapshot: RegistrySnapshot = Object.freeze({
    revision,
    snapshot_id: `reg-snap-${randomUUID()}`,
    created_at: new Date().toISOString(),
    entries: frozenEntries,
  });

  genuineRegistrySnapshots.add(snapshot);
  return snapshot;
}

/**
 * Creates an initial RegistrySnapshot (revision 0), optionally registering initial entries.
 */
export function createRegistrySnapshot(
  initialEntries?: readonly RegistryEntryInput[],
): RegistrySnapshot {
  if (initialEntries === undefined) {
    return makeSnapshot(0, []);
  }

  if (!Array.isArray(initialEntries)) {
    throw new TypeError("INVALID_INITIAL_ENTRIES: Expected array of RegistryEntryInput");
  }

  let rawLen: unknown;
  try {
    rawLen = initialEntries.length;
  } catch {
    throw new Error("HOSTILE_INPUT_ERROR: Malformed or hostile array access in initialEntries");
  }

  if (typeof rawLen !== "number" || !Number.isSafeInteger(rawLen) || rawLen < 0) {
    throw new TypeError("INVALID_INITIAL_ENTRIES: Expected array of RegistryEntryInput");
  }

  if (rawLen === 0) {
    return makeSnapshot(0, []);
  }

  const rawElements: unknown[] = [];
  try {
    for (const raw of initialEntries) {
      rawElements.push(raw);
    }
  } catch {
    throw new Error("HOSTILE_INPUT_ERROR: Malformed or hostile array access in initialEntries");
  }

  // Validate initial entries atomically
  const now = new Date().toISOString();
  const seenKeys = new Set<string>();
  const createdEntries: RegistryEntry[] = [];

  for (const raw of rawElements) {
    const validated = validateEntryInput(raw as RegistryEntryInput);
    const key = `${validated.category}:${validated.id}`;

    if (seenKeys.has(key)) {
      throw new Error("DUPLICATE_ENTRY_IN_BATCH: Duplicate composite key within entry batch");
    }
    seenKeys.add(key);

    createdEntries.push({
      category: validated.category,
      id: validated.id,
      description: validated.description,
      status: "ACTIVE",
      ...(validated.owner_module_id !== undefined
        ? { owner_module_id: validated.owner_module_id }
        : {}),
      registered_at: now,
      updated_at: now,
    });
  }

  return makeSnapshot(0, createdEntries);
}

/**
 * Registers a batch of new entries into a registry snapshot using copy-on-write semantics.
 * Returns a new frozen RegistrySnapshot with incremented revision.
 * Batch registration is atomic: if any entry is invalid or conflicts, throws error without mutating.
 */
export function registerEntries(
  snapshot: RegistrySnapshot,
  entries: readonly RegistryEntryInput[],
): RegistrySnapshot {
  if (!isGenuineRegistrySnapshot(snapshot)) {
    throw new Error(
      "UNAUTHENTIC_REGISTRY_SNAPSHOT: Function requires a genuine platform-issued RegistrySnapshot",
    );
  }

  if (!Array.isArray(entries)) {
    throw new TypeError("INVALID_ENTRY_BATCH: Expected non-empty array of RegistryEntryInput");
  }

  let rawLen: unknown;
  try {
    rawLen = entries.length;
  } catch {
    throw new Error("HOSTILE_INPUT_ERROR: Malformed or hostile array access in entries");
  }

  if (typeof rawLen !== "number" || !Number.isSafeInteger(rawLen) || rawLen < 0) {
    throw new TypeError("INVALID_ENTRY_BATCH: Expected non-empty array of RegistryEntryInput");
  }

  if (rawLen === 0) {
    throw new TypeError("INVALID_ENTRY_BATCH: Expected non-empty array of RegistryEntryInput");
  }

  const rawElements: unknown[] = [];
  try {
    for (const raw of entries) {
      rawElements.push(raw);
    }
  } catch {
    throw new Error("HOSTILE_INPUT_ERROR: Malformed or hostile array access in entries");
  }

  // Build key map of existing snapshot entries
  const existingMap = new Map<string, RegistryEntry>();
  const retiredIdsInSnapshot = new Set<string>();

  for (const entry of snapshot.entries) {
    const key = `${entry.category}:${entry.id}`;
    existingMap.set(key, entry);
    if (entry.status === "RETIRED") {
      retiredIdsInSnapshot.add(`${entry.category}:${entry.id}`);
    }
  }

  const now = new Date().toISOString();
  const batchKeys = new Set<string>();
  const newEntries: RegistryEntry[] = [];

  // Validate entire batch atomically
  for (const raw of rawElements) {
    const validated = validateEntryInput(raw as RegistryEntryInput);
    const key = `${validated.category}:${validated.id}`;

    if (batchKeys.has(key)) {
      throw new Error("DUPLICATE_ENTRY_IN_BATCH: Duplicate composite key within entry batch");
    }
    batchKeys.add(key);

    if (retiredIdsInSnapshot.has(key)) {
      throw new Error(
        "RETIRED_IDENTITY_REUSE_FORBIDDEN: Cannot re-register a RETIRED entry identity",
      );
    }

    if (existingMap.has(key)) {
      throw new Error("DUPLICATE_ENTRY_DETECTED: Composite key already exists in registry");
    }

    newEntries.push({
      category: validated.category,
      id: validated.id,
      description: validated.description,
      status: "ACTIVE",
      ...(validated.owner_module_id !== undefined
        ? { owner_module_id: validated.owner_module_id }
        : {}),
      registered_at: now,
      updated_at: now,
    });
  }

  const allEntries = [...snapshot.entries, ...newEntries];
  return makeSnapshot(snapshot.revision + 1, allEntries);
}

/**
 * Retrieves a single registry entry by category and id from a snapshot.
 */
export function getRegistryEntry(
  snapshot: RegistrySnapshot,
  category: RegistryCategory,
  id: string,
): RegistryEntry | undefined {
  if (!isGenuineRegistrySnapshot(snapshot)) {
    throw new Error(
      "UNAUTHENTIC_REGISTRY_SNAPSHOT: Function requires a genuine platform-issued RegistrySnapshot",
    );
  }

  if (!isValidRegistryCategory(category)) {
    throw new Error("INVALID_REGISTRY_CATEGORY: Unrecognized or invalid registry category");
  }

  if (!isCanonicalNamespaceIdentifier(id)) {
    throw new Error("INVALID_REGISTRY_ID: Registry ID must be a canonical namespace identifier");
  }

  const key = `${category}:${id}`;
  for (const entry of snapshot.entries) {
    if (`${entry.category}:${entry.id}` === key) {
      return entry;
    }
  }
  return undefined;
}

/**
 * Lists registry entries from a snapshot, optionally filtered by category.
 * Returns a frozen array sorted deterministically by {category, id}.
 */
export function listRegistryEntries(
  snapshot: RegistrySnapshot,
  category?: RegistryCategory,
): readonly RegistryEntry[] {
  if (!isGenuineRegistrySnapshot(snapshot)) {
    throw new Error(
      "UNAUTHENTIC_REGISTRY_SNAPSHOT: Function requires a genuine platform-issued RegistrySnapshot",
    );
  }

  if (category !== undefined && !isValidRegistryCategory(category)) {
    throw new Error("INVALID_REGISTRY_CATEGORY: Unrecognized or invalid registry category");
  }

  if (category === undefined) {
    return snapshot.entries;
  }

  const filtered = snapshot.entries.filter((e) => e.category === category);
  return Object.freeze(filtered);
}

/**
 * Transitions the lifecycle status of an existing entry in a snapshot.
 * Returns a new frozen RegistrySnapshot with incremented revision.
 * Enforces ACTIVE -> DEPRECATED -> RETIRED rules.
 */
export function transitionRegistryEntry(
  snapshot: RegistrySnapshot,
  category: RegistryCategory,
  id: string,
  targetStatus: RegistryEntryStatus,
): RegistrySnapshot {
  if (!isGenuineRegistrySnapshot(snapshot)) {
    throw new Error(
      "UNAUTHENTIC_REGISTRY_SNAPSHOT: Function requires a genuine platform-issued RegistrySnapshot",
    );
  }

  if (!isValidRegistryCategory(category)) {
    throw new Error("INVALID_REGISTRY_CATEGORY: Unrecognized or invalid registry category");
  }

  if (!isCanonicalNamespaceIdentifier(id)) {
    throw new Error("INVALID_REGISTRY_ID: Registry ID must be a canonical namespace identifier");
  }

  if (!isValidRegistryStatus(targetStatus)) {
    throw new Error("INVALID_REGISTRY_STATUS: Unrecognized or invalid target status");
  }

  const key = `${category}:${id}`;
  const exists = snapshot.entries.some((entry) => `${entry.category}:${entry.id}` === key);
  if (!exists) {
    throw new Error("ENTRY_NOT_FOUND: Registry entry not found for transition");
  }
  const now = new Date().toISOString();

  const updatedEntries = snapshot.entries.map((entry) => {
    if (`${entry.category}:${entry.id}` === key) {
      validateRegistryLifecycleTransition(entry.status, targetStatus);
      return Object.freeze({
        ...entry,
        status: targetStatus,
        updated_at: now,
      });
    }
    return entry;
  });

  return makeSnapshot(snapshot.revision + 1, updatedEntries);
}
