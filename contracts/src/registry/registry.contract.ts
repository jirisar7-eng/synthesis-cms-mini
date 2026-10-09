/**
 * Synthesis CMS mini — Registry Framework Contract
 *
 * Defines the immutable contract and interfaces for the Synthesis CMS mini
 * registry framework, supporting seven distinct registry categories.
 *
 * ARCHITECTURAL INVARIANTS:
 * 1. Seven registry categories: module, event, permission, settings, route, ui_extension, provider.
 * 2. Registry categories are distinct from Step 13 NamespaceKind values.
 * 3. Identifiers must satisfy Step 13 canonical namespace grammar.
 * 4. Third-party modules (ext.<publisher>.<module>) cannot escape their namespace or claim unowned prefixes.
 * 5. Registry entries are pure data descriptors (no executable callbacks, metadata bags, or credentials).
 * 6. Entry status lifecycle follow ACTIVE -> DEPRECATED -> RETIRED.
 *    RETIRED entries are permanent tombstones; their IDs cannot be reused.
 */

import { validateNamespaceIdentifier, validateNamespaceRoot } from "../namespace/index.ts";

export const REGISTRY_CONTRACT_ID = "CONTRACT-CORE-REGISTRY-FRAMEWORK-001" as const;

/**
 * The seven distinct registry categories supported by Synthesis CMS mini.
 */
export const REGISTRY_CATEGORIES = Object.freeze([
  "module",
  "event",
  "permission",
  "settings",
  "route",
  "ui_extension",
  "provider",
] as const);

export type RegistryCategory = (typeof REGISTRY_CATEGORIES)[number];

/**
 * Entry lifecycle statuses.
 */
export const REGISTRY_STATUSES = Object.freeze(["ACTIVE", "DEPRECATED", "RETIRED"] as const);

export type RegistryEntryStatus = (typeof REGISTRY_STATUSES)[number];

export const MAX_DESCRIPTION_LENGTH = 512;

/**
 * Input descriptor required to register an entry.
 */
export interface RegistryEntryInput {
  readonly category: RegistryCategory;
  readonly id: string;
  readonly description: string;
  readonly owner_module_id?: string | undefined;
}

/**
 * Immutable registered entry within a registry snapshot.
 */
export interface RegistryEntry {
  readonly category: RegistryCategory;
  readonly id: string;
  readonly description: string;
  readonly status: RegistryEntryStatus;
  readonly owner_module_id?: string | undefined;
  readonly registered_at: string;
  readonly updated_at: string;
}

/**
 * Immutable, versioned registry snapshot.
 */
export interface RegistrySnapshot {
  readonly revision: number;
  readonly snapshot_id: string;
  readonly created_at: string;
  readonly entries: readonly RegistryEntry[];
}

/**
 * Validates whether a value is a valid RegistryCategory.
 */
export function isValidRegistryCategory(cat: unknown): cat is RegistryCategory {
  return typeof cat === "string" && (REGISTRY_CATEGORIES as readonly string[]).includes(cat);
}

/**
 * Validates whether a value is a valid RegistryEntryStatus.
 */
export function isValidRegistryStatus(stat: unknown): stat is RegistryEntryStatus {
  return typeof stat === "string" && (REGISTRY_STATUSES as readonly string[]).includes(stat);
}

/**
 * Validates a registry entry description string.
 */
export function isValidRegistryDescription(desc: unknown): desc is string {
  if (typeof desc !== "string") return false;
  if (desc.length < 1 || desc.length > MAX_DESCRIPTION_LENGTH) return false;
  // Control characters or shell metacharacters rejection
  if (/[\x00-\x1F\x7F;`$()]/.test(desc)) return false;
  return true;
}

/**
 * Validates module ownership rules for registry entries.
 * Enforces third-party namespace isolation (ext.<pub>.<mod>).
 */
export function validateRegistryOwnership(
  id: string,
  category: RegistryCategory,
  ownerModuleId: string,
): void {
  validateNamespaceIdentifier(ownerModuleId);
  validateNamespaceIdentifier(id);

  const { root: ownerRoot, segments: ownerSegments } = validateNamespaceRoot(ownerModuleId);
  if (ownerRoot === "ext" && ownerSegments.length !== 3) {
    throw new Error(
      "INVALID_OWNER_MODULE_ID: Third-party owner module ID must have arity 3 (ext.<publisher>.<module>)",
    );
  }

  if (category === "module") {
    if (id !== ownerModuleId) {
      throw new Error("MODULE_PREFIX_MISMATCH: Module category ID must equal owner_module_id");
    }
    return;
  }

  const requiredPrefix = ownerModuleId + ".";
  if (!id.startsWith(requiredPrefix)) {
    throw new Error("MODULE_PREFIX_MISMATCH: Registry ID must start with owner module prefix");
  }

  if (ownerModuleId.startsWith("ext.")) {
    if (!id.startsWith("ext.")) {
      throw new Error(
        "THIRD_PARTY_ESCAPE: Third-party module cannot declare identifiers outside ext.* namespace",
      );
    }
  }
}

/**
 * Validates status lifecycle transitions for registry entries.
 * Enforces ACTIVE -> DEPRECATED -> RETIRED.
 */
export function validateRegistryLifecycleTransition(
  currentStatus: RegistryEntryStatus,
  targetStatus: RegistryEntryStatus,
): void {
  if (currentStatus === targetStatus) {
    throw new Error("NOOP_STATUS_TRANSITION: Target status is identical to current status");
  }

  if (currentStatus === "ACTIVE" && targetStatus === "DEPRECATED") {
    return; // Valid
  }

  if (currentStatus === "DEPRECATED" && targetStatus === "RETIRED") {
    return; // Valid
  }

  if (currentStatus === "ACTIVE" && targetStatus === "RETIRED") {
    throw new Error(
      "INVALID_LIFECYCLE_TRANSITION: Cannot transition directly from ACTIVE to RETIRED",
    );
  }

  if (currentStatus === "RETIRED") {
    throw new Error(
      "RETIRED_ENTRY_IMMUTABLE: RETIRED entries are permanent tombstones and cannot be changed",
    );
  }

  throw new Error(
    "INVALID_LIFECYCLE_TRANSITION: Reverse or invalid lifecycle transition forbidden",
  );
}
