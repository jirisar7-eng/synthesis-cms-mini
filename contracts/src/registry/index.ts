/**
 * Synthesis CMS mini — Registry Contract Public Exports
 */

export {
  REGISTRY_CONTRACT_ID,
  REGISTRY_CATEGORIES,
  type RegistryCategory,
  REGISTRY_STATUSES,
  type RegistryEntryStatus,
  MAX_DESCRIPTION_LENGTH,
  type RegistryEntryInput,
  type RegistryEntry,
  type RegistrySnapshot,
  isValidRegistryCategory,
  isValidRegistryStatus,
  isValidRegistryDescription,
  validateRegistryOwnership,
  validateRegistryLifecycleTransition,
} from "./registry.contract.ts";
