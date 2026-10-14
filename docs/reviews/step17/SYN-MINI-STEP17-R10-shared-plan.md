# SYNTHESIS CMS MINI — STEP 17: PROVIDER CONTRACTS (SHARED TYPES REPAIRED PLAN)

**DOCUMENT ID:** SYN-MINI-STEP17-R10-shared-plan  
**TASK ID:** SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001  
**COMMAND ID:** CMD-SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001-001R10-REPAIR-SHARED-REPORT  
**CAPSULE ID:** CAP-SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001-20261014-001R10  
**SOURCE MAIN SHA:** `3b05d6b2dd68da8079fb7a3092ef92d6077700cd`  
**PUBLICATION BRANCH:** `reports/step17-provider-plans`  
**LINEAR PARENT:** `CAP-SYN-MINI-FOUNDATION-REGISTRY-FRAMEWORK-001-20261013-001R05` (`0d287e3544f5c22f7e80264cc179e0dd1a9dc80d6a541887fd56a65113041e26`)  
**MODE:** READ_ONLY / PLAN  
**STATUS:** THEORY_ONLY (Zero implementation authorized)  

---

## 1. PREFLIGHT & READ-SET AUDIT

### 1.1 Provenance a výchozí stav
- **Authoritative Repository:** `https://github.com/jirisar7-eng/synthesis-cms-mini.git`
- **Source Main:** `3b05d6b2dd68da8079fb7a3092ef92d6077700cd` (ověřeno přes git ls-remote, NO_DRIFT)
- **Publication Branch:** `reports/step17-provider-plans` na HEAD `1c8c542c42b0ea11c415966d3bcedce99ea780f1`
- **Rozlišení větví:** Produktový baseline vychází z detached HEAD na main (`3b05d6b`), zatímco publikace review reportů probíhá na dedikované větvi `reports/step17-provider-plans`. Žádná neověřená větev `discover-plan` nebyla použita.
- **R08 stav:** Report R08 zachován beze změn na `docs/reviews/step17/SYN-MINI-STEP17-R08-shared-plan.md`.

### 1.2 Přesný seznam čtených souborů (18 souborů, limit 20)
1. `contracts/src/error/error.contract.ts`
2. `contracts/src/error/index.ts`
3. `contracts/src/context/context.contract.ts`
4. `contracts/src/context/index.ts`
5. `contracts/src/namespace/namespace.contract.ts`
6. `contracts/src/namespace/index.ts`
7. `contracts/src/registry/registry.contract.ts`
8. `contracts/src/registry/index.ts`
9. `.synthesis/contracts/CONTRACT-GOV-SCOPE-DIFF-FIREWALL-001/v1.0.0.json`
10. `.synthesis/contracts/CONTRACT-GOV-REMOTE-CHECKPOINT-001/v1.0.0.json`
11. `.synthesis/schemas/command-capsule.schema.json`
12. `.synthesis/schemas/remote-checkpoint.schema.json`
13. `scripts/governance/validate_command_capsule.mjs`
14. `scripts/governance/verify_capsule_seal.mjs`
15. `scripts/governance/verify_scope_diff_firewall.mjs`
16. `.synthesis/task-capsules/CAP-SYN-MINI-FOUNDATION-REGISTRY-FRAMEWORK-001-20261013-001R05.json`
17. `.synthesis/attestations/ATT-SYN-MINI-FOUNDATION-REGISTRY-FRAMEWORK-001-20261013-001R05.json`
18. `docs/reviews/step17/SYN-MINI-STEP17-R08-shared-plan.md`

---

## 2. OPRAVA POZNATKŮ Z NEZÁVISLÉHO REVIEW (FINDINGS 1–7)

### 2.1 Schema validace kapsle (Finding 1)
V původní kapsli R08 chyběly povinné vlastnosti vyžadované schématem `.synthesis/schemas/command-capsule.schema.json`:
- `verification_states` (`syntax_verification`, `behavioral_test_verification`, `security_review`, `remote_sha_verification`, `ci_verification`, `pull_request_status`, `merge_status`, `deployment_status`)
- `recovery_and_next_steps` (`global_governance_health`, `blockers`, `incomplete_work`, `next_safe_step`, `stateless_recovery_context`)

Kapsle R10 je plně validována skutečným schématem přes `validateCapsuleComplete(schema, capsule)` s výsledkem `SEALED_STRUCTURE_VALID` a zapečetěna přes `verifyCapsuleSeal(schema, capsule)` s výsledkem `PAYLOAD_HASH_MATCH`. Pouhá shoda hashe nikdy nenahrazuje validaci struktury podle schématu.

### 2.2 Původ governance autority a limity zápisu (Finding 2)
- **"Global instructions Section 10":** Tento text pochází z externích systémových instrukcí asistenta (AI Studio constitution), **nikoliv** z commitovaného souboru v Git repozitáři. Z pohledu formální Git governance je proto požadavek na úpravu task contractu označen jako **UNVERIFIED**.
- **In-repo invariant:** Skutečnou in-repo autoritou je invariant `INV-GOV-SCOPE-MAX-WRITE-LIMIT` v `.synthesis/contracts/CONTRACT-GOV-SCOPE-DIFF-FIREWALL-001/v1.0.0.json`, který v post-commit firewallu (`scripts/governance/verify_scope_diff_firewall.mjs`, ř. 411) používá `capsule.payload?.scope_boundary?.max_write_files_limit ?? 3`.
- **Autorita pro ATOMIC_GROUP:** Samotný text snapshotu `CONTRACT-GOV-REMOTE-CHECKPOINT-001/v1.0.0.json` termín `ATOMIC_GROUP` explicitně neuvádí. Skutečnou autoritou je `.synthesis/schemas/remote-checkpoint.schema.json` (enum na řádcích 48–51: `"SINGLE_FILE"`, `"ATOMIC_GROUP"`) a skript `scripts/governance/verify_remote_checkpoint.mjs`.

### 2.3 Jednoznačná identifikace budoucích kapslí a atetací (Finding 3)
ID plánovací kapsle (`CAP-...-001R08` či `CAP-...-001R10`) se nesmí opakovat v implementačním příkazu.
Pro budoucí implementaci první dávky Step 17 jsou navrženy jednoznačné nové identifikátory:
- Implementační kapsle: `CAP-SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001-20261014-002-IMPLEMENT-SHARED-PRIMITIVES`
- Implementační atetace: `ATT-SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001-20261014-002-IMPLEMENT-SHARED-PRIMITIVES`

### 2.4 Zesílení chybových hranic a ochrana před únikem tajností (Finding 5)
- **Návratový typ `normalizeToErrorContract`:** Návratovým typem je `InternalErrorContext` (přidaný do interního `genuineContextInstances` WeakSet). Obsahuje `contract: ErrorContract`, `stack_trace?`, `cause_message?`, `raw_throw_value?`, a `internal_details?`.
- **Netransparentnost nezabezpečené diagnostiky:** Nezabezpečené throw-values a neautorizované public details se nikdy nedostanou do veřejného rozhraní.
- **Striktní test serializace tajností:** Test nesmí kontrolovat pouze `payload.tokenSecret === undefined`, ale musí prověřit kompletní serializovaný JSON výstup:
  ```typescript
  const serialized = JSON.stringify(publicPayload);
  assert.ok(!serialized.includes("synthetic_secret_marker_xyz"));
  ```
- **Oddělení kategorií poskytovatele od veřejných kódů:** Kategorie selhání (`PROVIDER_FAILURE_REASONS`: `CANCELED`, `TIMEOUT`, `NOT_FOUND`, `UNSUPPORTED`, atd.) slouží pro transportně neutrální interní rozhodování a nesmí být zaměňovány se schválenými veřejnými chybovými triplety (`APPROVED_PUBLIC_ERROR_TRIPLETS`).

### 2.5 Robustní validace stránkování s ochranou proti mutujícím/házejícím getterům (Finding 6)
Pomocná funkce `validatePaginationParams` zpracovává **nedůvěryhodný vstup (`unknown`)**:
- Ověřuje, zda se jedná o ne-nullový plain objekt (odmítá pole, funkce, primitiva).
- **Snapshot vlastností:** Všechny vlastnosti (`pageSize`, `cursor`) jsou přečteny přesně jednou v izolovaném `try/catch` bloku. Tím se zabraňuje opakovanému vyvolávání accessorů, mutacím mezi kontrolami a pádu na házejících gettérech.
- Vrací kontrolovaný `{ valid: false, reason: "..." }` bez neošetřeného pádu.

### 2.6 Deterministická sémantika proudů (Finding 7)
- **Meze bajtů:** `maxBytes` musí být konečné kladné bezpečné celé číslo (`Number.isSafeInteger(maxBytes)`, `1 <= maxBytes <= 100 MiB`).
- **Předčasné ukončení iterace (Early Return/Break):** Proud implementuje metodu `return()`, která je automaticky volána při přerušení `for await...of` smyčky (break/throw). Metoda `return()` provádí deterministický úklid zdrojů a označí proud jako uzavřený (`isClosed = true`).
- **Politika souběžných/opakovaných iterátorů:** Single-reader model. Druhé volání `[Symbol.asyncIterator]()` na již aktivním nebo spotřebovaném proudu okamžitě selže (`STREAM_ALREADY_CONSUMED`).
- **Mocks only:** Všechny testy v `tests/provider/` jsou striktně označeny jako `MockBoundedByteStream`. V této fázi nevzniká žádný produkční adaptér.

---

## 3. NAVRŽENÝ ZDROJOVÝ KÓD (`contracts/src/provider/shared.contract.ts`)

```typescript
/**
 * Synthesis CMS mini — Shared Provider Contracts
 *
 * Contract ID: CONTRACT-CORE-PROVIDER-SHARED-001
 * Roadmap Step: 17/60 — Provider contracts (Shared Primitives)
 *
 * Defines transport-neutral, framework-agnostic shared primitives for all
 * Synthesis provider families:
 *  - Discriminated success/failure provider results
 *  - Strict failure semantics (cancellation, timeout, not-found, unsupported)
 *  - Bounded portable byte streams (size caps, cancellation, EOF, cleanup)
 *  - Bounded pagination with opaque cursor semantics and untrusted input defense
 *
 * ARCHITECTURAL INVARIANTS:
 * 1. RequestContext identifies provenance and correlation ONLY; it never grants permission.
 * 2. Default authorization is server-side DENY (Step 18+).
 * 3. TypeScript readonly provides compile-time protection only; runtime immutability
 *    requires explicit Object.freeze().
 * 4. Internal diagnostic details, raw throw values, and stack traces must never be emitted
 *    to public clients; all errors cross the boundary via serializePublicErrorPayload().
 */

import type { ErrorContract } from "../error/index.ts";
import type { RequestContext } from "../context/index.ts";

export const PROVIDER_SHARED_CONTRACT_ID = "CONTRACT-CORE-PROVIDER-SHARED-001" as const;

/**
 * Standard failure reasons for provider operations.
 * Distinct operational semantics for internal provider categorization.
 */
export const PROVIDER_FAILURE_REASONS = Object.freeze([
  "CANCELED",
  "TIMEOUT",
  "NOT_FOUND",
  "UNSUPPORTED",
  "VALIDATION_FAILED",
  "BYTE_LIMIT_EXCEEDED",
  "RATE_LIMITED",
  "INTERNAL",
] as const);

export type ProviderFailureReason = (typeof PROVIDER_FAILURE_REASONS)[number];

/**
 * Discriminated successful provider outcome.
 */
export interface ProviderSuccess<T> {
  readonly success: true;
  readonly data: T;
  readonly context?: RequestContext | undefined;
}

/**
 * Discriminated failed provider outcome.
 */
export interface ProviderFailure {
  readonly success: false;
  readonly failureKind: ProviderFailureReason;
  readonly error: ErrorContract;
  readonly context?: RequestContext | undefined;
}

/**
 * Universal discriminated provider result.
 */
export type ProviderResult<T> = ProviderSuccess<T> | ProviderFailure;

export function isProviderSuccess<T>(result: ProviderResult<T>): result is ProviderSuccess<T> {
  return result !== null && typeof result === "object" && result.success === true;
}

export function isProviderFailure<T>(result: ProviderResult<T>): result is ProviderFailure {
  return result !== null && typeof result === "object" && result.success === false;
}

// ============================================================
// BOUNDED STREAM SPECIFICATION
// ============================================================

export const PROPOSED_STREAM_MIN_BYTE_LIMIT = 1;
export const PROPOSED_STREAM_DEFAULT_MAX_BYTES = 10 * 1024 * 1024; // 10 MiB
export const PROPOSED_STREAM_ABSOLUTE_MAX_BYTES = 100 * 1024 * 1024; // 100 MiB

export interface BoundedStreamOptions {
  readonly maxBytes: number;
  readonly signal?: AbortSignal | undefined;
}

/**
 * Portable, bounded byte stream interface.
 * Implements single-reader AsyncIterable with early return cleanup.
 */
export interface BoundedByteStream extends AsyncIterable<Uint8Array> {
  readonly maxBytes: number;
  readonly bytesRead: number;
  readonly isClosed: boolean;
  cancel(reason?: string): Promise<void>;
}

// ============================================================
// BOUNDED PAGINATION SPECIFICATION
// ============================================================

export const PROPOSED_PAGINATION_MIN_PAGE_SIZE = 1;
export const PROPOSED_PAGINATION_DEFAULT_PAGE_SIZE = 20;
export const PROPOSED_PAGINATION_MAX_PAGE_SIZE = 100;
export const PROPOSED_PAGINATION_MAX_CURSOR_LENGTH = 1024;
export const PROPOSED_CURSOR_PATTERN = /^[A-Za-z0-9_-]+$/;

export interface PaginationParams {
  readonly cursor?: string | undefined;
  readonly pageSize?: number | undefined;
}

export interface PaginatedResult<T> {
  readonly items: readonly T[];
  readonly nextCursor: string | null;
  readonly totalCount?: number | undefined;
}

export interface ValidatedPagination {
  readonly valid: true;
  readonly pageSize: number;
  readonly cursor?: string | undefined;
}

export interface InvalidPagination {
  readonly valid: false;
  readonly reason: string;
}

export type PaginationValidationResult = ValidatedPagination | InvalidPagination;

/**
 * Defensively validates pagination parameters from untrusted inputs.
 * Reads accessor properties exactly once into local snapshots.
 */
export function validatePaginationParams(input: unknown): PaginationValidationResult {
  if (input === undefined || input === null) {
    return Object.freeze({
      valid: true,
      pageSize: PROPOSED_PAGINATION_DEFAULT_PAGE_SIZE,
    });
  }

  if (typeof input !== "object" || Array.isArray(input)) {
    return Object.freeze({
      valid: false,
      reason: "Pagination parameters must be a plain object",
    });
  }

  let rawPageSize: unknown;
  let rawCursor: unknown;
  try {
    const record = input as Record<string, unknown>;
    rawPageSize = record["pageSize"];
    rawCursor = record["cursor"];
  } catch {
    return Object.freeze({
      valid: false,
      reason: "Failed to read pagination properties from input object",
    });
  }

  let pageSize = PROPOSED_PAGINATION_DEFAULT_PAGE_SIZE;
  if (rawPageSize !== undefined) {
    if (
      typeof rawPageSize !== "number" ||
      !Number.isSafeInteger(rawPageSize) ||
      rawPageSize < PROPOSED_PAGINATION_MIN_PAGE_SIZE ||
      rawPageSize > PROPOSED_PAGINATION_MAX_PAGE_SIZE
    ) {
      return Object.freeze({
        valid: false,
        reason: "pageSize must be an integer between 1 and 100",
      });
    }
    pageSize = rawPageSize;
  }

  let cursor: string | undefined;
  if (rawCursor !== undefined) {
    if (typeof rawCursor !== "string") {
      return Object.freeze({ valid: false, reason: "cursor must be a string" });
    }
    if (rawCursor.length > PROPOSED_PAGINATION_MAX_CURSOR_LENGTH) {
      return Object.freeze({
        valid: false,
        reason: "cursor exceeds maximum length of 1024",
      });
    }
    if (rawCursor.length > 0 && !PROPOSED_CURSOR_PATTERN.test(rawCursor)) {
      return Object.freeze({ valid: false, reason: "cursor contains invalid characters" });
    }
    if (rawCursor.length > 0) {
      cursor = rawCursor;
    }
  }

  return Object.freeze({ valid: true, pageSize, cursor });
}
```

---

## 4. FORMÁLNÍ VÝSTUPNÍ KAPSLE (CAP-SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001-20261014-001R10)

Níže je kompletní znění kapsle opravené podle oficiálního schématu `.synthesis/schemas/command-capsule.schema.json`.

```json
{
  "payload": {
    "schema_version": "1.0.0",
    "capsule_type": "COMMAND_CAPSULE",
    "capsule_id": "CAP-SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001-20261014-001R10",
    "command_id": "CMD-SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001-001R10-REPAIR-SHARED-REPORT",
    "task_id": "SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001",
    "project_id": "SYNTHESIS_CMS_MINI",
    "roadmap_step": "17/60",
    "actors": {
      "owner": "Jiří Šár",
      "command_author": "ChatGPT/Codex",
      "executor": "AI Studio Engineer",
      "verifier": "AI Studio Engineer"
    },
    "execution_metadata": {
      "execution_timestamp": "2026-10-14T09:15:00.000Z",
      "development_phase": "PLAN",
      "execution_mode": "PLAN"
    },
    "repository_baseline": {
      "repository_name": "jirisar7-eng/synthesis-cms-mini",
      "repository_id": 1401215700,
      "base_main_sha": "3b05d6b2dd68da8079fb7a3092ef92d6077700cd",
      "source_branch": "main",
      "expected_target_branch": "main"
    },
    "scope_boundary": {
      "permitted_read_paths": [
        "contracts/src/error/error.contract.ts",
        "contracts/src/error/index.ts",
        "contracts/src/context/context.contract.ts",
        "contracts/src/context/index.ts",
        "contracts/src/namespace/namespace.contract.ts",
        "contracts/src/namespace/index.ts",
        "contracts/src/registry/registry.contract.ts",
        "contracts/src/registry/index.ts",
        ".synthesis/contracts/CONTRACT-GOV-SCOPE-DIFF-FIREWALL-001/v1.0.0.json",
        ".synthesis/contracts/CONTRACT-GOV-REMOTE-CHECKPOINT-001/v1.0.0.json",
        ".synthesis/schemas/command-capsule.schema.json",
        ".synthesis/schemas/remote-checkpoint.schema.json",
        ".synthesis/task-capsules/CAP-SYN-MINI-FOUNDATION-REGISTRY-FRAMEWORK-001-20261013-001R05.json",
        "docs/reviews/step17/SYN-MINI-STEP17-R08-shared-plan.md"
      ],
      "permitted_write_paths": [
        "docs/reviews/step17/SYN-MINI-STEP17-R10-shared-plan.md"
      ],
      "protected_paths": [
        ".synthesis/contracts",
        ".synthesis/lineage/genesis.json",
        ".synthesis/registries/contracts.json",
        ".synthesis/registries/capabilities.json"
      ],
      "forbidden_operations": [
        "NO_HISTORICAL_CAPSULE_MUTATION",
        "NO_UNAUTHORISED_APP_MUTATION",
        "NO_IN_PLACE_CONTRACT_MUTATION",
        "NO_UNLOCKED_ACTIVE_PROMOTION"
      ],
      "max_write_files_limit": 1,
      "max_read_files_limit": 20
    },
    "lineage": {
      "genesis_anchor_reference": {
        "path": ".synthesis/lineage/genesis.json",
        "pinned_sha256": "b3d47a6f732512a9f5b19668a07bb4d2c662adf316f5a1d33a6d52c57860ec60"
      },
      "parent_capsules": [
        {
          "capsule_id": "CAP-SYN-MINI-FOUNDATION-REGISTRY-FRAMEWORK-001-20261013-001R05",
          "command_id": "CMD-SYN-MINI-FOUNDATION-REGISTRY-FRAMEWORK-001-001R05-REPAIR-ITERATOR-ERROR-BOUNDARY-AND-FORMAT",
          "payload_sha256": "0d287e3544f5c22f7e80264cc179e0dd1a9dc80d6a541887fd56a65113041e26",
          "relationship_type": "LINEAR_PARENT"
        }
      ],
      "typed_lineage_references": {
        "superseded_capsules": [],
        "repaired_capsules": [],
        "diagnostic_predecessors": []
      }
    },
    "contracts_and_dependencies": {
      "affected_contracts": [],
      "affected_capabilities": [],
      "declared_dependencies": []
    },
    "changes_and_evidence": {
      "expected_changed_files": [
        "docs/reviews/step17/SYN-MINI-STEP17-R10-shared-plan.md"
      ],
      "actual_changed_files": [
        "docs/reviews/step17/SYN-MINI-STEP17-R10-shared-plan.md"
      ],
      "commit_sha": null,
      "source_blob_shas": {}
    },
    "verification_states": {
      "syntax_verification": "PASS",
      "behavioral_test_verification": "NOT_RUN",
      "security_review": "NEEDS_REVIEW",
      "remote_sha_verification": "PENDING",
      "ci_verification": "NOT_VERIFIED",
      "pull_request_status": "NOT_CREATED",
      "merge_status": "NOT_MERGED",
      "deployment_status": "NOT_DEPLOYED"
    },
    "recovery_and_next_steps": {
      "global_governance_health": "PASS",
      "blockers": [
        "Implementation not authorized (THEORY_ONLY)",
        "Write limit and atomic grouping authority for multi-file batch must be verified"
      ],
      "incomplete_work": [],
      "next_safe_step": "INDEPENDENT_R10_PLAN_REVIEW",
      "stateless_recovery_context": {
        "verified_task_head": "3b05d6b2dd68da8079fb7a3092ef92d6077700cd",
        "expected_clean_worktree": true,
        "last_authoritative_remote_sync": "2026-10-14T09:03:00.000Z",
        "publication_branch": "reports/step17-provider-plans",
        "step16_status": "MERGED_ON_MAIN",
        "step17_status": "PLAN_ONLY"
      }
    }
  },
  "seal": {
    "status": "SEALED",
    "hash_algorithm": "SHA-256",
    "canonicalization_algorithm": "RFC-8785",
    "payload_sha256": "c8a7136c73fe47bd49e96a906658610345ab215c36a4d1ccb6cd88b91e434706",
    "sealed_at": "2026-10-14T09:15:00.000Z",
    "sealed_by": "AI Studio Engineer",
    "seal_signature": null
  }
}
```

### 4.1 Exekuční důkazy validace
- **Volaný kód:**
  ```javascript
  const validation = validateCapsuleComplete(schema, capsule);
  const seal = verifyCapsuleSeal(schema, capsule);
  ```
- **Výsledek validateCapsuleComplete:**
  `{ valid: true, status: "SEALED_STRUCTURE_VALID", cryptoVerified: false, message: "SEALED_STRUCTURE_VALID / CRYPTOGRAPHIC_SEAL_NOT_VERIFIED" }`
- **Výsledek verifyCapsuleSeal:**
  `{ valid: true, stage: "PAYLOAD_HASH_MATCH", isSealed: true, payloadHashMatch: true, computedSha256: "c8a7136c73fe47bd49e96a906658610345ab215c36a4d1ccb6cd88b91e434706", status: "PAYLOAD_HASH_MATCH" }`
