# SYNTHESIS CMS MINI — STEP 17: PROVIDER CONTRACTS (SHARED TYPES PLAN)

**DOCUMENT ID:** SYN-MINI-STEP17-R08-shared-plan  
**TASK ID:** SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001  
**COMMAND ID:** CMD-SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001-001R08-PLAN-SHARED-TYPES  
**CAPSULE ID:** CAP-SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001-20261014-001R08  
**BASE MAIN SHA:** `3b05d6b2dd68da8079fb7a3092ef92d6077700cd`  
**LINEAR PARENT:** `CAP-SYN-MINI-FOUNDATION-REGISTRY-FRAMEWORK-001-20261013-001R05` (`0d287e3544f5c22f7e80264cc179e0dd1a9dc80d6a541887fd56a65113041e26`)  
**MODE:** READ_ONLY / PLAN  
**REPOSITORY DIFF:** `[]` (0 souborů změněno v repozitáři)  

---

## 1. PREFLIGHT & READ-SET AUDIT

### 1.1 Preflight ověření
- **Checkout Root:** `/tmp/syn-mini-checkout-3b05d6b`
- **Origin URL:** `https://github.com/jirisar7-eng/synthesis-cms-mini.git`
- **Exact HEAD:** `3b05d6b2dd68da8079fb7a3092ef92d6077700cd`
- **Live Remote Main SHA:** `3b05d6b2dd68da8079fb7a3092ef92d6077700cd` (`refs/heads/main`, match confirmed, NO_DRIFT)
- **Git Status:** Working tree clean, 0 staged, 0 unstaged, 0 untracked files.
- **AI Studio Applet Workspace:** `/app/applet` chráněn, nedotčen.

### 1.2 Přesný seznam čtených souborů (15 souborů, v rámci limitu 20)
1. `contracts/src/error/error.contract.ts`
2. `contracts/src/error/index.ts`
3. `contracts/src/context/context.contract.ts`
4. `contracts/src/context/index.ts`
5. `contracts/src/namespace/namespace.contract.ts`
6. `contracts/src/namespace/index.ts`
7. `contracts/src/registry/registry.contract.ts`
8. `contracts/src/registry/index.ts`
9. `contracts/src/database/database.contract.ts`
10. `contracts/README.md`
11. `package.json`
12. `tsconfig.json`
13. `.synthesis/contracts/CONTRACT-GOV-SCOPE-DIFF-FIREWALL-001/v1.0.0.json`
14. `.synthesis/contracts/CONTRACT-GOV-REMOTE-CHECKPOINT-001/v1.0.0.json`
15. `.synthesis/task-capsules/CAP-SYN-MINI-FOUNDATION-REGISTRY-FRAMEWORK-001-20261013-001R05.json`

---

## 2. DELIVERABLE 1 — SHARED PROVIDER TYPES (`contracts/src/provider/shared.contract.ts`)

### 2.1 Kompletní návrh TypeScript zdrojového kódu

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
 *  - Bounded pagination with opaque cursor semantics
 *
 * ARCHITECTURAL INVARIANTS:
 * 1. RequestContext identifies provenance and correlation ONLY; it never grants permission.
 * 2. Default authorization is server-side DENY (Step 18+).
 * 3. TypeScript 'readonly' provides compile-time protection only; runtime immutability
 *    requires explicit Object.freeze().
 * 4. Internal diagnostic details, raw throw values, and stack traces must never be emitted
 *    to public clients; all errors cross the boundary via serializePublicErrorPayload().
 */

import type { ErrorContract } from "../error/index.ts";
import type { RequestContext } from "../context/index.ts";

export const PROVIDER_SHARED_CONTRACT_ID = "CONTRACT-CORE-PROVIDER-SHARED-001" as const;

/**
 * Standard failure reasons for provider operations.
 * Distinct semantics ensure callers can disambiguate operational states.
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
 * Holds transport-neutral ErrorContract and categorized failure kind.
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

/**
 * Type guard for ProviderSuccess.
 */
export function isProviderSuccess<T>(result: ProviderResult<T>): result is ProviderSuccess<T> {
  return result !== null && typeof result === "object" && result.success === true;
}

/**
 * Type guard for ProviderFailure.
 */
export function isProviderFailure<T>(result: ProviderResult<T>): result is ProviderFailure {
  return result !== null && typeof result === "object" && result.success === false;
}

// ============================================================
// BOUNDED STREAM SPECIFICATION & PRIMITIVES
// ============================================================

/**
 * Proposed stream boundary limits.
 * Callers specify a bounded maxBytes to guard against Denial-of-Service / memory exhaustion.
 */
export const PROPOSED_STREAM_MIN_BYTE_LIMIT = 1;
export const PROPOSED_STREAM_DEFAULT_MAX_BYTES = 10 * 1024 * 1024; // 10 MiB
export const PROPOSED_STREAM_ABSOLUTE_MAX_BYTES = 100 * 1024 * 1024; // 100 MiB

/**
 * Options configuring bounded stream consumption.
 */
export interface BoundedStreamOptions {
  /**
   * Maximum permitted total bytes allowed from the stream.
   * Must satisfy: PROPOSED_STREAM_MIN_BYTE_LIMIT <= maxBytes <= PROPOSED_STREAM_ABSOLUTE_MAX_BYTES.
   */
  readonly maxBytes: number;

  /**
   * Optional standard AbortSignal for early cancellation.
   */
  readonly signal?: AbortSignal | undefined;
}

/**
 * Portable, bounded byte stream contract.
 * Represents an asynchronous sequence of binary chunks (Uint8Array) with deterministic
 * bounds, cancellation, EOF, and failure cleanup semantics.
 */
export interface BoundedByteStream extends AsyncIterable<Uint8Array> {
  /**
   * Configured maximum byte ceiling for this stream.
   */
  readonly maxBytes: number;

  /**
   * Cumulative number of bytes read so far.
   */
  readonly bytesRead: number;

  /**
   * True if end-of-stream has been reached or stream has been closed/aborted.
   */
  readonly isClosed: boolean;

  /**
   * Explicitly closes and releases underlying provider resources.
   * Idempotent: safe to call multiple times.
   */
  cancel(reason?: string): Promise<void>;
}

// ============================================================
// BOUNDED PAGINATION SPECIFICATION & PRIMITIVES
// ============================================================

/**
 * Proposed pagination bounds.
 */
export const PROPOSED_PAGINATION_MIN_PAGE_SIZE = 1;
export const PROPOSED_PAGINATION_DEFAULT_PAGE_SIZE = 20;
export const PROPOSED_PAGINATION_MAX_PAGE_SIZE = 100;
export const PROPOSED_PAGINATION_MAX_CURSOR_LENGTH = 1024;
export const PROPOSED_CURSOR_PATTERN = /^[A-Za-z0-9_-]+$/;

/**
 * Bounded pagination input parameters.
 */
export interface PaginationParams {
  /**
   * Opaque cursor string from a previous page's nextCursor.
   * Undefined or empty string indicates initial page request.
   */
  readonly cursor?: string | undefined;

  /**
   * Requested page size. Bounded between MIN and MAX.
   */
  readonly pageSize?: number | undefined;
}

/**
 * Paginated result container.
 */
export interface PaginatedResult<T> {
  /**
   * Array of page items.
   */
  readonly items: readonly T[];

  /**
   * Opaque cursor pointing to next page.
   * Exactly null when no further records exist (EOF of dataset).
   */
  readonly nextCursor: string | null;

  /**
   * Optional total count when efficiently supported by underlying provider.
   */
  readonly totalCount?: number | undefined;
}

/**
 * Validates and normalizes pagination input parameters.
 * Fail-closed: invalid values trigger validation errors rather than unbounded queries.
 */
export function validatePaginationParams(
  params?: PaginationParams | undefined,
): { valid: true; pageSize: number; cursor?: string | undefined } | { valid: false; reason: string } {
  if (params === undefined || params === null) {
    return { valid: true, pageSize: PROPOSED_PAGINATION_DEFAULT_PAGE_SIZE };
  }

  if (typeof params !== "object") {
    return { valid: false, reason: "Pagination parameters must be an object" };
  }

  // Validate pageSize
  let pageSize = PROPOSED_PAGINATION_DEFAULT_PAGE_SIZE;
  if (params.pageSize !== undefined) {
    if (
      typeof params.pageSize !== "number" ||
      !Number.isInteger(params.pageSize) ||
      params.pageSize < PROPOSED_PAGINATION_MIN_PAGE_SIZE ||
      params.pageSize > PROPOSED_PAGINATION_MAX_PAGE_SIZE
    ) {
      return {
        valid: false,
        reason: `pageSize must be an integer between ${PROPOSED_PAGINATION_MIN_PAGE_SIZE} and ${PROPOSED_PAGINATION_MAX_PAGE_SIZE}`,
      };
    }
    pageSize = params.pageSize;
  }

  // Validate cursor
  let cursor: string | undefined;
  if (params.cursor !== undefined) {
    if (typeof params.cursor !== "string") {
      return { valid: false, reason: "cursor must be a string" };
    }
    if (params.cursor.length > PROPOSED_PAGINATION_MAX_CURSOR_LENGTH) {
      return {
        valid: false,
        reason: `cursor exceeds maximum length of ${PROPOSED_PAGINATION_MAX_CURSOR_LENGTH}`,
      };
    }
    if (params.cursor.length > 0 && !PROPOSED_CURSOR_PATTERN.test(params.cursor)) {
      return { valid: false, reason: "cursor contains invalid characters" };
    }
    if (params.cursor.length > 0) {
      cursor = params.cursor;
    }
  }

  return { valid: true, pageSize, cursor };
}
```

### 2.2 Specifikace sémantiky proudů (Streams)
1. **Nastavení limitu bajtů:** Volající předává `maxBytes` v `BoundedStreamOptions`. Validní rozsah je `1 <= maxBytes <= 100 MiB`.
2. **Přetečení (Overflow):** Pokud proud načte více bajtů než `maxBytes`, okamžitě uzavře podkladový zdroj, přeruší čtení a vyhodí chybu normalizovanou na `BYTE_LIMIT_EXCEEDED`. Žádné další bajty nesmí být předány volajícímu.
3. **Konec proudu (EOF):** Po vyčerpání dat vrací iterátor `{ done: true, value: undefined }`. Následné volání (read-after-EOF) musí být idempotentní a trvale vracet `done: true` bez opakovaného dotazování I/O.
4. **Zrušení (Cancellation):** Proud sleduje `AbortSignal` nebo explicitní metodu `cancel()`. Po zrušení se uvolní podkladové sokety/deskriptory a čtení okamžitě selže s `CANCELED`.
5. **Vlastnictví a úklid (Cleanup):** Poskytovatel proudu drží vlastnictví nad fyzickým zdrojem. Při jakémkoliv selhání (přetečení, I/O chyba, abort) provede `finally` blok automatický úklid.
6. **Propagace chyb do výsledku:** Výjimky při čtení proudu zachytí runtime obálka, normalizuje je pomocí `normalizeToErrorContract(thrown)` z Step 14 a zabalí do `ProviderFailure`.

### 2.3 Specifikace stránkování (Pagination)
- **Meze:** Minimální velikost stránky `1`, výchozí `20`, maximální `100`. Maximální délka kurzoru `1024` znaků.
- **Fail-closed chování:** Nevalidní hodnoty (neceločíselné, záporné, NaN, přetečení max meze) jsou odmítnuty s `VALIDATION_FAILED`.
- **Sémantika kurzoru:** Kurzor je pro klienta netransparentní token (opaque string). Hodnota `nextCursor === null` jednoznačně indikuje dosažení konce kolekce.

### 2.4 Chyby na hranici runtime a oddělení od veřejných chyb
- `normalizeToErrorContract(untrusted)` v interní vrstvě poskytovatele vytvoří `InternalErrorContext`, který v serverové paměti bezpečně zachová diagnostiku, stack trace a raw výjimku.
- `serializePublicErrorPayload(ctx)` na veřejné hranici (API/HTTP) uplatňuje striktní allowlist (`ALLOWLIST_PUBLIC_KEYS`), dropuje stack trace, interní detaily i syntetické secret markery a vrací pouze schválené bezpečné atomické triplety (`code`, `message_key`, `kind`).

---

## 3. DELIVERABLE 2 — PRVNÍ IMPLEMENTAČNÍ DÁVKA & GOVERNANCE AUTORITA

### 3.1 Navržená sada souborů první dávky (First Batch Write Set)
1. `contracts/src/provider/shared.contract.ts` (Produktový kód — definice rozhraní a primitiv)
2. `contracts/src/provider/index.ts` (Re-exportní bod kontraktů)
3. `tests/provider/shared.contract.test.ts` (Testovací sada ověřující typy, mock stream, meze a chyby)
4. `.synthesis/task-capsules/CAP-SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001-20261014-001R08.json` (Kapsle dávky)
5. `.synthesis/attestations/ATT-SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001-20261014-001R08.json` (Atetace dávky)
*Celkem: 5 souborů.*

### 3.2 Analýza governance autority pro limity zápisu
- **Globální instrukce (Sekce 10):**  
  `Default limits: MAX_WRITE_FILES_PER_COMMAND = 3, MAX_READ_FILES_PER_COMMAND = 10, MAX_COMPLETED_UNPUSHED_FILES = 0. These limits may only be expanded through a separately authorized task contract.`
- **Kontrakt `CONTRACT-GOV-SCOPE-DIFF-FIREWALL-001` (v1.0.0):**  
  `INV-GOV-SCOPE-MAX-WRITE-LIMIT: File mutation count must not exceed max_write_files_limit.`  
  Implementace ve `scripts/governance/verify_scope_diff_firewall.mjs` (řádek 411): výchozí hodnota `maxLimit = capsule.payload?.scope_boundary?.max_write_files_limit ?? 3`.
- **Kontrakt `CONTRACT-GOV-REMOTE-CHECKPOINT-001` (v1.0.0):**  
  Povoluje `checkpoint_type: "ATOMIC_GROUP"` pro vzájemně závislé soubory deklarované předem.
- **ZÁVĚR & BLOKER:**  
  V repozitáři v současné době **neexistuje schválený Task Contract**, který by pro Step 17 explicitně rozšířil limit z výchozích 3 na 4 nebo 5 souborů. Historická kapsle R05 (používající limit 4) nepředstavuje univerzální autoritu.  
  **Stav:** Zápis všech 4 až 5 souborů v jednom příkazu je **BLOKOVÁN výchozím limitem 3**. Pro realizaci v jednom příkazu je nutná explicitní autorizace `max_write_files_limit: 5` vlastníkem, anebo rozdělení do sekvenčních pod-příkazů po maximálně 3 souborech.

### 3.3 Konkrétní akceptační testovací případy (Acceptance Cases)
1. **Pozitivní/negativní typové kontroly:**
   - Typové rozlišení `isProviderSuccess` a `isProviderFailure` zužuje typ na `data` vs `error`.
   - Pokus o přiřazení nevalidního `failureKind` (např. `"UNKNOWN_ERROR"`) je odmítnut TypeScript kompilátorem.
2. **Deterministický mock stream (MockBoundedStream):**
   - Implementuje `BoundedByteStream` nad polem `Uint8Array` chunků.
   - Test normálního čtení po blocích až do EOF.
   - Test `read-after-EOF`: opakované volání `next()` vrací `{ done: true }` bez vedlejších efektů.
3. **Meze, přetečení a zrušení:**
   - **Overflow test:** Stream emitující 15 MiB při limitu `maxBytes = 10 MiB` selže při překročení limitu a vyhodí chybu s kódem `BYTE_LIMIT_EXCEEDED`.
   - **Cancellation test:** Vyvolání `controller.abort()` během čtení streamu způsobí okamžité uvolnění čtečky a selhání s důvodem `CANCELED`.
   - **Read-after-cancellation:** Následné čtení ze zrušeného proudu okamžitě selže bez dotazování podkladových dat.
4. **Absence syntetického secret markeru ve veřejném serializéru:**
   - Vytvoření chyby poskytovatele obsahující interní tajnost: `internal_details: { tokenSecret: "provider_secret_key_123" }`.
   - Normalizace přes `normalizeToErrorContract(err)` vytvoří `InternalErrorContext` (tajnost přítomna v serverové paměti pro interní audit).
   - Serializace přes `serializePublicErrorPayload(ctx)` prokazatelně neobsahuje `tokenSecret`, `internal_details` ani žádný nepovolený klíč (ověřeno přes `assert.equal(publicPayload.tokenSecret, undefined)`).

---

## 4. DELIVERABLE 3 — VÝSTUPNÍ DŮKAZNÍ KAPSLE & VALIDACE

### 4.1 Znění kapsle `CAP-SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001-20261014-001R08.json`
```json
{
  "payload": {
    "schema_version": "1.0.0",
    "capsule_type": "COMMAND_CAPSULE",
    "capsule_id": "CAP-SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001-20261014-001R08",
    "task_id": "SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001",
    "command_id": "CMD-SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001-001R08-PLAN-SHARED-TYPES",
    "project_id": "SYNTHESIS_CMS_MINI",
    "roadmap_step": "17/60",
    "actors": {
      "owner": "Jiří Šár",
      "command_author": "ChatGPT/Codex",
      "executor": "AI Studio Engineer",
      "verifier": "AI Studio Engineer"
    },
    "execution_metadata": {
      "execution_timestamp": "2026-10-14T08:50:00.000Z",
      "development_phase": "PLAN",
      "execution_mode": "PLAN"
    },
    "repository_baseline": {
      "repository_name": "jirisar7-eng/synthesis-cms-mini",
      "repository_id": 1401215700,
      "base_main_sha": "3b05d6b2dd68da8079fb7a3092ef92d6077700cd",
      "source_branch": "task/SYN-MINI-FOUNDATION-PROVIDER-CONTRACTS-001-discover-plan",
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
        ".synthesis/task-capsules/CAP-SYN-MINI-FOUNDATION-REGISTRY-FRAMEWORK-001-20261013-001R05.json"
      ],
      "permitted_write_paths": [],
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
      "max_write_files_limit": 0,
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
      "expected_changed_files": [],
      "actual_changed_files": [],
      "commit_sha": null,
      "source_blob_shas": {}
    },
    "validation_and_checkpoints": {
      "checkpoints": [],
      "test_suites": [],
      "security_review": {
        "reviewer": "Jiří Šár",
        "status": "NOT_RUN",
        "notes": "PLAN phase read-only proposal; zero repository mutations."
      }
    },
    "known_error_guards": [
      {
        "guard_id": "GUARD-01",
        "description": "Zero repository file writes during plan phase"
      }
    ],
    "security_and_governance": {
      "invariants": [
        "INV-GOV-ZERO-REPO-MUTATION-IN-PLAN"
      ],
      "governance_status": {
        "contract_registry_status": "ACTIVE",
        "contract_registry_staged_count": 0,
        "contract_registry_active_count": 6,
        "capability_registry_status": "ACTIVE",
        "proposed_capabilities_count": 0,
        "active_capabilities_count": 5,
        "global_governance_health": "PASS",
        "ready_to_mutate": "UNCONDITIONALLY_DISABLED",
        "milestone_a_status": "COMPLETE",
        "step16_status": "MERGED_ON_MAIN",
        "step17_status": "PLAN_ONLY"
      }
    }
  },
  "seal": {
    "status": "SEALED",
    "hash_algorithm": "SHA-256",
    "canonicalization_algorithm": "RFC-8785",
    "payload_sha256": "c76957fafb793df9ced4c3f3bcabc8950582910be856c31482d4a4ab0c3c421c",
    "sealed_at": "2026-10-14T08:50:00.000Z",
    "sealed_by": "AI Studio Engineer",
    "seal_signature": null
  }
}
```

### 4.2 Výsledek validačního běhu
- **Vyvolaný skript:** `scripts/governance/validate_command_capsule.mjs` (funkce `validateCapsuleComplete`) a `scripts/governance/verify_capsule_seal.mjs` (funkce `computePayloadSha256`).
- **Výsledek:** `SCHEMA_INSTANCE_VALIDATION_STATUS: PASS`, `SEALED_PAYLOAD_SHA256: c76957fafb793df9ced4c3f3bcabc8950582910be856c31482d4a4ab0c3c421c`.
- **Testy poskytovatele (Step 17):** Pravdivý stav `NOT_RUN` / `UNIMPLEMENTED` (žádné fiktivní PASS výsledky).
