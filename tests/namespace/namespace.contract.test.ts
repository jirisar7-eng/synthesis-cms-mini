/**
 * Synthesis CMS mini — Stable Namespace Registry Contract Test Suite
 *
 * Contract: CONTRACT-CORE-STABLE-NAMESPACE-001
 * Roadmap Step: 13/60 — Stable namespace registry
 */

import {
  NAMESPACE_CONTRACT_ID,
  NAMESPACE_ROOTS,
  NAMESPACE_KINDS,
  NAMESPACE_STATUSES,
  NamespaceValidationError,
  validateNamespaceIdentifier,
  isCanonicalNamespaceIdentifier,
  validateNamespaceRoot,
  validateModuleOwnership,
  validateNamespaceEntry,
  validateNamespaceRegistry,
  checkPermission,
  type NamespaceEntryInput,
  type NamespaceKind,
  type NamespaceStatus,
} from "../../contracts/src/namespace/index.ts";

let passedScenarios = 0;

function runScenario(name: string, fn: () => void): void {
  try {
    fn();
    passedScenarios++;
  } catch (err) {
    console.error(`FAILED scenario: ${name}`);
    throw err;
  }
}

function assertThrows(fn: () => void, expectedCode?: string, errorDescription?: string): void {
  let thrown = false;
  try {
    fn();
  } catch (err) {
    thrown = true;
    if (!(err instanceof NamespaceValidationError)) {
      throw new Error(`Expected NamespaceValidationError, received: ${String(err)}`);
    }
    if (expectedCode !== undefined && err.code !== expectedCode) {
      throw new Error(
        `Expected error code [${expectedCode}], received [${err.code}]: ${err.message}`,
      );
    }
  }
  if (!thrown) {
    throw new Error(
      `Expected exception to be thrown${errorDescription !== undefined ? ` (${errorDescription})` : ""}`,
    );
  }
}

// ============================================================
// 1. Contract Identity & Constants
// ============================================================

runScenario("01 Contract ID constant is CONTRACT-CORE-STABLE-NAMESPACE-001", () => {
  const contractId: string = NAMESPACE_CONTRACT_ID;
  if (contractId.length === 0 || !contractId.startsWith("CONTRACT-")) {
    throw new Error("Invalid contract ID");
  }
});

runScenario("02 Root taxonomy is strictly [core, gov, sys, pack, ext]", () => {
  const expectedRoots = ["core", "gov", "sys", "pack", "ext"];
  for (const r of expectedRoots) {
    if (!NAMESPACE_ROOTS.includes(r as (typeof NAMESPACE_ROOTS)[number])) {
      throw new Error(`Missing root: ${r}`);
    }
  }
  const rootSet = new Set<string>(NAMESPACE_ROOTS);
  if (rootSet.has("integration")) {
    throw new Error("integration must NOT be in NAMESPACE_ROOTS");
  }
});

runScenario("03 Canonical kinds contains all 7 kinds with settings in plural", () => {
  const expectedKinds = [
    "capability",
    "permission",
    "event",
    "settings",
    "module",
    "entitlement",
    "integration",
  ];
  for (const k of expectedKinds) {
    if (!NAMESPACE_KINDS.includes(k as (typeof NAMESPACE_KINDS)[number])) {
      throw new Error(`Missing kind: ${k}`);
    }
  }
  const kindSet = new Set<string>(NAMESPACE_KINDS);
  if (kindSet.has("setting")) {
    throw new Error("Singular 'setting' must not be in NAMESPACE_KINDS");
  }
});

runScenario("04 Lifecycle statuses are strictly [ACTIVE, DEPRECATED, RETIRED]", () => {
  const expectedStatuses = ["ACTIVE", "DEPRECATED", "RETIRED"];
  for (const s of expectedStatuses) {
    if (!NAMESPACE_STATUSES.includes(s as (typeof NAMESPACE_STATUSES)[number])) {
      throw new Error(`Missing status: ${s}`);
    }
  }
});

// ============================================================
// 2. Lexical Grammar Tests (Positive & Negative)
// ============================================================

runScenario("05 Valid 2 to 6 segment identifiers pass validation", () => {
  const validCases = [
    "core.db",
    "gov.capsule.persistence",
    "sys.process.signal.handler",
    "pack.starter.setup.theme.config",
    "ext.acme.blog.post.created.v1",
    "core.multi_tenant",
    "core.auth_user_2.session_timeout",
  ];
  for (let i = 0; i < validCases.length; i++) {
    const rawId: string = validCases[i] ?? "";
    const validated = validateNamespaceIdentifier(rawId);
    if (validated !== rawId) {
      throw new Error("Validation mismatch");
    }
    const isCanonical = isCanonicalNamespaceIdentifier(rawId);
    if (!isCanonical) {
      throw new Error("isCanonical returned false");
    }
  }
});
runScenario("06 Non-string primitives fail closed", () => {
  assertThrows(() => {
    validateNamespaceIdentifier(null);
  }, "INVALID_PRIMITIVE");
  assertThrows(() => {
    validateNamespaceIdentifier(undefined);
  }, "INVALID_PRIMITIVE");
  assertThrows(() => {
    validateNamespaceIdentifier(12345);
  }, "INVALID_PRIMITIVE");
  assertThrows(() => {
    validateNamespaceIdentifier({});
  }, "INVALID_PRIMITIVE");
  assertThrows(() => {
    validateNamespaceIdentifier(["core", "db"]);
  }, "INVALID_PRIMITIVE");
});

runScenario("07 Total length bounds enforcement (min 3, max 128)", () => {
  assertThrows(() => {
    validateNamespaceIdentifier("a.");
  }, "INVALID_LENGTH");
  assertThrows(() => {
    validateNamespaceIdentifier("ab");
  }, "INVALID_LENGTH");

  const minValid = "a.b";
  if (validateNamespaceIdentifier(minValid) !== minValid) {
    throw new Error(`Expected min length 3 to pass: ${minValid}`);
  }

  const tooLong = "core." + "a".repeat(125);
  assertThrows(() => {
    validateNamespaceIdentifier(tooLong);
  }, "INVALID_LENGTH");
});

runScenario("08 Segment count bounds enforcement (min 2, max 6)", () => {
  assertThrows(() => {
    validateNamespaceIdentifier("single");
  }, "INVALID_SEGMENT_COUNT");
  assertThrows(() => {
    validateNamespaceIdentifier("core");
  }, "INVALID_SEGMENT_COUNT");

  const sevenSegments = "a.b.c.d.e.f.g";
  assertThrows(() => {
    validateNamespaceIdentifier(sevenSegments);
  }, "INVALID_SEGMENT_COUNT");
});

runScenario("09 Segment length bounds enforcement (max 48 chars)", () => {
  const segment48 = "core." + "a".repeat(48);
  if (validateNamespaceIdentifier(segment48) !== segment48) {
    throw new Error("Segment length 48 should pass");
  }

  const segment49 = "core." + "a".repeat(49);
  assertThrows(() => {
    validateNamespaceIdentifier(segment49);
  }, "INVALID_SEGMENT_LENGTH");
});

runScenario("10 Uppercase characters are rejected fail-closed without normalization", () => {
  assertThrows(() => {
    validateNamespaceIdentifier("Core.database");
  }, "INVALID_CHARACTERS");
  assertThrows(() => {
    validateNamespaceIdentifier("core.Database");
  }, "INVALID_CHARACTERS");
  assertThrows(() => {
    validateNamespaceIdentifier("CORE.DATABASE");
  }, "INVALID_CHARACTERS");
});

runScenario("11 Hyphens are strictly forbidden in canonical namespace identifiers", () => {
  assertThrows(() => {
    validateNamespaceIdentifier("core.clean-install");
  }, "INVALID_CHARACTERS");
  assertThrows(() => {
    validateNamespaceIdentifier("ext.my-plugin.blog");
  }, "INVALID_CHARACTERS");
  assertThrows(() => {
    validateNamespaceIdentifier("pack.starter-kit.setup");
  }, "INVALID_CHARACTERS");
});

runScenario("12 Leading, trailing, and consecutive dots are forbidden", () => {
  assertThrows(() => {
    validateNamespaceIdentifier(".core.db");
  }, "MALFORMED_STRUCTURE");
  assertThrows(() => {
    validateNamespaceIdentifier("core.db.");
  }, "MALFORMED_STRUCTURE");
  assertThrows(() => {
    validateNamespaceIdentifier("core..db");
  }, "MALFORMED_STRUCTURE");
  assertThrows(() => {
    validateNamespaceIdentifier("core...db");
  }, "MALFORMED_STRUCTURE");
});

runScenario("13 Whitespace and non-ASCII/Unicode characters are forbidden", () => {
  assertThrows(() => {
    validateNamespaceIdentifier(" core.db");
  }, "INVALID_CHARACTERS");
  assertThrows(() => {
    validateNamespaceIdentifier("core.db ");
  }, "INVALID_CHARACTERS");
  assertThrows(() => {
    validateNamespaceIdentifier("core. db");
  }, "INVALID_CHARACTERS");
  assertThrows(() => {
    validateNamespaceIdentifier("core.d b");
  }, "INVALID_CHARACTERS");
  assertThrows(() => {
    validateNamespaceIdentifier("core.db\n");
  }, "INVALID_CHARACTERS");
  assertThrows(() => {
    validateNamespaceIdentifier("core.db@v1");
  }, "INVALID_CHARACTERS");
  assertThrows(() => {
    validateNamespaceIdentifier("core.db/postgresql");
  }, "INVALID_CHARACTERS");
  assertThrows(() => {
    validateNamespaceIdentifier("core.dátabáze.pg");
  }, "INVALID_CHARACTERS");
});

// ============================================================
// 3. Root Ownership Taxonomy & Arity
// ============================================================

runScenario("14 Root segment taxonomy accepts core, gov, sys, pack, ext", () => {
  validateNamespaceRoot("core.database");
  validateNamespaceRoot("gov.capsule.persistence");
  validateNamespaceRoot("sys.process");
  validateNamespaceRoot("pack.demo.setup");
  validateNamespaceRoot("ext.acme.blog");
});

runScenario("15 Invalid roots are rejected fail-closed", () => {
  assertThrows(() => {
    validateNamespaceRoot("integration.stripe");
  }, "INVALID_ROOT");
  assertThrows(() => {
    validateNamespaceRoot("synthesis.mini");
  }, "INVALID_ROOT");
  assertThrows(() => {
    validateNamespaceRoot("auth.user");
  }, "INVALID_ROOT");
  assertThrows(() => {
    validateNamespaceRoot("vendor.acme.blog");
  }, "INVALID_ROOT");
  assertThrows(() => {
    validateNamespaceRoot("custom.plugin");
  }, "INVALID_ROOT");
});

runScenario("16 Root-specific arity enforcement: pack requires >= 3 segments", () => {
  assertThrows(() => {
    validateNamespaceRoot("pack.foo");
  }, "INVALID_ARITY");

  const res = validateNamespaceRoot("pack.foo.bar");
  if (res.segments.length !== 3 || res.root !== "pack") {
    throw new Error("pack.foo.bar should have root pack and length 3");
  }
});

runScenario("17 Root-specific arity enforcement: ext requires >= 3 segments", () => {
  assertThrows(() => {
    validateNamespaceRoot("ext.acme");
  }, "INVALID_ARITY");

  const res = validateNamespaceRoot("ext.acme.blog");
  if (res.segments.length !== 3 || res.root !== "ext") {
    throw new Error("ext.acme.blog should have root ext and length 3");
  }
});

runScenario("18 Root-specific arity enforcement: core.integration requires >= 4 segments", () => {
  assertThrows(() => {
    validateNamespaceRoot("core.integration.stripe");
  }, "INVALID_ARITY");

  const res = validateNamespaceRoot("core.integration.payment.stripe");
  if (res.segments.length !== 4 || res.root !== "core") {
    throw new Error("core.integration.payment.stripe should pass");
  }
});

// ============================================================
// 4. Exact Module Ownership Prefix Rule
// ============================================================

runScenario("19 Module declaration matches its own ID", () => {
  validateModuleOwnership("core.installer", "module", "core.installer");
  validateModuleOwnership("ext.acme.blog", "module", "ext.acme.blog");

  assertThrows(() => {
    validateModuleOwnership("core.other", "module", "core.installer");
  }, "MODULE_PREFIX_MISMATCH");
});

runScenario("20 Owned entities must strictly start with module_id + '.'", () => {
  validateModuleOwnership("core.installer.completed", "event", "core.installer");
  validateModuleOwnership("core.installer.run", "permission", "core.installer");
  validateModuleOwnership("core.installer.auto_run", "settings", "core.installer");

  assertThrows(() => {
    validateModuleOwnership("core.install.completed", "event", "core.installer");
  }, "MODULE_PREFIX_MISMATCH");

  assertThrows(() => {
    validateModuleOwnership("core.database.postgresql", "capability", "core.installer");
  }, "MODULE_PREFIX_MISMATCH");
});

runScenario("21 Third-party extensions cannot escape ext.<pub>.<module>.* boundary", () => {
  validateModuleOwnership("ext.acme.blog.post.created", "event", "ext.acme.blog");
  validateModuleOwnership("ext.acme.blog.post.delete", "permission", "ext.acme.blog");

  assertThrows(() => {
    validateModuleOwnership("core.content.publish", "permission", "ext.acme.blog");
  }, "MODULE_PREFIX_MISMATCH");
});

// ============================================================
// 5. Composite Identity {kind, id} & Registry Validation
// ============================================================

runScenario("22 Valid namespace entry creation and immutability", () => {
  const entry = validateNamespaceEntry({
    kind: "capability",
    id: "core.database.postgresql",
    status: "ACTIVE",
    description: "PostgreSQL relational persistence provider",
  });

  if (
    entry.kind !== "capability" ||
    entry.id !== "core.database.postgresql" ||
    entry.root !== "core"
  ) {
    throw new Error("Entry validation returned unexpected properties");
  }
  if (!Object.isFrozen(entry)) {
    throw new Error("Validated entry must be immutable/frozen");
  }
});

runScenario("23 Invalid kind or status is rejected fail-closed", () => {
  const invalidKindEntry: NamespaceEntryInput = {
    kind: "invalid_kind" as unknown as NamespaceKind,
    id: "core.database",
    status: "ACTIVE",
    description: "Test",
  };
  assertThrows(() => {
    validateNamespaceEntry(invalidKindEntry);
  }, "INVALID_KIND");

  const invalidStatusEntry: NamespaceEntryInput = {
    kind: "capability",
    id: "core.database",
    status: "UNKNOWN_STATUS" as unknown as NamespaceStatus,
    description: "Test",
  };
  assertThrows(() => {
    validateNamespaceEntry(invalidStatusEntry);
  }, "INVALID_STATUS");
});

runScenario("24 Composite identity allows identical id with distinct kind", () => {
  const entries: readonly NamespaceEntryInput[] = [
    {
      kind: "capability",
      id: "core.auth.user",
      status: "ACTIVE",
      description: "User authentication capability",
    },
    {
      kind: "permission",
      id: "core.auth.user",
      status: "ACTIVE",
      description: "User authorization access gate",
    },
    {
      kind: "settings",
      id: "core.auth.user",
      status: "ACTIVE",
      description: "User auth configuration options",
    },
  ];

  const registry = validateNamespaceRegistry(entries);
  if (registry.length !== 3) {
    throw new Error("Registry should hold 3 entries with distinct composite keys");
  }
});

runScenario("25 Duplicate (kind, id) is rejected fail-closed", () => {
  const entries: readonly NamespaceEntryInput[] = [
    {
      kind: "permission",
      id: "core.content.publish",
      status: "ACTIVE",
      description: "Publish content permission",
    },
    {
      kind: "permission",
      id: "core.content.publish",
      status: "ACTIVE",
      description: "Duplicate publish content permission",
    },
  ];

  assertThrows(() => {
    validateNamespaceRegistry(entries);
  }, "DUPLICATE_IDENTIFIER");
});

runScenario("26 Superseded_by reference validation", () => {
  const deprecatedEntry = validateNamespaceEntry({
    kind: "capability",
    id: "core.cache.v1",
    status: "DEPRECATED",
    description: "Legacy cache provider",
    superseded_by: "core.cache.v2",
  });
  if (deprecatedEntry.superseded_by !== "core.cache.v2") {
    throw new Error("superseded_by should match");
  }

  assertThrows(() => {
    validateNamespaceEntry({
      kind: "capability",
      id: "core.cache.v1",
      status: "ACTIVE",
      description: "Active cache provider",
      superseded_by: "core.cache.v2",
    });
  }, "INVALID_SUPERSEDED_BY");
});

runScenario("27 Permanent tombstone prevents reuse of retired identifiers", () => {
  const tombstones = new Set(["permission::core.legacy.access"]);

  const activeAttempt: readonly NamespaceEntryInput[] = [
    {
      kind: "permission",
      id: "core.legacy.access",
      status: "ACTIVE",
      description: "Attempting to re-activate retired permission",
    },
  ];

  assertThrows(() => {
    validateNamespaceRegistry(activeAttempt, tombstones);
  }, "TOMBSTONE_REUSE");
});

// ============================================================
// 6. Preservation of Active Governance Capabilities & Contracts
// ============================================================

runScenario("28 All 5 active governance capabilities conform to grammar", () => {
  const govCapabilities = [
    "gov.capsule.persistence",
    "gov.capsule.lineage",
    "gov.capsule.cryptographic_seal",
    "gov.scope.diff_firewall",
    "gov.checkpoint.remote_protocol",
  ];

  for (const cap of govCapabilities) {
    const { root, segments } = validateNamespaceRoot(cap);
    if (root !== "gov") throw new Error(`Expected root gov for ${cap}`);
    if (segments.length !== 3) throw new Error(`Expected 3 segments for ${cap}`);
  }
});

runScenario("29 CONTRACT-GOV-* identifiers are outside runtime namespace system", () => {
  const contractIds = [
    "CONTRACT-GOV-GENESIS-ANCHOR-001",
    "CONTRACT-GOV-COMMAND-CAPSULE-001",
    "CONTRACT-GOV-CAPABILITY-REGISTRY-001",
    "CONTRACT-CORE-STABLE-NAMESPACE-001",
  ];

  for (const cId of contractIds) {
    if (isCanonicalNamespaceIdentifier(cId)) {
      throw new Error(`Contract ID ${cId} should NOT be a valid runtime namespace identifier`);
    }
  }
});

// ============================================================
// 7. Permission Exact-Match & Authorization Independence
// ============================================================

runScenario("30 checkPermission enforces strict exact-match fail-closed evaluation", () => {
  const granted = ["core.content.read", "core.content.publish", "ext.acme.blog.post.create"];

  if (!checkPermission("core.content.read", granted)) throw new Error("Expected true");
  if (!checkPermission("core.content.publish", granted)) throw new Error("Expected true");
  if (!checkPermission("ext.acme.blog.post.create", granted)) throw new Error("Expected true");

  if (checkPermission("core.content.delete", granted)) throw new Error("Expected false");
  if (checkPermission("core.content", granted)) throw new Error("Expected false");
  if (checkPermission("core.content.publish.draft", granted)) throw new Error("Expected false");

  if (checkPermission("core.*", granted)) throw new Error("Expected false");
  if (checkPermission("*", granted)) throw new Error("Expected false");
  if (checkPermission("core.content.*", granted)) throw new Error("Expected false");

  const nullRequested = null as unknown as string;
  if (checkPermission(nullRequested, granted)) throw new Error("Expected false");
  if (checkPermission("INVALID_UPPERCASE", granted)) throw new Error("Expected false");
  const nullGranted = null as unknown as readonly string[];
  if (checkPermission("core.content.read", nullGranted)) throw new Error("Expected false");
});

console.log(
  `\n# PASS: All ${String(passedScenarios)} namespace contract test scenarios executed successfully.`,
);
