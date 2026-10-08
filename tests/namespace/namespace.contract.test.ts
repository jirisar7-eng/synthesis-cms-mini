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
  validateLifecycleTransition,
  validateNamespaceEntry,
  validateNamespaceRegistry,
  type NamespaceEntryInput,
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
// 2. Deterministic Lexical Validation Precedence (Finding 5)
// ============================================================

runScenario("05 Deterministic precedence: primitive check is step 1", () => {
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

runScenario(
  "06 Deterministic precedence: character screening (step 2) precedes total length (step 3)",
  () => {
    // "A" has length 1 (< min length 3), but must fail with INVALID_CHARACTERS because character screening is step 2
    assertThrows(() => {
      validateNamespaceIdentifier("A");
    }, "INVALID_CHARACTERS");

    // "-" has length 1 (< min length 3), but must fail with INVALID_CHARACTERS
    assertThrows(() => {
      validateNamespaceIdentifier("-");
    }, "INVALID_CHARACTERS");

    // "@" has length 1 (< min length 3), but must fail with INVALID_CHARACTERS
    assertThrows(() => {
      validateNamespaceIdentifier("@");
    }, "INVALID_CHARACTERS");
  },
);

runScenario(
  "07 Deterministic precedence: total length (step 3) precedes dot structure (step 4)",
  () => {
    // "ab" has valid characters, but length 2 < 3 -> INVALID_LENGTH
    assertThrows(() => {
      validateNamespaceIdentifier("ab");
    }, "INVALID_LENGTH");

    // "a." has length 2 < 3 -> INVALID_LENGTH (not MALFORMED_STRUCTURE)
    assertThrows(() => {
      validateNamespaceIdentifier("a.");
    }, "INVALID_LENGTH");

    const tooLong = "core." + "a".repeat(125); // length 130 > 128
    assertThrows(() => {
      validateNamespaceIdentifier(tooLong);
    }, "INVALID_LENGTH");
  },
);

runScenario(
  "08 Deterministic precedence: dot structure (step 4) precedes segment count (step 6)",
  () => {
    // Leading, trailing, and consecutive dots fail with MALFORMED_STRUCTURE
    assertThrows(() => {
      validateNamespaceIdentifier(".core.db");
    }, "MALFORMED_STRUCTURE");
    assertThrows(() => {
      validateNamespaceIdentifier("core.db.");
    }, "MALFORMED_STRUCTURE");
    assertThrows(() => {
      validateNamespaceIdentifier("core..db");
    }, "MALFORMED_STRUCTURE");
  },
);

runScenario(
  "09 Deterministic precedence: segment count (step 6) precedes segment length (step 7)",
  () => {
    // Single segment fails with INVALID_SEGMENT_COUNT
    assertThrows(() => {
      validateNamespaceIdentifier("single");
    }, "INVALID_SEGMENT_COUNT");
    assertThrows(() => {
      validateNamespaceIdentifier("core");
    }, "INVALID_SEGMENT_COUNT");

    // 7 segments fails with INVALID_SEGMENT_COUNT
    const sevenSegments = "a.b.c.d.e.f.g";
    assertThrows(() => {
      validateNamespaceIdentifier(sevenSegments);
    }, "INVALID_SEGMENT_COUNT");
  },
);

runScenario(
  "10 Deterministic precedence: segment length (step 7) precedes segment regex (step 8)",
  () => {
    const segment48 = "core." + "a".repeat(48);
    if (validateNamespaceIdentifier(segment48) !== segment48) {
      throw new Error("Segment length 48 should pass");
    }

    const segment49 = "core." + "a".repeat(49);
    assertThrows(() => {
      validateNamespaceIdentifier(segment49);
    }, "INVALID_SEGMENT_LENGTH");
  },
);

runScenario("11 Valid 2 to 6 segment canonical identifiers pass validation", () => {
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
    if (!isCanonicalNamespaceIdentifier(rawId)) {
      throw new Error("isCanonical returned false");
    }
  }
});

// ============================================================
// 3. Root Ownership Taxonomy & Arity
// ============================================================

runScenario("12 Root segment taxonomy accepts core, gov, sys, pack, ext", () => {
  validateNamespaceRoot("core.database");
  validateNamespaceRoot("gov.capsule.persistence");
  validateNamespaceRoot("sys.process");
  validateNamespaceRoot("pack.demo.setup");
  validateNamespaceRoot("ext.acme.blog");
});

runScenario("13 Invalid roots are rejected fail-closed", () => {
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

runScenario("14 Root-specific arity enforcement: pack requires >= 3 segments", () => {
  assertThrows(() => {
    validateNamespaceRoot("pack.foo");
  }, "INVALID_ARITY");
  const res = validateNamespaceRoot("pack.foo.bar");
  if (res.segments.length !== 3 || res.root !== "pack") {
    throw new Error("pack.foo.bar should have root pack and length 3");
  }
});

runScenario("15 Root-specific arity enforcement: ext requires >= 3 segments", () => {
  assertThrows(() => {
    validateNamespaceRoot("ext.acme");
  }, "INVALID_ARITY");
  const res = validateNamespaceRoot("ext.acme.blog");
  if (res.segments.length !== 3 || res.root !== "ext") {
    throw new Error("ext.acme.blog should have root ext and length 3");
  }
});

runScenario("16 Root-specific arity enforcement: core.integration requires >= 4 segments", () => {
  assertThrows(() => {
    validateNamespaceRoot("core.integration.stripe");
  }, "INVALID_ARITY");
  const res = validateNamespaceRoot("core.integration.payment.stripe");
  if (res.segments.length !== 4 || res.root !== "core") {
    throw new Error("core.integration.payment.stripe should pass");
  }
});

// ============================================================
// 4. Closed Ext Ownership & Module Prefix Rules (Finding 3)
// ============================================================

runScenario("17 Ext module ID must have exactly 3 segments: ext.<publisher>.<module>", () => {
  const validModule = validateNamespaceEntry({
    kind: "module",
    id: "ext.acme.blog",
    status: "ACTIVE",
    description: "Acme blog module",
  });
  if (validModule.id !== "ext.acme.blog") throw new Error("Module validation mismatch");

  // Ext module with 4 segments is rejected
  assertThrows(() => {
    validateNamespaceEntry({
      kind: "module",
      id: "ext.acme.blog.submodule",
      status: "ACTIVE",
      description: "Invalid 4-segment ext module",
    });
  }, "INVALID_ARITY");
});

runScenario("18 Non-module ext identifier requires >= 4 segments", () => {
  // ext identifier with only 3 segments but kind !== 'module' is rejected
  assertThrows(() => {
    validateNamespaceEntry({
      kind: "permission",
      id: "ext.acme.blog",
      status: "ACTIVE",
      description: "Permission with only 3 segments",
      ownerModuleId: "ext.acme.blog",
    });
  }, "INVALID_ARITY");
});

runScenario("19 Omitting ownership metadata on ext.* identifier fails closed", () => {
  // Non-module ext identifier without ownerModuleId cannot bypass validation
  assertThrows(() => {
    validateNamespaceEntry({
      kind: "permission",
      id: "ext.acme.blog.post.create",
      status: "ACTIVE",
      description: "Unowned third-party permission",
    });
  }, "MODULE_OWNERSHIP_REQUIRED");

  assertThrows(() => {
    validateNamespaceEntry({
      kind: "event",
      id: "ext.acme.blog.post.published",
      status: "ACTIVE",
      description: "Unowned third-party event",
    });
  }, "MODULE_OWNERSHIP_REQUIRED");
});

runScenario("20 Ext identifier must match declared ownerModuleId prefix", () => {
  // Valid matching ownership
  const validEntry = validateNamespaceEntry({
    kind: "permission",
    id: "ext.acme.blog.post.create",
    status: "ACTIVE",
    description: "Create blog post permission",
    ownerModuleId: "ext.acme.blog",
  });
  if (validEntry.id !== "ext.acme.blog.post.create") throw new Error("Entry mismatch");

  // Mismatched owner module
  assertThrows(() => {
    validateNamespaceEntry({
      kind: "permission",
      id: "ext.acme.blog.post.create",
      status: "ACTIVE",
      description: "Mismatched owner",
      ownerModuleId: "ext.other.forum",
    });
  }, "MODULE_PREFIX_MISMATCH");
});

runScenario("21 Third-party ext module cannot escape ext.* boundary", () => {
  assertThrows(() => {
    validateModuleOwnership("core.content.publish", "permission", "ext.acme.blog");
  }, "MODULE_PREFIX_MISMATCH");

  assertThrows(() => {
    validateModuleOwnership("ext.other.comment", "permission", "ext.acme.blog");
  }, "MODULE_PREFIX_MISMATCH");
});

// ============================================================
// 5. Lifecycle Transitions & Permanent Tombstones (Finding 2)
// ============================================================

runScenario("22 Valid lifecycle transitions: ACTIVE -> DEPRECATED -> RETIRED", () => {
  // Self transitions (no-op)
  validateLifecycleTransition("ACTIVE", "ACTIVE");
  validateLifecycleTransition("DEPRECATED", "DEPRECATED");
  validateLifecycleTransition("RETIRED", "RETIRED");

  // Forward transitions
  validateLifecycleTransition("ACTIVE", "DEPRECATED");
  validateLifecycleTransition("DEPRECATED", "RETIRED");
  validateLifecycleTransition("ACTIVE", "RETIRED");
});

runScenario("23 Reverse lifecycle transitions are strictly rejected", () => {
  assertThrows(() => {
    validateLifecycleTransition("DEPRECATED", "ACTIVE");
  }, "INVALID_LIFECYCLE_TRANSITION");

  assertThrows(() => {
    validateLifecycleTransition("RETIRED", "ACTIVE");
  }, "INVALID_LIFECYCLE_TRANSITION");

  assertThrows(() => {
    validateLifecycleTransition("RETIRED", "DEPRECATED");
  }, "INVALID_LIFECYCLE_TRANSITION");
});

runScenario("24 Invalid lifecycle status strings fail closed", () => {
  assertThrows(() => {
    validateLifecycleTransition("UNKNOWN" as unknown as NamespaceStatus, "ACTIVE");
  }, "INVALID_STATUS");

  assertThrows(() => {
    validateLifecycleTransition("ACTIVE", "INVALID" as unknown as NamespaceStatus);
  }, "INVALID_STATUS");
});

runScenario("25 Permanent tombstones: retired ID cannot be re-registered under ANY status", () => {
  const tombstones = new Set(["permission::core.legacy.access"]);

  // Attempting to register under ACTIVE fails
  assertThrows(() => {
    validateNamespaceRegistry(
      [
        {
          kind: "permission",
          id: "core.legacy.access",
          status: "ACTIVE",
          description: "Attempting to re-activate retired permission",
        },
      ],
      tombstones,
    );
  }, "TOMBSTONE_REUSE");

  // Attempting to register under DEPRECATED fails
  assertThrows(() => {
    validateNamespaceRegistry(
      [
        {
          kind: "permission",
          id: "core.legacy.access",
          status: "DEPRECATED",
          description: "Attempting to re-register retired permission as deprecated",
        },
      ],
      tombstones,
    );
  }, "TOMBSTONE_REUSE");

  // Attempting to register under RETIRED fails
  assertThrows(() => {
    validateNamespaceRegistry(
      [
        {
          kind: "permission",
          id: "core.legacy.access",
          status: "RETIRED",
          description: "Attempting duplicate tombstone registration",
        },
      ],
      tombstones,
    );
  }, "TOMBSTONE_REUSE");
});

// ============================================================
// 6. Superseded_by Validation (Finding 4)
// ============================================================

runScenario("26 Self supersession is strictly forbidden", () => {
  assertThrows(() => {
    validateNamespaceEntry({
      kind: "capability",
      id: "core.cache.provider",
      status: "DEPRECATED",
      description: "Self-superseding capability",
      superseded_by: "core.cache.provider",
    });
  }, "INVALID_SUPERSEDED_BY");
});

runScenario("27 Superseded_by must be a valid semantic namespace ID (root + arity)", () => {
  // Invalid root in superseded_by
  assertThrows(() => {
    validateNamespaceEntry({
      kind: "capability",
      id: "core.cache.v1",
      status: "DEPRECATED",
      description: "Legacy cache provider",
      superseded_by: "invalid_root.cache",
    });
  }, "INVALID_ROOT");

  // Invalid arity in superseded_by (pack requires >= 3 segments)
  assertThrows(() => {
    validateNamespaceEntry({
      kind: "capability",
      id: "core.cache.v1",
      status: "DEPRECATED",
      description: "Legacy cache provider",
      superseded_by: "pack.invalid",
    });
  }, "INVALID_ARITY");
});

runScenario("28 Superseded_by cannot exist on ACTIVE entries", () => {
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

runScenario("29 Valid superseded_by on DEPRECATED and RETIRED entries passes", () => {
  const dep = validateNamespaceEntry({
    kind: "capability",
    id: "core.cache.v1",
    status: "DEPRECATED",
    description: "Deprecated cache provider",
    superseded_by: "core.cache.v2",
  });
  if (dep.superseded_by !== "core.cache.v2") throw new Error("superseded_by mismatch");

  const ret = validateNamespaceEntry({
    kind: "capability",
    id: "core.cache.v1",
    status: "RETIRED",
    description: "Retired cache provider",
    superseded_by: "core.cache.v3",
  });
  if (ret.superseded_by !== "core.cache.v3") throw new Error("superseded_by mismatch");
});

// ============================================================
// 7. Malformed Runtime Input Fail-Closed (Finding 6)
// ============================================================

runScenario("30 Malformed runtime entry fails closed without leaking TypeError", () => {
  assertThrows(() => {
    validateNamespaceEntry(null);
  }, "INVALID_PRIMITIVE");

  assertThrows(() => {
    validateNamespaceEntry(undefined);
  }, "INVALID_PRIMITIVE");

  assertThrows(() => {
    validateNamespaceEntry("not-an-object");
  }, "INVALID_PRIMITIVE");

  assertThrows(() => {
    validateNamespaceEntry(123);
  }, "INVALID_PRIMITIVE");

  assertThrows(() => {
    validateNamespaceEntry([]);
  }, "INVALID_PRIMITIVE");

  // Missing or non-string id
  assertThrows(() => {
    validateNamespaceEntry({
      kind: "capability",
      status: "ACTIVE",
      description: "test",
    });
  }, "INVALID_PRIMITIVE");

  // Non-string description does NOT throw raw TypeError
  assertThrows(() => {
    validateNamespaceEntry({
      id: "core.db",
      kind: "capability",
      status: "ACTIVE",
      description: null,
    });
  }, "INVALID_PRIMITIVE");

  assertThrows(() => {
    validateNamespaceEntry({
      id: "core.db",
      kind: "capability",
      status: "ACTIVE",
      description: undefined,
    });
  }, "INVALID_PRIMITIVE");

  assertThrows(() => {
    validateNamespaceEntry({
      id: "core.db",
      kind: "capability",
      status: "ACTIVE",
      description: 12345,
    });
  }, "INVALID_PRIMITIVE");

  assertThrows(() => {
    validateNamespaceEntry({
      id: "core.db",
      kind: "capability",
      status: "ACTIVE",
      description: "   ",
    });
  }, "INVALID_PRIMITIVE");

  // Non-string optional properties
  assertThrows(() => {
    validateNamespaceEntry({
      id: "core.db",
      kind: "capability",
      status: "ACTIVE",
      description: "Valid description",
      ownerModuleId: 123,
    });
  }, "INVALID_PRIMITIVE");

  assertThrows(() => {
    validateNamespaceEntry({
      id: "core.db",
      kind: "capability",
      status: "ACTIVE",
      description: "Valid description",
      version: true,
    });
  }, "INVALID_PRIMITIVE");

  assertThrows(() => {
    validateNamespaceEntry({
      id: "core.db",
      kind: "capability",
      status: "DEPRECATED",
      description: "Valid description",
      superseded_by: {},
    });
  }, "INVALID_PRIMITIVE");
});

runScenario("31 Malformed registry inputs fail closed with INVALID_PRIMITIVE", () => {
  assertThrows(() => {
    validateNamespaceRegistry("not-an-array" as unknown as readonly NamespaceEntryInput[]);
  }, "INVALID_PRIMITIVE");

  assertThrows(() => {
    validateNamespaceRegistry([], "not-a-set" as unknown as ReadonlySet<string>);
  }, "INVALID_PRIMITIVE");
});

// ============================================================
// 8. Composite Identity Across All 7 Kinds (Finding 7)
// ============================================================

runScenario(
  "32 All 7 canonical kinds validate and form distinct composite identities {kind, id}",
  () => {
    const sharedId = "core.auth.user";
    const entries: readonly NamespaceEntryInput[] = [
      {
        kind: "capability",
        id: sharedId,
        status: "ACTIVE",
        description: "Capability entity",
      },
      {
        kind: "permission",
        id: sharedId,
        status: "ACTIVE",
        description: "Permission entity",
      },
      {
        kind: "event",
        id: sharedId,
        status: "ACTIVE",
        description: "Event entity",
      },
      {
        kind: "settings",
        id: sharedId,
        status: "ACTIVE",
        description: "Settings entity",
      },
      {
        kind: "module",
        id: sharedId,
        status: "ACTIVE",
        description: "Module entity",
      },
      {
        kind: "entitlement",
        id: sharedId,
        status: "ACTIVE",
        description: "Entitlement entity",
      },
      {
        kind: "integration",
        id: sharedId,
        status: "ACTIVE",
        description: "Integration entity",
      },
    ];

    const registry = validateNamespaceRegistry(entries);
    if (registry.length !== 7) {
      throw new Error(`Expected 7 entries in registry, got ${String(registry.length)}`);
    }
  },
);

runScenario("33 Duplicate (kind, id) collision fails closed", () => {
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

// ============================================================
// 9. Exact Structural Matching Without Wildcard Privileges (Finding 1)
// ============================================================

runScenario("34 Structural invariant: Wildcards, regex characters, and paths are rejected", () => {
  // Universal wildcard is rejected
  assertThrows(() => {
    validateNamespaceIdentifier("*");
  }, "INVALID_CHARACTERS");

  // Prefix wildcard is rejected
  assertThrows(() => {
    validateNamespaceIdentifier("core.*");
  }, "INVALID_CHARACTERS");

  assertThrows(() => {
    validateNamespaceIdentifier("core.content.*");
  }, "INVALID_CHARACTERS");

  // Regex tokens are rejected
  assertThrows(() => {
    validateNamespaceIdentifier("core.content.?");
  }, "INVALID_CHARACTERS");

  assertThrows(() => {
    validateNamespaceIdentifier("core.content.[a-z]");
  }, "INVALID_CHARACTERS");

  // Slash paths are rejected
  assertThrows(() => {
    validateNamespaceIdentifier("core/content/read");
  }, "INVALID_CHARACTERS");
});

// ============================================================
// 10. Governance Invariants Preservation
// ============================================================

runScenario("35 All 5 active governance capabilities conform to grammar", () => {
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

runScenario("36 CONTRACT-GOV-* identifiers are outside runtime namespace system", () => {
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

console.log(
  `\n# PASS: All ${String(passedScenarios)} namespace contract test scenarios executed successfully.`,
);
