import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { describe, it } from "node:test";
import {
  REGISTRY_CONTRACT_ID,
  REGISTRY_CATEGORIES,
  type RegistryCategory,
  type RegistryEntryInput,
  type RegistrySnapshot,
  isValidRegistryCategory,
  isValidRegistryStatus,
  isValidRegistryDescription,
} from "../../contracts/src/registry/index.ts";
import {
  createRegistrySnapshot,
  registerEntries,
  getRegistryEntry,
  listRegistryEntries,
  transitionRegistryEntry,
  isGenuineRegistrySnapshot,
} from "../../core/src/registry/registry.framework.ts";

void describe("Step 16: Registry Framework Contract", () => {
  // =========================================================================
  // POSITIVE TEST SUITE
  // =========================================================================

  void describe("Positive Scenarios (P1 - P9)", () => {
    void it("P1: Supports all seven registry categories defined in contract", () => {
      assert.strictEqual(REGISTRY_CATEGORIES.length, 7);
      const expectedCategories: readonly RegistryCategory[] = [
        "module",
        "event",
        "permission",
        "settings",
        "route",
        "ui_extension",
        "provider",
      ];
      for (const cat of expectedCategories) {
        assert.ok(isValidRegistryCategory(cat), `Category ${cat} must be valid`);
      }
    });

    void it("P2: Registers entries across canonical Step 13 namespace roots", () => {
      const inputs: RegistryEntryInput[] = [
        {
          category: "module",
          id: "core.kernel.boot",
          description: "Core boot module",
          owner_module_id: "core.kernel.boot",
        },
        {
          category: "event",
          id: "gov.audit.system.logged",
          description: "Governance audit event",
          owner_module_id: "gov.audit.system",
        },
        {
          category: "permission",
          id: "sys.auth.core.read",
          description: "System auth permission",
          owner_module_id: "sys.auth.core",
        },
        {
          category: "settings",
          id: "pack.base.core.theme",
          description: "Base pack setting",
          owner_module_id: "pack.base.core",
        },
        {
          category: "route",
          id: "ext.acme.blog.home",
          description: "ACME blog home route",
          owner_module_id: "ext.acme.blog",
        },
      ];

      const snap = createRegistrySnapshot(inputs);
      assert.ok(isGenuineRegistrySnapshot(snap));
      assert.strictEqual(snap.revision, 0);
      assert.strictEqual(snap.entries.length, 5);
    });

    void it("P3: Enforces third-party module ownership and namespace boundaries", () => {
      const inputs: RegistryEntryInput[] = [
        {
          category: "module",
          id: "ext.publisher.blog",
          description: "Publisher blog module",
          owner_module_id: "ext.publisher.blog",
        },
        {
          category: "route",
          id: "ext.publisher.blog.posts",
          description: "Blog posts route",
          owner_module_id: "ext.publisher.blog",
        },
        {
          category: "ui_extension",
          id: "ext.publisher.blog.panel",
          description: "Blog admin panel UI",
          owner_module_id: "ext.publisher.blog",
        },
      ];

      const snap = createRegistrySnapshot(inputs);
      assert.strictEqual(snap.entries.length, 3);
      for (const e of snap.entries) {
        assert.strictEqual(e.owner_module_id, "ext.publisher.blog");
        assert.ok(e.id.startsWith("ext.publisher.blog"));
      }
    });

    void it("P4: Disambiguates identical namespace IDs across distinct registry categories", () => {
      const sharedId = "ext.acme.shop.item";
      const ownerId = "ext.acme.shop";
      const inputs: RegistryEntryInput[] = [
        {
          category: "event",
          id: sharedId,
          description: "Shop item event",
          owner_module_id: ownerId,
        },
        {
          category: "permission",
          id: sharedId,
          description: "Shop item permission",
          owner_module_id: ownerId,
        },
        {
          category: "settings",
          id: sharedId,
          description: "Shop item setting",
          owner_module_id: ownerId,
        },
      ];

      const snap = createRegistrySnapshot(inputs);
      assert.strictEqual(snap.entries.length, 3);

      const eventEntry = getRegistryEntry(snap, "event", sharedId);
      const permEntry = getRegistryEntry(snap, "permission", sharedId);
      const settingEntry = getRegistryEntry(snap, "settings", sharedId);

      assert.ok(eventEntry);
      assert.ok(permEntry);
      assert.ok(settingEntry);
      assert.strictEqual(eventEntry.category, "event");
      assert.strictEqual(permEntry.category, "permission");
      assert.strictEqual(settingEntry.category, "settings");
    });

    void it("P5: Executes copy-on-write batch registration with revision increments", () => {
      const snap0 = createRegistrySnapshot();
      assert.strictEqual(snap0.revision, 0);
      assert.strictEqual(snap0.entries.length, 0);

      const batch1: RegistryEntryInput[] = [
        {
          category: "module",
          id: "core.auth.main",
          description: "Core auth module",
          owner_module_id: "core.auth.main",
        },
        {
          category: "permission",
          id: "core.auth.main.login",
          description: "Login permission",
          owner_module_id: "core.auth.main",
        },
      ];
      const snap1 = registerEntries(snap0, batch1);
      assert.strictEqual(snap1.revision, 1);
      assert.strictEqual(snap1.entries.length, 2);
      assert.strictEqual(snap0.entries.length, 0); // Copy-on-write preservation

      const batch2: RegistryEntryInput[] = [
        {
          category: "route",
          id: "core.auth.main.login_page",
          description: "Login page route",
          owner_module_id: "core.auth.main",
        },
      ];
      const snap2 = registerEntries(snap1, batch2);
      assert.strictEqual(snap2.revision, 2);
      assert.strictEqual(snap2.entries.length, 3);
      assert.strictEqual(snap1.entries.length, 2); // Copy-on-write preservation
    });

    void it("P6: Produces deterministic sorted entry listings and filters by category", () => {
      const inputs: RegistryEntryInput[] = [
        { category: "route", id: "core.app.route_b", description: "Route B" },
        { category: "event", id: "core.app.event_a", description: "Event A" },
        { category: "route", id: "core.app.route_a", description: "Route A" },
      ];
      const snap = createRegistrySnapshot(inputs);

      const routesOnly = listRegistryEntries(snap, "route");
      assert.strictEqual(routesOnly.length, 2);
      assert.strictEqual(routesOnly[0]?.id, "core.app.route_a");
      assert.strictEqual(routesOnly[1]?.id, "core.app.route_b");

      const allEntries = listRegistryEntries(snap);
      assert.strictEqual(allEntries.length, 3);
      assert.strictEqual(allEntries[0]?.category, "event");
      assert.strictEqual(allEntries[1]?.category, "route");
    });

    void it("P7: Enforces deep freeze immutability on snapshots and entries", () => {
      const snap = createRegistrySnapshot([
        { category: "provider", id: "sys.db.postgres", description: "Postgres provider" },
      ]);

      assert.ok(Object.isFrozen(snap));
      assert.ok(Object.isFrozen(snap.entries));
      assert.ok(Object.isFrozen(snap.entries[0]));

      assert.throws(() => {
        // @ts-expect-error Intentionally testing immutable freeze
        snap.revision = 99;
      }, TypeError);

      assert.throws(() => {
        // @ts-expect-error Intentionally testing immutable freeze
        snap.entries[0].description = "Tampered";
      }, TypeError);
    });

    void it("P8: Enforces lifecycle status transitions and RETIRED tombstone persistence", () => {
      const snap0 = createRegistrySnapshot([
        { category: "permission", id: "sys.legacy.read", description: "Legacy read permission" },
      ]);
      const [entry0] = snap0.entries;
      assert.strictEqual(entry0?.status, "ACTIVE");
      // ACTIVE -> DEPRECATED
      const snap1 = transitionRegistryEntry(snap0, "permission", "sys.legacy.read", "DEPRECATED");
      assert.strictEqual(snap1.revision, 1);
      const [entry1] = snap1.entries;
      assert.strictEqual(entry1?.status, "DEPRECATED");
      // DEPRECATED -> RETIRED
      const snap2 = transitionRegistryEntry(snap1, "permission", "sys.legacy.read", "RETIRED");
      assert.strictEqual(snap2.revision, 2);
      const [entry2] = snap2.entries;
      assert.strictEqual(entry2?.status, "RETIRED");
      // Verify original snapshots were untouched
      const [entry0Again] = snap0.entries;
      assert.strictEqual(entry0Again?.status, "ACTIVE");
      const [entry1Again] = snap1.entries;
      assert.strictEqual(entry1Again?.status, "DEPRECATED");
    });
    void it("P9: Interoperates cleanly with Step 13, 14, and 15 contracts", () => {
      assert.strictEqual(REGISTRY_CONTRACT_ID, "CONTRACT-CORE-REGISTRY-FRAMEWORK-001");
      assert.ok(isValidRegistryStatus("ACTIVE"));
      assert.ok(isValidRegistryStatus("DEPRECATED"));
      assert.ok(isValidRegistryStatus("RETIRED"));
      assert.ok(isValidRegistryDescription("Valid description text"));
    });
  });

  // =========================================================================
  // NEGATIVE TEST SUITE
  // =========================================================================

  void describe("Negative Scenarios (N1 - N14)", () => {
    void it("N1: Duplicate composite keys are rejected in batch and against existing snapshot", () => {
      const input: RegistryEntryInput = {
        category: "event",
        id: "core.user.created",
        description: "User created event",
      };

      // Duplicate in same batch
      assert.throws(() => createRegistrySnapshot([input, input]), /DUPLICATE_ENTRY_IN_BATCH/);

      // Duplicate against existing snapshot
      const snap = createRegistrySnapshot([input]);
      assert.throws(() => registerEntries(snap, [input]), /DUPLICATE_ENTRY_DETECTED/);
    });

    void it("N2: Invalid or non-canonical namespace identifiers are rejected", () => {
      assert.throws(
        () =>
          createRegistrySnapshot([
            { category: "event", id: "core.invalid..id", description: "Double dot" },
          ]),
        /INVALID_REGISTRY_ID/,
      );

      assert.throws(
        () =>
          createRegistrySnapshot([
            { category: "event", id: "core.UPPERCASE.NOT.ALLOWED", description: "Uppercase" },
          ]),
        /INVALID_REGISTRY_ID/,
      );
    });

    void it("N3: Cross-module ownership escape attempts are rejected", () => {
      // Third-party ext module trying to declare an identifier outside its namespace
      assert.throws(
        () =>
          createRegistrySnapshot([
            {
              category: "event",
              id: "core.kernel.escaped", // Tries to claim core prefix
              description: "Escaped event",
              owner_module_id: "ext.attacker.mod",
            },
          ]),
        /MODULE_PREFIX_MISMATCH/,
      );
    });

    void it("N4: Unknown or invalid registry category is rejected", () => {
      assert.strictEqual(isValidRegistryCategory("INVALID_CAT"), false);
      assert.strictEqual(isValidRegistryCategory(""), false);
      assert.strictEqual(isValidRegistryCategory(123), false);

      assert.throws(
        () =>
          createRegistrySnapshot([
            {
              // @ts-expect-error Testing invalid category runtime rejection
              category: "INVALID_CAT",
              id: "core.app.item",
              description: "Invalid category test",
            },
          ]),
        /INVALID_REGISTRY_CATEGORY/,
      );
    });

    void it("N5: Accessor properties and getters are rejected fail-closed", () => {
      let getterRan = false;
      const hostileInput = {};
      Object.defineProperty(hostileInput, "category", {
        get() {
          getterRan = true;
          return "event";
        },
        enumerable: true,
      });
      Object.defineProperty(hostileInput, "id", {
        value: "core.app.hostile",
        enumerable: true,
      });
      Object.defineProperty(hostileInput, "description", {
        value: "Hostile input test",
        enumerable: true,
      });

      assert.throws(
        () => createRegistrySnapshot([hostileInput as RegistryEntryInput]),
        /HOSTILE_PROPERTY_DETECTED/,
      );
      assert.strictEqual(getterRan, false);
    });

    void it("N6: Prototype pollution attempts are detected and rejected", () => {
      const pollutedInput = JSON.parse(
        '{"__proto__":{"polluted":true},"category":"event","id":"core.app.polluted","description":"Polluted"}',
      ) as RegistryEntryInput;

      assert.throws(
        () => createRegistrySnapshot([pollutedInput]),
        /HOSTILE_OBJECT_DETECTED|UNKNOWN_PROPERTY_DETECTED/,
      );
    });

    void it("N7: Unknown properties in entry descriptors are rejected", () => {
      assert.throws(
        () =>
          createRegistrySnapshot([
            {
              category: "event",
              id: "core.app.extra",
              description: "Extra property test",
              // @ts-expect-error Testing unknown property rejection
              unexpected_field: "injected",
            },
          ]),
        /UNKNOWN_PROPERTY_DETECTED/,
      );
    });

    void it("N8: Validation errors do NOT disclose untrusted input values or secrets", () => {
      const secretToken = "ghp_SECRET_REGISTRY_TOKEN_987654321";
      let errorThrown: Error | null = null;

      try {
        createRegistrySnapshot([
          {
            // @ts-expect-error Testing secret-bearing invalid category
            category: secretToken,
            id: "core.app.item",
            description: "Secret test",
          },
        ]);
      } catch (err) {
        errorThrown = err as Error;
      }

      assert.ok(errorThrown);
      assert.strictEqual(errorThrown.message.includes(secretToken), false);
      assert.strictEqual(
        errorThrown.message,
        "INVALID_REGISTRY_CATEGORY: Unrecognized or invalid registry category",
      );
    });

    void it("N9: Invalid lifecycle transitions are rejected", () => {
      const snapActive = createRegistrySnapshot([
        { category: "permission", id: "sys.perm.direct", description: "Direct retired test" },
      ]);

      // Direct ACTIVE -> RETIRED is forbidden
      assert.throws(
        () => transitionRegistryEntry(snapActive, "permission", "sys.perm.direct", "RETIRED"),
        /INVALID_LIFECYCLE_TRANSITION/,
      );

      // DEPRECATED -> ACTIVE reverse transition is forbidden
      const snapDep = transitionRegistryEntry(
        snapActive,
        "permission",
        "sys.perm.direct",
        "DEPRECATED",
      );
      assert.throws(
        () => transitionRegistryEntry(snapDep, "permission", "sys.perm.direct", "ACTIVE"),
        /INVALID_LIFECYCLE_TRANSITION/,
      );
    });

    void it("N10: Re-registering a RETIRED entry identity is forbidden", () => {
      const snap0 = createRegistrySnapshot([
        { category: "route", id: "core.app.old_route", description: "Old route" },
      ]);

      const snap1 = transitionRegistryEntry(snap0, "route", "core.app.old_route", "DEPRECATED");
      const snap2 = transitionRegistryEntry(snap1, "route", "core.app.old_route", "RETIRED");

      // Re-registering same category + id after RETIRED must fail
      assert.throws(
        () =>
          registerEntries(snap2, [
            { category: "route", id: "core.app.old_route", description: "Re-registered route" },
          ]),
        /RETIRED_IDENTITY_REUSE_FORBIDDEN/,
      );
    });

    void it("N11: Lifecycle transition on non-existent entry ID throws ENTRY_NOT_FOUND", () => {
      const snap = createRegistrySnapshot();
      assert.throws(
        () => transitionRegistryEntry(snap, "event", "core.app.nonexistent", "DEPRECATED"),
        /ENTRY_NOT_FOUND/,
      );
    });

    void it("N12: Mutation attempts on frozen snapshot throw TypeError", () => {
      const snap = createRegistrySnapshot();
      assert.throws(() => {
        // @ts-expect-error Testing runtime frozen object safety
        snap.entries = [];
      }, TypeError);
    });

    void it("N13: Forged RegistrySnapshot objects passed to framework functions are rejected", () => {
      const forgedSnap = {
        revision: 0,
        snapshot_id: "reg-snap-forged",
        created_at: new Date().toISOString(),
        entries: [],
      };

      assert.strictEqual(isGenuineRegistrySnapshot(forgedSnap), false);
      assert.throws(
        () =>
          registerEntries(forgedSnap, [
            { category: "event", id: "core.app.e", description: "Desc" },
          ]),
        /UNAUTHENTIC_REGISTRY_SNAPSHOT/,
      );
    });

    void it("N14: Snapshot fixture verifies frozen shape consistency", () => {
      const snapshotPath = path.resolve(
        import.meta.dirname,
        "fixtures/registry.contract.snapshot.json",
      );
      const snapshotContent = fs.readFileSync(snapshotPath, "utf8");
      const snapshotData = JSON.parse(snapshotContent) as {
        contract_id: string;
        categories: readonly string[];
        statuses: readonly string[];
      };

      assert.strictEqual(snapshotData.contract_id, "CONTRACT-CORE-REGISTRY-FRAMEWORK-001");
      assert.deepStrictEqual(snapshotData.categories, [
        "module",
        "event",
        "permission",
        "settings",
        "route",
        "ui_extension",
        "provider",
      ]);
      assert.deepStrictEqual(snapshotData.statuses, ["ACTIVE", "DEPRECATED", "RETIRED"]);
    });

    void it("N15: Reject unauthorized roots and malformed pack/ext namespace arity", () => {
      // Unapproved root
      assert.throws(
        () =>
          createRegistrySnapshot([{ category: "event", id: "badroot.app.e", description: "Desc" }]),
        /INVALID_REGISTRY_ID/,
      );
      // Malformed core.integration (arity < 4)
      assert.throws(
        () =>
          createRegistrySnapshot([
            { category: "event", id: "core.integration.e", description: "Desc" },
          ]),
        /INVALID_REGISTRY_ID/,
      );
    });

    void it("N16: Converting untrusted validation exceptions into safe static error codes without reflecting input", () => {
      const invalidId = "core.app.INVALID_id_with_secret_value_12345";
      try {
        createRegistrySnapshot([{ category: "event", id: invalidId, description: "Desc" }]);
        assert.fail("Should have thrown");
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "";
        assert.ok(!msg.includes("secret_value"));
        assert.ok(msg.includes("INVALID_REGISTRY_ID"));
      }
    });

    void it("N17: ext.* registration requires explicit owner_module_id with self-ownership for modules", () => {
      // ext.* without owner
      assert.throws(
        () =>
          createRegistrySnapshot([
            { category: "event", id: "ext.publisher.module.entry", description: "Desc" },
          ]),
        /OWNER_MODULE_REQUIRED/,
      );
      // module without owner (missing owner)
      assert.throws(
        () =>
          createRegistrySnapshot([
            { category: "module", id: "core.app.module", description: "Desc" },
          ]),
        /OWNER_MODULE_REQUIRED/,
      );
      // module with mismatching owner
      assert.throws(
        () =>
          createRegistrySnapshot([
            {
              category: "module",
              id: "core.app.module",
              description: "Desc",
              owner_module_id: "core.app.other",
            },
          ]),
        /MODULE_PREFIX_MISMATCH/,
      );
    });

    void it("N18: Reject forged {length: 0} objects in createRegistrySnapshot", () => {
      const forged = { length: 0 } as unknown as readonly RegistryEntryInput[];
      assert.throws(() => createRegistrySnapshot(forged), TypeError);
    });

    void it("N19: Reject unexpected accessor properties and proxy descriptors fail-closed", () => {
      // Accessor property
      const badInput = {} as unknown as RegistryEntryInput;
      Object.defineProperty(badInput, "category", {
        get() {
          throw new Error("Trap triggered!");
        },
      });
      assert.throws(() => createRegistrySnapshot([badInput]), /HOSTILE_|MALFORMED_ENTRY/);

      // Hostile proxy
      const handler = {
        getOwnPropertyDescriptor() {
          throw new Error("Trap triggered!");
        },
      };
      const proxyInput = new Proxy(
        { category: "event", id: "core.app.e", description: "Desc" },
        handler,
      ) as unknown as RegistryEntryInput;
      assert.throws(() => createRegistrySnapshot([proxyInput]), /HOSTILE_|MALFORMED_ENTRY/);
    });

    void it("N20: Enforces snapshot immutability and rejects forged snapshots with unsafe revisions", () => {
      const snap = createRegistrySnapshot([]);
      assert.throws(() => {
        // @ts-expect-error Intentionally writing to frozen property to verify TypeError
        snap.revision = 999;
      }, TypeError);

      const forgedSnap = {
        revision: Number.MAX_SAFE_INTEGER + 10,
        snapshot_id: "reg-snap-forged",
        created_at: new Date().toISOString(),
        entries: [],
      } as unknown as RegistrySnapshot;

      assert.throws(
        () =>
          registerEntries(forgedSnap, [
            { category: "event", id: "core.app.e", description: "Desc" },
          ]),
        /UNAUTHENTIC_REGISTRY_SNAPSHOT/,
      );
    });
  });
});
