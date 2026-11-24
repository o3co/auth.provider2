import { type Eraser, erasers, type Walk } from "@mod/erasure-extensions";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import secretHashModule from "@mod/secret-hash/module";
import { store, storeControl } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { contactStore } from "@mod/users";
import usersModule from "@mod/users/module";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });
const seen = contract<readonly Eraser[]>("users-store-test.erasers");
const collecting = defineModule(
	{ name: "collecting", replicaSafe: true, takes: [erasers] },
	(m) => [m.provide(seen).by((c) => c.collect(erasers))],
);

it("migrates the contacts the reader phase wrote, then erases a subject's contacts", async () => {
	const simulated = simulatedStore();
	const base = await assemble({
		modules: [simulated.module, wiring],
		config: kernelConfig(),
		runtime,
	});
	const shared = defineModule({ name: "store", replicaSafe: true, takes: [] }, (m) => [
		m.provide(store).by(() => base.get(store)),
		m.provide(storeControl).by(() => base.get(storeControl)),
	]);

	// Written raw, as before records were indexed.
	const reader = await assemble({ modules: [shared, wiring], config: kernelConfig(), runtime });
	const email = (value: string) => [{ kind: "email", value }] as never;
	await reader.get(contactStore).save("s-a", email("a@example.com"), "endless", "s-a");
	await reader.get(contactStore).save("s-b", email("b@example.com"), "endless", "s-b");

	// The maintenance window marks records indexed; an instance started after it migrates.
	simulated.mark("subject-records.phase", "indexed");
	const app = await assemble({
		modules: [shared, wiring, usersModule, secretHashModule, collecting],
		config: { ...kernelConfig(), users: {} },
		runtime,
	});
	const eraser = app.get(seen).find((e) => e.name === "users");
	expect(eraser?.erasable).toBe(true);
	const inner = base.get(store);
	const walk: Walk = {
		sweep: async (space, cursor) => {
			const page = await inner.scan(simulated.declaredSpace(space), cursor);
			return page.cursor === undefined
				? { keys: page.keys, server: "one" }
				: { keys: page.keys, cursor: page.cursor, server: "one" };
		},
	};
	const signal = new AbortController().signal;
	expect(await eraser?.migrate(walk, signal)).toContainEqual({
		kind: "migrated",
		space: "users-store.contacts",
		indexed: 2,
		removed: 0,
	});
	const erased = await eraser?.online("s-a", signal);
	expect(erased?.reports.every((report) => report.kind === "erased")).toBe(true);
	const contacts = app.get(contactStore);
	expect(await contacts.read("s-a")).toBeUndefined();
	// Another subject's contacts stay, and nothing is created past the erasure.
	expect(await contacts.read("s-b")).toEqual([{ kind: "email", value: "b@example.com" }]);
	expect(await contacts.save("s-a", email("c@example.com"), "endless", "s-a")).toBe("erased");
});
