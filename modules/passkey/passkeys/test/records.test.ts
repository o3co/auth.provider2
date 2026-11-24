import { emptyState, type FlowState } from "@mod/authority-rules";
import type { Ending, Json } from "@mod/transparency";
import { describe, expect, it } from "vitest";
import {
	committing,
	keyChanges,
	keysGoneWith,
	keysOwner,
	type Reservation,
	removing,
} from "../src/records.ts";

const reservation: Reservation = {
	version: "v1",
	state: "verified",
	credential: "c1",
	publicKey: "p1",
	generation: 0,
	first: false,
	until: 100,
	verification: "x1",
};
const held = (r: Partial<Reservation> = {}) => [{ ...reservation, ...r } as unknown as Json];
const key = (credential: string) => ({
	credential,
	publicKey: "p",
	chain: [] as string[],
	position: 1,
	acceptedAt: 0,
});
const state = (
	keys: Record<string, ReturnType<typeof key>> = {},
	keyGeneration = 0,
): FlowState => ({
	...emptyState,
	keyGeneration,
	keys,
});
const registered = { digest: "d", eff: { key: { credential: "c1", publicKey: "p1" } } };
const registering = (_s: FlowState, h: readonly (Json | undefined)[]) => ({
	...registered,
	records: h.map(() => undefined),
});

describe("the key change's end", () => {
	const end = (op: string, ending: Ending, r = held()) => keyChanges.end({ op, ending }, r);
	it("confirms the reservation its op is of where the key took, and releases it otherwise", () => {
		expect(end("v1", "took")).toEqual([{ value: { ...reservation, state: "active" } }]);
		expect(end("v1", "held")).toEqual([{ value: { ...reservation, state: "ended" } }]);
		expect(end("v1", "abandoned")).toEqual([{ value: { ...reservation, state: "ended" } }]);
		// Refused, or not taken: still verified, to be decided again.
		expect(end("v1", "didNotTake")).toEqual([undefined]);
		expect(end("v1", "refused")).toEqual([undefined]);
	});
	it("leaves a reservation of another op, or not verified, as it is", () => {
		expect(end("v2", "took")).toEqual([undefined]);
		expect(end("v1", "took", held({ state: "cancelled" }))).toEqual([undefined]);
		expect(end("v1", "took", [{ broken: true }])).toEqual([undefined]);
	});
});

describe("committing (KE-C01 of a registration)", () => {
	const commit = (s: FlowState, r = held(), at = { now: 50, max: 2 }) =>
		committing({ reservation: "v1", verification: "x1" }, at, registering)(s, r);
	it("decides on a verified reservation, writing none of its records", () => {
		expect(commit(state())).toEqual({ ...registered, records: [undefined] });
	});
	it("refuses a lapsed one, one of another key generation, a first where a key is held, a full flow", () => {
		expect(commit(state(), held(), { now: 101, max: 2 })).toEqual({ refused: "expired" });
		expect(commit(state({}, 1))).toEqual({ refused: "fenced" });
		expect(commit(state({ k: key("c9") }), held({ first: true }))).toEqual({ refused: "held" });
		expect(commit(state({ k: key("c1") }))).toEqual({ refused: "taken" });
		expect(commit(state({ a: key("a"), b: key("b") }))).toEqual({ refused: "full" });
		expect(commit(state(), held({ version: "v2" }))).toEqual({ refused: "unknown" });
	});
});

describe("removing", () => {
	const writer = { value: "mine" };
	const remove = (s: FlowState, credential = "c1", removeKey = "k1") =>
		removing({ credential, op: "rm" }, (_s, h) => ({
			digest: "d",
			eff: { removeKey },
			records: h.map(() => writer),
		}))(s, [...held(), null]);
	const under = (credential: string, chain: string[]) => ({ ...key(credential), chain });
	it("refuses what would leave no key, the keys whose chain holds it counted", () => {
		expect(remove(state({ k1: key("c1") }))).toEqual({ refused: "last" });
		expect(remove(state({ k1: key("c1"), k2: under("c2", ["k1"]) }))).toEqual({
			refused: "last",
		});
		// The writer's own records are kept; passkeys' reservation, first, is left as it is.
		expect(remove(state({ k1: key("c1"), k2: key("c2") }))).toEqual({
			digest: "d",
			eff: { removeKey: "k1" },
			records: [undefined, writer],
		});
	});
	it("refuses the reservation's op, and throws where the writer's changes remove another key", () => {
		const s = state({ k1: key("c1"), k2: key("c2") });
		expect(
			removing({ credential: "c1", op: "v1" }, () => ({
				digest: "d",
				eff: {},
				records: [],
			}))(s, held()),
		).toEqual({ refused: "op" });
		expect(() => remove(s, "c2", "k1")).toThrow(TypeError);
	});
	it("tells the credentials a removal takes: its key and every key whose chain holds it", () => {
		const s = state({ k1: key("c1"), k2: under("c2", ["k1"]), k3: key("c3") });
		expect(keysGoneWith(s, "c1")).toEqual(["c1", "c2"]);
		expect(keysGoneWith(s, "c3")).toEqual(["c3"]);
		expect(keysGoneWith(s, "none")).toEqual([]);
	});
});

describe("the keys' owner", () => {
	it("keeps the key generation and the keys, writing only what changed", () => {
		const s = state({ k1: key("c1") }, 2);
		const [written] = keysOwner.write(s, [undefined]);
		expect(written).toEqual({ value: { keyGeneration: 2, keys: s.keys } });
		const value = (written as { value: Json }).value;
		expect(keysOwner.read([value])).toEqual({ keyGeneration: 2, keys: s.keys });
		expect(keysOwner.write(s, [value])).toEqual([undefined]);
	});
});
