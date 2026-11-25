import { emptyState, type FlowState } from "@mod/authority-rules";
import type { Ending, Json } from "@mod/transparency";
import { describe, expect, it } from "vitest";
import { committing, keyChanges, keysOwner, type Reservation, removing } from "../records.ts";

const reservation: Reservation = {
	version: "v1",
	state: "verified",
	credential: "c1",
	publicKey: "p1",
	generation: 0,
	first: true,
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
		expect(commit(state({ k: key("c1") }), held({ first: false }))).toEqual({ refused: "taken" });
		expect(commit(state({ a: key("a"), b: key("b") }), held({ first: false }))).toEqual({
			refused: "full",
		});
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
	it("refuses what would leave no key; a key under it stays and counts", () => {
		expect(remove(state({ k1: key("c1") }))).toEqual({ refused: "last" });
		// The writer's own refusal is read first, on the same state.
		const refusing = removing({ credential: "c1", op: "rm" }, () => ({ refused: "approver" }));
		expect(refusing(state({ k1: key("c1") }), held())).toEqual({ refused: "approver" });
		expect(remove(state({ k1: key("c1"), k2: under("c2", ["k1"]) }))).toMatchObject({
			eff: { removeKey: "k1" },
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
		// Nor may a removal add a key.
		const adding = removing({ credential: "c1", op: "rm" }, () => ({
			digest: "d",
			eff: { removeKey: "k1", key: { credential: "c9", publicKey: "p" } },
			records: [],
		}));
		expect(() => adding(s, held())).toThrow(TypeError);
	});
});

describe("the keys' owner", () => {
	it("keeps the key generation and the keys, writing only what changed", () => {
		const s = state({ k1: key("c1") }, 2);
		const [written, noted] = keysOwner.write(s, [undefined, undefined]);
		expect(written).toEqual({ value: { keyGeneration: 2, keys: s.keys } });
		expect(noted).toBeUndefined();
		const value = (written as { value: Json }).value;
		expect(keysOwner.read([value, undefined])).toEqual({ keyGeneration: 2, keys: s.keys });
		expect(keysOwner.write(s, [value, undefined])).toEqual([undefined, undefined]);
	});
	it("notes, in the same write, each credential the Step takes off, keeping the latest", () => {
		const before = { keyGeneration: 0, keys: { k1: key("c1"), k2: key("c2") } } as unknown as Json;
		const [, noted] = keysOwner.write(state({ k2: key("c2") }), [before, { next: 4, gone: [] }]);
		expect(noted).toEqual({ value: { next: 5, gone: [{ n: 5, credential: "c1" }] } });
		const many = {
			next: 64,
			gone: Array.from({ length: 64 }, (_, i) => ({ n: i + 1, credential: `x${i}` })),
		};
		const [, kept] = keysOwner.write(state({ k2: key("c2") }), [before, many as unknown as Json]);
		const gone = (kept as { value: { gone: { n: number }[] } }).value.gone;
		expect(gone).toHaveLength(64);
		expect(gone.at(-1)).toEqual({ n: 65, credential: "c1" });
	});
});
