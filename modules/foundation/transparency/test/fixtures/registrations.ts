import type { FlowState } from "@mod/authority-rules";
import type { Json } from "@mod/store";
import type { Flow } from "@mod/transparency-wire";
import type { OperationKind, PartNext, Stage, StateOwner } from "../../src/contract.ts";

/** A state owner keeping its fields of a flow's state in one record of its own part. */
function fieldsOwner(name: string, holds: readonly (keyof FlowState)[]): StateOwner {
	return {
		name,
		holds,
		parts: [name],
		records: () => [{ part: name, name: "state" }],
		read: ([held]) => (held ?? {}) as Partial<FlowState>,
		write: (state, [held]): PartNext[] => {
			const mine = Object.fromEntries(holds.map((field) => [field, state[field]])) as Json;
			return [JSON.stringify(mine) === JSON.stringify(held ?? null) ? undefined : { value: mine }];
		},
	};
}

/** The owners of every field: keys (with the key generation), grants (approvals, use-once marks), families. */
export const owners: readonly StateOwner[] = [
	fieldsOwner("keys", ["keyGeneration", "keys"]),
	fieldsOwner("grants", ["approvals", "consumed"]),
	fieldsOwner("families", ["families"]),
];

/** The flow's state a test starts from: a first-trust key `k1` and its approval `a1`. */
export const seeded = {
	keys: {
		keyGeneration: 0,
		keys: {
			k1: { credential: "c1", publicKey: "p1", chain: [], position: 1, acceptedAt: 0 },
		},
	},
	grants: {
		approvals: { a1: { chain: ["k1"], code: "code1", client: "rp", position: 1, acceptedAt: 0 } },
		consumed: [],
	},
	families: { families: {} },
} as const;

/** Issuing: its last stage a bundle, holding no records of its own. */
export const issue: OperationKind = {
	name: "issue",
	bundle: true,
	parts: [],
	records: () => [],
	end: () => [],
};

export interface Reservation {
	readonly version: string;
	readonly state: "verified" | "active" | "ended" | "cancelled";
	readonly credential: string;
	readonly publicKey: string;
}
export const reservationRecord = { part: "reservations", name: "reservation" } as const;

/** A key change's stage, from its reservation: the same id and content on every send. */
export const keyStage = (flow: Flow, r: Reservation): Stage => ({
	kind: "keyChange",
	flow,
	op: r.version,
	stage: 1,
	last: true,
	preimage: {
		v: 1,
		evidence: [],
		content: { variant: "first", credential: r.credential, publicKey: r.publicKey },
	},
});

/** A key change over a reservation record its writer keeps: its end confirms or releases it. */
export const keyChange: OperationKind = {
	name: "key",
	bundle: false,
	parts: ["reservations"],
	records: () => [reservationRecord],
	end: ({ ending }, [held]) => {
		const r = held as unknown as Reservation;
		const state =
			ending === "took"
				? "active"
				: ending === "held" || ending === "abandoned"
					? "ended"
					: "verified";
		return [{ value: { ...r, state } }];
	},
	resend: (flow, op, [held]) => {
		const r = held as unknown as Reservation | undefined;
		return r && r.version === op ? keyStage(flow, r) : undefined;
	},
};

export const allParts = ["keys", "grants", "families", "reservations"] as const;
