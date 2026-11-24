import { ruleSchemas } from "@mod/authority-rules";
import type {
	Deciding,
	IntentUnit,
	Json,
	OperationKind,
	PartNext,
	StateOwner,
} from "@mod/transparency";
import type { Flow } from "@mod/transparency-wire";
import { z } from "zod";

/**
 * The records passkeys keeps in its part of a subject's flow, the keys and the one reservation, and
 * the pure functions over them its registrations on `transparency` run.
 */

export const part = "passkeys";
const keysRecord = { part, name: "keys" } as const;
const reservationRecord = { part, name: "reservation" } as const;

/** A subject's flow: the unit its records are kept under. */
export const flowOf = (subject: string): Flow => ({ of: "subject", id: subject });
export const unitOf = (subject: string): IntentUnit => ({ flow: { of: "subject", id: subject } });

const id = z.string().min(1);

/** The flow state's fields passkeys holds, as its keys record keeps them. */
const keysShape = ruleSchemas.flowState.pick({ keyGeneration: true, keys: true });
export type Keys = z.output<typeof keysShape>;
const noKeys: Keys = { keyGeneration: 0, keys: {} };
/** The keys record read, none read as no key yet; a record of another shape decides nothing. */
export const keysOf = (held: Json | undefined): Keys =>
	held === undefined ? noKeys : keysShape.parse(held);
/** The active key of a credential, with the id of the record that made it. */
export const activeKey = (keys: Keys, credential: string) =>
	Object.entries(keys.keys).find(([, key]) => key.credential === credential);

/**
 * The reservation: the key reserved, its version (its key change's op), its state, the key
 * generation it was reserved under, and when it lapses (kernel clock) while reserved or verified.
 */
const reservationShape = z
	.object({
		version: id,
		state: z.enum(["reserved", "verified", "active", "ended", "cancelled"]),
		credential: id,
		publicKey: id,
		generation: z.number().int().nonnegative(),
		first: z.boolean(),
		until: z.number(),
		verification: id.optional(),
	})
	.strict();
export type Reservation = z.output<typeof reservationShape>;
/** The reservation read; none for none, or for a record of another shape. */
export const reservationOf = (held: Json | undefined): Reservation | undefined => {
	const read = reservationShape.safeParse(held);
	return read.success ? read.data : undefined;
};
/** Whether it holds its subject's one pending place at `now`. */
export const pendingAt = (r: Reservation | undefined, now: number) =>
	(r?.state === "reserved" || r?.state === "verified") && now <= r.until;
export const asJson = (r: Reservation) => r as unknown as Json;

/** A credential's record: its subject and what the authenticator answers beside the key. */
const credentialShape = z
	.object({
		subject: id,
		userHandle: id,
		signCount: z.number().int().nonnegative(),
		backupEligible: z.boolean(),
		backedUp: z.boolean(),
		transports: z.array(z.string()).optional(),
	})
	.strict();
export type CredentialRecord = z.output<typeof credentialShape>;
export const credentialRecordOf = (stored: unknown): CredentialRecord =>
	credentialShape.parse(stored);

/** passkeys as the owner of the keys and the key generation of a subject's flow state. */
export const keysOwner: StateOwner = {
	name: "passkeys",
	holds: ["keyGeneration", "keys"],
	parts: [part],
	records: () => [keysRecord],
	read: ([held]) => keysOf(held),
	write: (state, [held]) => {
		const next: Keys = { keyGeneration: state.keyGeneration, keys: state.keys };
		return [JSON.stringify(next) === JSON.stringify(keysOf(held)) ? undefined : { value: next }];
	},
};
export const keysRecords = keysOwner.records;

/** The ends that release a verified reservation's version for good (A19: held, abandoned). */
const ended = new Set(["held", "abandoned"]);

/** The key change's kind, but for its writer's `bundle` and `resend`. */
export const keyChanges: Pick<OperationKind, "name" | "parts" | "records" | "end"> = {
	name: "passkey",
	parts: [part],
	records: () => [reservationRecord],
	// Confirms the reservation its op is of where its key took, releases it otherwise.
	end: ({ op, ending }, [held]): PartNext[] => {
		const r = reservationOf(held);
		if (r?.version !== op || r.state !== "verified") return [undefined];
		if (ending === "took") return [{ value: asJson({ ...r, state: "active" }) }];
		return [ended.has(ending) ? { value: asJson({ ...r, state: "ended" }) } : undefined];
	},
};
export const reservationRecords = (subject: string) => keyChanges.records(flowOf(subject));

/** KE-C01 of a registration, on its reservation and the flow's state. */
export function committing(
	p: { readonly reservation: string; readonly verification: string },
	at: { readonly now: number; readonly max: number },
	inner: Deciding,
): Deciding {
	return (state, held) => {
		const r = reservationOf(held[0]);
		if (r?.version !== p.reservation) return { refused: "unknown" };
		if (r.state !== "verified") return { refused: "state" };
		if (r.verification !== p.verification) return { refused: "verification" };
		if (at.now > r.until) return { refused: "expired" };
		// A reset since it was reserved: a key approved before it never comes after it.
		if (r.generation !== state.keyGeneration) return { refused: "fenced" };
		const count = Object.keys(state.keys).length;
		if (r.first && count > 0) return { refused: "held" };
		if (activeKey(state, r.credential)) return { refused: "taken" };
		if (count >= at.max) return { refused: "full" };
		const asked = inner(state, held);
		if ("refused" in asked) return asked;
		const key = asked.eff.key;
		if (key?.credential !== r.credential || key.publicKey !== r.publicKey)
			throw new TypeError("a key change's changes name another key");
		return { ...asked, records: held.map(() => undefined) };
	};
}

/** KE-C01 of a removal of an active key; refused for the last unless `last` lets it go. */
export function removing(credential: string, last: boolean, inner: Deciding): Deciding {
	return (state, held) => {
		const key = activeKey(state, credential);
		if (!key) return { refused: "unknown" };
		if (!last && Object.keys(state.keys).length === 1) return { refused: "last" };
		const asked = inner(state, held);
		if ("refused" in asked) return asked;
		if (asked.eff.removeKey !== key[0])
			throw new TypeError("a key change's changes name another key");
		return { ...asked, records: held.map(() => undefined) };
	};
}
