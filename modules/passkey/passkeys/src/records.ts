import { type FlowState, ruleSchemas, withoutRooted } from "@mod/authority-rules";
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
const settledRecord = { part, name: "settled" } as const;

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
		/** The digest of the response that verified it, and what it showed: the same response, the same answer. */
		shown: id.optional(),
		userVerified: z.boolean().optional(),
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

/**
 * A credential's record: the binding to its subject (none once released) and the count, kept as the
 * log keeps the key's flow; and what the authenticator answered beside the key, dropped once the
 * subject holds the key no more.
 */
const credentialShape = z
	.object({
		subject: id.optional(),
		signCount: z.number().int().nonnegative(),
		details: z
			.object({
				userHandle: id,
				backupEligible: z.boolean(),
				backedUp: z.boolean(),
				transports: z.array(z.string()).optional(),
			})
			.strict()
			.optional(),
	})
	.strict();
export type CredentialRecord = z.output<typeof credentialShape>;
export const credentialRecordOf = (stored: unknown): CredentialRecord =>
	credentialShape.parse(stored);

/** What the last settle told of: the key generation and the credentials active then. */
const settledShape = z
	.object({ generation: z.number().int().nonnegative(), credentials: z.array(id) })
	.strict();
export type Settled = z.output<typeof settledShape>;
export const settledOf = (held: Json | undefined): Settled | undefined => {
	const read = settledShape.safeParse(held);
	return read.success ? read.data : undefined;
};
export const settledRecords = () => [settledRecord];

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

/** The credentials active in a state. */
export const credentialsOf = (keys: Keys) => Object.values(keys.keys).map((k) => k.credential);
/** The credentials a removal of `credential`'s key takes: it and every key whose chain holds it. */
export function keysGoneWith(state: FlowState, credential: string): readonly string[] {
	const key = activeKey(state, credential);
	if (!key) return [];
	const left = new Set(credentialsOf(withoutRooted(state, key[0])));
	return credentialsOf(state).filter((c) => !left.has(c));
}

/** The ends that release a verified reservation's version for good (A19: held, abandoned). */
const ended = new Set(["held", "abandoned"]);

/**
 * The key change's kind, but for its writer's `bundle` and `resend`. Its records are passkeys' alone
 * (the reservation); a writer keeping its own appends them after, and its end answers for its own.
 */
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
		return { ...asked, records: writersOwn(asked.records, held) };
	};
}

/** The writer's records of the kind kept as it wrote them; passkeys' reservation, first, left. */
function writersOwn(records: readonly PartNext[], held: readonly (Json | undefined)[]) {
	if (records.length !== held.length)
		throw new TypeError("a key change wrote another count of records than it read");
	return [undefined, ...records.slice(1)];
}

/**
 * KE-C01 of a removal of an active key: refused where no key would be left after it, as the fold
 * takes every key whose chain holds it too. Never the reservation's op.
 */
export function removing(
	p: { readonly credential: string; readonly op: string },
	inner: Deciding,
): Deciding {
	return (state, held) => {
		if (reservationOf(held[0])?.version === p.op) return { refused: "op" };
		const key = activeKey(state, p.credential);
		if (!key) return { refused: "unknown" };
		if (Object.keys(withoutRooted(state, key[0]).keys).length === 0) return { refused: "last" };
		const asked = inner(state, held);
		if ("refused" in asked) return asked;
		if (asked.eff.removeKey !== key[0])
			throw new TypeError("a key change's changes name another key");
		return { ...asked, records: writersOwn(asked.records, held) };
	};
}
