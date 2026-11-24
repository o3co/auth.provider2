import { Unavailable } from "@mod/kernel";
import type { Transparency } from "@mod/transparency";
import { credentialOf as readCredential } from "@mod/webauthn";
import type {
	PasskeyClearing,
	PasskeyWitnessing,
	Registrations,
	ReserveRefusal,
	StoredCredential,
} from "./contract.ts";
import { counted, credentialOf, credentialRecord, type KeptParts, keysHeld } from "./kept.ts";
import {
	activeKey,
	asJson,
	committing,
	flowOf,
	keyChanges,
	pendingAt,
	type Reservation,
	removing,
	reservationOf,
	reservationRecords,
	unitOf,
} from "./records.ts";

/** How many times a change held to a reservation read is tried before it is unavailable. */
const tries = 3;

export interface RegisteringParts extends KeptParts {
	readonly transparency: Transparency;
	readonly witnessing: PasskeyWitnessing | undefined;
	readonly now: () => number;
	/** A new reservation's version or verification: 16 random bytes, unpadded base64url. */
	readonly token: () => string;
	readonly lifetimeMs: number;
	readonly max: number;
}

/** Registrations and clearing: every change of a reservation is held to the frame (`changeHeld`). */
export function registeringOver(p: RegisteringParts): Registrations & PasskeyClearing {
	/** The reservation as read now, with the change held to it: refused where it moved since. */
	const reservationAt = async (subject: string) => {
		const records = reservationRecords(subject);
		const read = await p.frames.read(unitOf(subject), records);
		const raw = read.held[0];
		return {
			reservation: reservationOf(raw),
			/** Writes `next` (none keeps it) held to the frame, only where the record holds what was read. */
			change: async (next: Reservation | undefined) => {
				let same = false;
				const changed = await p.transparency.changeHeld({
					kind: keyChanges.name,
					flow: flowOf(subject),
					records,
					change: ([held]) => {
						same = JSON.stringify(held) === JSON.stringify(raw);
						return [same && next ? { value: asJson(next) } : undefined];
					},
				});
				if ("refused" in changed) return changed.refused === "open" ? "open" : "moved";
				return same ? "changed" : "moved";
			},
		};
	};
	/** Runs `attempt` again while the record it read moved under it. */
	const held = async <T>(attempt: () => Promise<T | "moved">): Promise<T> => {
		for (let i = 0; i < tries; i++) {
			const done = await attempt();
			if (done !== "moved") return done;
		}
		throw new Unavailable("passkeys");
	};
	/** Keeps the credential's record for the subject, unless another subject's names it. */
	const recorded = async (
		subject: string,
		c: Parameters<Registrations["reserve"]>[0]["credential"],
	) => {
		const record = {
			subject,
			userHandle: c.userHandle,
			signCount: c.signCount,
			backupEligible: c.backupEligible,
			backedUp: c.backedUp,
			...(c.transports ? { transports: c.transports } : {}),
		} as unknown as StoredCredential;
		if ((await p.store.create(c.id, record)) === "created") return true;
		const changed = await p.store.change(c.id, (now) =>
			(now as unknown as { subject: string }).subject === subject ? { value: record } : undefined,
		);
		return (changed?.after as unknown as { subject?: string } | undefined)?.subject === subject;
	};
	const removal = (last: boolean) => async (q: Parameters<PasskeyClearing["clear"]>[0]) =>
		p.transparency.decide({
			kind: keyChanges.name,
			flow: flowOf(q.subject),
			op: q.op,
			decide: removing(q.credential, last, q.decide),
		});

	return {
		async reserve(q) {
			if (!readCredential(q.credential)) throw new TypeError("a reserved credential is malformed");
			const { subject, credential } = q;
			const holds = async () => Object.keys((await keysHeld(p.frames, subject)).keys).length > 0;
			// The witness settles first: a first key only where the mark, in line with the keys, says none.
			if (q.first && (p.witnessing ? await p.witnessing.settle(subject, holds) : await holds()))
				return { refused: "held" };
			return held<{ reservation: string } | { refused: ReserveRefusal }>(async () => {
				const keys = await keysHeld(p.frames, subject);
				const at = await reservationAt(subject);
				const r = at.reservation;
				if (q.first && Object.keys(keys.keys).length > 0) return { refused: "held" };
				if (activeKey(keys, credential.id)) return { refused: "taken" };
				if (q.retrying !== undefined && r?.version !== q.retrying) return { refused: "unknown" };
				if (q.retrying !== undefined && (r?.state === "active" || r?.state === "cancelled"))
					return { refused: "state" };
				if (q.retrying === undefined && pendingAt(r, p.now())) return { refused: "pending" };
				if (!(await recorded(subject, credential))) return { refused: "taken" };
				const next: Reservation = {
					version: p.token(),
					state: "reserved",
					credential: credential.id,
					publicKey: credential.publicKey,
					// A retry keeps the key generation of the one it releases.
					generation: q.retrying !== undefined && r ? r.generation : keys.keyGeneration,
					first: q.first === true,
					until: p.now() + p.lifetimeMs,
				};
				const changed = await at.change(next);
				if (changed === "open") return { refused: "open" };
				return changed === "changed" ? { reservation: next.version } : "moved";
			});
		},
		async verifyPending(q) {
			return held(async () => {
				const at = await reservationAt(q.subject);
				const r = at.reservation;
				if (r?.version !== q.reservation) return { refused: "unknown" as const };
				if (r.state !== "reserved" && r.state !== "verified") return { refused: "state" as const };
				if (p.now() > r.until) return { refused: "expired" as const };
				const id = (q.response as { id?: unknown } | null)?.id;
				const record = id === r.credential ? await credentialRecord(p.store, id) : undefined;
				if (record?.subject !== q.subject) return { refused: "unknown" as const };
				// The possession request names the reserved key alone.
				const asserted = await p.ceremonies.assert(
					q.response,
					{ challenge: q.challenge, named: true },
					credentialOf(r.credential, r.publicKey, record),
					p.verification,
				);
				if (asserted.kind === "refused") return { refused: asserted.reason };
				const verification = r.verification ?? p.token();
				const changed =
					r.state === "verified"
						? "changed"
						: await at.change({ ...r, state: "verified", verification });
				if (changed !== "changed")
					return changed === "open" ? { refused: "open" as const } : "moved";
				// Counted once verified, so a write that moved asks the same count again.
				if ((await counted(p.store, record, asserted.credential)) === "raced")
					return { refused: "raced" as const };
				return { verification, userVerified: asserted.userVerified };
			});
		},
		commit: (q) =>
			p.transparency.decide({
				kind: keyChanges.name,
				flow: flowOf(q.subject),
				op: q.reservation,
				decide: committing(q, { now: p.now(), max: p.max }, q.decide),
			}),
		async cancel(q) {
			return held(async () => {
				const at = await reservationAt(q.subject);
				const r = at.reservation;
				if (r?.version !== q.reservation) return { refused: "unknown" as const };
				if (r.state === "active" || r.state === "cancelled") return { refused: "state" as const };
				const changed = await at.change({ ...r, state: "cancelled" });
				if (changed === "open") return { refused: "open" as const };
				return changed === "changed" ? { cancelled: true as const } : "moved";
			});
		},
		remove: removal(false),
		clear: removal(true),
	};
}
