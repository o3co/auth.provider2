import { createHash } from "node:crypto";
import { Unavailable } from "@mod/kernel";
import type { Transparency } from "@mod/transparency";
import { type Credential, credentialOf as readCredential } from "@mod/webauthn";
import type {
	PasskeyClearing,
	Passkeys,
	PasskeyWitnessing,
	Registrations,
	ReserveRefusal,
} from "./contract.ts";
import {
	counted,
	credentialOf,
	credentialRecord,
	type KeptParts,
	keysHeld,
	stored,
} from "./kept.ts";
import {
	activeKey,
	asJson,
	committing,
	credentialRecordOf,
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
	readonly settle: Passkeys["settle"];
	readonly now: () => number;
	/** A new reservation's version or verification: 16 random bytes, unpadded base64url. */
	readonly token: () => string;
	readonly lifetimeMs: number;
	readonly max: number;
}

const digestOf = (response: unknown) =>
	createHash("sha256")
		.update(JSON.stringify(response) ?? "")
		.digest("base64url");

/** Registrations and clearing: every change of a reservation is held to the frame (`changeHeld`). */
export function registeringOver(p: RegisteringParts): Registrations & PasskeyClearing {
	/** The reservation as read now, with the change held to it: refused where it moved since. */
	const reservationAt = async (subject: string) => {
		const records = reservationRecords(subject);
		const read = await p.frames.read(unitOf(subject), records);
		const raw = read.held[0];
		return {
			reservation: reservationOf(raw),
			/** Writes `next` held to the frame, only where the record holds what was read. */
			change: async (next: Reservation) => {
				let same = false;
				const changed = await p.transparency.changeHeld({
					kind: keyChanges.name,
					flow: flowOf(subject),
					records,
					change: ([held]) => {
						same = JSON.stringify(held) === JSON.stringify(raw);
						return [same ? { value: asJson(next) } : undefined];
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
	/**
	 * Binds the credential to the subject, unless another subject's binding or other details name it.
	 * Never lowers a count nor overwrites a backup state kept: a reserve that loses rolls nothing back.
	 */
	const bound = async (subject: string, c: Credential) => {
		const details = {
			userHandle: c.userHandle,
			backupEligible: c.backupEligible,
			backedUp: c.backedUp,
			...(c.transports ? { transports: [...c.transports] } : {}),
		};
		const created = await p.store.create(
			c.id,
			stored({ subject, signCount: c.signCount, details }),
		);
		if (created === "created") return true;
		const same = (r: ReturnType<typeof credentialRecordOf>) =>
			(r.subject === undefined || r.subject === subject) &&
			(!r.details ||
				(r.details.userHandle === c.userHandle && r.details.backupEligible === c.backupEligible));
		const changed = await p.store.change(c.id, (current) => {
			const now = credentialRecordOf(current);
			if (!same(now) || (now.subject === subject && now.details)) return undefined;
			const signCount = Math.max(now.signCount, c.signCount);
			return { value: stored({ subject, signCount, details: now.details ?? details }) };
		});
		const after = changed && credentialRecordOf(changed.after);
		return after?.subject === subject && same(after);
	};
	/** Releases a never-active credential's binding, so another subject may register it. */
	const release = async (subject: string, r: Reservation | undefined, keep?: string) => {
		if (!r || r.state === "active" || r.credential === keep) return;
		if (activeKey(await keysHeld(p.frames, subject), r.credential)) return;
		await p.store.change(r.credential, (current) => {
			const now = credentialRecordOf(current);
			return now.subject === subject ? { value: stored({ signCount: now.signCount }) } : undefined;
		});
	};
	const removal = (last: boolean) => async (q: Parameters<PasskeyClearing["clear"]>[0]) =>
		p.transparency.decide({
			kind: keyChanges.name,
			flow: flowOf(q.subject),
			op: q.op,
			decide: removing({ credential: q.credential, op: q.op, last }, q.decide),
		});

	return {
		async reserve(q) {
			if (!readCredential(q.credential)) throw new TypeError("a reserved credential is malformed");
			const { subject, credential } = q;
			// The mark settled first: a first key only where the keys and the witness both say none.
			if (q.first && ((await p.settle(subject)) || (await p.witnessing?.marked(subject))))
				return { refused: "held" };
			const reserved = await held<
				{ reservation: string; replaced?: Reservation } | { refused: ReserveRefusal }
			>(async () => {
				const keys = await keysHeld(p.frames, subject);
				const at = await reservationAt(subject);
				const r = at.reservation;
				if (q.first && Object.keys(keys.keys).length > 0) return { refused: "held" };
				if (activeKey(keys, credential.id)) return { refused: "taken" };
				if (q.retrying !== undefined && r?.version !== q.retrying) return { refused: "unknown" };
				if (q.retrying !== undefined && (r?.state === "active" || r?.state === "cancelled"))
					return { refused: "state" };
				if (q.retrying === undefined && pendingAt(r, p.now())) return { refused: "pending" };
				// A retry keeps the key generation of the one it releases.
				const generation = q.retrying !== undefined && r ? r.generation : keys.keyGeneration;
				if (q.generation !== generation) return { refused: "fenced" };
				if (!(await bound(subject, credential))) return { refused: "taken" };
				const next: Reservation = {
					version: p.token(),
					state: "reserved",
					credential: credential.id,
					publicKey: credential.publicKey,
					generation,
					first: q.first === true,
					until: p.now() + p.lifetimeMs,
				};
				const changed = await at.change(next);
				if (changed === "open") return { refused: "open" };
				if (changed !== "changed") return "moved";
				return { reservation: next.version, ...(r ? { replaced: r } : {}) };
			});
			if (!("reservation" in reserved)) return reserved;
			await release(subject, reserved.replaced, credential.id);
			return { reservation: reserved.reservation };
		},
		async verifyPending(q) {
			const shown = digestOf(q.response);
			return held(async () => {
				const at = await reservationAt(q.subject);
				const r = at.reservation;
				if (r?.version !== q.reservation) return { refused: "unknown" as const };
				if (r.state !== "reserved" && r.state !== "verified") return { refused: "state" as const };
				// The response that verified it, sent again: the same answer, the count not asked again.
				if (r.verification && r.shown === shown)
					return { verification: r.verification, userVerified: r.userVerified === true };
				if (p.now() > r.until) return { refused: "expired" as const };
				const id = (q.response as { id?: unknown } | null)?.id;
				const record = id === r.credential ? await credentialRecord(p.store, id) : undefined;
				const credential = record && credentialOf(r.credential, r.publicKey, record);
				if (!credential || record?.subject !== q.subject) return { refused: "unknown" as const };
				// The possession request names the reserved key alone.
				const asserted = await p.ceremonies.assert(
					q.response,
					{ challenge: q.challenge, named: true },
					credential,
					p.verification,
				);
				if (asserted.kind === "refused") return { refused: asserted.reason };
				const verification = r.verification ?? p.token();
				const { userVerified } = asserted;
				const changed = await at.change({
					...r,
					state: "verified",
					verification,
					shown,
					userVerified,
				});
				if (changed !== "changed")
					return changed === "open" ? { refused: "open" as const } : "moved";
				// Counted once verified, so a write that moved asks the same count again.
				if ((await counted(p.store, record, asserted.credential)) === "raced")
					return { refused: "raced" as const };
				return { verification, userVerified };
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
			const cancelled = await held(async () => {
				const at = await reservationAt(q.subject);
				const r = at.reservation;
				if (r?.version !== q.reservation) return { refused: "unknown" as const };
				if (r.state === "active" || r.state === "cancelled") return { refused: "state" as const };
				const changed = await at.change({ ...r, state: "cancelled" });
				if (changed === "open") return { refused: "open" as const };
				return changed === "changed" ? r : "moved";
			});
			if ("refused" in cancelled) return cancelled;
			await release(q.subject, cancelled);
			return { cancelled: true };
		},
		remove: removal(false),
		clear: removal(true),
	};
}
