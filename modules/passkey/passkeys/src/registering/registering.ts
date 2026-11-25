import { createHash } from "node:crypto";
import { Unavailable } from "@mod/kernel";
import type { Transparency } from "@mod/transparency";
import { type Credential, credentialOf as readCredential } from "@mod/webauthn";
import type { Passkeys, PasskeyWitnessing, Registrations, ReserveRefusal } from "../contract.ts";
import { credentialOf, credentialRecord, type KeptParts, keysHeld, stored } from "../kept/kept.ts";
import {
	activeKey,
	asJson,
	type CredentialRecord,
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
} from "../records.ts";

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

/** Registrations: every change of a reservation is held to the frame (`changeHeld`). */
export function registeringOver(p: RegisteringParts): Registrations {
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
	 * Binds the credential to the subject under the reservation `version`, unless another subject's
	 * binding or other details name it, or another reservation of the subject's, unfinished, holds it
	 * (any but the one `replacing`, before its lapse). Never lowers a count nor overwrites the details
	 * kept; details made, or kept with no time, take this reservation's time. Answers the binding it took over, to hand back where the reservation is not written.
	 */
	const bound = async (subject: string, c: Credential, version: string, replacing?: string) => {
		const details = {
			userHandle: c.userHandle,
			backupEligible: c.backupEligible,
			backedUp: c.backedUp,
			...(c.transports ? { transports: [...c.transports] } : {}),
			createdAt: p.now(),
		};
		const until = p.now() + p.lifetimeMs;
		const made = { subject, version, until, signCount: c.signCount, details };
		if ((await p.store.create(c.id, stored(made))) === "created") return { previous: undefined };
		const same = (r: CredentialRecord) =>
			(r.subject === undefined || r.subject === subject) &&
			(!r.details ||
				(r.details.userHandle === c.userHandle && r.details.backupEligible === c.backupEligible));
		const heldByAnother = (r: CredentialRecord) =>
			r.subject === subject &&
			r.version !== undefined &&
			r.version !== replacing &&
			(r.until ?? 0) >= p.now();
		let previous: CredentialRecord | undefined;
		const changed = await p.store.change(c.id, (current) => {
			const now = credentialRecordOf(current);
			if (!same(now) || heldByAnother(now)) return undefined;
			previous = now;
			const signCount = Math.max(now.signCount, c.signCount);
			return {
				value: stored({
					...now,
					subject,
					version,
					until,
					signCount,
					// Details kept keep their time; a record from before times gets this reservation's.
					details: now.details
						? { ...now.details, createdAt: now.details.createdAt ?? details.createdAt }
						: details,
				}),
			};
		});
		const after = changed && credentialRecordOf(changed.after);
		return after?.subject === subject && after.version === version && same(after)
			? { previous }
			: undefined;
	};
	/**
	 * Releases the binding `version` made, so another subject may register the credential; never a
	 * key active now or once.
	 */
	const release = async (subject: string, credential: string, version: string) => {
		if (activeKey(await keysHeld(p.frames, subject), credential)) return;
		await p.store.change(credential, (current) => {
			const now = credentialRecordOf(current);
			if (now.subject !== subject || now.version !== version || now.active) return undefined;
			return { value: stored({ signCount: now.signCount }) };
		});
	};
	/** A reservation not written hands back the binding it took over, or unbinds the one it made. */
	const handBack = async (
		subject: string,
		credential: string,
		version: string,
		previous: CredentialRecord | undefined,
	) => {
		if (previous?.subject !== subject) return release(subject, credential, version);
		await p.store.change(credential, (current) => {
			const now = credentialRecordOf(current);
			if (now.subject !== subject || now.version !== version) return undefined;
			const { version: _v, until: _u, ...kept } = now;
			return {
				value: stored({
					...kept,
					...(previous.version ? { version: previous.version } : {}),
					...(previous.until !== undefined ? { until: previous.until } : {}),
				}),
			};
		});
	};
	/** Saves the count a pending key's assertion showed, never lowering it. */
	const saved = (subject: string, credential: string, count: number) =>
		p.store.change(credential, (current) => {
			const now = credentialRecordOf(current);
			if (now.subject !== subject || now.signCount >= count) return undefined;
			return { value: stored({ ...now, signCount: count }) };
		});

	return {
		async reserve(q) {
			if (!readCredential(q.credential)) throw new TypeError("a reserved credential is malformed");
			const { subject, credential } = q;
			// The mark settled first: a first key only where the keys and the witness both say none.
			if (q.first && ((await p.settle(subject)) || (await p.witnessing?.marked(subject))))
				return { refused: "held" };
			let binding: { version: string; previous: CredentialRecord | undefined } | undefined;
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
				const version = p.token();
				const took = await bound(subject, credential, version, r?.version);
				if (!took) return { refused: "taken" };
				binding = { version, previous: took.previous };
				const next: Reservation = {
					version,
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
			if (!("reservation" in reserved)) {
				// A reserve that bound and then lost leaves the binding as it found it.
				if (binding) await handBack(subject, credential.id, binding.version, binding.previous);
				return reserved;
			}
			const { replaced } = reserved;
			if (replaced && replaced.state !== "active")
				await release(subject, replaced.credential, replaced.version);
			return { reservation: reserved.reservation };
		},
		async verifyPending(q) {
			const shown = digestOf({ response: q.response, challenge: q.challenge });
			return held(async () => {
				const at = await reservationAt(q.subject);
				const r = at.reservation;
				if (r?.version !== q.reservation) return { refused: "unknown" as const };
				if (r.state !== "reserved" && r.state !== "verified") return { refused: "state" as const };
				// The response and challenge that verified it, sent again: its count saved, the same answer.
				if (r.verification && r.shown === shown && r.count !== undefined) {
					await saved(q.subject, r.credential, r.count);
					return { verification: r.verification, userVerified: r.userVerified === true };
				}
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
				const count = asserted.credential.signCount;
				const changed = await at.change({
					...r,
					state: "verified",
					verification,
					shown,
					userVerified,
					count,
				});
				if (changed !== "changed")
					return changed === "open" ? { refused: "open" as const } : "moved";
				// Saved once verified: a call that fails here is answered alike when sent again, saving it.
				await saved(q.subject, r.credential, count);
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
			await release(q.subject, cancelled.credential, cancelled.version);
			return { cancelled: true };
		},
		remove: (q) =>
			p.transparency.decide({
				kind: keyChanges.name,
				flow: flowOf(q.subject),
				op: q.op,
				decide: removing({ credential: q.credential, op: q.op }, q.decide),
			}),
	};
}
