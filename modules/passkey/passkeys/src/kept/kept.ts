import { Unavailable } from "@mod/kernel";
import type { FrameStore, Transparency } from "@mod/transparency";
import type { Ceremonies, Credential, Verification } from "@mod/webauthn";
import type {
	Held,
	PasskeyRemoval,
	PasskeyStore,
	Passkeys,
	PasskeyWitnessing,
	StoredCredential,
} from "../contract.ts";
import {
	activeKey,
	type CredentialRecord,
	credentialRecordOf,
	credentialsOf,
	flowOf,
	keyChanges,
	keysOf,
	keysRecords,
	noticesOf,
	pendingAt,
	reservationOf,
	reservationRecords,
	settledOf,
	settledRecords,
	unitOf,
} from "../records.ts";

/** What reads and asserts the keys kept: the frames, the credential records, the ceremonies. */
export interface KeptParts {
	readonly frames: FrameStore;
	readonly store: PasskeyStore;
	readonly ceremonies: Ceremonies;
	readonly verification: Verification;
}

/** The keys a subject's flow holds, as its keys record keeps them: the applied state. */
export async function keysHeld(frames: FrameStore, subject: string) {
	const read = await frames.read(unitOf(subject), keysRecords(unitOf(subject).flow));
	return keysOf(read.held[0]);
}

/**
 * A subject's keys and pending reservation as its flow's records hold them, in one read, and the
 * witness's mark, frozen: all always read.
 */
export async function heldOf(
	frames: FrameStore,
	witnessing: PasskeyWitnessing | undefined,
	subject: string,
	now: number,
): Promise<Held> {
	const unit = unitOf(subject);
	const records = keysRecords(unit.flow);
	const read = await frames.read(unit, [...records, ...reservationRecords(subject)]);
	const keys = keysOf(read.held[0]);
	const r = reservationOf(read.held[records.length]);
	const marked = (await witnessing?.marked(subject)) === true;
	const pending =
		r && pendingAt(r, now)
			? { reservation: r.version, credential: r.credential, publicKey: r.publicKey }
			: undefined;
	return Object.freeze({
		credentials: Object.freeze(credentialsOf(keys)),
		marked,
		...(pending ? { pending: Object.freeze(pending) } : {}),
	});
}

/** A credential's record, read in the shape written; a record of another shape is unavailable. */
export async function credentialRecord(store: PasskeyStore, id: string) {
	const stored = await store.read(id);
	if (stored === undefined) return undefined;
	try {
		return credentialRecordOf(stored);
	} catch {
		throw new Unavailable("passkeys");
	}
}
export const stored = (r: CredentialRecord) => r as unknown as StoredCredential;

/** The credential the ceremonies check with, where the record binds it and keeps its details. */
export const credentialOf = (
	id: string,
	publicKey: string,
	r: CredentialRecord,
): Credential | undefined =>
	r.details && {
		id,
		publicKey,
		signCount: r.signCount,
		userHandle: r.details.userHandle,
		backupEligible: r.details.backupEligible,
		backedUp: r.details.backedUp,
		...(r.details.transports ? { transports: r.details.transports } : {}),
	};

/**
 * Moves the count and backup state on, only over the record judged: one whose subject or count moved
 * meanwhile is `raced`, and changes nothing.
 */
export async function counted(store: PasskeyStore, judged: CredentialRecord, after: Credential) {
	const changed = await store.change(after.id, (current) => {
		const now = credentialRecordOf(current);
		if (now.subject !== judged.subject || now.signCount !== judged.signCount || !now.details)
			return undefined;
		const details = { ...now.details, backedUp: after.backedUp };
		return { value: stored({ ...now, signCount: after.signCount, details }) };
	});
	return changed && credentialRecordOf(changed.after).signCount === after.signCount
		? "counted"
		: "raced";
}

/** Assertions by active keys, their public keys, and the settle after a key change. */
export function keptOver(
	p: KeptParts & {
		readonly transparency: Transparency;
		readonly witnessing: PasskeyWitnessing | undefined;
		readonly removals: readonly PasskeyRemoval[];
	},
): Passkeys {
	/** A credential's record and its active key, none where its subject's flow holds no such key. */
	const active = async (id: string) => {
		const record = await credentialRecord(p.store, id);
		if (!record?.subject) return undefined;
		const key = activeKey(await keysHeld(p.frames, record.subject), id);
		const credential = key && credentialOf(id, key[1].publicKey, record);
		return credential && { record, subject: record.subject, credential, registration: key[0] };
	};
	const refused = (reason: "unknown-credential" | "not-named" | "raced") =>
		({ kind: "refused", reason }) as const;
	/** Drops a gone credential's details, keeping its binding and count. */
	const dropDetails = (subject: string, id: string) =>
		p.store.change(id, (current) => {
			const { details, ...now } = credentialRecordOf(current);
			return now.subject === subject && details ? { value: stored(now) } : undefined;
		});
	/** Notes on an active key's record that it was active: its binding is never released. */
	const wasActive = (subject: string, id: string) =>
		p.store.change(id, (current) => {
			const now = credentialRecordOf(current);
			return now.subject === subject && !now.active
				? { value: stored({ ...now, active: true }) }
				: undefined;
		});
	return {
		async assert(response, asked) {
			const id = (response as { id?: unknown } | null)?.id;
			if (typeof id !== "string") return { kind: "refused", reason: "malformed" };
			// WebAuthn §7.2 step 6: a request that named credentials takes only those.
			if (asked.allow.length > 0 && !asked.allow.includes(id)) return refused("not-named");
			const found = await active(id);
			if (!found) return refused("unknown-credential");
			const asserted = await p.ceremonies.assert(
				response,
				{ challenge: asked.challenge, named: asked.allow.length > 0 },
				found.credential,
				p.verification,
			);
			if (asserted.kind === "refused") return asserted;
			if ((await counted(p.store, found.record, asserted.credential)) === "raced")
				return refused("raced");
			return {
				kind: "asserted",
				subject: found.subject,
				credential: id,
				registration: found.registration,
				userVerified: asserted.userVerified,
				backupEligible: found.credential.backupEligible,
			};
		},
		async publicKeyOf(id) {
			const found = await active(id);
			return (
				found && {
					subject: found.subject,
					publicKey: found.credential.publicKey,
					registration: found.registration,
				}
			);
		},
		async settle(subject) {
			const records = settledRecords();
			const read = await p.frames.read(unitOf(subject), [
				...keysRecords(flowOf(subject)),
				...records,
			]);
			const [keysHeldNow, noted, settledHeld] = read.held;
			const keys = keysOf(keysHeldNow);
			const notices = noticesOf(noted);
			const before = settledOf(settledHeld);
			// Keys behind what a settle saw were lost or rolled back: telling from them would mislead.
			if (
				before &&
				(keysHeldNow === undefined ||
					keys.keyGeneration < before.generation ||
					notices.next < before.told)
			)
				throw new Unavailable("passkeys");
			const now = credentialsOf(keys);
			for (const id of now) await wasActive(subject, id);
			// Marks of a generation before the current go at every settle, one a stopped settle left too.
			await p.witnessing?.withdraw(subject, keys.keyGeneration);
			if (now.length > 0 && p.witnessing) {
				await p.witnessing.mark(subject, keys.keyGeneration);
				// A boundary taken in meanwhile leaves the mark just set behind: read again and withdraw it.
				const again = await keysHeld(p.frames, subject);
				if (again.keyGeneration > keys.keyGeneration)
					await p.witnessing.withdraw(subject, again.keyGeneration);
			}
			for (const { credential } of notices.gone.filter((g) => g.n > (before?.told ?? 0))) {
				if (now.includes(credential)) continue;
				for (const removal of p.removals)
					await removal.removed(subject, credential, now.length === 0);
				await dropDetails(subject, credential);
			}
			// A flow whose keys were never written leaves nothing to be held to.
			if (keysHeldNow === undefined) return false;
			const next = { generation: keys.keyGeneration, told: notices.next };
			// Held to what it read; a write refused leaves the next settle to tell the same again.
			await p.transparency.changeHeld({
				kind: keyChanges.name,
				flow: flowOf(subject),
				records,
				change: ([held]) => [
					JSON.stringify(held) === JSON.stringify(settledHeld) ? { value: next } : undefined,
				],
			});
			return now.length > 0;
		},
	};
}
