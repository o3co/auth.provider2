import { Unavailable } from "@mod/kernel";
import type { FrameStore } from "@mod/transparency";
import type { Ceremonies, Credential, Verification } from "@mod/webauthn";
import type {
	PasskeyRemoval,
	PasskeyStore,
	Passkeys,
	PasskeyWitnessing,
	StoredCredential,
} from "./contract.ts";
import {
	activeKey,
	type CredentialRecord,
	credentialRecordOf,
	keysOf,
	keysRecords,
	unitOf,
} from "./records.ts";

/** What reads and asserts the keys kept: the frames, the credential records, the ceremonies. */
export interface KeptParts {
	readonly frames: FrameStore;
	readonly store: PasskeyStore;
	readonly ceremonies: Ceremonies;
	readonly verification: Verification;
}

/** The keys a subject's flow holds, as its keys record keeps them. */
export async function keysHeld(frames: FrameStore, subject: string) {
	const read = await frames.read(unitOf(subject), keysRecords(unitOf(subject).flow));
	return keysOf(read.held[0]);
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

/** The credential the ceremonies check with: the record's, and the key its flow or reservation holds. */
export const credentialOf = (id: string, publicKey: string, r: CredentialRecord): Credential => ({
	id,
	publicKey,
	signCount: r.signCount,
	userHandle: r.userHandle,
	backupEligible: r.backupEligible,
	backedUp: r.backedUp,
	...(r.transports ? { transports: r.transports } : {}),
});

/**
 * Moves the count and backup state on, only over the record judged: one whose count moved meanwhile
 * is `raced`.
 */
export async function counted(store: PasskeyStore, judged: CredentialRecord, after: Credential) {
	const changed = await store.change(after.id, (stored) => {
		const now = credentialRecordOf(stored);
		if (now.subject !== judged.subject || now.signCount !== judged.signCount) return undefined;
		const next = { ...now, signCount: after.signCount, backedUp: after.backedUp };
		return { value: next as unknown as StoredCredential };
	});
	return changed && credentialRecordOf(changed.after).signCount === after.signCount
		? "counted"
		: "raced";
}

/** Assertions by active keys, their public keys, and the settle after a key change. */
export function keptOver(
	p: KeptParts & {
		readonly witnessing: PasskeyWitnessing | undefined;
		readonly removals: readonly PasskeyRemoval[];
	},
): Passkeys {
	/** A credential's record and its active key, none where its subject's flow holds no such key. */
	const active = async (id: string) => {
		const record = await credentialRecord(p.store, id);
		if (!record) return undefined;
		const key = activeKey(await keysHeld(p.frames, record.subject), id);
		return key && { record, publicKey: key[1].publicKey };
	};
	const refused = (reason: "unknown-credential" | "not-named" | "raced") =>
		({ kind: "refused", reason }) as const;
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
				credentialOf(id, found.publicKey, found.record),
				p.verification,
			);
			if (asserted.kind === "refused") return asserted;
			if ((await counted(p.store, found.record, asserted.credential)) === "raced")
				return refused("raced");
			return {
				kind: "asserted",
				subject: found.record.subject,
				credential: id,
				userVerified: asserted.userVerified,
				backupEligible: found.record.backupEligible,
			};
		},
		async publicKeyOf(id) {
			const found = await active(id);
			return found && { subject: found.record.subject, publicKey: found.publicKey };
		},
		async settle(subject, gone = []) {
			const keys = await keysHeld(p.frames, subject);
			const emptied = Object.keys(keys.keys).length === 0;
			for (const id of gone.filter((c) => !activeKey(keys, c))) {
				for (const removal of p.removals) await removal.removed(subject, id, emptied);
			}
			const holds = async () => Object.keys((await keysHeld(p.frames, subject)).keys).length > 0;
			return p.witnessing ? p.witnessing.settle(subject, holds) : !emptied;
		},
	};
}
