import { createHash } from "node:crypto";
import type { Approval, Approvals, KeptCreation, StepResult } from "@mod/approvals";
import { Unavailable } from "@mod/kernel";
import type { Held, Passkeys, Registrations } from "@mod/passkeys";
import { challengeInput, payloads } from "@mod/sdk-core-wire";
import type { SubjectRevocation } from "@mod/subject-revocation";
import {
	type Ceremonies,
	type Credential,
	credentialLimits,
	isCanonical,
	keyThumbprint,
} from "@mod/webauthn";
import type { Changed, FirstKeyChange } from "../key-change/key-change.ts";

/** A continuation of a creation's statement, as the screen signed it. */
export interface Continuation {
	readonly statement: string;
	readonly seq: number;
	readonly body: string;
	readonly sig: string;
}

/** A registration's answer: the possession, or the completion sealed to the screen; or refused, its reason for the log alone. */
export type Registered =
	| { readonly kind: "possession"; readonly statement: string }
	| { readonly kind: "completed"; readonly enc: string; readonly ct: string }
	| { readonly kind: "refused"; readonly reason: string };

export interface RegistrationParts {
	readonly approvals: Pick<
		Approvals,
		"continue" | "issue" | "creationOf" | "use" | "usedOf" | "completeKeyChange"
	>;
	readonly registrations: Pick<Registrations, "reserve" | "verifyPending">;
	readonly held: { of(subject: string): Promise<Held> };
	readonly ceremonies: Pick<Ceremonies, "attest">;
	readonly revocation: Pick<SubjectRevocation, "check">;
	readonly passkeys: Pick<Passkeys, "publicKeyOf">;
	readonly keyChange: {
		change(k: FirstKeyChange): Promise<Changed>;
		receipts(k: FirstKeyChange): Promise<readonly string[] | undefined>;
	};
}

/** A possession's items, every one its `sdk-core-wire` schema names, which the registration fills. */
export const possessionItems = {
	purpose: "possession",
	names: ["creation_hash", "key_jkt", "credential_id", "reservation_id"],
	by: "passkey-management",
} as const;

const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");
const refused = (reason: string) => ({ kind: "refused", reason }) as const;
const unavailable = (): never => {
	throw new Unavailable("passkey-management");
};
const json = (text: string): unknown => {
	try {
		return JSON.parse(text);
	} catch {
		return undefined;
	}
};
/** A compact JWS's payload, unverified: its caller trusts it only as what it checks next. */
const payloadOf = (jws: string): unknown =>
	json(Buffer.from(jws.split(".")[1] ?? "", "base64url").toString("utf8"));
/** When a statement was issued, in ms, from bytes its record holds. */
const issuedAt = (jws: string) =>
	((payloadOf(jws) as { iat?: number } | undefined)?.iat ?? 0) * 1000;
/** Only the first key's path registers here: a creation of another basis is refused. */
const firstKey = (c: KeptCreation["items"]) => c.basis === undefined || c.basis === "first-key";

/**
 * A first key's registration after its creation (§3.13's steps 4 to 6): `register`, the creation's
 * continuation, reserves the key and signs its possession; `finish` checks the possession's
 * assertion, uses the possession, puts the key change on the subject's flow and completes it.
 */
export function registrationOver(p: RegistrationParts) {
	/**
	 * The reservation of the new key: one of the same credential and key already pending is carried on
	 * as it is, never replaced, so a step run again (its first run fell after it reserved, or ran late
	 * past another's) names the reservation a possession kept may name. A possession naming a pending
	 * reservation completes only with that key's assertion over that possession, which only the key's
	 * holder makes: the same credential and key need no creation's hash beside them.
	 * Any other pending reservation refuses.
	 */
	async function reservedFor(c: KeptCreation["items"], k: Credential) {
		for (let tried = 0; tried < 2; tried++) {
			const pending = (await p.held.of(c.subject)).pending;
			if (pending)
				return pending.credential === k.id && pending.publicKey === k.publicKey
					? pending.reservation
					: { refused: "pending" };
			const reserved = await p.registrations.reserve({
				subject: c.subject,
				credential: k,
				generation: c.kg,
				first: true,
			});
			if ("reservation" in reserved) return reserved.reservation;
			// The flow open meanwhile: nothing kept, the same continuation asked again later.
			if (reserved.refused === "open") return unavailable();
			// Another call reserved it between the read and now: read again, once.
			if (reserved.refused !== "pending") return { refused: reserved.refused };
		}
		return { refused: "pending" };
	}

	/** The continuation's step: what it answers is kept on the creation's record and answered again alike. */
	const step =
		(q: Continuation, hash: string) =>
		async (kept: KeptCreation): Promise<StepResult> => {
			const c = kept.items;
			if (!firstKey(c)) return { refused: "basis" };
			const response = json(q.body);
			if (response === undefined) return { refused: "malformed" };
			const challenge = sha256(challengeInput(q.statement, "create"));
			const attested = await p.ceremonies.attest(
				response,
				challenge,
				c.options.user_id,
				"required",
			);
			if (attested.kind === "refused") return { refused: attested.reason };
			const k = attested.credential;
			// An id past what a continuation's body carries would list a key that is never deleted.
			if (!isCanonical(k.id, credentialLimits.idBytes)) return { refused: "credential" };
			const thumb = keyThumbprint(k.publicKey);
			const offered: readonly number[] = c.options.algorithms;
			if (!thumb || !offered.includes(thumb.alg)) return { refused: "key" };
			if ((await p.revocation.check(c.subject, issuedAt(q.statement))) === "revoked")
				return { refused: "revoked" };
			const reservation = await reservedFor(c, k);
			if (typeof reservation !== "string") return reservation;
			const issued = await p.approvals.issue({
				purpose: "possession",
				items: {
					creation_hash: hash,
					key_jkt: thumb.jkt,
					credential_id: k.id,
					reservation_id: reservation,
				},
				screen: kept.screen,
				by: c.subject,
			});
			// Counted out, busy or withdrawn: nothing kept, the same continuation asked again later.
			if (issued.kind === "refused" && issued.reason !== "items") return unavailable();
			if (issued.kind === "refused") return { refused: "items" };
			return { statement: issued.statement };
		};

	async function register(q: Continuation): Promise<Registered> {
		const hash = sha256(q.statement);
		const continued = await p.approvals.continue({
			hash,
			seq: q.seq,
			body: q.body,
			signature: q.sig,
			step: step(q, hash),
		});
		if (continued.kind === "refused") {
			// Another call holds its step: asked again, as a store that cannot tell yet.
			if (continued.reason === "pending") return unavailable();
			return refused(continued.reason);
		}
		const result = continued.result as { statement?: string; refused?: string } | null;
		if (typeof result?.statement === "string")
			return { kind: "possession", statement: result.statement };
		return refused(result?.refused ?? "step");
	}

	/** A possession's completion as approvals answers it: the one kept, or one signed with `receipt`. */
	async function completion(hash: string, receipt?: string): Promise<Registered> {
		const done = await p.approvals.completeKeyChange({
			hash,
			purpose: "first-key",
			...(receipt === undefined ? {} : { receipt }),
		});
		if (done.kind === "completed") return { kind: "completed", enc: done.enc, ct: done.ct };
		// The ring signing no more for now: the change stands, its completion asked again later.
		return done.reason === "withdrawn" ? unavailable() : refused(done.reason);
	}
	/** The completion approvals keeps for a possession it holds completed: none is signed anew. */
	const kept = (hash: string) => completion(hash);
	/** A completion signed with the first receipt its change was answered with; never one without. */
	const receipted = (hash: string, receipts: readonly string[]) => {
		const [receipt] = receipts;
		return receipt === undefined ? unavailable() : completion(hash, receipt);
	};

	/**
	 * A change placed already, by this call's change or another replica's: completed with the receipt
	 * the log first answered, its stage made again from the key now active; none where it is not.
	 */
	async function placed(hash: string, k: Omit<FirstKeyChange, "publicKey">, jkt: string) {
		const key = await p.passkeys.publicKeyOf(k.credential);
		if (key?.subject !== k.subject || keyThumbprint(key.publicKey)?.jkt !== jkt)
			return refused("ended");
		const receipts = await p.keyChange.receipts({ ...k, publicKey: key.publicKey });
		return receipts ? receipted(hash, receipts) : refused("ended");
	}

	async function finish(q: {
		readonly statement: string;
		readonly assertion: string;
	}): Promise<Registered> {
		const hash = sha256(q.statement);
		// A completion kept is answered as kept, whatever has lapsed since of what made it.
		const used = await p.approvals.usedOf(hash);
		if (used?.purpose === "possession" && used.completed) return kept(hash);
		// Unverified until approvals holds it used: what it names only picks what it is checked against.
		const read = payloads.possession.safeParse(payloadOf(q.statement));
		if (!read.success) return refused("unknown");
		const named = read.data.possession;
		const creation = await p.approvals.creationOf(named.creation_hash);
		if (!creation || !firstKey(creation.items)) return refused("unknown");
		const subject = creation.items.subject;
		const response = json(q.assertion);
		if (response === undefined) return refused("malformed");
		const verified = await p.registrations.verifyPending({
			subject,
			reservation: named.reservation_id,
			response,
			challenge: sha256(challengeInput(q.statement, "get")),
		});
		let approval: Approval;
		if ("refused" in verified) {
			// Its reservation moved on past verified: a finish asked again once its change was decided.
			const used = verified.refused === "state" ? await p.approvals.usedOf(hash) : undefined;
			if (!used || used.purpose !== "possession") return refused(verified.refused);
			approval = used;
		} else {
			if (!verified.userVerified) return refused("unverified");
			const used = await p.approvals.use({
				statement: q.statement,
				verification: verified.verification,
			});
			if (used.kind === "refused") return refused(used.reason);
			approval = used.approval;
		}
		// The possession is the Core's from here: the creation it names, and that creation's subject, hold.
		if (approval.completed) return kept(hash);
		if (approval.verification === undefined) return refused("unknown");
		if ((await p.revocation.check(subject, issuedAt(creation.statement))) === "revoked")
			return refused("revoked");
		const k = {
			subject,
			reservation: named.reservation_id,
			verification: approval.verification,
			credential: named.credential_id,
			creation: creation.statement,
			possession: q.statement,
			assertion: q.assertion,
		};
		const held = await p.held.of(subject);
		const pending = held.pending;
		if (pending?.reservation !== named.reservation_id || pending.credential !== named.credential_id)
			return held.credentials.includes(named.credential_id)
				? placed(hash, k, named.key_jkt)
				: refused("reservation");
		if (keyThumbprint(pending.publicKey)?.jkt !== named.key_jkt) return refused("key");
		const changed = await p.keyChange.change({ ...k, publicKey: pending.publicKey });
		if (changed.kind === "refused") return refused(changed.reason);
		if (changed.kind === "took") return receipted(hash, changed.receipts);
		// Ended otherwise: taken in by another replica, or closed; only a change the log placed completes.
		return placed(hash, k, named.key_jkt);
	}

	return { register, finish };
}
