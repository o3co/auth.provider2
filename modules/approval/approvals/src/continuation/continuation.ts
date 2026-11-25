import { createPublicKey, verify, type webcrypto } from "node:crypto";
import { continuations } from "@mod/continuation-wire";
import { Unavailable } from "@mod/kernel";
import type { Keys } from "@mod/keys";
import { continuation, hpke, type SigningKey } from "@mod/sdk-core-wire";
import type {
	ApprovalStore,
	Approvals,
	Continued,
	ItemsOf,
	KeptManage,
	OpenedBody,
	StepResult,
} from "../contract.ts";
import {
	current,
	issuedAtOf,
	itemsIn,
	recordEnd,
	recordOf,
	type StatementRecord,
	sha256,
	stored,
} from "../statement/statement.ts";

/** Whether `signature` (ES256, r‖s, base64url) is the screen's over `input`. */
function signedBy(key: SigningKey, input: string, signature: string): boolean {
	try {
		const publicKey = createPublicKey({ key: key as webcrypto.JsonWebKey, format: "jwk" });
		const bytes = Buffer.from(signature, "base64url");
		return verify(
			"sha256",
			Buffer.from(input, "utf8"),
			{ key: publicKey, dsaEncoding: "ieee-p1363" },
			bytes,
		);
	} catch {
		return false;
	}
}

/** The purposes whose ceremony goes on by continuations: a creation's, its registration. */
const continued = new Set(["creation"]);

/** How long a call that took a continuation's step holds it, in ms: past it, the same continuation runs the step again. */
const claimMs = 30_000;

/** The most a continuation's body holds, in UTF-8 bytes: what `front-core-wire`'s `continue` carries. */
const maxBodyBytes = 8192;

/** A signature's one spelling: 64 bytes (`r‖s`), base64url without padding, its last bits zero. */
const canonicalSignature = /^[A-Za-z0-9_-]{85}[AQgw]$/;

/** A sealed continuation's ciphertext: its padded plaintext and the AEAD's tag. */
const sealedBytes = continuations.plainBytes + 16;

/** The most continuations a statement takes. */
const maxSeq = 16;

/** Base64url bytes in their one spelling; none for any other text. */
const bytesOf = (text: string) => {
	if (!/^[A-Za-z0-9_-]*$/.test(text)) return undefined;
	const bytes = Buffer.from(text, "base64url");
	return bytes.toString("base64url") === text ? new Uint8Array(bytes) : undefined;
};

/** A continuation asked: a creation's (`continue`), or a T's sign-up (`continueSignUp`). */
type Ask =
	| (Parameters<Approvals["continue"]>[0] & { readonly stage: "register" })
	| (Parameters<Approvals["continueSignUp"]>[0] & { readonly stage: "sign-up" });
type Refusal = Extract<Continued, { kind: "refused" }>["reason"];

/**
 * Why a T's sign-up may not be taken now (F1), read in the write that takes it: its owner did not
 * allow it, the T is no longer issued, or it expired; none where it may.
 */
const signUpRefusal = (r: StatementRecord, now: number): Refusal | undefined => {
	if (!r.continues?.includes("sign-up")) return "purpose";
	if (r.state !== "issued") return "used";
	return now > r.exp ? "expired" : undefined;
};

/** Continuations: each the next sequence number, verified and taken in one write, its step run by one call and its answer kept. */
export function continuationsOver(p: {
	readonly keys: Pick<Keys, "verify" | "open">;
	readonly store: ApprovalStore;
	readonly now: () => number;
	readonly token: () => string;
}) {
	/**
	 * Takes the step of continuation `seq` for this call, in one write: the next number, once the last
	 * one's answer is kept; or the same one again, where its answer is not kept and no call holds it.
	 */
	const claim = async (
		hash: string,
		seq: number,
		body: string,
		sent: StatementRecord["sent"],
		by: string,
		signUp: boolean,
	) => {
		let refused: Refusal | undefined;
		const changed = await p.store.change(hash, (current) => {
			const now = recordOf(current);
			if (!now) return undefined;
			const claimed = { by, until: p.now() + claimMs };
			const next = now.seq === seq - 1 && (now.seq === 0 || now.result !== undefined);
			const free = now.claimed === undefined || now.claimed.until < p.now();
			const same = now.seq === seq && now.body === body && now.result === undefined;
			if (!next && !(same && free)) return undefined;
			// A sign-up is taken only while its T may begin one, on either path; its taking marks it begun.
			// Another stage's new number only before its statement expires, one taken again only before its record's end.
			refused = signUp
				? signUpRefusal(now, p.now())
				: p.now() > (next ? now.exp : recordEnd(now))
					? "expired"
					: undefined;
			if (refused) return undefined;
			const begun = signUp ? { signUp: now.signUp ?? {} } : {};
			if (next) {
				// The body and signature as sent are written with the number they took, never again for it.
				const { result: _kept, ...rest } = now;
				return {
					value: stored({ ...rest, ...begun, seq, body, ...(sent ? { sent } : {}), claimed }),
				};
			}
			return { value: stored({ ...now, ...begun, claimed }) };
		});
		return { after: recordOf(changed?.after), refused };
	};

	/** Keeps the step's answer where this call still holds the continuation. */
	const kept = async (hash: string, seq: number, by: string, result: StepResult) => {
		const changed = await p.store.change(hash, (current) => {
			const now = recordOf(current);
			if (now?.seq !== seq || now.claimed?.by !== by) return undefined;
			const { claimed: _done, ...rest } = now;
			return { value: stored({ ...rest, result: result as StatementRecord["result"] }) };
		});
		return recordOf(changed?.after);
	};

	/**
	 * After its checks: what was kept for this continuation, or its number taken (a new one before
	 * `exp` alone) and its step run under this call's hold, its answer kept.
	 */
	const proceed = async (
		q: { readonly hash: string; readonly seq: number },
		r: StatementRecord,
		body: string,
		sent: StatementRecord["sent"],
		signUp: boolean,
		step: () => Promise<StepResult>,
	): Promise<Continued> => {
		const answered = (x: StatementRecord | undefined, again: boolean): Continued | undefined =>
			x?.seq === q.seq && x.body === body && x.result !== undefined
				? { kind: "continued", seq: q.seq, again, result: x.result }
				: undefined;
		const before = answered(r, true);
		if (before) return before;
		if (!signUp && r.seq !== q.seq && p.now() > r.exp)
			return { kind: "refused", reason: "expired" };
		const by = p.token();
		const held = await claim(q.hash, q.seq, body, sent, by, signUp);
		if (held.refused) return { kind: "refused", reason: held.refused };
		if (held.after?.claimed?.by !== by) {
			const now = recordOf(await p.store.read(q.hash));
			const same = now?.seq === q.seq && now.body === body;
			return answered(now, true) ?? { kind: "refused", reason: same ? "pending" : "seq" };
		}
		const after = await kept(q.hash, q.seq, by, await step());
		return (
			answered(after, r.seq === q.seq) ??
			answered(recordOf(await p.store.read(q.hash)), true) ?? { kind: "refused", reason: "pending" }
		);
	};

	const run = async (q: Ask): Promise<Continued> => {
		const signUp = q.stage === "sign-up";
		const r = recordOf(await p.store.read(q.hash));
		if (!r) return { kind: "refused", reason: "unknown" };
		const purpose = signUp ? r.purpose === "authorization" : continued.has(r.purpose);
		if (!purpose) return { kind: "refused", reason: "purpose" };
		if (Buffer.byteLength(q.body, "utf8") > maxBodyBytes)
			return { kind: "refused", reason: "body" };
		// A sign-up's body is `{}` alone, its number 1 (continuation-wire's sign-up body, F1).
		if (signUp && q.body !== continuations.bodyText("sign-up", {}))
			return { kind: "refused", reason: "body" };
		if (signUp && q.seq !== 1) return { kind: "refused", reason: "seq" };
		if (!canonicalSignature.test(q.signature)) return { kind: "refused", reason: "signature" };
		const body = sha256(q.body);
		const input = signUp
			? continuations.of("sign-up", q.hash, q.seq, body)
			: continuation.of("register", q.hash, q.seq, body);
		if (!signedBy(r.e_sig, input, q.signature)) return { kind: "refused", reason: "signature" };
		const sent = { body: q.body, signature: q.signature };
		// Its items read from its bytes, the screen's keys from its record.
		const screen = { eEnc: r.e_enc, eSig: r.e_sig };
		return proceed(q, r, body, sent, signUp, () =>
			q.stage === "sign-up"
				? q.step({
						hash: q.hash,
						statement: r.jws,
						issuedAt: issuedAtOf(r.jws),
						items: itemsIn(r.jws, "authorization") as ItemsOf["authorization"],
						screen,
					})
				: q.step({ items: itemsIn(r.jws, "creation") as ItemsOf["creation"], screen }),
		);
	};

	/** The used passkey-manage a sealed continuation goes on from, and its body opened; none for any failure. */
	const openedFor = async (
		q: Parameters<Approvals["continueSealed"]>[0],
	): Promise<
		{ kept: KeptManage; opened: OpenedBody; r: StatementRecord } | "expired" | undefined
	> => {
		const enc = bytesOf(q.sealed.enc);
		const ct = bytesOf(q.sealed.ct);
		if (enc?.length !== 65 || ct?.length !== sealedBytes) return undefined;
		const r = recordOf(await p.store.read(q.hash));
		if (r?.purpose !== "passkey-manage" || r.state === "issued") return undefined;
		if (!r.subject || !r.credential || !r.registration) return undefined;
		if (!(await current(p.keys, r.jws))) return undefined;
		// A new number past expiry is refused before the holder is asked to open it.
		if (r.seq !== q.seq && p.now() > r.exp) return "expired";
		const aad = new TextEncoder().encode(continuations.aad(q.stage, q.hash, q.seq));
		const opened = await p.keys.open({ enc, ct }, hpke.info.continuation, aad);
		if (opened.kind === "withdrawn") throw new Unavailable("approvals");
		if (opened.kind !== "opened") return undefined;
		let text: string;
		try {
			text = new TextDecoder("utf-8", { fatal: true }).decode(opened.plaintext);
		} catch {
			return undefined;
		}
		const read = continuations.readPlain(q.stage, text);
		const bodyText = read && continuations.bodyText(q.stage, read.body);
		if (!read || bodyText === undefined) return undefined;
		const bodyHash = sha256(bodyText);
		const input = continuations.of(q.stage, q.hash, q.seq, bodyHash);
		if (!signedBy(r.e_sig, input, read.sig)) return undefined;
		const kept = {
			hash: q.hash,
			subject: r.subject,
			credential: r.credential,
			registration: r.registration,
			screen: { eEnc: r.e_enc, eSig: r.e_sig },
			until: recordEnd(r),
		};
		return { kept, opened: { stage: q.stage, body: read.body as OpenedBody["body"], bodyHash }, r };
	};

	const continueSealed = async (
		q: Parameters<Approvals["continueSealed"]>[0],
	): Promise<Continued> => {
		if (!Number.isInteger(q.seq) || q.seq < 1 || q.seq > maxSeq)
			return { kind: "refused", reason: "seq" };
		const found = await openedFor(q);
		if (found === "expired") return { kind: "refused", reason: "expired" };
		if (!found) return { kind: "refused", reason: "sealed" };
		// The body's hash alone is kept, never the opened text; a rename's carries a label and a
		// delete's none, so the two stages' hashes never meet.
		return proceed(q, found.r, found.opened.bodyHash, undefined, false, () =>
			q.step(found.kept, found.opened),
		);
	};

	return {
		continue: (q: Parameters<Approvals["continue"]>[0]) => run({ ...q, stage: "register" }),
		continueSignUp: (q: Parameters<Approvals["continueSignUp"]>[0]) =>
			run({ ...q, stage: "sign-up" }),
		continueSealed,
	};
}
