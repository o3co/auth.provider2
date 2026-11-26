import { z } from "zod";
import {
	approvalDigests,
	count,
	digest,
	ecKey,
	type Flow,
	flow,
	id,
	keyChangeDigests,
	ordinal,
	type RecordRef,
	recordId,
	recordRef,
	v,
	writer,
} from "../records/records.ts";
import type { ReceiverKey, SignerSet } from "../signed-bodies/signed-bodies.ts";
import { canonical, coordinate, isObject, onP256, readJson } from "../text/text.ts";
import { frames, logTyps, recordKinds } from "../words/words.ts";

/**
 * The token receipt gate: the claim a token carries its receipt in, the frames, the one JSON
 * reading, what a token's digest covers, the input of an ID token's `esig`, and the words of the
 * receivers' checks (R16–R18).
 */
export const tokens = Object.freeze({
	claim: "txr",
	frames,
	/** Reads a JSON text, refusing a key named twice at any depth and a number past a double. */
	parse: readJson,
	/**
	 * From a token's header and claims texts, each read by `parse` and an object: the two, the
	 * receipt claim left out, canonically. The digest is this text's SHA-256.
	 */
	digestInput: (
		header: string,
		claims: string,
	): { readonly input: string } | { readonly error: string } => {
		const h = readJson(header);
		const c = readJson(claims);
		if ("error" in h) return h;
		if ("error" in c) return c;
		if (!isObject(h.value) || !isObject(c.value)) return { error: "not_object" };
		return { input: canonical({ header: h.value, claims: { ...c.value, txr: undefined } }) };
	},
	/**
	 * A P-256 key's RFC 7638 thumbprint input (its members sorted, no whitespace), the thumbprint
	 * being this text's SHA-256: `esig`'s. None for a key of other members, kind or curve, or whose x
	 * or y is not 32 bytes in canonical base64url, or is no point of the curve: a key exported with
	 * more members (`kid`, `alg`, `ext`, `key_ops`) is trimmed to these four first.
	 */
	ecThumbprintInput: (jwk: unknown): string | undefined => {
		if (!isObject(jwk) || Object.keys(jwk).sort().join() !== "crv,kty,x,y") return undefined;
		if (jwk.kty !== "EC" || jwk.crv !== "P-256") return undefined;
		const x = coordinate(jwk.x);
		const y = coordinate(jwk.y);
		if (x === undefined || y === undefined || !onP256(x, y)) return undefined;
		return `{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`;
	},
	/**
	 * The receivers' checks: the frames a receipt check (R16, R17) reads, and each check's faults,
	 * the first that holds named. A receipt: none in the token (`noReceipt`); one not signed by the
	 * log or of another shape (`receipt`); its digest not the token's (`digest`); not a bundle's of
	 * the frame (`kind`); another flow (`flow`); older than `maxAge` allows (`tooOld`); its `n` past
	 * the status's W_s (`notYetChecked`: fetch the status again and take nothing until it covers
	 * it); in the not-accepted ids (`denied`); a status not signed by enough of its set
	 * (`status`). A callback: the proof unreadable or unsigned (`proof`); its key's thumbprint not
	 * the ID token's `esig` (`key`); its `apr` not the ID token's (`apr`); `iss`, `client_id`,
	 * `state` or `code_hash` not the expected (`field`). Fetching the status every τ_sdk and keeping
	 * each signer set's newest version are the SDK's.
	 */
	checks: Object.freeze({
		frames: Object.freeze(["idToken", "accessToken"] as const),
		receiptFaults: Object.freeze([
			"noReceipt",
			"receipt",
			"digest",
			"kind",
			"flow",
			"tooOld",
			"notYetChecked",
			"denied",
			"status",
		] as const),
		callbackFaults: Object.freeze(["proof", "key", "apr", "field"] as const),
	}),
});

/** A P-256 key held to the thumbprint's form: x and y 32 bytes in canonical base64url, a point of the curve. */
const p256Key = ecKey.refine((key) => tokens.ecThumbprintInput(key) !== undefined, {
	message: "x and y are no point of P-256 in canonical base64url",
});

export const receipt = z
	.object({
		v,
		iss: id,
		id: recordId,
		writer,
		kind: z.enum([
			...recordKinds.core,
			...recordKinds.monitor,
			...recordKinds.publisher,
			...recordKinds.human,
		]),
		flow,
		position: ordinal,
		shard: id,
		n: ordinal,
		acceptedAt: count,
		plaintextDigest: digest,
		/** A token's frame and the digest of its header and claims (`tokens.digestInput`). */
		token: z
			.object({ frame: z.enum(frames), digest })
			.strict()
			.optional(),
		approval: approvalDigests.optional(),
		keyChange: keyChangeDigests.optional(),
	})
	.strict()
	.refine(
		(r) =>
			(r.token !== undefined) === (r.kind === "bundle") &&
			(r.approval === undefined || r.kind === "approval") &&
			(r.keyChange === undefined || r.kind === "keyChange"),
		{
			message:
				"a token goes with a bundle's receipt, approval digests with an approval's, key change digests with a key change's",
		},
	);

/** The callback's proof (A38): its header, E_sig's public key in it. */
export const callbackHeader = z
	.object({ alg: z.literal("ES256"), typ: z.literal(logTyps.callback), jwk: p256Key })
	.strict();
/** Its body: the issuer, the client, the state, the code's whole UTF-8 SHA-256, ⑤'s record, and the device's time in seconds (no freshness rests on it). */
export const callbackProof = z
	.object({ iss: id, client_id: id, state: id, code_hash: digest, apr: recordRef, iat: count })
	.strict();
/** An ID token's evidence claims, the two taken out of its claims and read alone: the thumbprint of the approved T's E_sig, and the approval's record. */
export const idTokenEvidence = z.object({ esig: digest, apr: recordRef }).strict();

export type Receipt = z.infer<typeof receipt>;
export type ReceiptFault = (typeof tokens.checks.receiptFaults)[number];
export type CallbackFault = (typeof tokens.checks.callbackFaults)[number];

/** R16 (an ID token) and R17 (an access token): what a receiver reads to take a token by its receipt. */
export interface ReceiptCheck {
	/** A token already verified the standard way: its issuer's JWKS signature, `iss`, `aud`, `exp`. */
	readonly token: string;
	readonly frame: (typeof tokens.checks.frames)[number];
	/** The flow the token must be of: a person's token its `sub`'s subject flow, a client's its client flow. */
	readonly flow: Flow;
	/** The newest status the receiver holds, as `setSigned` reads it (JWS JSON General Serialization). */
	readonly status: string;
	/** The log's keys, fixed from C1's source. */
	readonly logKeys: readonly ReceiverKey[];
	/** The status's signer set: its keys by kid and how many of it must sign; the newest version the receiver holds. */
	readonly statusSigners: SignerSet;
	/** The receiver's clock, ms. */
	readonly now: number;
	/** σ: the most the receiver's clock and the log's differ by, ms. */
	readonly skew: number;
	/** R17: a token's life counted from its receipt's time; R16: the oldest a receipt may be. ms. */
	readonly maxAge: number;
}

/** R18 (an `openid` client): the callback's proof, read against the ID token that passed R16. */
export interface CallbackCheck {
	readonly proof: string;
	readonly idToken: {
		readonly esig: string;
		readonly apr: RecordRef;
		readonly iss: string;
		readonly aud: string;
	};
	readonly expected: {
		readonly iss: string;
		readonly client_id: string;
		readonly state: string;
		readonly code: string;
	};
}
