import { createHash, createPublicKey } from "node:crypto";
import type { Keys } from "@mod/keys";
import { type FirstKeyStage, firstKey, hpke, type SigningKey } from "@mod/sdk-core-wire";
import type { z } from "zod";

/** A first key's sealed request as front-core-wire carries it: the stage's nonce, the screen's keys, the sealing. */
export interface SealedRequest {
	readonly nonce: string;
	readonly eEnc: Uint8Array;
	readonly eSigX: Uint8Array;
	readonly eSigY: Uint8Array;
	readonly enc: Uint8Array;
	readonly ct: Uint8Array;
}

/** The screen's keys as the request named them: HPKE's point and E_sig, base64url. */
export interface Screen {
	readonly eEnc: string;
	readonly eSig: SigningKey;
}

export type Opened<T> =
	| {
			readonly kind: "opened";
			readonly plain: T;
			/** SHA-256 of the sealing's `enc` then `ct`, base64url: the request's digest and its `ct_hash`. */
			readonly digest: string;
			readonly screen: Screen;
	  }
	/** It does not open, or opens to text of no shape its stage takes. */
	| { readonly kind: "unopened" }
	/** The keys' holder no longer lets this Core open. */
	| { readonly kind: "withdrawn" };

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

/** Whether x and y are a point of P-256. */
function isPoint(x: Uint8Array, y: Uint8Array): boolean {
	try {
		createPublicKey({ key: { kty: "EC", crv: "P-256", x: b64(x), y: b64(y) }, format: "jwk" });
		return true;
	} catch {
		return false;
	}
}

/** Whether the screen's keys are points of P-256: `eEnc` uncompressed, E_sig by its coordinates. */
export const screenKeysHold = (r: SealedRequest) =>
	r.eEnc.length === 65 &&
	r.eEnc[0] === 0x04 &&
	isPoint(r.eEnc.subarray(1, 33), r.eEnc.subarray(33)) &&
	isPoint(r.eSigX, r.eSigY);

/** The request's digest: SHA-256 of its `enc` then `ct`, base64url. */
export const digestOf = (r: Pick<SealedRequest, "enc" | "ct">) =>
	createHash("sha256").update(r.enc).update(r.ct).digest("base64url");

/** The screen's keys the request names. */
export const screenOf = (r: SealedRequest): Screen => ({
	eEnc: b64(r.eEnc),
	eSig: { kty: "EC", crv: "P-256", x: b64(r.eSigX), y: b64(r.eSigY) } as SigningKey,
});

/**
 * Opens a first key's sealed request of its stage under the Core's sealing key, its additional data
 * its stage, nonce and the screen's keys, so a key swapped fails to open; its plain text read by the
 * stage's shape.
 */
export async function openSealed<T>(
	keys: Pick<Keys, "open">,
	stage: FirstKeyStage,
	request: SealedRequest,
	shape: z.ZodType<T>,
): Promise<Opened<T>> {
	// A key of no point could neither be bound nor answered: the request is not opened.
	if (!screenKeysHold(request)) return { kind: "unopened" };
	const screen = screenOf(request);
	const aad = firstKey.aad(stage, request.nonce, screen.eEnc, screen.eSig);
	const opened = await keys.open(
		{ enc: request.enc, ct: request.ct },
		hpke.info.firstKeyRequest,
		new TextEncoder().encode(aad),
	);
	if (opened.kind !== "opened") return opened;
	let plain: unknown;
	try {
		plain = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(opened.plaintext));
	} catch {
		return { kind: "unopened" };
	}
	const read = shape.safeParse(plain);
	if (!read.success) return { kind: "unopened" };
	return { kind: "opened", plain: read.data, digest: digestOf(request), screen };
}
