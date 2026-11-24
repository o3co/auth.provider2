import {
	logTyps,
	type Receipt,
	type ReceiptCheck,
	type ReceiptFault,
	type ReceiverKey,
	type Status,
	schemas,
	tokens,
} from "@mod/transparency-wire";
import { digest, fromBase64url, textOf } from "./bytes.ts";
import { type Jwk, keyIdentity, verifyCompact } from "./jws.ts";

const decoded = (part: string | undefined) => {
	const bytes = fromBase64url(part ?? "");
	return bytes && textOf(bytes);
};
const objectOf = (text: string | undefined): Record<string, unknown> | undefined => {
	if (text === undefined) return undefined;
	const read = tokens.parse(text);
	if ("error" in read) return undefined;
	const value = read.value;
	return value !== null && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: undefined;
};

/** A protocol key as WebCrypto's JWK, with its kid where it has one; members left undefined are left out. */
const jwkOf = (key: ReceiverKey, kid?: string): Jwk =>
	Object.fromEntries(Object.entries({ ...key, kid }).filter(([, value]) => value !== undefined));

/**
 * The status, where enough of its set signed it: the set read as the wire's (so at least one
 * signature required), each signature verified with the set's key of its kid, and each key counted
 * once by its identity, so one key the set names under two kids is one signer.
 */
async function statusOf(check: ReceiptCheck): Promise<Status | undefined> {
	const given = schemas.signerSet.safeParse(check.statusSigners);
	if (!given.success || given.data.purpose !== "status") return undefined;
	const set = given.data;
	let envelope: unknown;
	try {
		envelope = JSON.parse(check.status);
	} catch {
		return undefined;
	}
	const read = schemas.setSigned.safeParse(envelope);
	if (!read.success) return undefined;
	const { payload, signatures } = read.data;
	const signed = new Set<string>();
	for (const one of signatures) {
		const header = objectOf(decoded(one.protected));
		const kid = header?.kid;
		const key = set.keys.find((entry) => entry.kid === kid);
		if (!key || typeof kid !== "string" || header?.typ !== logTyps.status) continue;
		const jwk = jwkOf(key.key, kid);
		const verified = await verifyCompact(`${one.protected}.${payload}.${one.signature}`, [jwk]);
		const identity = keyIdentity(jwk);
		if (verified && identity !== undefined) signed.add(identity);
	}
	if (signed.size < set.required) return undefined;
	const body = schemas.status.safeParse(objectOf(decoded(payload)));
	return body.success ? body.data : undefined;
}

/**
 * R16 (an ID token) and R17 (an access token): the token taken by its receipt. The token was
 * verified the standard way already; here its receipt (`txr`) must be the log's, a bundle's of the
 * frame, of the token's own digest (`tokens.digestInput`) and of the flow expected, accepted no
 * longer ago than `maxAge` (σ aside) and not later than now (σ aside), and covered by a status enough of its set signed: its record
 * at or below its shard's watermark and not among the not-accepted ids. The faults, the first that
 * holds named, are `tokens.checks.receiptFaults`; the status is read before the record's place in
 * it, so a status that does not read is `status` whatever else. A receipt accepted after now is
 * `receipt`, at its place; a time given that is not a finite number is `tooOld`. A record's shard is one the status itself
 * names, never a name every object answers (`constructor`).
 */
export async function checkReceipt(
	check: ReceiptCheck,
): Promise<{ readonly receipt: Receipt } | { readonly fault: ReceiptFault }> {
	const parts = check.token.split(".");
	if (parts.length !== 3) return { fault: "noReceipt" };
	const [h, c] = parts;
	const headerText = decoded(h);
	const claimsText = decoded(c);
	const claims = objectOf(claimsText);
	const txr = claims?.[tokens.claim];
	if (headerText === undefined || claimsText === undefined || typeof txr !== "string")
		return { fault: "noReceipt" };
	const verified = await verifyCompact(
		txr,
		check.logKeys.map((key) => jwkOf(key)),
	);
	const read =
		verified?.header.typ === logTyps.receipt
			? schemas.receipt.safeParse(verified.payload)
			: undefined;
	if (!read?.success) return { fault: "receipt" };
	const receipt = read.data;
	const clock = [check.now, check.skew, check.maxAge].every(Number.isFinite);
	if (clock && receipt.acceptedAt > check.now + check.skew) return { fault: "receipt" };
	if (!receipt.token) return { fault: "kind" };
	const input = tokens.digestInput(headerText, claimsText);
	if ("error" in input || receipt.token.digest !== (await digest(input.input)))
		return { fault: "digest" };
	if (receipt.kind !== "bundle" || receipt.token.frame !== check.frame) return { fault: "kind" };
	if (receipt.flow.of !== check.flow.of || receipt.flow.id !== check.flow.id)
		return { fault: "flow" };
	if (!clock || check.now - check.skew > receipt.acceptedAt + check.maxAge)
		return { fault: "tooOld" };
	const status = await statusOf(check);
	if (!status) return { fault: "status" };
	const shard = Object.hasOwn(status.shards, receipt.shard)
		? status.shards[receipt.shard]
		: undefined;
	if (!shard || receipt.n > shard.watermark) return { fault: "notYetChecked" };
	if (status.deny.includes(receipt.id)) return { fault: "denied" };
	return { receipt };
}
