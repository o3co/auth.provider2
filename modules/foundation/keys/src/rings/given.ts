import { type KeyObject, verify } from "node:crypto";
import type { Read } from "../contract.ts";
import { isCanonicalJws } from "../material/jws.ts";
import { type Jwk, publicJwk, verifiesUnder } from "../material/public.ts";
import { kinds } from "./ring.ts";
import type { Alg } from "./section.ts";
import { jsonOf } from "./signer.ts";

const isAlg = (value: unknown): value is Alg =>
	typeof value === "string" && Object.hasOwn(kinds, value);
const isRecord = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);
const bytesOf = (segment: string) => new Uint8Array(Buffer.from(segment, "base64url"));

/**
 * A compact JWS verified at once by the key of `keys` its `kid` names, under the `alg` its header
 * names where the key may verify under it (`verifiesUnder`: its `use` and `key_ops` allow it, and its
 * own `alg`, where it has one, is the same): its header and payload as read, or none. A key with a private member, a JWS not in its one form, and a header or
 * payload naming a member twice read as none.
 */
export function verifiedBy(jws: string, keys: readonly unknown[]): Read | undefined {
	if (!isCanonicalJws(jws)) return undefined;
	const [h = "", p = "", s = ""] = jws.split(".");
	const header = jsonOf(bytesOf(h));
	if (!isRecord(header) || !isAlg(header.alg) || typeof header.kid !== "string") return undefined;
	const named = keys.find((k) => isRecord(k) && k.kid === header.kid) as Jwk | undefined;
	const read = named && publicJwk(named);
	if (!read || !named || !verifiesUnder(named, header.alg)) return undefined;
	const alg = header.alg;
	if (!kinds[alg](read.key)) return undefined;
	const input = Buffer.from(`${h}.${p}`);
	const signature = bytesOf(s);
	const holds =
		alg === "EdDSA"
			? verify(null, input, read.key, signature)
			: verify(
					"sha256",
					input,
					alg === "ES256" ? { key: read.key, dsaEncoding: "ieee-p1363" } : read.key,
					signature,
				);
	if (!holds) return undefined;
	const payload = jsonOf(bytesOf(p));
	return payload === undefined ? undefined : { header, payload };
}

/** A ring key as a JWK set lists it: its public members, its kid, its alg, for signatures. */
export const jwkOf = (k: {
	readonly kid: string;
	readonly alg: Alg;
	readonly key: KeyObject;
}): Jwk => ({
	...k.key.export({ format: "jwk" }),
	kid: k.kid,
	alg: k.alg,
	use: "sig",
});
