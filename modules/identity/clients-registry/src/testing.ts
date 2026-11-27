import { generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { registryWire } from "@mod/registry-wire";

/** A key pair made for the test, its public half as the publisher hands it over. */
export function publisherKey(kind: "ed25519" | "p256" = "ed25519", kid = "publisher-1") {
	const pair =
		kind === "ed25519"
			? generateKeyPairSync("ed25519")
			: generateKeyPairSync("ec", { namedCurve: "P-256" });
	const alg = kind === "ed25519" ? "EdDSA" : "ES256";
	const jwk = { ...pair.publicKey.export({ format: "jwk" }), kid, alg, use: "sig" };
	return { privateKey: pair.privateKey, jwk, kid, alg };
}

const segment = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");

/** A compact JWS of `payload` under the header given, as a publisher would sign one. */
export function signedBy(
	key: { readonly privateKey: KeyObject; readonly kid: string; readonly alg: string },
	payload: unknown,
	header: Readonly<Record<string, unknown>> = {},
): string {
	const input = `${segment({ alg: key.alg, typ: registryWire.typ, kid: key.kid, ...header })}.${segment(payload)}`;
	const signature =
		key.alg === "EdDSA"
			? sign(null, Buffer.from(input), key.privateKey)
			: sign("sha256", Buffer.from(input), { key: key.privateKey, dsaEncoding: "ieee-p1363" });
	return `${input}.${signature.toString("base64url")}`;
}
