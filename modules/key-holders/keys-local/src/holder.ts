import {
	constants,
	createPrivateKey,
	createPublicKey,
	diffieHellman,
	type KeyObject,
	sign,
} from "node:crypto";
import { readFile } from "node:fs/promises";
import type { Refusal } from "@mod/kernel";
import type { KeyHolder } from "@mod/keys";
import type { Section } from "./section.ts";

/** A key read from PEM: the private key where one was written, else the public one. */
function keyOfPem(pem: string): KeyObject | undefined {
	try {
		// createPrivateKey refuses a public key, so what it reads is always private.
		return createPrivateKey(pem);
	} catch {
		try {
			// A public key, or a certificate's key taken out of it: the key is the provider's own, so
			// no outside party's certificate is trusted.
			return createPublicKey(pem);
		} catch {
			return undefined;
		}
	}
}

/** The JWS algorithms a private key of each kind signs under here. */
const algorithms: Readonly<Record<string, readonly string[]>> = {
	ed25519: ["EdDSA"],
	ec: ["ES256"],
	rsa: ["PS256", "RS256"],
};

/** The signature over `input`, as a JWS writes it: an ECDSA signature as r and s, PSS's salt as long as SHA-256. */
function signed(key: KeyObject, alg: string, input: Uint8Array): Uint8Array {
	if (alg === "EdDSA") return sign(null, input, key);
	if (alg === "ES256") return sign("sha256", input, { key, dsaEncoding: "ieee-p1363" });
	if (alg === "PS256") {
		const pss = constants.RSA_PKCS1_PSS_PADDING;
		return sign("sha256", input, {
			key,
			padding: pss,
			saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
		});
	}
	return sign("sha256", input, key);
}

const unreadable =
	"not readable as a PEM key: write a PEM key, private where it signs (the example's REPLACE- placeholder is none)";

/** Reads every key the section holds into a holder in process, or why boot is refused, by key path. */
export async function localHolder(
	s: Section,
): Promise<KeyHolder | { readonly refused: Refusal[] }> {
	const refused: Refusal[] = [];
	const keys = new Map<string, KeyObject>();
	for (const [i, entry] of s.keys.entries()) {
		let pem = entry.pem;
		if (entry.file !== undefined) {
			pem = await readFile(entry.file, "utf8").catch(() => undefined);
			if (pem === undefined) {
				refused.push({
					where: `keys-local.keys.${i}.file`,
					reason: "not readable: write the path of a PEM file",
				});
				continue;
			}
		}
		const key = pem === undefined ? undefined : keyOfPem(pem);
		if (key === undefined) {
			const where = `keys-local.keys.${i}.${entry.file === undefined ? "pem" : "file"}`;
			refused.push({ where, reason: unreadable });
			continue;
		}
		keys.set(entry.kid, key);
	}
	if (refused.length > 0) return { refused };
	const privateOf = (kid: string) => {
		const key = keys.get(kid);
		if (key?.type !== "private") throw new TypeError(`keys-local: no private key of kid ${kid}`);
		return key;
	};
	return {
		powers: { withdrawable: false, countedOutside: false },
		held: (kid) => {
			const key = keys.get(kid);
			if (key === undefined) return undefined;
			const own = key.type === "private";
			return {
				publicKey: own ? createPublicKey(key) : key,
				signsUnder: own ? (algorithms[key.asymmetricKeyType ?? ""] ?? []) : [],
				agrees: own && key.asymmetricKeyType === "ec",
			};
		},
		sign: async (kid, alg, input) => ({
			kind: "signed",
			signature: signed(privateOf(kid), alg, input),
		}),
		agree: async (kid, peer) => ({
			kind: "agreed",
			shared: diffieHellman({ privateKey: privateOf(kid), publicKey: peer }),
		}),
	};
}
