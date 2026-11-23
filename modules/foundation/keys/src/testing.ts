import {
	createPublicKey,
	diffieHellman,
	generateKeyPairSync,
	type KeyObject,
	sign,
} from "node:crypto";
import { defineModule, type Module } from "@mod/kernel";
import type { z } from "zod";
import type { KeyHolder } from "./contract.ts";
import { keyHolders } from "./holder.ts";
import type { section } from "./section.ts";

export type KeysSettings = z.input<typeof section>;

/** The kids `keysConfig` names: the authority's signing key, the Core's key of generation 1, and the sealing key. */
const kids = ["test", "core-test", "seal-test"] as const;

let made: Readonly<Record<string, KeyObject>> | undefined;
/** One P-256 key per kid for the process: a test needs no fresh one. */
const shared = () => {
	made ??= Object.fromEntries(
		kids.map((kid) => [kid, generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey]),
	);
	return made;
};

/**
 * The keys part of a test's configuration: ES256 keys in both rings and a sealing key, held by
 * `testHolder`, unless the test sets a part.
 */
export function keysConfig(settings: Partial<KeysSettings> = {}) {
	return {
		keys: {
			authority: { signing: { kid: "test", alg: "ES256" } },
			core: { generation: 1, keys: [{ generation: 1, kid: "core-test", alg: "ES256" }] },
			sealing: { kid: "seal-test" },
			...settings,
		},
	};
}

/** The JWS algorithms a key of each kind signs under, and how its signature is written. */
const signer = (key: KeyObject, input: Uint8Array) =>
	key.asymmetricKeyType === "ed25519"
		? sign(null, input, key)
		: sign("sha256", input, { key, dsaEncoding: "ieee-p1363" });
const algs: Readonly<Record<string, readonly string[]>> = {
	ed25519: ["EdDSA"],
	ec: ["ES256"],
	rsa: ["RS256"],
};
const algsOf = (key: KeyObject) => algs[key.asymmetricKeyType ?? ""] ?? [];

/**
 * A module holding, for a test, the keys of `keysConfig`'s kids and those given (a private key
 * signs and agrees, a public one only verifies), as an adapter of the keys axis does, in process.
 */
export function testHolder(given: Readonly<Record<string, KeyObject>> = {}): Module {
	const held = { ...shared(), ...given };
	const holder: KeyHolder = {
		powers: { withdrawable: false, countedOutside: false },
		held: (kid) => {
			const key = held[kid];
			if (key === undefined) return undefined;
			const own = key.type === "private";
			return {
				publicKey: own ? createPublicKey(key) : key,
				signsUnder: own ? algsOf(key) : [],
				agrees: own && key.asymmetricKeyType === "ec",
			};
		},
		sign: async (kid, _alg, input) => ({
			kind: "signed",
			signature: signer(held[kid] as KeyObject, input),
		}),
		agree: async (kid, peer) => ({
			kind: "agreed",
			shared: diffieHellman({ privateKey: held[kid] as KeyObject, publicKey: peer }),
		}),
	};
	return defineModule({ name: "keys-test-holder", replicaSafe: true, takes: [] }, (m) => [
		m.contribute(keyHolders).by(() => holder),
	]);
}
