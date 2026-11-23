import { createPublicKey, type KeyObject } from "node:crypto";
import type { Refusal } from "@mod/kernel";
import type { KeyHolder } from "../contract.ts";
import type { Alg, Section } from "./section.ts";

export interface RingKey {
	readonly kid: string;
	readonly alg: Alg;
	/** The key's public half, whatever the holder answers. */
	readonly key: KeyObject;
	readonly expiresAt?: number;
}

export interface Ring {
	readonly signing: RingKey;
	/** The key that signs next, among `verifying` too. */
	readonly next?: RingKey;
	/** The keys that verify, in the order they are published: the signing key first. */
	readonly verifying: readonly RingKey[];
}

/** The Core's sealing key: its kid, and its point as HPKE writes it. */
export interface SealingKey {
	readonly kid: string;
	readonly point: Uint8Array;
}

/** The Core's ring: its current generation's key signs and verifies; each generation's key, by generation. */
export interface CoreRing extends Ring {
	readonly generation: number;
	readonly generations: ReadonlyMap<number, RingKey>;
}

export interface Rings {
	readonly authority: Ring;
	readonly core: CoreRing;
	readonly sealing: SealingKey;
}

/** RS256's least modulus, in bits (RFC 7518 §3.3). */
const rsaModulusFloor = 2048;

export const kinds: Readonly<Record<Alg, (key: KeyObject) => boolean>> = {
	EdDSA: (key) => key.asymmetricKeyType === "ed25519",
	ES256: p256,
	RS256: (key) =>
		key.asymmetricKeyType === "rsa" &&
		(key.asymmetricKeyDetails?.modulusLength ?? 0) >= rsaModulusFloor,
};

function p256(key: KeyObject): boolean {
	return key.asymmetricKeyType === "ec" && key.asymmetricKeyDetails?.namedCurve === "prime256v1";
}

/** A key's public half: itself where it is public, as the platform reads none out of a public key. */
export const publicHalf = (key: KeyObject) => (key.type === "public" ? key : createPublicKey(key));

/** True once the key's expiry has passed; reads the clock only for keys that expire. */
export function expired(key: RingKey, now: () => number): boolean {
	return key.expiresAt !== undefined && key.expiresAt <= now();
}

/** A P-256 key's point, uncompressed. */
export function pointOf(key: KeyObject): Uint8Array {
	const jwk = key.export({ format: "jwk" });
	return new Uint8Array(
		Buffer.concat([
			Buffer.of(4),
			Buffer.from(jwk.x ?? "", "base64url"),
			Buffer.from(jwk.y ?? "", "base64url"),
		]),
	);
}

/**
 * Each key held for a second role or generation, where the first holds it too: one key serves one
 * ring, one generation and the sealing apart, so each is withdrawn apart.
 */
function sameKeys(
	read: readonly { readonly key: KeyObject; readonly path: readonly (string | number)[] }[],
	sealing: { readonly key: KeyObject; readonly path: readonly (string | number)[] } | undefined,
): Refusal[] {
	const first = new Map<string, readonly (string | number)[]>();
	const refused: Refusal[] = [];
	for (const { key, path } of [...read, ...(sealing ? [sealing] : [])]) {
		const der = key.export({ format: "der", type: "spki" }).toString("base64url");
		const earlier = first.get(der);
		if (earlier === undefined) first.set(der, path);
		else {
			refused.push({
				where: `keys.${[...path, "kid"].join(".")}`,
				reason: `the same key as keys.${[...earlier, "kid"].join(".")}: a key serves one ring, one generation or the sealing`,
			});
		}
	}
	return refused;
}

/** Reads the rings from the section and what the holder holds: the rings, or why boot is refused, by key path. */
export function readRings(s: Section, holder: KeyHolder): Rings | { readonly refused: Refusal[] } {
	const refused: Refusal[] = [];
	const at = (...path: readonly (string | number)[]) => `keys.${path.join(".")}`;
	/** Every key read, with the path of its entry, in the order the section names them. */
	const all: { key: KeyObject; path: readonly (string | number)[] }[] = [];
	/** The ring key the holder holds for `kid`, of `alg`'s kind; signing under it where `signs`. */
	const read = (
		path: readonly (string | number)[],
		entry: { readonly kid: string; readonly alg: Alg; readonly "expires-at"?: string },
		signs: boolean,
	): RingKey | undefined => {
		const where = at(...path, "kid");
		const held = holder.held(entry.kid);
		if (held === undefined) {
			refused.push({
				where,
				reason: "no key of this kid is held: hold it in the section of the keys axis's adapter",
			});
			return undefined;
		}
		const key = publicHalf(held.publicKey);
		if (!kinds[entry.alg](key)) {
			refused.push({
				where,
				reason: `the key held for it is not of the kind ${at(...path, "alg")} names`,
			});
			return undefined;
		}
		if (signs && !held.signsUnder.includes(entry.alg)) {
			refused.push({
				where,
				reason: `its holder does not sign with it under ${at(...path, "alg")}: hold its private key`,
			});
			return undefined;
		}
		const expires = entry["expires-at"];
		all.push({ key, path });
		return {
			kid: entry.kid,
			alg: entry.alg,
			key,
			...(expires ? { expiresAt: Date.parse(expires) } : {}),
		};
	};

	const { authority, core } = s;
	const signing = read(["authority", "signing"], authority.signing, true);
	const previous = authority.previous.map((p, i) => read(["authority", "previous", i], p, false));
	const next = authority.next && read(["authority", "next"], authority.next, false);
	const generations = core.keys
		.map((k, i) => ({
			generation: k.generation,
			key: read(["core", "keys", i], k, k.generation === core.generation),
		}))
		.sort((x, y) => x.generation - y.generation);
	const sealingHeld = holder.held(s.sealing.kid);
	const sealingKey = sealingHeld && publicHalf(sealingHeld.publicKey);
	if (!sealingKey || !p256(sealingKey) || !sealingHeld?.agrees) {
		refused.push({
			where: at("sealing", "kid"),
			reason: "no P-256 key of this kid is held that its holder agrees with: hold its private key",
		});
	}
	const coreSigning = generations.find((g) => g.generation === core.generation)?.key;
	const coreNext = generations.find((g) => g.generation > core.generation)?.key;
	refused.push(...sameKeys(all, sealingKey && { key: sealingKey, path: ["sealing"] }));
	if (refused.length > 0 || !signing || !coreSigning || !sealingKey) return { refused };
	const known = (keys: readonly (RingKey | undefined)[]) => keys as readonly RingKey[];
	return {
		authority: {
			signing,
			...(next ? { next } : {}),
			verifying: known([signing, ...previous, ...(next ? [next] : [])]),
		},
		core: {
			signing: coreSigning,
			...(coreNext ? { next: coreNext } : {}),
			verifying: [coreSigning],
			generation: core.generation,
			generations: new Map(generations.map((g) => [g.generation, g.key as RingKey])),
		},
		sealing: { kid: s.sealing.kid, point: pointOf(sealingKey) },
	};
}
