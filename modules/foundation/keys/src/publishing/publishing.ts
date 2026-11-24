import { rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Published } from "../contract.ts";
import { publicJwk } from "../material/public.ts";
import { jwkOf } from "../rings/given.ts";
import { expired, type Rings } from "../rings/ring.ts";

const usage: Published = { lines: ["usage: keys-publish <directory>"], code: 64 };

/** The Core generation's public keys, each with its kid, its alg and its generation; none for a generation not in the ring. */
export function coreJwks(rings: Rings, generation: number) {
	const key = rings.core.generations.get(generation);
	return key && [{ ...jwkOf(key), generation }];
}

/**
 * Every Core generation's public keys held, in the ring's order: the one place they are gathered,
 * each read as a public JWK (a private member never goes out).
 */
export const allCoreJwks = (rings: Rings) =>
	[...rings.core.generations]
		.flatMap(([generation]) => coreJwks(rings, generation) ?? [])
		.filter((jwk) => publicJwk(jwk) !== undefined);

/** The two sets, as the publisher serves them: the authority's unexpired keys (the JWKS), and the Core's ring with its sealing key. */
export function keySets(rings: Rings, now: number) {
	const sealing = rings.sealing;
	const [x, y] = [sealing.point.subarray(1, 33), sealing.point.subarray(33)];
	return {
		"jwks.json": {
			keys: rings.authority.verifying.filter((k) => !expired(k, () => now)).map(jwkOf),
		},
		"core-keys.json": {
			keys: [
				...allCoreJwks(rings),
				{
					kty: "EC",
					crv: "P-256",
					x: Buffer.from(x).toString("base64url"),
					y: Buffer.from(y).toString("base64url"),
					kid: sealing.kid,
					use: "enc",
				},
			],
		},
	};
}

/** Writes each set into the one directory given, each file whole or not at all; a usage line and 64 otherwise. */
export async function publish(
	rings: Rings,
	now: number,
	args: readonly string[],
): Promise<Published> {
	const [dir] = args;
	if (args.length !== 1 || !dir) return usage;
	const lines: string[] = [];
	for (const [name, set] of Object.entries(keySets(rings, now))) {
		const path = join(dir, name);
		// Written beside it, then renamed, so a reader never sees half a set.
		await writeFile(`${path}.writing`, `${JSON.stringify(set)}\n`, { flag: "w" });
		await rename(`${path}.writing`, path);
		lines.push(`wrote ${path}`);
	}
	return { lines, code: 0 };
}
