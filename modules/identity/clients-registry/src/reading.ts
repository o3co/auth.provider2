import type { ClientRecord } from "@mod/clients";
import type { Refusal } from "@mod/kernel";
import { type Jwk, publicJwk, type Read, verifiesUnder } from "@mod/keys";
import { type RegistryClient, type RegistryVersion, registryWire } from "@mod/registry-wire";
import type { Settings } from "./section.ts";

/** The curve each algorithm a publisher signs under takes. */
const curves: Readonly<Record<string, string>> = { EdDSA: "Ed25519", ES256: "P-256" };

/** Whether the publisher's key is a public JWK with a kid, for EdDSA or ES256, that may verify signatures. */
export function publisherKeyFits(jwk: Jwk): boolean {
	const alg = typeof jwk.alg === "string" && Object.hasOwn(curves, jwk.alg) ? jwk.alg : undefined;
	return (
		alg !== undefined &&
		jwk.crv === curves[alg] &&
		typeof jwk.kid === "string" &&
		jwk.kid.length > 0 &&
		publicJwk(jwk) !== undefined &&
		verifiesUnder(jwk, alg)
	);
}

const at = (key: string, reason: string): { readonly refused: Refusal } => ({
	refused: { where: `clients-registry.${key}`, reason },
});

/**
 * The version a signed text holds, checked in order: the signature under the publisher's key (by
 * `verify`, `keys`' `verifyJws`), the header's `typ`, registry-wire's schema, and the least version
 * taken. A refusal names the setting and why, never a value read.
 */
export function versionOf(
	text: string,
	s: Settings,
	verify: (jws: string, keys: readonly unknown[]) => Read | undefined,
): { readonly version: RegistryVersion } | { readonly refused: Refusal } {
	const read = verify(text.trim(), [s["publisher-key"]]);
	if (read === undefined) return at("file", "its signature does not verify under publisher-key");
	const { typ } = read.header as { readonly typ?: unknown };
	if (typ !== registryWire.typ) {
		return at("file", `its signed header's typ is not ${registryWire.typ}`);
	}
	const parsed = registryWire.version.safeParse(read.payload);
	if (!parsed.success) {
		const paths = parsed.error.issues.map((issue) => issue.path.join(".") || "(top)");
		return at("file", `does not fit registry-wire's version, at ${paths.join(", ")}`);
	}
	if (parsed.data.version < s["min-version"]) {
		return at("min-version", "is above the version the file holds: an older version is refused");
	}
	return { version: parsed.data };
}

/** A registry client in `clients`' words: the record a source answers. */
export const recordOf = (client: RegistryClient): ClientRecord => ({
	id: client.id,
	kind: client.kind,
	method: client.method,
	sections: client.sections,
});
