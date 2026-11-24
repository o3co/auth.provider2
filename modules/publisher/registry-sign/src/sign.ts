import { createPrivateKey, type KeyObject, sign } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { registryWire } from "@mod/registry-wire";

/** A run of `registry-sign`: the lines it writes and its exit code. */
export interface Run {
	readonly lines: readonly string[];
	readonly code: number;
}

const usage: Run = {
	lines: ["usage: registry-sign <private-key.jwk> <version.json> <out.jws>"],
	code: 64,
};
const refused = (line: string): Run => ({ lines: [line], code: 1 });

/** The algorithm each key kind signs under here, by its JWK `kty` and `crv`. */
const algorithms: Readonly<Record<string, string>> = {
	"OKP Ed25519": "EdDSA",
	"EC P-256": "ES256",
};

/** The signing key a private JWK holds, its kid and its algorithm; or what is wrong, naming no member's value. */
function signerOf(text: string): { key: KeyObject; kid: string; alg: string } | string {
	const jwk = jsonOf(text);
	if (typeof jwk !== "object" || jwk === null || Array.isArray(jwk)) return "the key is no JWK";
	const given = jwk as Record<string, unknown>;
	const alg = algorithms[`${String(given.kty)} ${String(given.crv)}`];
	if (alg === undefined) return "the key is neither an Ed25519 (EdDSA) nor a P-256 (ES256) key";
	if (given.alg !== undefined && given.alg !== alg) return `the key's alg is not ${alg}`;
	if (typeof given.kid !== "string" || given.kid.length === 0) return "the key has no kid";
	if (typeof given.d !== "string") return "the key is no private key";
	try {
		return { key: createPrivateKey({ key: given as never, format: "jwk" }), kid: given.kid, alg };
	} catch {
		return "the key cannot be read as a private JWK";
	}
}

function jsonOf(text: string): unknown {
	try {
		return JSON.parse(text);
	} catch {
		return undefined;
	}
}

const segment = (text: string) => Buffer.from(text).toString("base64url");

/**
 * `registry-sign <private-key.jwk> <version.json> <out.jws>`: holds the version to registry-wire's
 * schema, signs it as a compact JWS under the key, its header `alg`, `typ` (`registryWire.typ`) and
 * `kid`, and writes it, with a newline. A refusal writes nothing.
 */
export async function signRegistry(args: readonly string[]): Promise<Run> {
	const [keyPath, inputPath, outPath] = args;
	if (args.length !== 3 || !keyPath || !inputPath || !outPath) return usage;
	const keyText = await readFile(keyPath, "utf8").catch(() => undefined);
	if (keyText === undefined) return refused("the key file cannot be read");
	const signer = signerOf(keyText);
	if (typeof signer === "string") return refused(signer);
	const inputText = await readFile(inputPath, "utf8").catch(() => undefined);
	if (inputText === undefined) return refused("the version file cannot be read");
	const parsed = registryWire.version.safeParse(jsonOf(inputText));
	if (!parsed.success) {
		const paths = parsed.error.issues.map((issue) => issue.path.join(".") || "(top)");
		return refused(`the version does not fit registry-wire's version, at ${paths.join(", ")}`);
	}
	const header = { alg: signer.alg, typ: registryWire.typ, kid: signer.kid };
	const input = `${segment(JSON.stringify(header))}.${segment(JSON.stringify(parsed.data))}`;
	const signature =
		signer.alg === "EdDSA"
			? sign(null, Buffer.from(input), signer.key)
			: sign("sha256", Buffer.from(input), { key: signer.key, dsaEncoding: "ieee-p1363" });
	const written = await writeFile(outPath, `${input}.${signature.toString("base64url")}\n`).then(
		() => true,
		() => false,
	);
	if (!written) return refused("the signed version cannot be written");
	const count = parsed.data.clients.length;
	return {
		lines: [
			`signed version ${parsed.data.version} (${count} client${count === 1 ? "" : "s"}) as ${signer.kid} under ${signer.alg}`,
		],
		code: 0,
	};
}
