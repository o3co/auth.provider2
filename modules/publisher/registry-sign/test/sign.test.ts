import { generateKeyPairSync, type KeyObject, verify } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { registryWire } from "@mod/registry-wire";
import { afterEach, describe, expect, it } from "vitest";
import { signRegistry } from "../src/sign.ts";

const version = {
	v: 1,
	version: 4,
	issuedAt: 1_700_000_000,
	clients: [{ id: "rp-1", kind: "public", method: "none", sections: {} }],
};
const ed25519 = generateKeyPairSync("ed25519");
const p256 = generateKeyPairSync("ec", { namedCurve: "P-256" });
const privateJwk = (key: KeyObject, more: Record<string, unknown> = { kid: "publisher-1" }) => ({
	...key.export({ format: "jwk" }),
	...more,
});

let dir = "";
afterEach(async () => {
	if (dir) await rm(dir, { recursive: true, force: true });
	dir = "";
});

/** Runs the tool over a key and a version written to files, answering its run and the paths. */
async function run(key: unknown, input: unknown) {
	dir = await mkdtemp(join(tmpdir(), "registry-sign-"));
	const paths = {
		key: join(dir, "key.jwk"),
		input: join(dir, "version.json"),
		out: join(dir, "registry.jws"),
	};
	await writeFile(paths.key, typeof key === "string" ? key : JSON.stringify(key));
	await writeFile(paths.input, typeof input === "string" ? input : JSON.stringify(input));
	return { ...(await signRegistry([paths.key, paths.input, paths.out])), paths };
}

const parts = (jws: string) => {
	const [h = "", p = "", s = ""] = jws.split(".");
	const json = (part: string) => JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
	return {
		header: json(h),
		payload: json(p),
		input: Buffer.from(`${h}.${p}`),
		signature: Buffer.from(s, "base64url"),
	};
};

describe("registry-sign", () => {
	it("signs a version under EdDSA as a compact JWS, its header naming the registry's typ and the key's kid", async () => {
		const done = await run(privateJwk(ed25519.privateKey), version);
		expect(done.code).toBe(0);
		const jws = (await readFile(done.paths.out, "utf8")).trim();
		const { header, payload, input, signature } = parts(jws);
		expect(header).toEqual({ alg: "EdDSA", typ: registryWire.typ, kid: "publisher-1" });
		expect(payload).toEqual(version);
		expect(verify(null, input, ed25519.publicKey, signature)).toBe(true);
		expect(done.lines).toEqual(["signed version 4 (1 client) as publisher-1 under EdDSA"]);
	});

	it("signs under ES256 with a P-256 key, the signature as r and s", async () => {
		const done = await run(privateJwk(p256.privateKey, { kid: "p", alg: "ES256" }), version);
		expect(done.code).toBe(0);
		const { header, input, signature } = parts(await readFile(done.paths.out, "utf8"));
		expect(header.alg).toBe("ES256");
		const key = { key: p256.publicKey, dsaEncoding: "ieee-p1363" } as const;
		expect(verify("sha256", input, key, signature)).toBe(true);
	});

	it("refuses a version that does not fit registry-wire's schema, writing nothing", async () => {
		for (const input of [{ ...version, extra: 1 }, { ...version, version: 0 }, "not json"]) {
			const done = await run(privateJwk(ed25519.privateKey), input);
			expect(done.code, JSON.stringify(input)).toBe(1);
			expect(done.lines.join("\n")).toContain("version");
			await expect(readFile(done.paths.out)).rejects.toThrow();
		}
	});

	it("refuses a key that is no private Ed25519 or P-256 JWK with a kid, never writing its members", async () => {
		const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
		const noKid = ed25519.privateKey.export({ format: "jwk" });
		for (const key of [
			noKid,
			privateJwk(rsa.privateKey),
			{ ...ed25519.publicKey.export({ format: "jwk" }), kid: "k" },
			privateJwk(ed25519.privateKey, { kid: "k", alg: "ES256" }),
			"not json",
		]) {
			const done = await run(key, version);
			expect(done.code).toBe(1);
			expect(done.lines.join("\n")).toContain("key");
			const d = (privateJwk(ed25519.privateKey) as { d?: string }).d ?? "";
			expect(done.lines.join("\n")).not.toContain(d);
			await expect(readFile(done.paths.out)).rejects.toThrow();
		}
	});

	it("answers its usage and 64 unless given a key, a version and where to write", async () => {
		expect(await signRegistry([])).toEqual({
			lines: ["usage: registry-sign <private-key.jwk> <version.json> <out.jws>"],
			code: 64,
		});
		expect((await signRegistry(["a", "b"])).code).toBe(64);
	});

	it("refuses a file it cannot read, naming the argument", async () => {
		const done = await signRegistry(["/no/such/key.jwk", "/no/such/version.json", "/no/out"]);
		expect(done.code).toBe(1);
		expect(done.lines).toEqual(["the key file cannot be read"]);
	});
});
