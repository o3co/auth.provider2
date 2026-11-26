import { generateKeyPairSync } from "node:crypto";
import { BootRefused } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { composed } from "../../../test/composed.ts";
import { clientKeys, type Jwk } from "../../contract.ts";
import { clientKeysFor } from "../../testing.ts";

const now = 1_800_000_000_000;
const { ec, rsa, jwk, boot, tried } = composed(() => now);

describe("private_key_jwt", () => {
	it("takes only public keys for verifying signatures", async () => {
		const notForSigning: Record<string, Jwk> = {
			"a private key": jwk(ec.privateKey),
			"a shared secret": { kty: "oct", k: "AAAA" },
			"one for encryption": jwk(ec.publicKey, { use: "enc" }),
			"one for deriving keys": jwk(ec.publicKey, { key_ops: ["deriveKey"] }),
			"key_ops not a list": jwk(ec.publicKey, { key_ops: "verify" }),
			"a kid that is no string": jwk(ec.publicKey, { kid: 7 }),
			...Object.fromEntries(
				["p", "q", "dp", "dq", "qi", "k", "oth"].map((member) => [
					`an RSA key with ${member}`,
					jwk(rsa.publicKey, { [member]: "AAAA" }),
				]),
			),
			"a point off the curve": { kty: "EC", crv: "P-256", x: "AAAA", y: "AAAA" },
			"a key-agreement curve": jwk(generateKeyPairSync("x25519").publicKey),
		};
		// The section refuses each; one boot shows a refused section refuses boot, as for any of them.
		for (const [name, bad] of Object.entries(notForSigning)) {
			const read = await clientKeys.schema["~standard"].validate({ keys: [bad] });
			expect(
				read.issues?.map((i) => i.path?.map(String)),
				name,
			).toEqual([["keys", "0"]]);
		}
		const refused = await boot({ keys: [jwk(ec.privateKey)] }).catch((error) => error);
		expect(refused).toBeInstanceOf(BootRefused);
		const marked = await boot({
			keys: [jwk(ec.publicKey, { kid: "ec", use: "sig", key_ops: ["verify"] })],
		});
		expect(await tried(marked.c)).toBe("app");
		await expect(
			boot({ keys: [jwk(generateKeyPairSync("ed448").publicKey)] }),
		).resolves.toBeDefined();
		const keys = await clientKeys.schema["~standard"].validate({ keys: [], other: 1 });
		expect(keys.issues).toBeDefined();
		expect(clientKeysFor([])).toEqual({ "client-assertion": { keys: [] } });
	});

	it("holds a client to the issuer alone unless its section accepts a loose audience, a boolean", async () => {
		const validated = (value: Record<string, unknown>) =>
			clientKeys.schema["~standard"].validate({ keys: [], ...value });
		expect(await validated({})).toMatchObject({ value: { "accept-loose-audience": false } });
		expect(await validated({ "accept-loose-audience": true })).toMatchObject({
			value: { "accept-loose-audience": true },
		});
		expect((await validated({ "accept-loose-audience": "true" })).issues).toBeDefined();
	});
});
