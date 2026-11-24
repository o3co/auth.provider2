import { generateKeyPairSync } from "node:crypto";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { keysConfig } from "@mod/keys/testing";
import { describe, expect, it } from "vitest";
import {
	bothOf,
	composedHttp,
	composedKeys,
	composedModules,
	composedWith,
} from "../../../test/composed.ts";
import { revokedInMemory } from "../../../test/revoked.ts";
import type { AccessGrant, Actor } from "../../contract.ts";

const runtime = quietRuntime();
const grant: AccessGrant = {
	subject: "s",
	subjectKind: "user",
	issuedTo: "c",
	audience: ["api"],
	scope: [],
};

describe("a token past 16 KiB once signed", () => {
	it("refuses an issuance whose token would pass 16 KiB once signed, warning its size and the added claims' names, never a value", async () => {
		const logged = recordingLog();
		const app = await assemble({
			modules: [...composedModules, revokedInMemory(() => runtime.clock.now()).module],
			config: {
				...kernelConfig(),
				...composedHttp(),
				...composedKeys(),
				...issuerConfig({ url: "https://issuer.example" }),
				tokens: { "subject-check": "none", revocation: "unsupported" },
			},
			runtime: { ...runtime, log: logged.log },
		});
		const wide = {
			...grant,
			scope: Array.from({ length: 2000 }, (_, i) => `scope-${i}`),
			claims: { x_secret_kept: "s3cr3t" },
		};
		expect(await bothOf(app).issue({ grant: wide, grantType: "test" })).toEqual({
			kind: "refused",
			policy: "tokens",
			reason: "token_too_large",
			description: "too large",
		});
		const warned = logged.lines().filter((l) => l.event === "tokens.token_too_large");
		expect(warned).toMatchObject([{ fields: { limit: 16_384, claims: "x_secret_kept" } }]);
		expect(Number(warned[0]?.fields.length)).toBeGreaterThan(16_384);
		expect(JSON.stringify(logged.lines())).not.toContain("s3cr3t");
	});
});

describe("an access token at its largest", () => {
	it("fits 16 KiB with added claims at size's 8 KiB ceiling, over the standard claims this covers", async () => {
		// The maxima covered, not bounds: tokens bounds none of the standard claims' lengths, so past
		// these a token may pass 16 KiB, and issue then refuses it (`token_too_large`). Subject, client
		// and two audiences of 256 characters, 1 KiB of scope, an actor chain of four subjects of 64,
		// an acr of 64 and room for a `cnf` (a DPoP thumbprint), signed with RSA-4096.
		const rsa = generateKeyPairSync("rsa", { modulusLength: 4096 }).privateKey;
		const kid = "k".repeat(64);
		const app = await assemble({
			modules: [...composedWith({ [kid]: rsa }), revokedInMemory(() => runtime.clock.now()).module],
			config: {
				...kernelConfig(),
				...composedHttp(),
				...keysConfig({ authority: { signing: { kid, alg: "RS256" } } }),
				...issuerConfig({ url: "https://issuer.example" }),
				tokens: {
					"subject-check": "none",
					revocation: "unsupported",
					"added-claims": { size: "8KiB", "string-length": 8192 },
				},
			},
			runtime,
		});
		const long = (n: number) => "a".repeat(n);
		const chain = (n: number): Actor => ({
			subject: long(64),
			...(n > 1 ? { actor: chain(n - 1) } : {}),
		});
		const claims = { x_entitled: long(8100) };
		const largest: AccessGrant = {
			subject: long(256),
			subjectKind: "user",
			issuedTo: long(256),
			audience: [long(256), `${long(255)}b`],
			scope: Array.from({ length: 128 }, (_, i) => `scope-${String(i).padStart(3, "0")}`),
			actor: chain(4),
			amr: ["pwd", "otp", "hwk"],
			acr: long(64),
			claims,
		};
		const issued = await bothOf(app).issue({ grant: largest, grantType: "test" });
		if (issued.kind !== "issued") throw new Error(`refused: ${issued.reason}`);
		// What a DPoP binding adds, `,"cnf":{"jkt":<43 characters>}`, encoded.
		expect(issued.access.token.length).toBeLessThanOrEqual(16_384 - 80);
	});
});
