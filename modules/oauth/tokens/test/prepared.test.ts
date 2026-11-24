import { assemble, type BootRefused, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { accessTokenSigning } from "@mod/keys";
import { promiseNames, promises, stances } from "@mod/promises";
import promisesModule from "@mod/promises/module";
import { tokens as receipts } from "@mod/transparency-wire";
import { describe, expect, it } from "vitest";
import {
	type AccessGrant,
	accessTokenIssuance,
	accessTokens,
	type PreparedAccess,
} from "../src/contract.ts";
import { tokensConfig, tokensStandIn } from "../src/testing.ts";
import { bothOf, composedConfig, composedModules, composedWith } from "./composed.ts";

const now = 1_800_000_000_000;
const runtime = quietRuntime({ clock: { now: () => now } });
const grant: AccessGrant = {
	subject: "s",
	subjectKind: "user",
	issuedTo: "c",
	audience: ["api"],
	scope: [],
};
const segment = (text: string) => Buffer.from(text).toString("base64url");

async function boot(modules = composedModules, config: object = composedConfig()) {
	const app = await assemble({ modules, config: { ...config, ...tokensConfig() }, runtime });
	return { t: bothOf(app), signer: app.get(accessTokenSigning), app };
}

describe("prepare and sign", () => {
	it("prepares the header and claims as the texts the token carries, which sign then signs as they are", async () => {
		const { t } = await boot();
		const prepared = await t.prepare({ grant, grantType: "test" });
		if (prepared.kind !== "prepared") throw new Error(prepared.policy);
		expect(JSON.parse(prepared.headerText)).toEqual({ alg: "EdDSA", typ: "at+jwt", kid: "k" });
		const issued = await t.sign(prepared);
		if (issued.kind !== "issued") throw new Error(issued.policy);
		const [header, claims] = issued.access.token.split(".");
		expect([header, claims]).toEqual([segment(prepared.headerText), segment(prepared.claimsText)]);
		expect(JSON.parse(prepared.claimsText).jti).toBe(issued.access.id);
		expect((await t.verifyAccess(issued.access.token)).kind).toBe("valid");
		// The texts are what a bundle's record digests a token by.
		expect(receipts.digestInput(prepared.headerText, prepared.claimsText)).toHaveProperty("input");
	});

	it("signs one prepared again with the same header and claims, and nothing it did not prepare", async () => {
		const { t } = await boot();
		const prepared = (await t.prepare({ grant, grantType: "test" })) as PreparedAccess;
		const [first, second] = [await t.sign(prepared), await t.sign(prepared)];
		const payload = (issued: typeof first) =>
			issued.kind === "issued" ? issued.access.token.split(".").slice(0, 2) : [];
		expect(payload(second)).toEqual(payload(first));
		await expect(t.sign({ ...prepared })).rejects.toThrow(TypeError);
	});

	it("is unavailable where the keys' holder no longer lets this Core sign, handing nothing out", async () => {
		const withdrawn = defineModule({ name: "keys", replicaSafe: true, takes: [] }, (m) => [
			m.provide(accessTokenSigning).by(async () => ({
				prepare: () => ({
					ring: "authority",
					header: { alg: "EdDSA", typ: "at+jwt", kid: "k" },
					headerText: '{"alg":"EdDSA","typ":"at+jwt","kid":"k"}',
				}),
				sign: async () => ({ kind: "withdrawn" }),
				verify: async () => ({ kind: "invalid", reason: "signature" }),
			})),
		]);
		const [http, server, , , ...rest] = composedModules;
		const { keys: _, ...config } = composedConfig();
		const { t } = await boot([http, server, withdrawn, ...rest] as typeof composedModules, config);
		await expect(t.issue({ grant, grantType: "test" })).rejects.toSatisfy(isUnavailable);
	});
});

it("says where it stands on the promises, as accessTokenSigning asks of its taker: an access token carries no receipt", async () => {
	const { app } = await boot([...composedWith(), promisesModule]);
	const contained = app
		.get(promises)
		.judgment()
		.find((j) => j.promise === "core-compromise-contained");
	expect(contained?.breaking).toContainEqual({
		by: "tokens",
		reason: "an access token carries no receipt of the transparency log",
	});
});

it("is taken for issuing only by a module that declares where it stands on the promises, and for checking tokens by any", async () => {
	const taking = (handle: typeof accessTokens | typeof accessTokenIssuance, declares: boolean) =>
		defineModule({ name: "taker", replicaSafe: true, takes: [handle] }, (m) =>
			declares
				? [
						m.contribute(stances).by(() => ({
							promise: promiseNames.clientToken,
							holds: false,
							by: "taker",
						})),
					]
				: [],
		);
	const booted = (module: ReturnType<typeof taking>) => boot([...composedWith(), module]);
	const unsaid = await booted(taking(accessTokenIssuance, false)).catch((error: unknown) => error);
	expect((unsaid as BootRefused).refusals).toEqual([
		{
			where: "taker",
			reason: "tokens.issuance is taken only by a module that contributes to promises.stances",
		},
	]);
	await expect(booted(taking(accessTokenIssuance, true))).resolves.toBeDefined();
	await expect(booted(taking(accessTokens, false))).resolves.toBeDefined();
});

it("hands checking and revoking alone through accessTokens, no issuing member at run time, in tokens and its stand-in", async () => {
	const standIn = await assemble({ modules: [tokensStandIn()], config: kernelConfig(), runtime });
	for (const app of [(await boot()).app, standIn]) {
		expect(Object.keys(app.get(accessTokens)).sort()).toEqual([
			"issuedToOf",
			"revocable",
			"revokeAccess",
			"revokeReferenced",
			"subjectsChecked",
			"verifyAccess",
		]);
		expect(Object.keys(app.get(accessTokenIssuance)).sort()).toEqual([
			"accessTokenLifetimeSeconds",
			"admits",
			"issue",
			"prepare",
			"sign",
		]);
	}
});
