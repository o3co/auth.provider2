import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { testServer } from "@mod/http-server/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import keysModule from "@mod/keys/module";
import { keysConfig, testHolder } from "@mod/keys/testing";
import senderBindingModule from "@mod/sender-binding/module";
import { simulatedStore } from "@mod/store/testing";
// Revocations through tokens, kept by this wiring on records over a store that fails as real ones do.
import {
	type AccessTokenIssuance,
	accessTokenIssuance,
	accessTokens,
	referenceOf,
} from "@mod/tokens";
import tokensModule from "@mod/tokens/module";
import { issueAtOnce, tokensConfig } from "@mod/tokens/testing";
import { expect, it, vi } from "vitest";
import tokensStore from "../src/module.ts";

let now = 1_800_000_000_000;
const runtime = quietRuntime({ clock: { now: () => now } });
const grant = {
	subject: "s",
	subjectKind: "user" as const,
	issuedTo: "c",
	audience: ["api"],
	scope: [],
};
/** An access token `t` issues for the grant, under the issuance policies. */
async function issuedAccess(t: AccessTokenIssuance) {
	const issued = await issueAtOnce(t, { grant, grantType: "test" });
	if (issued.kind !== "issued") throw new Error(issued.reason);
	return issued.access;
}

async function boot() {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [
			http,
			testServer(),
			keysModule,
			testHolder(),
			issuerModule,
			senderBindingModule,
			tokensModule,
			tokensStore,
			simulated.module,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": "https://issuer.example" }),
			...keysConfig(),
			...issuerConfig(),
			...tokensConfig({ revocation: "denylist", "access-token-lifetime": "1h" }),
		},
		runtime,
	});
	const t = app.get(accessTokens);
	const issuing = app.get(accessTokenIssuance);
	return { simulated, t, issuing, token: (await issuedAccess(issuing)).token };
}

it("answers a revocation whose reply was lost only once it is kept, so it survives a failover", async () => {
	const { simulated, t, token } = await boot();
	simulated.loseNextReply();
	expect(await t.revokeAccess(token)).toEqual({ kind: "revoked" });
	await simulated.failover();
	expect(await t.verifyAccess(token)).toEqual({ kind: "invalid", reason: "revoked" });
});

it("keeps one of two concurrent revocations whose replies were lost, through a failover", async () => {
	const { simulated, t, token } = await boot();
	simulated.loseNextReply();
	const answers = await Promise.all([t.revokeAccess(token), t.revokeAccess(token)]);
	expect(answers).toEqual([{ kind: "revoked" }, { kind: "revoked" }]);
	await simulated.failover();
	expect(await t.verifyAccess(token)).toEqual({ kind: "invalid", reason: "revoked" });
});

it("answers a second revocation only once the first is kept, so a failover between them loses neither", async () => {
	const { simulated, t, token } = await boot();
	const seen: { second?: unknown; after?: unknown } = {};
	// The first revocation applies; before it is confirmed, a second one finds it, and the store
	// fails over at once, before the first can be sent again.
	simulated.beforeConfirm("putIfAbsent", "tokens-store.revoked", async () => {
		seen.second = await t.revokeAccess(token);
		await simulated.failover();
		seen.after = await t.verifyAccess(token);
	});
	await t.revokeAccess(token).catch(() => undefined);
	expect(seen).toEqual({
		second: { kind: "revoked" },
		after: { kind: "invalid", reason: "revoked" },
	});
});

it("is unavailable when only writes fail, once its patience is spent", async () => {
	const { simulated, t, token } = await boot();
	simulated.failWrites(true);
	expect((await t.verifyAccess(token)).kind).toBe("valid");
	// The resends' pauses run on a fake clock: the patience spent is the same, its seconds none.
	vi.useFakeTimers({ toFake: ["setTimeout"] });
	try {
		let settled = false;
		const revoking = expect(t.revokeAccess(token))
			.rejects.toThrow()
			.finally(() => {
				settled = true;
			});
		// A pause at a time: each is set only once the send before it failed.
		while (!settled) await vi.advanceTimersByTimeAsync(1000);
		await revoking;
	} finally {
		vi.useRealTimers();
	}
});

it("keeps refusing after a failover to a store host whose clock runs ahead within the allowance", async () => {
	const { simulated, t, token } = await boot();
	expect(await t.revokeAccess(token)).toEqual({ kind: "revoked" });
	await simulated.failover();
	simulated.shiftClock(50_000);
	now += 3_599_000;
	expect(await t.verifyAccess(token)).toEqual({ kind: "invalid", reason: "revoked" });
});

it("revokes an issued token by its reference, without the token itself", async () => {
	const { simulated, t, issuing } = await boot();
	const issued = await issuedAccess(issuing);
	expect(issued.expiresAt).toBe(now + 3_600_000);
	expect(t.revocable()).toBe(true);
	expect(await t.revokeReferenced(referenceOf(issued))).toEqual({ kind: "revoked" });
	await simulated.failover();
	expect(await t.verifyAccess(issued.token)).toEqual({ kind: "invalid", reason: "revoked" });
	expect(await t.revokeReferenced(referenceOf({ id: "other", expiresAt: now - 61_000 }))).toEqual({
		kind: "invalid",
	});
});
