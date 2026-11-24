import { createHash, randomBytes } from "node:crypto";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient } from "@mod/clients/testing";
import {
	type BundleRequest,
	type Grant,
	type GrantInput,
	grants,
	sessionIssuances,
	targetRules,
} from "@mod/grants";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { testServer } from "@mod/http-server/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import {
	assemble,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
	type Module,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime, takesUnused, unavailableSwitch } from "@mod/kernel/testing";
import { crowdingFor, memoryRecords } from "@mod/records/testing";
import secretHashModule from "@mod/secret-hash/module";
import { type Binding, senderBindings } from "@mod/sender-binding";
import { sessions } from "@mod/session";
import { openedOf, sessionStandIn } from "@mod/session/testing";
import { subjectRevocation } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { grantCaller, grantCalls, grantInput } from "@mod/token-endpoint/testing";
import {
	accessTokenIssuance,
	accessTokens,
	type IssuanceRequest,
	type IssuedAccess,
	issuancePolicies,
} from "@mod/tokens";
import { issueAtOnce, tokensStandIn } from "@mod/tokens/testing";
import { afterEach, describe, expect, it } from "vitest";
import { digestOf, fromStored } from "../src/codes.ts";
import {
	type ApprovedFacts,
	type CodeFacts,
	type CodeStore,
	codeStore,
	codes,
	type FamilyRequest,
	families,
	type IdTokenRequest,
	idTokens,
	type Redeemed,
	type RedemptionHook,
	redemptionHooks,
	redemptionRecords,
	type StoredCode,
	type StoredRedemptionRecord,
	storedRecordMaxMs,
	type VoidList,
	voidList,
} from "../src/contract.ts";
import codeGrantModule from "../src/module.ts";
import { fromStoredRedemptionRecord } from "../src/redemption-record/redemption-record.ts";
import { codeGrantConfig, codeStoreContract } from "../src/testing.ts";

const grantsSeen = contract<readonly Grant[]>("grants-seen");

let shift = 0;
/** A copy of every draw of 32 bytes the composition made, in order, so a test can tell what a code was made from. */
const drawn: Uint8Array[] = [];
const runtime = quietRuntime({
	clock: { now: () => Date.now() + shift },
	random: {
		bytes: (n) => {
			const bytes = new Uint8Array(randomBytes(n));
			if (n === 32) drawn.push(bytes.slice());
			return bytes;
		},
	},
});
let stop = async () => {};
/** A code's name as a place might make it: not the code, so a test that peeks by code finds nothing. */
const nameOf = (code: string) => `n.${createHash("sha256").update(code).digest("base64url")}`;
/**
 * code-grant's stores on the records stand-in, with its clock from the composition; the void list
 * behind a switch, and redemption records that may answer a subject erased.
 */
const memoryStores = () => {
	let clock = () => 0;
	const stand = memoryRecords<StoredCode>(() => clock(), { shards: 16, perShard: 100 });
	const redeemed = memoryRecords<StoredRedemptionRecord>(() => clock(), { shards: 1, perShard: 1 });
	/** Subjects erased: no redemption record is created for them. */
	const erased = new Set<string>();
	const voids = unavailableSwitch<VoidList>("void list");
	/** Whether the next change finds nothing, as a read that has not yet seen the record. */
	let missing = false;
	/** Runs once before the next redemption record is created: the window after a code's use-up. */
	let beforeRecord: (() => Promise<void>) | undefined;
	const update: CodeStore["update"] = (name, change) => {
		if (!missing) return stand.records.change(name, change);
		missing = false;
		return Promise.resolve(undefined);
	};
	const module = defineModule({ name: "code-stores", replicaSafe: false, takes: [] }, (m) => [
		m.provide(codeStore).by((c) => {
			clock = c.clock.now;
			// Created by the code, under its name, as a Store keyed by secrets names it.
			const create: CodeStore["create"] = (code, record, lifetimeMs) =>
				stand.records.create(nameOf(code), record, lifetimeMs);
			return { nameOf, create, update };
		}),
		m.provide(voidList).by(() => voids.wrap(stand.deferred)),
		m.provide(redemptionRecords).by(() => ({
			create: async (name, record, lifetimeMs, subject) => {
				const step = beforeRecord;
				beforeRecord = undefined;
				await step?.();
				return erased.has(subject) ? "erased" : redeemed.records.create(name, record, lifetimeMs);
			},
			read: redeemed.records.read,
			update: redeemed.records.change,
		})),
	]);
	return {
		module,
		...stand,
		voids,
		missNextChange: () => (missing = true),
		beforeNextRecord: (step: () => Promise<void>) => {
			beforeRecord = step;
		},
		redeemed,
		erase: (subject: string) => erased.add(subject),
	};
};
/** Records each token issued from a session, as `session-tokens` does, so a logout ends it. */
const recordedTo = (recorded: Map<string, string>) =>
	defineModule({ name: "session-recording", replicaSafe: false, takes: [] }, (m) => [
		m.contribute(sessionIssuances).by(() => ({
			issued: async (session, { id }) => {
				recorded.set(id, session);
			},
		})),
	]);
afterEach(async () => {
	shift = 0;
	drawn.length = 0;
	await stop();
});

codeStoreContract("records stand-in", async () => {
	let now = 0;
	const size = { shards: 4, perShard: 5 };
	const stand = memoryRecords<StoredCode>(() => now, size);
	const redeemed = memoryRecords<StoredRedemptionRecord>(() => now, size);
	return {
		codes: {
			nameOf,
			create: (code, record, lifetimeMs) => stand.records.create(nameOf(code), record, lifetimeMs),
			update: stand.records.change,
		},
		redemptionRecords: {
			create: (name, record, lifetimeMs) => redeemed.records.create(name, record, lifetimeMs),
			read: redeemed.records.read,
			update: redeemed.records.change,
		},
		voids: stand.deferred,
		advance: (ms) => {
			now += ms;
		},
		raceNextUpdate: (_name, change) => stand.raceNextChange(change),
		crowd: { limit: size.perShard, names: crowdingFor(size).jobs },
	};
});
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
/** Hands the grants to the test, so it can call the code grant directly. */
const reader = defineModule({ name: "reader", replicaSafe: true, takes: [grants] }, (m) => [
	m.provide(grantsSeen).by((c) => c.collect(grants)),
]);

/** The same answer for every refused code, as the token endpoint sends it and as the grant gives it. */
const refusedBody = { error: "invalid_grant", error_description: "invalid code" };
const refusedOutcome = { kind: "error", error: "invalid_grant", description: "invalid code" };
/** A stored record with fields written over, as a broken or foreign writer might leave it. */
const overwritten = (kept: StoredCode, over: object) =>
	({ ...(kept as unknown as object), ...over }) as unknown as StoredCode;
/** Waits until the sweep, every second here, has run once. */
const afterSweep = () => new Promise((resolve) => setTimeout(resolve, 1300));
const refusedFor = (reason: string) =>
	expect.objectContaining({
		refusals: expect.arrayContaining([expect.objectContaining({ reason })]),
	});
/** A DPoP binding of the key named. */
const dpop = (confirmation: string): Binding => ({
	member: "jkt",
	confirmation,
	tokenType: "DPoP",
});

/** A binding kind writing `jkt`, so a token bound by it verifies as bound. */
const dpopKind = defineModule({ name: "dpop-kind", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(senderBindings).by(() => ({
		member: "jkt",
		tokenType: "DPoP",
		explicit: true,
		read: async () => ({ kind: "absent" }),
	})),
]);

/** A policy that allows what `allows` allows, and refuses the rest. */
const policy = (allows: (request: IssuanceRequest) => boolean) =>
	defineModule({ name: "test-policy", replicaSafe: false, takes: [] }, (m) => [
		m.contribute(issuancePolicies).by(() => ({
			name: "test-policy",
			judge: async (request) =>
				allows(request)
					? { kind: "allowed" }
					: { kind: "refused", reason: "test_reason", description: "refused here" },
		})),
	]);

type Options = {
	revocation?: "denylist" | "unsupported";
	/** Whether the tokens issued from a session are recorded to it (as combinations composes it). */
	recorded?: boolean;
	extra?: Module[];
	codeGrant?: Parameters<typeof codeGrantConfig>[0];
	/** The grants the clients are allowed; the code grant alone unless told. */
	grants?: string[];
};

/** What `serve` assembles, with the stores it reaches into and the tokens recorded to their session. */
function assembly(options: Options = {}) {
	const stores = memoryStores();
	const recorded = new Map<string, string>();
	const input = {
		modules: [
			http,
			testServer(),
			tokensStandIn({ revocable: (options.revocation ?? "denylist") === "denylist" }),
			issuerModule,
			clientsModule,
			secretHashModule,
			grantCaller,
			clientAllowanceModule,
			sessionStandIn,
			subjectRevocationStandIn,
			stores.module,
			...(options.recorded === false ? [] : [recordedTo(recorded)]),
			codeGrantModule,
			reader,
			...(options.extra ?? []),
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": "https://as.example" }),
			...issuerConfig({ url: "https://as.example" }),
			...clientsConfig(
				["app", "other"].map((id) =>
					confidentialClient({
						id,
						sections: allowancesFor({
							grants: options.grants ?? ["authorization_code"],
							scopes: ["openid", "read"],
							audiences: ["https://api"],
						}),
					}),
				),
			),
			...codeGrantConfig(options.codeGrant ?? { "sweep-interval": "1s" }),
		},
		runtime,
	};
	return { input, stores, recorded };
}

/** Opens a session for the subject, ending in an hour unless told otherwise. */
const opened = async (
	app: Awaited<ReturnType<typeof assemble>>,
	subject = "alice",
	endsInMs = 3_600_000,
) =>
	openedOf(
		await app.get(sessions).open({
			subject,
			amr: ["hwk", "user"],
			authenticatedAt: runtime.clock.now(),
			provenSince: runtime.clock.now(),
			endsAt: runtime.clock.now() + endsInMs,
		}),
	);

async function serve(options: Options = {}) {
	const { input, stores, recorded } = assembly(options);
	const app = await assemble(input);
	await app.start();
	stop = () => app.stop(1000);
	const { session } = await opened(app);
	const facts: CodeFacts = {
		clientId: "app",
		redirectUri: "https://app.example/cb",
		challenge,
		scope: ["read"],
		audience: ["https://api"],
		session: session.id,
		subject: "alice",
	};
	/** A code, rooted in its approval's record as its issuer roots it. */
	const issue = async (scope = facts.scope) => {
		const code = await app.get(codes).issue({ ...facts, scope });
		await app.get(codes).root(code, "root-of-the-approval");
		return code;
	};
	/** Redeems through the grant harness, answering as the token endpoint would. */
	const redeem = async (
		code: string,
		extra: Record<string, string> = {},
		binding?: Binding,
	): Promise<{ status: number; body: Record<string, unknown> }> => {
		const params = {
			grant_type: "authorization_code",
			code,
			redirect_uri: "https://app.example/cb",
			code_verifier: verifier,
			...extra,
		};
		const outcome = await app
			.get(grantCalls)
			.call("authorization_code", "app", params, binding ? { binding } : {})
			.catch((error: unknown) => {
				if (isUnavailable(error)) return undefined;
				throw error;
			});
		if (!outcome) return { status: 503, body: { error: "temporarily_unavailable" } };
		if (outcome.kind === "issued") return { status: 200, body: { ...outcome.body } };
		const described = outcome.description ? { error_description: outcome.description } : {};
		return { status: 400, body: { error: outcome.error, ...described } };
	};
	return { app, stores, recorded, issue, redeem, session, facts };
}
type Served = Awaited<ReturnType<typeof serve>>;
/** A code issued for the facts and rooted, as its issuer roots it once the approval is placed. */
const rootedIssue = async (s: Served, facts: CodeFacts, approved?: ApprovedFacts) => {
	const code = await s.app.get(codes).issue(facts);
	await s.app.get(codes).root(code, "root-of-the-approval", approved);
	return code;
};
/** What a code's record holds now. */
const keptOf = (s: Served, code: string) => {
	const kept = s.stores.peek(nameOf(code));
	return kept && fromStored(kept);
};
/** What a code's redemption record holds now. */
const redeemedOf = (s: Served, code: string) =>
	fromStoredRedemptionRecord(s.stores.redeemed.peek(nameOf(code)));

const revoked = async (s: Served, token: string) =>
	(await s.app.get(accessTokens).verifyAccess(token)).kind === "invalid";
const directClient = {
	id: "app",
	kind: "confidential" as const,
	method: "client_secret_post",
	registered: true,
	section: <T>() => ({}) as T,
};
/** Issues the bundle's access token at once, as the endpoint would once the bundle is judged. */
const issuedNow = async (s: Served, bundle: BundleRequest) => {
	const issued = await issueAtOnce(s.app.get(accessTokenIssuance), {
		grant: bundle.access,
		grantType: "authorization_code",
	});
	if (issued.kind === "refused") throw new Error(issued.reason);
	return issued;
};
/** Calls the grant directly, so a test can step into the token's issuing or hand it a binding. */
async function handleDirectly(
	s: Served,
	code: string,
	over: Partial<Pick<GrantInput, "issue" | "binding">> = {},
	client = directClient,
) {
	const grant = s.app.get(grantsSeen).find((g) => g.grantType === "authorization_code");
	const params: Record<string, string> = {
		code,
		redirect_uri: "https://app.example/cb",
		code_verifier: verifier,
	};
	if (!grant) throw new Error("no authorization_code grant");
	const issuing = { ...s.app.get(accessTokenIssuance), ...s.app.get(accessTokens) };
	return grant.handle({ ...grantInput(issuing, grant, client, params), ...over });
}

it("gives the access token the code's amr, authentication time and acr, issued from its session", async () => {
	const asked: IssuanceRequest[] = [];
	const s = await serve({ extra: [policy((request) => asked.push(request) > 0)] });
	const code = await rootedIssue(s, { ...s.facts, acr: "urn:example:acr:high" });
	const answer = await s.redeem(code);
	const checked = await s.app.get(accessTokens).verifyAccess(String(answer.body.access_token));
	const { authenticatedAt } = s.session.context;
	expect(checked).toMatchObject({
		kind: "valid",
		grant: {
			subject: "alice",
			subjectKind: "user",
			amr: ["hwk", "user"],
			authenticatedAt: Math.floor(authenticatedAt / 1000) * 1000,
			acr: "urn:example:acr:high",
		},
	});
	expect(asked.map((request) => [request.grantType, request.session])).toEqual([
		["authorization_code", s.session.id],
		["authorization_code", s.session.id],
	]);
});

it("issues one bundle rooted in the code's approval, carrying the root's reference unread", async () => {
	const s = await serve();
	const bundles: BundleRequest[] = [];
	const answer = await handleDirectly(s, await s.issue(), {
		issue: async (bundle) => {
			bundles.push(bundle);
			return issuedNow(s, bundle);
		},
	});
	expect(answer.kind).toBe("issued");
	expect(bundles.map((bundle) => [bundle.root, bundle.via, bundle.parts])).toEqual([
		["root-of-the-approval", { via: "code" }, []],
	]);
});

describe("the binding the authorization asked for ahead", () => {
	it("redeems a code only with a proof by the key it asked for, the token holding that key", async () => {
		const s = await serve({ extra: [dpopKind] });
		const bound = await rootedIssue(s, { ...s.facts, binding: dpop("held") });
		const answer = await s.redeem(bound, {}, dpop("held"));
		expect(answer).toMatchObject({ status: 200, body: { token_type: "DPoP" } });
		const checked = await s.app.get(accessTokens).verifyAccess(String(answer.body.access_token));
		expect(checked).toMatchObject({ kind: "valid", binding: dpop("held") });
	});

	it("tells a proof by another key nothing of the policies, using the code up", async () => {
		const s = await serve({ extra: [dpopKind, policy(() => false)] });
		const bound = await rootedIssue(s, { ...s.facts, binding: dpop("held") });
		expect((await s.redeem(bound, {}, dpop("other"))).body).toEqual(refusedBody);
		expect(keptOf(s, bound)?.state).toBe("consumed");
	});

	it("refuses, using the code up, a proof by another key, no proof, or a proof for a code that asked none", async () => {
		const s = await serve();
		const cases: [string, Binding | undefined, Binding | undefined][] = [
			["another key", dpop("held"), dpop("other")],
			["no proof", dpop("held"), undefined],
			["a proof for a code that asked none", undefined, dpop("held")],
		];
		for (const [label, asked, proved] of cases) {
			const code = await rootedIssue(s, {
				...s.facts,
				...(asked ? { binding: asked } : {}),
			});
			expect((await s.redeem(code, {}, proved)).body, label).toEqual(refusedBody);
			expect(keptOf(s, code)?.state, label).toBe("consumed");
			expect((await s.redeem(code, {}, asked)).body, label).toEqual(refusedBody);
		}
	});
});

/** What an approval gives an openid code, as `authorize` hands it on. */
const approval = {
	esig: "e-sig-thumbprint",
	apr: { shard: "s1", n: 7 },
	approvedAt: 1_800_000_000_000,
};
/** An ID token maker that answers each part's request, made at once, as `oidc` would contribute it. */
const idTokenMaker = (asked: IdTokenRequest[], name = "id-tokens", fails = false) =>
	defineModule({ name, replicaSafe: true, takes: [] }, (m) => [
		m.contribute(idTokens).by(() => ({
			part: async (request) => {
				asked.push(request);
				if (fails) throw new Unavailable("attributes");
				return {
					frame: "idToken" as const,
					prepare: async (acceptedAt) => ({ prepared: acceptedAt, digest: "id-digest" }),
					sign: async (prepared, receipt) => `id-token.${String(prepared)}.${receipt}`,
				};
			},
		})),
	]);

/** A family maker that answers each part's request, made at once, and records what it was asked to end. */
const familyMaker = (
	asked: FamilyRequest[],
	revoked: string[],
	refuse?: string,
	name = "families",
) =>
	defineModule({ name, replicaSafe: true, takes: [] }, (m) => [
		m.contribute(families).by(() => ({
			part: async (request) => {
				asked.push(request);
				if (refuse) return { refused: refuse };
				return {
					frame: "family" as const,
					prepare: async () => ({ prepared: "f", digest: "family-digest" }),
					sign: async (_prepared, receipt, placed) => `refresh.${placed.id}.${receipt}`,
				};
			},
			revoke: async (code, subject) => {
				revoked.push(`${code} ${subject}`);
			},
		})),
	]);

describe("a refresh family, founded with a redemption", () => {
	const founding = { ...approval, statement: "t-hash" };
	const allowances = {
		grants: ["authorization_code", "refresh_token"],
		scopes: ["read"],
		audiences: ["https://api"],
	};
	const refreshing = { ...directClient, section: <T>() => allowances as T };

	it("is a part of the redemption's bundle for a client allowed to refresh, made from the code's facts, answered as refresh_token", async () => {
		const asked: FamilyRequest[] = [];
		const s = await serve({
			extra: [familyMaker(asked, [])],
			grants: ["authorization_code", "refresh_token"],
		});
		const code = await rootedIssue(
			s,
			{ ...s.facts, binding: { member: "jkt", confirmation: "k1", tokenType: "DPoP" } },
			founding,
		);
		const bundles: BundleRequest[] = [];
		const answer = await handleDirectly(
			s,
			code,
			{
				binding: { member: "jkt", confirmation: "k1", tokenType: "DPoP" },
				issue: async (bundle) => {
					bundles.push(bundle);
					return { ...(await issuedNow(s, bundle)), parts: ["the-refresh-token"] };
				},
			},
			refreshing,
		);
		expect(answer).toMatchObject({ kind: "issued", body: { refresh_token: "the-refresh-token" } });
		expect(bundles[0]?.parts?.map((p) => p.frame)).toEqual(["family"]);
		expect(asked).toEqual([
			{
				...founding,
				subject: "alice",
				clientId: "app",
				scope: ["read"],
				audience: ["https://api"],
				amr: ["hwk", "user"],
				session: s.session.id,
				binding: { member: "jkt", confirmation: "k1", tokenType: "DPoP" },
				code: digestOf(code),
			},
		]);
	});

	it("is founded for no client not allowed to refresh, and none of a code rooted without its statement", async () => {
		const asked: FamilyRequest[] = [];
		const s = await serve({ extra: [familyMaker(asked, [])] });
		expect((await s.redeem(await rootedIssue(s, s.facts, founding))).body).not.toHaveProperty(
			"refresh_token",
		);
		const allowed = await serve({
			extra: [familyMaker(asked, [])],
			grants: ["authorization_code", "refresh_token"],
		});
		expect(
			(await allowed.redeem(await rootedIssue(allowed, allowed.facts, approval))).body,
		).not.toHaveProperty("refresh_token");
		expect(asked).toEqual([]);
	});

	it("refused, uses the code up and answers it as every refused code, issuing nothing", async () => {
		const s = await serve({
			extra: [familyMaker([], [], "the key is bound to another live family")],
			grants: ["authorization_code", "refresh_token"],
		});
		const code = await rootedIssue(s, s.facts, founding);
		expect((await s.redeem(code)).body).toEqual(refusedBody);
		expect(keptOf(s, code)?.state).toBe("consumed");
		expect((await s.redeem(code)).body).toEqual(refusedBody);
	});

	it("is ended with the token when the code comes again, by the code's digest its redemption record keeps", async () => {
		const revoked: string[] = [];
		const s = await serve({
			extra: [familyMaker([], revoked)],
			grants: ["authorization_code", "refresh_token"],
		});
		const code = await rootedIssue(s, s.facts, founding);
		expect((await s.redeem(code)).status).toBe(200);
		expect(redeemedOf(s, code)?.redemption).toBe(digestOf(code));
		expect((await s.redeem(code)).body).toEqual(refusedBody);
		// Under the code's subject, which its record still names.
		expect(revoked).toEqual([`${digestOf(code)} alice`]);
	});

	it("is founded by at most one module: two refuse boot", async () => {
		const { input } = assembly({
			extra: [familyMaker([], []), familyMaker([], [], undefined, "other-families")],
		});
		await expect(assemble(input)).rejects.toEqual(
			refusedFor("at most one module founds refresh families"),
		);
	});
});

describe("an ID token, for a code whose scope has openid", () => {
	const openidFacts = (s: Served) => ({
		...s.facts,
		scope: ["openid", "read"],
		nonce: "n-0S6_WzA2Mj",
	});

	it("is a part of the redemption's bundle, made from the code's facts, and answered as id_token", async () => {
		const asked: IdTokenRequest[] = [];
		const s = await serve({ extra: [idTokenMaker(asked)] });
		const code = await rootedIssue(s, { ...openidFacts(s), acr: "urn:example:acr:high" }, approval);
		const answer = await s.redeem(code);
		expect(answer.status).toBe(200);
		expect(String(answer.body.id_token)).toMatch(/^id-token\.\d+\.test-receipt$/);
		expect(asked).toEqual([
			{
				...approval,
				subject: "alice",
				clientId: "app",
				nonce: "n-0S6_WzA2Mj",
				amr: ["hwk", "user"],
				acr: "urn:example:acr:high",
				scope: ["openid", "read"],
				session: s.session.id,
				code: digestOf(code),
			},
		]);
	});

	it("is asked in one bundle with the access token, rooted by its code", async () => {
		const s = await serve({ extra: [idTokenMaker([])] });
		const bundles: BundleRequest[] = [];
		const answer = await handleDirectly(s, await rootedIssue(s, openidFacts(s), approval), {
			issue: async (bundle) => {
				bundles.push(bundle);
				return { ...(await issuedNow(s, bundle)), parts: ["id"] };
			},
		});
		expect(answer).toMatchObject({ kind: "issued", body: { id_token: "id" } });
		expect(bundles.map((b) => [b.via, b.parts?.map((p) => p.frame)])).toEqual([
			[{ via: "code" }, ["idToken"]],
		]);
	});

	it("is never issued from a code without its nonce, nor rooted without its approval, which it keeps by name", async () => {
		const s = await serve({ extra: [idTokenMaker([])] });
		const { nonce: _, ...noNonce } = openidFacts(s);
		await expect(s.app.get(codes).issue(noNonce)).rejects.toThrow(TypeError);
		const code = await s.app.get(codes).issue(openidFacts(s));
		await expect(s.app.get(codes).root(code, "r")).rejects.toThrow(TypeError);
		expect(keptOf(s, code)?.root).toBeUndefined();
		const loud = { ...approval, extra: 1, apr: { ...approval.apr, more: 2 } } as ApprovedFacts;
		expect(await s.app.get(codes).root(code, "r", loud)).toBe("set");
		expect(keptOf(s, code)).toMatchObject({ root: "r", approval });
		// A code asking no ID token roots without one.
		expect(await s.app.get(codes).root(await s.app.get(codes).issue(s.facts), "r")).toBe("set");
	});

	it("is read before the bundle starts: a maker that cannot read fails the redemption, issuing nothing", async () => {
		const s = await serve({ extra: [idTokenMaker([], "id-tokens", true)] });
		const bundles: BundleRequest[] = [];
		const code = await rootedIssue(s, openidFacts(s), approval);
		await expect(
			handleDirectly(s, code, {
				issue: async (bundle) => {
					bundles.push(bundle);
					return issuedNow(s, bundle);
				},
			}),
		).rejects.toSatisfy(isUnavailable);
		expect(bundles).toEqual([]);
		expect(keptOf(s, code)?.state).toBe("consumed");
	});

	it("tells whether an ID token is made, for a request to be refused before a code asks one", async () => {
		expect((await serve({ extra: [idTokenMaker([])] })).app.get(codes).issuesIdTokens()).toBe(true);
		expect((await serve()).app.get(codes).issuesIdTokens()).toBe(false);
	});

	it("is made by at most one module: two refuse boot", async () => {
		const { input } = assembly({ extra: [idTokenMaker([]), idTokenMaker([], "other-maker")] });
		await expect(assemble(input)).rejects.toEqual(refusedFor("at most one module makes ID tokens"));
	});
});

it("answers invalid_scope for a code asking an ID token where no module makes one, issuing nothing", async () => {
	const s = await serve();
	const code = await rootedIssue(
		s,
		{ ...s.facts, scope: ["openid", "read"], nonce: "n" },
		approval,
	);
	expect((await s.redeem(code)).body).toEqual({
		error: "invalid_scope",
		error_description: "no ID token is issued",
	});
	expect(redeemedOf(s, code)).toBeUndefined();
});

it("has the access token recorded to the code's session", async () => {
	const s = await serve();
	const answer = await s.redeem(await s.issue());
	const checked = await s.app.get(accessTokens).verifyAccess(String(answer.body.access_token));
	if (checked.kind !== "valid") throw new Error("not valid");
	expect(s.recorded.get(checked.id)).toBe(s.session.id);
});

it("ends the access token no later than its session, when the session ends first [rfc6749-5.1-b]", async () => {
	const s = await serve();
	const { session } = await opened(s.app, "alice", 30_000);
	const answer = await s.redeem(await rootedIssue(s, { ...s.facts, session: session.id }));
	const checked = await s.app.get(accessTokens).verifyAccess(String(answer.body.access_token));
	if (checked.kind !== "valid") throw new Error("not valid");
	expect(checked.expiresAt).toBeLessThanOrEqual(runtime.clock.now() + 30_000);
});

it("asks the issuance policies before the code is used up, and only for its own client and verifier [rfc7636-4.6-b]", async () => {
	const s = await serve({ extra: [policy(() => false)] });
	const code = await s.issue();
	const refused = { error: "invalid_grant", error_description: "refused here" };
	expect((await s.redeem(code)).body).toEqual(refused);
	expect(keptOf(s, code)?.state).toBe("issued");
	// A wrong verifier is told nothing of the policies, and uses the code up.
	expect((await s.redeem(code, { code_verifier: "w".repeat(43) })).body).toEqual(refusedBody);
	expect(keptOf(s, code)?.state).toBe("consumed");
});

/** A rule narrowing to the `resource` asked when the issuance may have it, as resource indicators do. */
const narrowing = defineModule({ name: "narrowing", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(targetRules).by(() => ({
		target: ({ param, audience, within }) => {
			const asked = param("resource");
			if (!asked) return { kind: "audience", audience };
			return within(asked)
				? { kind: "audience", audience: [asked] }
				: { kind: "error", error: "invalid_target", description: `not ${asked}` };
		},
	})),
]);

it("refuses a resource outside the code's audience before the code is used up, and redeems it after", async () => {
	const s = await serve({ extra: [narrowing] });
	const code = await s.issue();
	expect((await s.redeem(code, { resource: "https://other" })).body).toEqual({
		error: "invalid_target",
		error_description: "not https://other",
	});
	expect(keptOf(s, code)?.state).toBe("issued");
	expect((await s.redeem(code, { resource: "https://api" })).status).toBe(200);
});

it("refuses a resource outside the code's audience when the look before use missed the code, issuing nothing", async () => {
	const s = await serve({ extra: [narrowing] });
	const code = await s.issue();
	s.stores.missNextChange();
	expect((await s.redeem(code, { resource: "https://other" })).body).toEqual({
		error: "invalid_target",
		error_description: "not https://other",
	});
	expect(redeemedOf(s, code)?.token).toBeUndefined();
});

it("reads no resource at the exchange where no rule is composed", async () => {
	const s = await serve();
	expect((await s.redeem(await s.issue(), { resource: "https://other" })).status).toBe(200);
});

it("refuses a code the policies refuse once it is used up, issuing nothing", async () => {
	let asks = 0;
	const s = await serve({ extra: [policy(() => ++asks < 2)] });
	const code = await s.issue();
	expect((await s.redeem(code)).body).toEqual({
		error: "invalid_grant",
		error_description: "refused here",
	});
	expect(keptOf(s, code)).toMatchObject({ state: "consumed" });
	expect(redeemedOf(s, code)?.token).toBeUndefined();
	expect((await s.redeem(code)).body).toEqual(refusedBody);
});

it("redeems a code once, and a code that comes again revokes what it gave [rfc6749-4.1.2-d] [rfc6749-4.1.2-e] [oidc-core-16.9-a]", async () => {
	const s = await serve();
	const code = await s.issue();
	const first = await s.redeem(code);
	expect(first.status).toBe(200);
	expect((await s.redeem(code)).body).toEqual(refusedBody);
	expect(await revoked(s, String(first.body.access_token))).toBe(true);
});

it("keeps neither the code nor the token it gave in its records, the token noted by its reference and end alone [rfc6749-10.3-a]", async () => {
	const s = await serve();
	const code = await s.issue();
	const redeemed = await s.redeem(code);
	expect(redeemed.status).toBe(200);
	const stored = JSON.stringify([
		s.stores.peek(nameOf(code)),
		s.stores.redeemed.peek(nameOf(code)),
	]);
	for (const secret of [code, String(redeemed.body.access_token)]) {
		expect(stored).not.toContain(secret);
	}
	expect(Object.keys(redeemedOf(s, code)?.token ?? {}).sort()).toEqual(["expiresAt", "reference"]);
});

it("refuses a code another exchange used up while this one was turning it, and lists it void [rfc6749-4.1.2-d]", async () => {
	const s = await serve();
	const code = await s.issue();
	s.stores.raceNextChange((kept) => overwritten(kept, { state: "consumed" }));
	expect((await s.redeem(code)).body).toEqual(refusedBody);
	// Listed while the code is kept: the exchange that used it up has made no record yet.
	expect(s.stores.pending()).toEqual([nameOf(code)]);
});

it("refuses a code whose record is in a state, format or shape it does not know, however often it comes", async () => {
	const s = await serve();
	const odd = {
		"unknown state": { state: "pending" },
		"scope not a list": { scope: "read" },
		"another format": { format: 2 },
		"an unknown field": { kept: true },
		"no root": { root: undefined },
	};
	for (const [label, over] of Object.entries(odd)) {
		const code = await s.issue();
		await s.stores.records.change(nameOf(code), (kept) => ({ value: overwritten(kept, over) }));
		for (const _ of [1, 2]) expect((await s.redeem(code)).body, label).toEqual(refusedBody);
	}
});

it("drops a listed void whose record is gone, as one it cannot revoke, at the next sweep", async () => {
	const s = await serve();
	await s.stores.deferred.add(nameOf("never-redeemed"));
	await afterSweep();
	expect(s.stores.pending()).toEqual([]);
});

it("refuses a request missing the code, the redirect URI or the verifier, a code or redirect URI sent empty as one left out, or with a malformed verifier, leaving the code unused [rfc6749-5.2-f] [rfc7636-4.5-b] [rfc6749-4.1.3-e] [rfc6749-3.2-b]", async () => {
	const s = await serve();
	const code = await s.issue();
	const cases: Record<string, Record<string, string>> = {
		"no code": { code: "" },
		"no redirect URI": { redirect_uri: "" },
		"no verifier": { code_verifier: "" },
		"a verifier too short": { code_verifier: "v".repeat(42) },
		"a verifier with a character outside its set": { code_verifier: `${"v".repeat(42)}+` },
	};
	for (const [name, extra] of Object.entries(cases)) {
		expect((await s.redeem(code, extra)).body.error, name).toBe("invalid_request");
	}
	expect(keptOf(s, code)?.state).toBe("issued");
	expect((await s.redeem(code)).status).toBe(200);
});

it("refuses a code whose subject was revoked after it signed in", async () => {
	const s = await serve();
	const code = await s.issue();
	shift = 1000;
	await s.app.get(subjectRevocation).revoke("alice");
	expect((await s.redeem(code)).body).toEqual(refusedBody);
	expect(redeemedOf(s, code)?.token).toBeUndefined();
});

it("refuses a code issued to another client, or presented with another redirect URI, only once and only while it lives [rfc6749-4.1.3-c] [rfc6749-4.1.3-e] [oidc-core-3.1.3.2-b] [oidc-core-3.1.3.2-c] [oidc-core-3.1.3.2-e]", async () => {
	const s = await serve({ codeGrant: { "code-lifetime": "10s", "sweep-interval": "1s" } });
	const elsewhere = await rootedIssue(s, { ...s.facts, clientId: "other" });
	expect((await s.redeem(elsewhere)).body).toEqual(refusedBody);
	const moved = await s.issue();
	expect((await s.redeem(moved, { redirect_uri: "https://app.example/other" })).body).toEqual(
		refusedBody,
	);
	expect((await s.redeem("not-a-code")).body).toEqual(refusedBody);
	const late = await s.issue();
	shift = 11_000;
	expect((await s.redeem(late)).body).toEqual(refusedBody);
});

it("issues nothing for a code whose session closed before the exchange", async () => {
	const s = await serve();
	const code = await s.issue();
	await s.app.get(sessions).close(s.session.id);
	expect((await s.redeem(code)).body).toEqual(refusedBody);
	expect(redeemedOf(s, code)?.token).toBeUndefined();
});

it("keeps an unused code for code-lifetime, and no longer [oidc-core-16.9-a]", async () => {
	const s = await serve({ codeGrant: { "code-lifetime": "10s" } });
	const code = await s.issue();
	shift = 9000;
	expect(keptOf(s, code)).toBeDefined();
	shift = 11_000;
	expect(keptOf(s, code)).toBeUndefined();
});

it("keeps a redemption record past its token's end, for storedRecordMaxMs, and a redeemed code no longer than issued", async () => {
	const s = await serve();
	const code = await s.issue();
	const before = Date.now();
	expect((await s.redeem(code)).status).toBe(200);
	shift = 61_000;
	expect([keptOf(s, code), redeemedOf(s, code)?.token]).toEqual([undefined, expect.anything()]);
	shift = before - Date.now() + storedRecordMaxMs - 1000;
	expect(redeemedOf(s, code)).toBeDefined();
	shift = before - Date.now() + storedRecordMaxMs + 1000;
	expect(redeemedOf(s, code)).toBeUndefined();
});

it("voids the token it issued when the code is used again while the token is made", async () => {
	const s = await serve();
	const code = await s.issue();
	const given: string[] = [];
	const answer = await handleDirectly(s, code, {
		issue: async (bundle) => {
			const issued = await issuedNow(s, bundle);
			given.push(issued.access.token);
			expect((await s.redeem(code)).body).toEqual(refusedBody);
			return issued;
		},
	});
	expect(answer).toEqual(refusedOutcome);
	expect(await revoked(s, given[0] as string)).toBe(true);
});

describe("a code that comes again before the redemption that used it up has made its record", () => {
	/** Redeems the code, running `meanwhile` after its use-up and before its redemption record; the token it issued, if any. */
	const racing = async (s: Served, code: string, meanwhile: () => Promise<void>) => {
		const given: string[] = [];
		s.stores.beforeNextRecord(meanwhile);
		const answer = await handleDirectly(s, code, {
			issue: async (bundle) => {
				const issued = await issuedNow(s, bundle);
				given.push(issued.access.token);
				return issued;
			},
		});
		return { answer, token: given[0] };
	};

	it("voids the token the redemption issues after, through the mark on the code", async () => {
		const s = await serve();
		const code = await s.issue();
		const { answer, token } = await racing(s, code, async () => {
			expect((await s.redeem(code)).body).toEqual(refusedBody);
		});
		expect(answer).toEqual(refusedOutcome);
		expect(await revoked(s, token as string)).toBe(true);
		expect(s.stores.pending()).toEqual([]);
	});

	it("voids it too where the code ended and its listing was dropped meanwhile", async () => {
		const s = await serve({ codeGrant: { "code-lifetime": "10s", "sweep-interval": "1s" } });
		const code = await s.issue();
		const { answer, token } = await racing(s, code, async () => {
			expect((await s.redeem(code)).body).toEqual(refusedBody);
			shift = 11_000;
			await afterSweep();
			expect(s.stores.pending()).toEqual([]);
		});
		expect(answer).toEqual(refusedOutcome);
		expect(await revoked(s, token as string)).toBe(true);
	});
});

it("uses a code up on a wrong verifier [rfc7636-4.6-b]", async () => {
	const s = await serve();
	const code = await s.issue();
	expect((await s.redeem(code, { code_verifier: "w".repeat(43) })).body.error).toBe(
		"invalid_grant",
	);
	expect((await s.redeem(code)).body).toEqual(refusedBody);
});

it("refuses a held challenge of another length, or of the same length with other bytes [rfc7636-4.5-a]", async () => {
	const s = await serve();
	const other = `${challenge.slice(0, -1)}${challenge.endsWith("A") ? "B" : "A"}`;
	for (const held of [challenge.slice(0, -1), `${challenge}A`, other]) {
		const code = await s.issue();
		await s.stores.records.change(nameOf(code), (kept) => ({
			value: overwritten(kept, { challenge: held }),
		}));
		expect((await s.redeem(code)).body, held).toEqual(refusedBody);
	}
});

it("refuses to start without revocable tokens, or without its tokens recorded to their session", async () => {
	await expect(serve({ revocation: "unsupported" })).rejects.toEqual(
		refusedFor("a configuration that cannot revoke access tokens cannot handle codes"),
	);
	// Composed by hand without a recorder, a logout would leave the code's tokens alive.
	await expect(serve({ recorded: false })).rejects.toEqual(
		refusedFor("its tokens must be recorded to their session, so that a logout ends them"),
	);
});

it("lists a reused code until it is settled, and drops one that issued nothing once its record is gone", async () => {
	const s = await serve({ codeGrant: { "code-lifetime": "10s", "sweep-interval": "1s" } });
	const code = await s.issue();
	await s.redeem(code, { code_verifier: "w".repeat(43) });
	await s.redeem(code);
	expect(s.stores.pending()).toHaveLength(1);
	shift += storedRecordMaxMs + 1000;
	await afterSweep();
	expect(s.stores.pending()).toHaveLength(0);
});

it("never brings back a code that expired while it was being redeemed, and answers no token", async () => {
	const s = await serve();
	const code = await s.issue();
	const answer = await handleDirectly(s, code, {
		issue: async () => {
			shift += storedRecordMaxMs + 1000;
			const expiresAt = Date.now() + shift + 3_600_000;
			const access = { token: "t", id: "id", expiresAt, expiresIn: 3600, tokenType: "Bearer" };
			return { kind: "issued", access: access as IssuedAccess };
		},
	});
	expect(answer).toEqual(refusedOutcome);
	expect(s.stores.peek(nameOf(code))).toBeUndefined();
});

it("voids the token of a redemption whose code ended while the token was made, with no reuse, answering none", async () => {
	const s = await serve({ codeGrant: { "code-lifetime": "10s", "sweep-interval": "1s" } });
	const code = await s.issue();
	const given: string[] = [];
	const answer = await handleDirectly(s, code, {
		issue: async (bundle) => {
			const issued = await issuedNow(s, bundle);
			given.push(issued.access.token);
			shift = 11_000;
			return issued;
		},
	});
	expect(answer).toEqual(refusedOutcome);
	expect(await revoked(s, given[0] as string)).toBe(true);
});

it("revokes, on a reuse after the code's own record ended, the token its redemption record holds", async () => {
	const s = await serve({ codeGrant: { "code-lifetime": "10s", "sweep-interval": "1s" } });
	const code = await s.issue();
	const first = await s.redeem(code);
	expect(first.status).toBe(200);
	shift = 11_000;
	expect(keptOf(s, code)).toBeUndefined();
	expect((await s.redeem(code)).body).toEqual(refusedBody);
	await afterSweep();
	expect(await revoked(s, String(first.body.access_token))).toBe(true);
	expect(s.stores.pending()).toEqual([]);
});

it("refuses a code whose subject was erased once it was used up, issuing nothing, and keeps it listed", async () => {
	const s = await serve();
	const code = await s.issue();
	s.stores.erase("alice");
	expect((await s.redeem(code)).body).toEqual(refusedBody);
	expect(redeemedOf(s, code)).toBeUndefined();
	await afterSweep();
	// No token to revoke, and the code kept: listed until the code ends.
	expect(s.stores.pending()).toEqual([nameOf(code)]);
});

it("refuses to issue a code for facts the session or the client contradict", async () => {
	const s = await serve();
	const issue = s.app.get(codes).issue;
	const bad = {
		"another subject": { subject: "mallory" },
		"scope outside the client": { scope: ["admin"] },
		"audience outside the client": { audience: ["https://other"] },
		"malformed challenge": { challenge: "short" },
		"unknown client": { clientId: "nobody" },
	};
	for (const [label, over] of Object.entries(bad)) {
		await expect(issue({ ...s.facts, ...over }), label).rejects.toThrow(TypeError);
	}
	// A session not entered at use may have closed meanwhile: the caller answers it as it can.
	await expect(issue({ ...s.facts, session: "x".repeat(43) }), "unknown session").rejects.toThrow(
		Unavailable,
	);
	expect(typeof (await issue(s.facts))).toBe("string");
});

it("marks nothing void when listing a reused code fails, so a later reuse still revokes [rfc6749-4.1.2-e]", async () => {
	const s = await serve();
	const code = await s.issue();
	const first = await s.redeem(code);
	s.stores.voids.failNext("add");
	expect((await s.redeem(code)).status).not.toBe(200);
	expect(redeemedOf(s, code)).not.toHaveProperty("void");
	expect((await s.redeem(code)).body).toEqual(refusedBody);
	expect(await revoked(s, String(first.body.access_token))).toBe(true);
});

it("tells how long a code lives, as code-lifetime says", async () => {
	expect((await serve()).app.get(codes).lifetimeMs()).toBe(60_000);
	await stop();
	const short = await serve({ codeGrant: { "code-lifetime": "30s", "sweep-interval": "1s" } });
	expect(short.app.get(codes).lifetimeMs()).toBe(30_000);
});

it("gives a code's digest, its SHA-256 in base64url, never the code [oidc-core-3.3.2.11-a]", async () => {
	const s = await serve();
	const code = await s.issue();
	const digest = createHash("sha256").update(code).digest("base64url");
	expect(s.app.get(codes).digestOf(code)).toBe(digest);
	expect(digest).not.toBe(code);
});

describe("tokens issued while the exchange goes wrong are revoked", () => {
	it("when the session closes between issuing and the second check", async () => {
		const s = await serve();
		const given: string[] = [];
		const answer = await handleDirectly(s, await s.issue(), {
			issue: async (bundle) => {
				const issued = await issuedNow(s, bundle);
				given.push(issued.access.token);
				await s.app.get(sessions).close(s.session.id);
				return issued;
			},
		});
		expect(answer).toEqual(refusedOutcome);
		expect(await revoked(s, given[0] as string)).toBe(true);
	});

	it("when recording it to the session fails in issuing, leaving the code used up", async () => {
		const told: string[] = [];
		const failing = defineModule({ name: "failing-record", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(sessionIssuances).by(() => ({
				issued: async (_, { id }) => {
					told.push(id);
					throw new Unavailable("test");
				},
			})),
		]);
		const s = await serve({ recorded: false, extra: [failing] });
		const code = await s.issue();
		expect((await s.redeem(code)).status).toBe(503);
		expect(told).toHaveLength(1);
		expect(keptOf(s, code)).toMatchObject({ state: "consumed" });
		expect(redeemedOf(s, code)?.token).toBeUndefined();
	});
});

it("makes each code of 32 fresh random bytes, nothing of its challenge, and gives the challenge out nowhere [rfc6749-10.10-a] [rfc6749-10.10-b] [rfc6749-10.10-c] [rfc7636-4.4-b]", async () => {
	const s = await serve();
	const code = await s.issue();
	const made = drawn.at(-1);
	expect(made && Buffer.from(made).toString("base64url")).toBe(code);
	const other = await s.issue();
	expect(other).not.toBe(code);
	expect(Buffer.from(drawn.at(-1) ?? []).toString("base64url")).toBe(other);
	expect(code).not.toContain(challenge);
	const redeemed = await s.redeem(code);
	expect(redeemed.status).toBe(200);
	expect(JSON.stringify(redeemed.body)).not.toContain(challenge);
});

it("offers the shape of an S256 challenge: 43 base64url characters, as RFC 7636 makes it", async () => {
	const { challengeShape } = await import("../src/contract.ts");
	expect(challengeShape.test("A".repeat(43))).toBe(true);
	expect(challengeShape.test(`${"a".repeat(42)}_`)).toBe(true);
	for (const refused of [
		"A".repeat(42),
		"A".repeat(44),
		`${"A".repeat(42)}+`,
		`${"A".repeat(42)}=`,
	]) {
		expect(challengeShape.test(refused), refused).toBe(false);
	}
});

it("takes all its module names", async () => {
	const { input } = assembly();
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(input))["code-grant"]).toBeUndefined();
});

describe("the redemption hooks", () => {
	/** A hook noting what it is told, failing where told to. */
	const hooked = (fail: { pin?: boolean; redeemed?: boolean } = {}) => {
		const told: string[] = [];
		const seen: Redeemed[] = [];
		const hook: RedemptionHook = {
			name: "noting",
			pin: async (redemption, subject) => {
				told.push(`pin ${redemption} ${subject}`);
				if (fail.pin) throw new Unavailable("hook");
			},
			redeemed: async (redeemed) => {
				seen.push(redeemed);
				if (fail.redeemed) throw new Unavailable("hook");
			},
		};
		const module = defineModule({ name: "noting", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(redemptionHooks).by(() => hook),
		]);
		return { told, seen, module };
	};

	it("pins the redemption by the code's digest for its subject, and tells it of the token issued", async () => {
		const h = hooked();
		const s = await serve({ extra: [h.module] });
		const code = await s.issue();
		const answered = await s.redeem(code);
		expect(answered.status).toBe(200);
		const redemption = s.app.get(codes).digestOf(code);
		expect(h.told).toEqual([`pin ${redemption} alice`]);
		expect(h.seen).toEqual([
			{
				redemption,
				subject: "alice",
				scope: ["read"],
				access: { id: expect.any(String), expiresAt: expect.any(Number) },
			},
		]);
	});

	/** Redeems through the grant directly, counting each issue and keeping the token it issued. */
	const redeemCounting = async (s: Served, code: string) => {
		const grant = s.app.get(grantsSeen).find((g) => g.grantType === "authorization_code");
		if (!grant) throw new Error("no authorization_code grant");
		const issuing = { ...s.app.get(accessTokenIssuance), ...s.app.get(accessTokens) };
		const params = { code, redirect_uri: "https://app.example/cb", code_verifier: verifier };
		const input = grantInput(issuing, grant, directClient, params);
		const issued: string[] = [];
		const outcome = await grant
			.handle({
				...input,
				issue: async (request, limits) => {
					const answer = await input.issue(request, limits);
					if (answer.kind === "issued") issued.push(answer.access.token);
					return answer;
				},
			})
			.catch((error: unknown) => error);
		return { outcome, issued };
	};

	it("voids the code where a pin fails, issuing nothing", async () => {
		const h = hooked({ pin: true });
		const s = await serve({ extra: [h.module] });
		const code = await s.issue();
		const { outcome, issued } = await redeemCounting(s, code);
		expect(isUnavailable(outcome)).toBe(true);
		expect(issued).toEqual([]);
		expect(h.seen).toEqual([]);
		expect(keptOf(s, code)?.void).toBe(true);
		expect(redeemedOf(s, code)?.token).toBeUndefined();
	});

	it("voids the code where the hook told of the token fails, revoking the token", async () => {
		const h = hooked({ redeemed: true });
		const s = await serve({ extra: [h.module] });
		const code = await s.issue();
		const { outcome, issued } = await redeemCounting(s, code);
		expect(isUnavailable(outcome)).toBe(true);
		expect(issued).toHaveLength(1);
		expect(h.seen[0]?.access.id).toBeDefined();
		expect(keptOf(s, code)?.void).toBe(true);
		expect(await revoked(s, issued[0] as string)).toBe(true);
	});
});

describe("a code whose root is set once it is made", () => {
	const rootless = (s: Served) => s.app.get(codes).issue(s.facts);

	it("redeems a code only once its root is set, one root once, and roots its bundle there", async () => {
		const s = await serve();
		const code = await rootless(s);
		expect(await s.app.get(codes).root(code, "approval-record")).toBe("set");
		expect(await s.app.get(codes).root(code, "approval-record")).toBe("set");
		expect(await s.app.get(codes).root(code, "another-record")).toBe("refused");
		expect(keptOf(s, code)?.root).toBe("approval-record");
		expect((await s.redeem(code)).status).toBe(200);
		expect(await s.app.get(codes).root(code, "approval-record")).toBe("refused");
	});

	it("uses up a code whose root was never set, issuing nothing", async () => {
		const s = await serve();
		const code = await rootless(s);
		expect(await s.redeem(code)).toMatchObject({ status: 400, body: refusedBody });
		expect(keptOf(s, code)?.state).toBe("consumed");
		expect(redeemedOf(s, code)).toBeUndefined();
		expect(await s.app.get(codes).root(code, "approval-record")).toBe("refused");
	});

	it("refuses a root for a code it does not know, and an empty one as its caller's bug", async () => {
		const s = await serve();
		expect(await s.app.get(codes).root("no-such-code", "approval-record")).toBe("refused");
		await expect(s.app.get(codes).root(await rootless(s), "")).rejects.toThrow(TypeError);
	});
});
