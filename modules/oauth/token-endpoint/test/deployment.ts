import { clientAllowance } from "@mod/client-allowance";
import clientsModule from "@mod/clients/module";
import { type Grant, type GrantInput, grants } from "@mod/grants";
import http from "@mod/http/module";
import { type HttpSettings, httpConfig } from "@mod/http/testing";
import { testServer } from "@mod/http-server/testing";
import { issuer } from "@mod/issuer";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { defineModule, kernelConfig, type Module } from "@mod/kernel";
import keysModule from "@mod/keys/module";
import { keysConfig, testHolder } from "@mod/keys/testing";
import secretHashModule from "@mod/secret-hash/module";
import senderBindingModule from "@mod/sender-binding/module";
import tokensModule from "@mod/tokens/module";
import { tokensConfig } from "@mod/tokens/testing";
import { frameStore, stateOwners, transparencyLog } from "@mod/transparency";
import transparencyModule from "@mod/transparency/module";
import { logBook, memoryFrames } from "@mod/transparency/testing";
import tokenEndpoint from "../src/module.ts";

/** The log the latest composition built, in memory, judging each append verified at once. */
export let logged: ReturnType<typeof logBook> | undefined;

/**
 * The transparency driver over a frame store and a log in memory, the log on the composition's
 * clock: one owner holds every field of a flow's state, folded on no client's flow.
 */
const transparencyInMemory = defineModule(
	{ name: "transparency-in-memory", replicaSafe: true, takes: [] },
	(m) => [
		m.provide(frameStore).by(() => memoryFrames(["state"]).frames),
		m.provide(transparencyLog).by((c) => {
			logged = logBook(c.clock.now);
			logged.judgeOnAppend({ verdict: "verified", outcome: "took" });
			return logged.as("w1");
		}),
		m.contribute(stateOwners).by(() => ({
			name: "every-field",
			holds: ["keyGeneration", "keys", "approvals", "families", "consumed"],
			parts: ["state"],
			records: () => [{ part: "state", name: "state" }],
			read: () => ({}),
			write: () => [undefined],
		})),
	],
);

/**
 * The client credentials grant (RFC 6749 §4.4) as a fixture: a confidential client takes a token
 * within its allowance, in one bundle, its subject a person's named after the client. A client's own
 * flow takes its assertion and DPoP proof, which `client-credentials`' own tests send.
 */
export const clientTokens = (issuer: string): Grant => ({
	grantType: "client_credentials",
	readsAmbient: "none",
	targets: true,
	handle: async ({ client, param, issue, target }) => {
		if (client.kind !== "confidential") return { kind: "error", error: "unauthorized_client" };
		const allowed = clientAllowance.allowedIssuance(client, param("scope"), issuer);
		if (allowed.kind === "error") return allowed;
		const { scope } = allowed;
		const asked = target(allowed.audience, (a) =>
			clientAllowance.allowsAudience(client, a, issuer),
		);
		if (asked.kind === "error") return asked;
		const { audience } = asked;
		const access = { subject: client.id, subjectKind: "user" as const, issuedTo: client.id };
		const issued = await issue({ access: { ...access, audience, scope } });
		if (issued.kind === "refused") return issued;
		const { token, tokenType, expiresIn } = issued.access;
		const body = { access_token: token, token_type: tokenType, expires_in: expiresIn };
		return { kind: "issued", body: { ...body, scope: scope.join(" ") } };
	},
});

/** The fixture grant, composed as a module of its own at the issuer's URL. */
export const clientTokensModule = defineModule(
	{ name: "client-tokens", replicaSafe: true, takes: [issuer] },
	(m) => [m.contribute(grants).by(async (c) => clientTokens((await c.get(issuer)).url))],
);

/** The token endpoint and the modules it cannot run without, then `extra`. */
export const endpointModules = (...extra: Module[]): Module[] => [
	http,
	testServer(),
	keysModule,
	testHolder(),
	tokensModule,
	issuerModule,
	senderBindingModule,
	clientsModule,
	secretHashModule,
	transparencyModule,
	transparencyInMemory,
	tokenEndpoint,
	clientTokensModule,
	...extra,
];

/** Their configuration, with http's `peer` settings and the issuer at `issuer` when given. */
export const endpointConfig = ({
	peer = {},
	issuer,
}: {
	peer?: Partial<HttpSettings>;
	issuer?: string;
} = {}) => ({
	...kernelConfig(),
	...httpConfig({ "public-origin": "https://issuer.example", ...peer }),
	...keysConfig(),
	...issuerConfig(issuer === undefined ? {} : { url: issuer }),
	...tokensConfig(),
});

/** The Basic authorization of a client by its id and secret. */
export const basicOf = (id: string, secret: string) =>
	`Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;

/** A grant's answer `body`, its token issued through `issue` under a subject named after the client, as a grant makes every credential it answers. */
export const answered = async (
	{ client, issue }: Pick<GrantInput, "client" | "issue">,
	body: Readonly<Record<string, unknown>>,
) => {
	const access = {
		subject: client.id,
		subjectKind: "user" as const,
		issuedTo: client.id,
		audience: [],
		scope: [],
	};
	const issued = await issue({ access });
	return issued.kind === "issued" ? ({ kind: "issued", body } as const) : issued;
};
