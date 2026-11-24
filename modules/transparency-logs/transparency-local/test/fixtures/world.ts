import { createHash, generateKeyPairSync, randomBytes, sign as signBytes } from "node:crypto";
import { tokenRules } from "@mod/authority-rules";
import { assemble, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { keys } from "@mod/keys";
import keysModule from "@mod/keys/module";
import { keysConfig, testHolder } from "@mod/keys/testing";
import { passkeys } from "@mod/passkeys";
import { challengeInput, typs } from "@mod/sdk-core-wire";
import { type Guarantee, type Space, spaces, store } from "@mod/store";
import storeModule from "@mod/store/module";
import { storeConfig } from "@mod/store/testing";
import { type Stage, transparencyLog } from "@mod/transparency";
import { type Flow, opIds, tokens } from "@mod/transparency-wire";
import { keyThumbprint } from "@mod/webauthn";
import webauthnModule from "@mod/webauthn/module";
import {
	type RequestOptions,
	softwareAuthenticator,
	testCeremonies,
	testOrigin,
	webauthnConfig,
} from "@mod/webauthn/testing";
import { clientRecords, logStore, logStoreOver } from "../../src/contract.ts";
import transparencyLocal from "../../src/module.ts";

export const digest = (data: string | Uint8Array) =>
	createHash("sha256").update(data).digest("base64url");

const all: Guarantee[] = [
	"no-eviction",
	"durable",
	"replicated",
	"confirmed-reads",
	"authenticated",
];
/** The log's place, as a wiring would declare and bind it. */
const space: Space = { name: "log-under-test", guarantees: all, subjectData: "retained" };
const placing = defineModule({ name: "placing", replicaSafe: true, takes: [store] }, (m) => [
	m.contribute(spaces).by(() => space),
	m.provide(logStore).by(async (c) =>
		logStoreOver({
			store: await c.get(store),
			space,
			random: c.random,
			where: "placing",
			refuse: (where, reason) => c.refuse(where, reason),
		}),
	),
]);

/** The credentials passkeys holds active, by id, as a test sets them. */
export function heldKeys() {
	const active = new Map<string, string>();
	const module = defineModule({ name: "passkeys", replicaSafe: true, takes: [] }, (m) => [
		m.provide(passkeys).by(() => ({
			assert: async () => ({ kind: "refused", reason: "unknown-credential" }) as const,
			publicKeyOf: async (credential: string) => {
				const subject = active.get(credential);
				return subject === undefined ? undefined : { subject, publicKey: "-", registration: "-" };
			},
			settle: async () => false,
		})),
	]);
	return { module, hold: (credential: string, subject: string) => active.set(credential, subject) };
}

export const issuerUrl = "https://core.example";

/** A client of a version its publisher signed, its keys written and its own ceiling, as the registry holds it. */
export interface TestClient {
	readonly id: string;
	readonly version: number;
	readonly keys: readonly Record<string, unknown>[];
	readonly self: readonly { readonly audience: string; readonly scopes: readonly string[] }[];
}

/** The registry's clients, as a test sets them, read as the log's judgment reads them. */
export function registry() {
	const held = new Map<string, TestClient>();
	const module = defineModule({ name: "registry", replicaSafe: true, takes: [] }, (m) => [
		m.provide(clientRecords).by(() => ({
			find: async (id: string) => held.get(id),
			version: (c) => (c as TestClient).version,
			signed: () => true,
			keys: (c) => (c as TestClient).keys,
			ceiling: (c, audience, scope) =>
				(c as TestClient).self.some(
					(e) =>
						e.audience === audience &&
						audience !== issuerUrl &&
						scope.split(" ").every((s) => e.scopes.includes(s)),
				),
		})),
	]);
	return { module, hold: (c: TestClient) => held.set(c.id, c) };
}

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
/** A client's P-256 key: its public JWK (with a kid) and its compact ES256 signing. */
export function clientKey(kid = fresh()) {
	const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const { kty, crv, x, y } = pair.publicKey.export({ format: "jwk" });
	const jwk = { kty, crv, x, y };
	const sign = (header: Record<string, unknown>, payload: Record<string, unknown>) => {
		const input = `${b64({ alg: "ES256", ...header })}.${b64(payload)}`;
		const signature = signBytes("sha256", Buffer.from(input), {
			key: pair.privateKey,
			dsaEncoding: "ieee-p1363",
		});
		return `${input}.${signature.toString("base64url")}`;
	};
	return { jwk: { ...jwk, kid }, bare: jwk, kid, sign };
}
export type ClientKey = ReturnType<typeof clientKey>;

/** A client's evidence, as its request carried it: its assertion and its DPoP proof, each by `key`, at `now`. */
export const clientEvidence = (client: string, key: ClientKey, now: number, jti = fresh()) => {
	const iat = Math.floor(now / 1000);
	const assertion = key.sign(
		{ typ: "JWT", kid: key.kid },
		{ iss: client, sub: client, aud: issuerUrl, jti, iat, exp: iat + 60 },
	);
	const proof = key.sign(
		{ typ: "dpop+jwt", jwk: key.bare },
		{ htm: "POST", htu: `${issuerUrl}/oauth/token`, jti: fresh(), iat },
	);
	return [
		{ form: "clientAssertion" as const, value: assertion },
		{ form: "dpopProof" as const, value: proof },
	];
};

/** RFC 7638: a P-256 key's thumbprint. */
export const thumbprint = (k: Readonly<Record<string, unknown>>) =>
	digest(JSON.stringify({ crv: k.crv, kty: k.kty, x: k.x, y: k.y }));

/** A client's start of that evidence, at its registry version: its op id and elements derived as the rules check them. */
export function clientStart(
	flow: Flow,
	evidence: ReturnType<typeof clientEvidence>,
	version: number,
): Stage {
	const read = tokenRules.client.start(evidence, digest);
	if ("refused" in read) throw new Error(read.refused);
	return {
		kind: "start",
		flow,
		op: read.op,
		stage: 1,
		last: false,
		registryVersion: version,
		elements: [...read.elements],
		preimage: { v: 1, evidence, content: { via: "client" } },
	};
}

/** A client's bundle after its start (placed at `id`, accepted at `acceptedAt`): one access token bound to `key`. */
export function clientBundle(
	start: Stage,
	at: { readonly id: string; readonly acceptedAt: number },
	key: ClientKey,
	over: Record<string, unknown> = {},
): Stage {
	const iat = Math.floor(at.acceptedAt / 1000);
	const header = JSON.stringify({ alg: "ES256", typ: "at+jwt", kid: "t1" });
	const claims = JSON.stringify({
		iss: issuerUrl,
		sub: start.flow.id,
		client_id: start.flow.id,
		aud: "https://api.example",
		scope: "read",
		iat,
		exp: iat + 300,
		jti: fresh(),
		cnf: { jkt: thumbprint(key.bare) },
		...over,
	});
	const input = tokens.digestInput(header, claims);
	if ("error" in input) throw new Error(input.error);
	return {
		kind: "bundle",
		flow: start.flow,
		op: start.op,
		stage: 2,
		last: true,
		tokens: [{ frame: "accessToken", digest: digest(input.input) }],
		preimage: {
			v: 1,
			parent: at.id,
			evidence: [],
			content: { via: "client", token: { header, claims } },
		},
	};
}

/** A clock a test moves; it starts now. */
export function testClock() {
	let at = Date.now();
	return { now: () => at, move: (ms: number) => (at += ms) };
}

/** The log composed over the memory store, with keys, webauthn and a passkeys stand-in. */
export async function boot(
	p: {
		readonly clock?: ReturnType<typeof testClock>;
		readonly section?: Record<string, unknown>;
		readonly modules?: readonly Module[];
	} = {},
) {
	const held = heldKeys();
	const clientsHeld = registry();
	const app = await assemble({
		modules: [
			storeModule,
			placing,
			keysModule,
			testHolder(),
			webauthnModule,
			held.module,
			clientsHeld.module,
			transparencyLocal,
			...(p.modules ?? []),
		],
		config: {
			...kernelConfig(),
			...storeConfig({ "accept-unauthenticated": true }),
			...keysConfig(),
			...webauthnConfig(),
			"transparency-local": { origin: testOrigin, ...p.section },
		},
		runtime: quietRuntime(p.clock ? { clock: { now: p.clock.now } } : {}),
	});
	return {
		app,
		log: await app.get(transparencyLog),
		keys: await app.get(keys),
		held,
		clients: clientsHeld,
	};
}
export type World = Awaited<ReturnType<typeof boot>>;

const ceremonies = testCeremonies({
	id: "rp.example",
	name: "RP",
	origins: [testOrigin],
	topOrigins: [],
	algorithms: ["ES256", "EdDSA", "RS256"],
});
const screen = { v: 1, e_enc: "ZW5j", e_sig: { kty: "EC", crv: "P-256", x: "eA", y: "eQ" } };
const fresh = () => randomBytes(32).toString("base64url");

/** A statement the Core's ring signs, valid from now for five minutes, by the world's clock. */
async function signed(world: World, payload: Record<string, unknown>, now: number) {
	const iat = Math.floor(now / 1000);
	const body = { iss: "https://core.example", sid: fresh(), iat, exp: iat + 300, ...screen };
	const prepared = world.keys.prepare("core", typs.statement);
	const made = await world.keys.sign(
		prepared,
		Buffer.from(JSON.stringify({ ...body, ...payload })),
	);
	if (made.kind !== "signed") throw new Error("the ring signs nothing");
	return made.jws;
}

/** A passkey of the authenticator, of the algorithm given (ES256 unless named), as the rules name it: its id and its COSE_Key. */
export async function passkey(algorithm: "ES256" | "EdDSA" | "RS256" = "ES256") {
	const authenticator = softwareAuthenticator({ algorithm });
	const challenge = fresh();
	const handle = fresh();
	const options = ceremonies.creation(challenge, { handle, name: "sam" }, []);
	const at = { origin: testOrigin };
	const attested = await ceremonies.attest(
		authenticator.create(options as never, at),
		challenge,
		handle,
	);
	if (attested.kind !== "attested") throw new Error(attested.reason);
	const credential = attested.credential;
	/** Its assertion over a statement, as the rules ask: the get challenge's digest, at `origin`. */
	const asserts = (statement: string, origin = testOrigin) => {
		const asked = digest(challengeInput(statement, "get"));
		const request = ceremonies.request(asked, [credential]) as RequestOptions;
		return JSON.stringify(authenticator.get(request, { origin }));
	};
	return { credential: credential.id, publicKey: credential.publicKey, asserts };
}
export type Passkey = Awaited<ReturnType<typeof passkey>>;

export const subjectFlow = (id = fresh()): Flow => ({ of: "subject", id });

/** The first key's stage: creation and possession signed by the ring, and the key asserting the possession. */
export async function firstKey(
	world: World,
	flow: Flow,
	key: Passkey,
	p: { readonly now: number; readonly op?: string; readonly forgedBy?: World },
): Promise<Stage> {
	const by = p.forgedBy ?? world;
	const creation = await signed(
		by,
		{
			nonce: "n1",
			purpose: "creation",
			creation: {
				account: "s***@example",
				evidence: "ev",
				ct_hash: "ct",
				subject: flow.id,
				kg: 0,
				options: {
					user_id: "u",
					rp_id: "rp.example",
					exclude_credentials: [],
					algorithms: [-7, -8, -257],
				},
			},
		},
		p.now,
	);
	const possession = await signed(
		by,
		{
			nonce: "n2",
			purpose: "possession",
			possession: {
				creation_hash: digest(creation),
				key_jkt: keyThumbprint(key.publicKey)?.jkt,
				credential_id: key.credential,
				reservation_id: "res-1",
			},
		},
		p.now,
	);
	return {
		kind: "keyChange",
		flow,
		op: p.op ?? fresh(),
		stage: 1,
		last: true,
		preimage: {
			v: 1,
			evidence: [
				{ form: "statement", value: creation },
				{ form: "statement", value: possession },
				{ form: "assertion", value: key.asserts(possession) },
			],
			content: { variant: "first", credential: key.credential, publicKey: key.publicKey },
		},
	};
}

/** An approval by the key registered at `parent`: T signed by the ring, and the key's assertion over it. */
export async function approval(
	world: World,
	flow: Flow,
	key: Passkey,
	p: { readonly now: number; readonly parent: string },
): Promise<Stage> {
	const t = await signed(
		world,
		{
			purpose: "authorization",
			approval: {
				client_id: "rp",
				redirect_uri: "https://rp.example/cb",
				response_type: "code",
				response_mode: "form_post",
				state: "st",
				scope: "openid",
				nonce: "n",
				code_challenge: "cc",
				code_challenge_method: "S256",
				dpop_jkt: "jkt",
				jar_hash: "jh",
			},
		},
		p.now,
	);
	const asserted = key.asserts(t);
	return {
		kind: "approval",
		flow,
		op: fresh(),
		stage: 1,
		last: true,
		approval: { statement: digest(t), assertion: digest(asserted), code: digest("code") },
		preimage: {
			v: 1,
			parent: p.parent,
			evidence: [
				{ form: "statement", value: t },
				{ form: "assertion", value: asserted },
			],
			content: {},
		},
	};
}

/** An abandonment of `abandoned`: a stage the rules allow as it is, holding no evidence. */
export const abandonment = (flow: Flow, abandoned = fresh(), attempt = 1): Stage => ({
	kind: "abandonment",
	flow,
	op: opIds.abandonment(abandoned, attempt),
	stage: 1,
	last: true,
	abandons: { op: abandoned, attempt, digest: digest(abandoned) },
	preimage: { v: 1, evidence: [], content: {} },
});
