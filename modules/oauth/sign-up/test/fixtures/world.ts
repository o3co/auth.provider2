import { createHash, generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { acr } from "@mod/acr";
import { approvalStore, type StoredStatement, statementItems } from "@mod/approvals";
import approvalsModule from "@mod/approvals/module";
import { jarReservations, type StoredReservation } from "@mod/authorize";
import authorizeModule from "@mod/authorize/module";
import { authorizeConfig } from "@mod/authorize/testing";
import { clientAssertion } from "@mod/client-assertion";
import { type Client, clients } from "@mod/clients";
import { codes } from "@mod/code-grant";
import { type Route, routes } from "@mod/http";
import { testRequest } from "@mod/http/testing";
import { issuer } from "@mod/issuer";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { keys } from "@mod/keys";
import keysModule from "@mod/keys/module";
import { keysConfig, testHolder } from "@mod/keys/testing";
import { keyChangePart } from "@mod/passkey-management";
import passkeyManagement from "@mod/passkey-management/module";
import { passkeyWitnessStandIn } from "@mod/passkey-witness/testing";
import {
	type PasskeyStore,
	passkeyStore,
	passkeyWitnessing,
	type StoredCredential,
} from "@mod/passkeys";
import passkeysModule from "@mod/passkeys/module";
import promisesModule from "@mod/promises/module";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import { redirects } from "@mod/redirect-uris";
import { delegation, familiesPart } from "@mod/refresh";
import { familiesOwning } from "@mod/refresh/testing";
import { typs } from "@mod/sdk-core-wire";
import { senderBinding } from "@mod/sender-binding";
import { sessions } from "@mod/session";
import { type SubjectRevocation, subjectRevocation } from "@mod/subject-revocation";
import { accessTokenIssuance } from "@mod/tokens";
import { frameStore, transparencyLog } from "@mod/transparency";
import transparencyModule from "@mod/transparency/module";
import { logBook, memoryFrames } from "@mod/transparency/testing";
import { type Users, users } from "@mod/users";
import webauthnModule from "@mod/webauthn/module";
import { webauthnConfig } from "@mod/webauthn/testing";
import signUp from "../../src/module.ts";

export const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const pointOf = (key: KeyObject) => {
	const { x, y } = key.export({ format: "jwk" }) as { x: string; y: string };
	return new Uint8Array(
		Buffer.concat([Buffer.from([4]), Buffer.from(x, "base64url"), Buffer.from(y, "base64url")]),
	);
};
export const payloadOf = (jws: string) =>
	JSON.parse(Buffer.from(jws.split(".")[1] ?? "", "base64url").toString("utf8"));

/** Records in memory under a clock, each living as long as it was given. */
function memoryRecords<T>(now: () => number) {
	const kept = new Map<string, { value: T; until: number }>();
	const live = (key: string) => {
		const entry = kept.get(key);
		return entry && now() < entry.until ? entry : undefined;
	};
	return {
		async create(key: string, value: T, lifetimeMs = Number.POSITIVE_INFINITY) {
			if (live(key)) return "exists" as const;
			kept.set(key, { value: structuredClone(value), until: now() + lifetimeMs });
			return "created" as const;
		},
		read: async (key: string) => structuredClone(live(key)?.value),
		async change(key: string, change: (value: T) => { value: T } | undefined) {
			const entry = live(key);
			if (!entry) return undefined;
			const next = change(structuredClone(entry.value));
			if (next) kept.set(key, { value: structuredClone(next.value), until: entry.until });
			return { before: entry.value, after: (kept.get(key) as { value: T }).value };
		},
	};
}

/** A screen: its HPKE key held by a keys holder of its own, its signing key signing continuations. */
export async function screen() {
	const enc = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
	const sig = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const app = await assemble({
		modules: [keysModule, testHolder({ "seal-test": enc })],
		config: { ...kernelConfig(), ...keysConfig() },
		runtime: quietRuntime(),
	});
	const own = await app.get(keys);
	const { x, y } = sig.publicKey.export({ format: "jwk" }) as { x: string; y: string };
	return {
		eEnc: b64(pointOf(enc)),
		eSigX: x,
		eSigY: y,
		open: own.open,
		signs: (input: string) =>
			sign("sha256", Buffer.from(input), {
				key: sig.privateKey,
				dsaEncoding: "ieee-p1363",
			}).toString("base64url"),
	};
}

/** The world's client, registering the redirect URIs given. */
const clientOf = (redirectUris: readonly string[]): Client => ({
	id: "c1",
	kind: "public",
	method: "none",
	registered: true,
	section: <T>(s: { name: string }) =>
		(s.name === redirects.name
			? { "redirect-uris": redirectUris }
			: { grants: ["authorization_code"], scopes: ["read"], audiences: [] }) as T,
});

const seen = contract<readonly Route[]>("f1-world.routes");

/**
 * F1 whole: authorize, sign-up, approvals, passkey-management, passkeys, webauthn, keys and
 * transparency, each append judged took at once. The users' ledger makes identifierless subjects in
 * memory; what follows a login's approval (its session, its code) and the client stand in, its
 * redirect URIs `https://rp.example/cb` unless given.
 */
export async function f1World(p: { readonly redirectUris?: readonly string[] } = {}) {
	const client = clientOf(p.redirectUris ?? ["https://rp.example/cb"]);
	const clock = 1_800_000_000_000;
	const now = () => clock;
	const core = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
	const frames = memoryFrames(["passkeys", "approvals", familiesPart, keyChangePart]);
	const book = logBook(now);
	book.judgeOnAppend({ verdict: "verified", outcome: "took" });
	const made = new Map<string, string>();
	const opened: { subject: string }[] = [];
	const codesMade: Record<string, unknown>[] = [];
	const rooted: { code: string; statement: string }[] = [];
	const standIns = defineModule({ name: "stand-ins", replicaSafe: true, takes: [routes] }, (m) => [
		m.provide(seen).by((c) => c.collect(routes)),
		m.provide(frameStore).by(() => frames.frames),
		m.provide(transparencyLog).by(() => book.as("w1")),
		m.provide(passkeyStore).by(() => memoryRecords<StoredCredential>(now) as PasskeyStore),
		m.provide(approvalStore).by(() => memoryRecords<StoredStatement>(now)),
		m.provide(jarReservations).by(() => memoryRecords<StoredReservation>(now)),
		m
			.provide(issuer)
			.by(() => ({ url: "https://issuer.example", endpointOrigin: "https://issuer.example" })),
		m
			.contribute(statementItems)
			.by(() => ({ purpose: "authorization", names: ["dpop_jkt"], by: "stand-ins" })),
		m.contribute(passkeyWitnessing).by(() => {
			const marks = new Map<string, number>();
			return {
				marked: async (subject: string) => marks.has(subject),
				mark: async (subject: string, generation: number) => {
					if ((marks.get(subject) ?? -1) < generation) marks.set(subject, generation);
				},
				withdraw: async (subject: string, generation: number) => {
					if ((marks.get(subject) ?? generation) < generation) marks.delete(subject);
				},
			};
		}),
		// The ledger: one subject per idempotency key, made once.
		m.provide(users).by(
			() =>
				({
					createIdentifierless: async (key: string) => {
						if (!made.has(key)) made.set(key, `s-${made.size + 1}`);
						return { subject: made.get(key), attributes: {} };
					},
					// Only a subject the ledger made is a user: the finish reads that one.
					bySubject: async (subject: string) =>
						[...made.values()].includes(subject)
							? { kind: "user", user: { subject, attributes: {} } }
							: { kind: "none" },
					byIdentifier: async () => ({ kind: "none" }),
					contactsOf: async () => [],
				}) as unknown as Users,
		),
		m
			.provide(subjectRevocation)
			.by(() => ({ check: async () => "valid" }) as unknown as SubjectRevocation),
		// The client, and its JAR "signed": its payload in the middle, its client's mark for a signature.
		m
			.provide(clients)
			.by(() => ({ find: async (id: string) => (id === "c1" ? client : undefined) }) as never),
		m.provide(clientAssertion).by(
			() =>
				({
					verifySignedBy: async (c: Client, jwt: string, typ: string) => {
						const [, payload, by] = jwt.split(".");
						if (typ !== typs.jar || by !== c.id) return { kind: "refused", reason: "signature" };
						return {
							kind: "signed",
							claims: JSON.parse(Buffer.from(payload ?? "", "base64url").toString()),
						};
					},
				}) as never,
		),
		m.provide(senderBinding).by(
			() =>
				({
					requestedOf: (param: (name: string) => string | undefined) => {
						const jkt = param("dpop_jkt");
						return jkt === undefined
							? { kind: "none" }
							: {
									kind: "requested",
									binding: { member: "jkt", confirmation: jkt, tokenType: "DPoP" },
								};
					},
				}) as never,
		),
		// After the approval: the session and the code stand in, noting whom they are for.
		m
			.provide(accessTokenIssuance)
			.by(() => ({ admits: async () => ({ kind: "allowed" }) }) as never),
		m.provide(sessions).by(
			() =>
				({
					open: async (o: { subject: string }) => {
						opened.push({ subject: o.subject });
						return { kind: "opened", session: { id: "session-1" } };
					},
					close: async () => {},
				}) as never,
		),
		m.provide(codes).by(
			() =>
				({
					issuesIdTokens: () => false,
					issue: async (o: Record<string, unknown>) => {
						const { subject, clientId, session, binding } = o;
						codesMade.push({ subject, clientId, session, binding });
						return "code-1";
					},
					digestOf: (code: string) => sha256(code),
					lifetimeMs: () => 60_000,
					root: async (code: string, _record: unknown, named: { statement: string }) => {
						rooted.push({ code, statement: named.statement });
						return "set";
					},
				}) as never,
		),
		m.provide(acr).by(() => ({ current: () => undefined }) as never),
		m.provide(delegation).by(() => ({ lifetimeMs: 86_400_000 })),
	]);
	const app = await assemble({
		modules: [
			standIns,
			// The state's families, as refresh owns them in a deployment.
			familiesOwning,
			rateLimitStandIn,
			keysModule,
			testHolder({ "seal-test": core }),
			transparencyModule,
			webauthnModule,
			passkeysModule,
			approvalsModule,
			promisesModule,
			passkeyWitnessStandIn().module,
			passkeyManagement,
			authorizeModule,
			signUp,
		],
		config: {
			...kernelConfig(),
			...keysConfig(),
			...webauthnConfig(),
			...authorizeConfig(),
			"sign-up": {},
		},
		runtime: quietRuntime({ clock: { now } }),
	});
	const all = app.get(seen);
	const post = async (path: string, json: Record<string, unknown>) => {
		const route = all.find((r) => r.path === path) as Route;
		const answered = await route.handle(testRequest({ method: "POST", path, json }));
		return {
			status: answered.status,
			json: (answered.body as { json: Record<string, unknown> }).json,
		};
	};
	return { app, post, book, now, made, opened, codesMade, rooted };
}
