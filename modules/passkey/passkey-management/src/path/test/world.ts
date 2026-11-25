import {
	createHash,
	createPublicKey,
	generateKeyPairSync,
	type KeyObject,
	sign,
	verify,
	type webcrypto,
} from "node:crypto";
import { approvalStore, type StoredStatement, statementItems } from "@mod/approvals";
import approvalsModule from "@mod/approvals/module";
import type { Ask, Checks, FlowState } from "@mod/authority-rules";
import { type Route, routes } from "@mod/http";
import { testRequest } from "@mod/http/testing";
import { issuer } from "@mod/issuer";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { keys } from "@mod/keys";
import keysModule from "@mod/keys/module";
import { keysConfig, testHolder } from "@mod/keys/testing";
import { type Message, mail } from "@mod/mail";
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
import {
	challengeInput,
	continuation,
	type FirstKeyStage,
	firstKey,
	hpke,
	payloads,
} from "@mod/sdk-core-wire";
import { type SubjectRevocation, subjectRevocation } from "@mod/subject-revocation";
import {
	frameStore,
	type Stage,
	type StateOwner,
	stateOwners,
	transparencyLog,
} from "@mod/transparency";
import transparencyModule from "@mod/transparency/module";
import { logBook, memoryFrames } from "@mod/transparency/testing";
import { type Users, users } from "@mod/users";
import { type Credential, ceremonies, keyThumbprint } from "@mod/webauthn";
import webauthnModule from "@mod/webauthn/module";
import { softwareAuthenticator, testOrigin, webauthnConfig } from "@mod/webauthn/testing";
import { memoryKept } from "../../../test/fixtures/kept.ts";
import {
	firstKeyNonces,
	firstKeyTokens,
	keyChangePart,
	type StoredNonce,
	type StoredToken,
} from "../../contract.ts";
import passkeyManagement from "../../module.ts";
import { passkeyManagementConfig } from "../../testing.ts";

export const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");
export const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
/** A P-256 public key's uncompressed point. */
export const pointOf = (key: KeyObject) => {
	const { x, y } = key.export({ format: "jwk" }) as { x: string; y: string };
	return new Uint8Array(
		Buffer.concat([Buffer.from([4]), Buffer.from(x, "base64url"), Buffer.from(y, "base64url")]),
	);
};

/** Records in memory under a clock, each living as long as it was given. */
function memoryRecords<T>(now: () => number) {
	const kept = new Map<string, { value: T; until: number }>();
	/** Changes to let through before the next one to a record throws, as a call that fell. */
	const falls = new Map<string, number>();
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
			const left = falls.get(key);
			if (left !== undefined) {
				if (left === 0) falls.delete(key);
				else falls.set(key, left - 1);
				if (left === 0) throw new Error("fell");
			}
			const entry = live(key);
			if (!entry) return undefined;
			const next = change(structuredClone(entry.value));
			if (next) kept.set(key, { value: structuredClone(next.value), until: entry.until });
			return { before: entry.value, after: (kept.get(key) as { value: T }).value };
		},
		/** The change to `key` after `through` more throws, writing nothing. */
		fallAfter: (key: string, through: number) => {
			falls.set(key, through);
		},
	};
}

const familiesOwner: StateOwner = {
	name: "families",
	holds: ["families"],
	parts: ["families"],
	records: () => [{ part: "families", name: "state" }],
	read: () => ({ families: {} }),
	write: () => [undefined],
};

/**
 * A screen: its encryption key held by a keys holder of its own, which seals to the Core and opens
 * what the Core sealed to it, as the screen's HPKE does; its signing key signing its continuations.
 */
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
	const eSig = { kty: "EC" as const, crv: "P-256" as const, x, y };
	return {
		eEnc: b64(pointOf(enc)),
		eSigX: x,
		eSigY: y,
		eSig,
		seal: own.seal,
		open: own.open,
		signs: (input: string) =>
			sign("sha256", Buffer.from(input), {
				key: sig.privateKey,
				dsaEncoding: "ieee-p1363",
			}).toString("base64url"),
	};
}

const seen = contract<readonly Route[]>("first-key-world.routes");

/**
 * The first key's path whole: passkey-management over keys, approvals, passkeys, transparency and
 * webauthn, each append judged took at once; users and mail standing in, one user `alice` (`s1`)
 * with a verified address.
 */
export async function firstKeyWorld() {
	let clock = 1_800_000_000_000;
	const now = () => clock;
	const core = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
	const frames = memoryFrames(["passkeys", "approvals", "families", keyChangePart]);
	const book = logBook(now);
	book.judgeOnAppend({ verdict: "verified", outcome: "took" });
	const sent: Message[] = [];
	let mailed: (m: Message) => void = () => {};
	const user = { subject: "s1", attributes: {} };
	const statements = memoryRecords<StoredStatement>(now);
	const standIns = defineModule({ name: "stand-ins", replicaSafe: true, takes: [routes] }, (m) => [
		m.provide(seen).by((c) => c.collect(routes)),
		m.provide(frameStore).by(() => frames.frames),
		m.provide(transparencyLog).by(() => book.as("w1")),
		m.provide(passkeyStore).by(() => memoryRecords<StoredCredential>(now) as PasskeyStore),
		m.provide(approvalStore).by(() => statements),
		m.provide(firstKeyNonces).by(() => memoryKept<StoredNonce>().store),
		m.provide(firstKeyTokens).by(() => memoryKept<StoredToken>().store),
		m
			.provide(issuer)
			.by(() => ({ url: "https://issuer.example", endpointOrigin: "https://issuer.example" })),
		m.contribute(stateOwners).by(() => familiesOwner),
		// The items of T as an authorization's modules fill them, so a T may be issued here.
		m.contribute(statementItems).by(() => ({
			purpose: "authorization",
			names: Object.keys(payloads.statement.shape.approval.shape),
			by: "stand-ins",
		})),
		// One mark per subject, for a key generation, as the witness keeps it.
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
		m.provide(users).by(
			() =>
				({
					byIdentifier: async (id: string) =>
						id === "alice" ? { kind: "user", user } : { kind: "none" },
					contactsOf: async () => [{ kind: "email", value: "inbox-of-alice" }],
					bySubject: async () => ({ kind: "user", user }),
				}) as unknown as Users,
		),
		m.provide(mail).by(() => ({
			send: async (message: Message) => {
				sent.push(message);
				mailed(message);
				return "sent" as const;
			},
		})),
		m
			.provide(subjectRevocation)
			.by(() => ({ check: async () => "valid" }) as unknown as SubjectRevocation),
	]);
	const recorded = recordingLog();
	const app = await assemble({
		modules: [
			standIns,
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
		],
		config: {
			...kernelConfig(),
			...keysConfig(),
			...webauthnConfig(),
			...passkeyManagementConfig({ "mail-link": `${testOrigin}/first-key` }),
		},
		runtime: quietRuntime({ clock: { now }, log: recorded.log }),
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
	return {
		app,
		post,
		book,
		frames,
		now,
		sent,
		recorded,
		statements,
		corePoint: pointOf(core),
		/** The next mail sent, once its job ran. */
		nextMail: () =>
			new Promise<Message>((resolve) => {
				mailed = resolve;
			}),
		advance: (ms: number) => {
			clock += ms;
		},
	};
}

type World = Awaited<ReturnType<typeof firstKeyWorld>>;
type Screen = Awaited<ReturnType<typeof screen>>;
const utf8 = (text: string) => new TextEncoder().encode(text);
export const payloadOf = (jws: string) =>
	JSON.parse(Buffer.from(jws.split(".")[1] ?? "", "base64url").toString("utf8"));

/** A request of a first key's stage, sealed by the screen to the Core under its nonce and keys. */
export async function sealed(w: World, s: Screen, stage: FirstKeyStage, plain: unknown) {
	const asked = await w.post("/first-key/nonce", { stage });
	const nonce = asked.json.nonce as string;
	const aad = firstKey.aad(stage, nonce, s.eEnc, s.eSig);
	const box = await s.seal(
		w.corePoint,
		hpke.info.firstKeyRequest,
		utf8(aad),
		utf8(JSON.stringify(plain)),
	);
	return {
		nonce,
		eEnc: s.eEnc,
		eSigX: s.eSigX,
		eSigY: s.eSigY,
		enc: b64(box.enc),
		ct: b64(box.ct),
	};
}

/** What the screen opens of a sealing the Core answered: its plain text, or none. */
export async function opened(
	s: Screen,
	box: { enc: string; ct: string },
	info: string,
	aad: string,
) {
	const read = await s.open(
		{ enc: Buffer.from(box.enc, "base64url"), ct: Buffer.from(box.ct, "base64url") },
		info,
		utf8(aad),
	);
	return read.kind === "opened" ? new TextDecoder().decode(read.plaintext) : undefined;
}

/** The rules' checks and context over this Core's ring and webauthn, as a monitor of its log reads them. */
export async function rulesOf(w: World) {
	const ring = await w.app.get(keys);
	const cer = await w.app.get(ceremonies);
	const checks: Checks = {
		verifyJws: (jws, keySet) => ring.verifyJws(jws, keySet),
		verifyAssertion: cer.verifyAssertion,
		attestedKey: cer.attestedKey,
		verifyEsig: (key, input, signature) => {
			try {
				const jwk = { kty: "EC", crv: "P-256", x: key.x, y: key.y } as webcrypto.JsonWebKey;
				const publicKey = createPublicKey({ key: jwk, format: "jwk" });
				const how = { key: publicKey, dsaEncoding: "ieee-p1363" } as const;
				return verify("sha256", Buffer.from(input), how, Buffer.from(signature, "base64url"));
			} catch {
				return false;
			}
		},
		digest: (data) => createHash("sha256").update(data).digest("base64url"),
		keyThumbprint,
	};
	const context = {
		ring: ring.coreRing(ring.generation()) ?? [],
		origin: testOrigin,
		limits: {
			codeLifetime: 60,
			refreshLifetime: 86_400,
			issueWindow: 60,
			epsilon: 0,
			propagation: 0,
			retry: 0,
		},
	};
	return (stage: Stage, state: FlowState): Ask => ({
		record: stage as Ask["record"],
		preimage: stage.preimage,
		state,
		prior: [],
		checks,
		context,
	});
}

const client = { origin: testOrigin };

/** `alice` (`s1`) holding one key, made through her first key's path over the routes. */
export async function withFirstKey() {
	const w = await firstKeyWorld();
	await w.app.start();
	const s = await screen();
	const mailing = w.nextMail();
	const start = await sealed(w, s, "start", { identifier: "alice" });
	const started = await w.post("/first-key/start", start);
	const aad = firstKey.aad("start", start.nonce, s.eEnc, s.eSig);
	const sealedCode = started.json.sealed as never;
	const code = JSON.parse((await opened(s, sealedCode, hpke.info.firstKeyCode, aad)) ?? "{}").code;
	const token = ((await mailing).values.link as string).split("#")[1];
	const side = await screen();
	const mail = await sealed(w, side, "mail", { token, identifier: "alice", code });
	const creation = (await w.post("/first-key/mail", mail)).json.statement as string;
	const cer = await w.app.get(ceremonies);
	const auth = softwareAuthenticator();
	const registered = await register(w, side, creation, auth);
	await w.post("/key/finish", {
		statement: registered.possession,
		assertion: registered.assertion,
	});
	return { w, cer, auth, key: registered.key };
}

/** A new key made by `auth` over `creation`, registered as continuation `seq`, and its assertion. */
export async function register(
	w: World,
	s: Screen,
	creation: string,
	auth: ReturnType<typeof softwareAuthenticator>,
	seq = 1,
) {
	const cer = await w.app.get(ceremonies);
	const items = payloadOf(creation).creation;
	const options = cer.creation(
		sha256(challengeInput(creation, "create")),
		{ handle: items.options.user_id, name: "alice" },
		[],
		"required",
	);
	const body = JSON.stringify(auth.create(options as never, client));
	const sig = s.signs(continuation.of("register", sha256(creation), seq, sha256(body)));
	const answered = await w.post("/continue", {
		statement: creation,
		stage: "register",
		seq: String(seq),
		body,
		sig,
	});
	const possession = answered.json.statement as string;
	const named = payloadOf(possession).possession;
	const key: Credential = {
		id: named.credential_id,
		publicKey: JSON.parse(body).response.publicKey ?? "",
		signCount: 0,
		userHandle: items.options.user_id,
		backupEligible: false,
		backedUp: false,
	};
	const request = cer.request(sha256(challengeInput(possession, "get")), [key], "required");
	const assertion = JSON.stringify(auth.get(request as never, client, {}));
	return { possession, assertion, key };
}
