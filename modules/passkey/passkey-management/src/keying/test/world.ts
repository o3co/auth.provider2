import {
	createHash,
	createPublicKey,
	generateKeyPairSync,
	type KeyObject,
	sign,
	verify,
	type webcrypto,
} from "node:crypto";
import { approvalStore, approvals, type StoredStatement, statementItems } from "@mod/approvals";
import approvalsModule from "@mod/approvals/module";
import type { Ask, Checks, FlowState } from "@mod/authority-rules";
import { continuations } from "@mod/continuation-wire";
import { type Route, routes } from "@mod/http";
import { testRequest } from "@mod/http/testing";
import { issuer } from "@mod/issuer";
import { assemble, contract, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { keys } from "@mod/keys";
import keysModule from "@mod/keys/module";
import { keysConfig, testHolder } from "@mod/keys/testing";
import { passkeyWitnessStandIn } from "@mod/passkey-witness/testing";
import {
	type PasskeyStore,
	passkeyRemovals,
	passkeyStore,
	passkeyWitnessing,
	type StoredCredential,
} from "@mod/passkeys";
import passkeysModule from "@mod/passkeys/module";
import promisesModule from "@mod/promises/module";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import { familiesPart } from "@mod/refresh";
import { familiesOwning } from "@mod/refresh/testing";
import { challengeInput, payloads } from "@mod/sdk-core-wire";
import { type SubjectRevocation, subjectRevocation } from "@mod/subject-revocation";
import { frameStore, type Stage, transparencyLog } from "@mod/transparency";
import transparencyModule from "@mod/transparency/module";
import { logBook, memoryFrames } from "@mod/transparency/testing";
import { type Users, users } from "@mod/users";
import { type Credential, ceremonies, keyThumbprint } from "@mod/webauthn";
import webauthnModule from "@mod/webauthn/module";
import { softwareAuthenticator, testOrigin, webauthnConfig } from "@mod/webauthn/testing";
import { keyChangePart, signUpCreations } from "../../contract.ts";
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

const seen = contract<readonly Route[]>("key-world.routes");

/**
 * passkey-management composed whole over keys, approvals, passkeys, transparency and
 * webauthn, each append judged took at once; users standing in, one user `alice` (`s1`)
 * with a verified address.
 */
export async function keyWorld() {
	let clock = 1_800_000_000_000;
	const now = () => clock;
	const core = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
	const frames = memoryFrames(["passkeys", "approvals", familiesPart, keyChangePart]);
	const book = logBook(now);
	book.judgeOnAppend({ verdict: "verified", outcome: "took" });
	const user = { subject: "s1", attributes: {} };
	const statements = memoryRecords<StoredStatement>(now);
	const standIns = defineModule({ name: "stand-ins", replicaSafe: true, takes: [routes] }, (m) => [
		m.provide(seen).by((c) => c.collect(routes)),
		m.provide(frameStore).by(() => frames.frames),
		m.provide(transparencyLog).by(() => book.as("w1")),
		m.provide(passkeyStore).by(() => memoryRecords<StoredCredential>(now) as PasskeyStore),
		m.provide(approvalStore).by(() => statements),
		m
			.provide(issuer)
			.by(() => ({ url: "https://issuer.example", endpointOrigin: "https://issuer.example" })),
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
		m
			.provide(subjectRevocation)
			.by(() => ({ check: async () => "valid" }) as unknown as SubjectRevocation),
	]);
	const recorded = recordingLog();
	// Each removal passkeys' settle tells, as a contributor (refresh, in a deployment) hears it.
	const told: (readonly [string, string, boolean])[] = [];
	let falls = 0;
	const removals = defineModule({ name: "removals", replicaSafe: true, takes: [] }, (m) => [
		m.contribute(passkeyRemovals).by(() => ({
			removed: async (subject: string, credential: string, emptied: boolean) => {
				if (falls > 0) {
					falls--;
					throw new Unavailable("removals");
				}
				told.push([subject, credential, emptied]);
			},
		})),
	]);
	const app = await assemble({
		modules: [
			standIns,
			removals,
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
		],
		config: {
			...kernelConfig(),
			...keysConfig(),
			...webauthnConfig(),
			...passkeyManagementConfig(),
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
		recorded,
		told,
		/** The next removal told fails, as a contributor whose store cannot tell. */
		failRemovalOnce: () => {
			falls = 1;
		},
		statements,
		corePoint: pointOf(core),
		advance: (ms: number) => {
			clock += ms;
		},
	};
}

type World = Awaited<ReturnType<typeof keyWorld>>;
type Screen = Awaited<ReturnType<typeof screen>>;
const utf8 = (text: string) => new TextEncoder().encode(text);
export const payloadOf = (jws: string) =>
	JSON.parse(Buffer.from(jws.split(".")[1] ?? "", "base64url").toString("utf8"));

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

/** The items of a T allowing a sign-up, as the sign-up package's step reads them. */
export const tItems = {
	client_id: "c1",
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
} as const;

/** `alice` (`s1`) holding one key, made on a sign-up's creation (F1) and registered over the routes. */
export async function withKey() {
	const w = await keyWorld();
	await w.app.start();
	const ap = await w.app.get(approvals);
	const creations = await w.app.get(signUpCreations);
	const s = await screen();
	const t = await ap.issue({
		purpose: "authorization",
		items: tItems,
		screen: { eEnc: s.eEnc, eSig: s.eSig },
		by: "src",
		continues: ["sign-up"],
	});
	if (t.kind !== "issued") throw new Error(t.reason);
	const step = await ap.continueSignUp({
		hash: t.hash,
		seq: 1,
		body: "{}",
		signature: s.signs(continuations.of("sign-up", t.hash, 1, sha256("{}"))),
		step: async (kept) => {
			const subject = (await ap.signUpSubject(kept.hash, "s1")) ?? "s1";
			const made = await creations.create({
				tHash: kept.hash,
				subject,
				screen: kept.screen,
				since: w.now(),
			});
			return made.kind === "issued" ? { creation: made.statement } : { refused: made.reason };
		},
	});
	if (step.kind !== "continued") throw new Error(step.reason);
	const creation = (step.result as { creation: string }).creation;
	const cer = await w.app.get(ceremonies);
	const auth = softwareAuthenticator();
	const registered = await register(w, s, creation, auth);
	const finished = await w.post("/key/finish", {
		statement: registered.possession,
		assertion: registered.assertion,
	});
	if (finished.status !== 200) throw new Error("a key's finish refused");
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
	const sig = s.signs(continuations.of("register", sha256(creation), seq, sha256(body)));
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
