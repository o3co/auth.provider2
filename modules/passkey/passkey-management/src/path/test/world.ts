import { createHash, generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { approvalStore, type StoredStatement } from "@mod/approvals";
import approvalsModule from "@mod/approvals/module";
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
import { type SubjectRevocation, subjectRevocation } from "@mod/subject-revocation";
import { frameStore, type StateOwner, stateOwners, transparencyLog } from "@mod/transparency";
import transparencyModule from "@mod/transparency/module";
import { logBook, memoryFrames } from "@mod/transparency/testing";
import { type Users, users } from "@mod/users";
import webauthnModule from "@mod/webauthn/module";
import { testOrigin, webauthnConfig } from "@mod/webauthn/testing";
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
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
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
	const standIns = defineModule({ name: "stand-ins", replicaSafe: true, takes: [routes] }, (m) => [
		m.provide(seen).by((c) => c.collect(routes)),
		m.provide(frameStore).by(() => frames.frames),
		m.provide(transparencyLog).by(() => book.as("w1")),
		m.provide(passkeyStore).by(() => memoryRecords<StoredCredential>(now) as PasskeyStore),
		m.provide(approvalStore).by(() => memoryRecords<StoredStatement>(now)),
		m.provide(firstKeyNonces).by(() => memoryKept<StoredNonce>().store),
		m.provide(firstKeyTokens).by(() => memoryKept<StoredToken>().store),
		m
			.provide(issuer)
			.by(() => ({ url: "https://issuer.example", endpointOrigin: "https://issuer.example" })),
		m.contribute(stateOwners).by(() => familiesOwner),
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
		sent,
		recorded,
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
