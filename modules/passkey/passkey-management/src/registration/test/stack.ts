import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { approvalStore, approvals, type StoredStatement, statementItems } from "@mod/approvals";
import approvalsModule from "@mod/approvals/module";
import { continuations } from "@mod/continuation-wire";
import { issuer } from "@mod/issuer";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import keysModule from "@mod/keys/module";
import { keysConfig, testHolder } from "@mod/keys/testing";
import {
	heldKeys,
	type PasskeyStore,
	passkeyStore,
	passkeys,
	registrations,
	type StoredCredential,
} from "@mod/passkeys";
import passkeysModule from "@mod/passkeys/module";
import { stances } from "@mod/promises";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import { familiesPart } from "@mod/refresh";
import { familiesOwning } from "@mod/refresh/testing";
import { challengeInput } from "@mod/sdk-core-wire";
import { frameStore, operationKinds, transparency, transparencyLog } from "@mod/transparency";
import transparencyModule from "@mod/transparency/module";
import { logBook, memoryFrames } from "@mod/transparency/testing";
import { type Credential, ceremonies, freshHandle } from "@mod/webauthn";
import webauthnModule from "@mod/webauthn/module";
import { softwareAuthenticator, testOrigin, webauthnConfig } from "@mod/webauthn/testing";
import { keyChangePart } from "../../contract.ts";
import { creationItems } from "../../creation/creation.ts";
import { keyChangeKind, keyChangesOver } from "../../key-change/key-change.ts";
import { possessionItems, registrationOver } from "../registration.ts";

export const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");

/** Records in memory under a clock, each living as long as it was given. */
function memoryRecords<T>(now: () => number) {
	const kept = new Map<string, { value: T; until: number }>();
	const live = (key: string) => {
		const entry = kept.get(key);
		return entry && (entry.until === Number.POSITIVE_INFINITY || now() < entry.until)
			? entry
			: undefined;
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

/** The screen's two keys, the signing one's private half kept to sign its continuations. */
export function screen() {
	const enc = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const sig = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const point = enc.publicKey.export({ format: "jwk" });
	const raw = Buffer.concat([
		Buffer.from([4]),
		Buffer.from(point.x as string, "base64url"),
		Buffer.from(point.y as string, "base64url"),
	]);
	const { x, y } = sig.publicKey.export({ format: "jwk" }) as { x: string; y: string };
	const signs = (input: string) =>
		sign("sha256", Buffer.from(input), { key: sig.privateKey, dsaEncoding: "ieee-p1363" }).toString(
			"base64url",
		);
	return {
		keys: {
			eEnc: raw.toString("base64url"),
			eSig: { kty: "EC" as const, crv: "P-256" as const, x, y },
		},
		signs,
	};
}

/**
 * A key's registration after its creation over approvals, passkeys, transparency, webauthn and keys
 * in memory: each append judged took at once, a subject's creation issued as the mail's side would.
 */
export async function stack(given: { readonly passkeys?: Record<string, unknown> } = {}) {
	let clock = 1_800_000_000_000;
	const now = () => clock;
	const frames = memoryFrames(["passkeys", "approvals", familiesPart, keyChangePart]);
	const book = logBook(now);
	book.judgeOnAppend({ verdict: "verified", outcome: "took" });
	const statements = memoryRecords<StoredStatement>(now);
	const credentials = memoryRecords<StoredCredential>(now);
	let revoked = false;
	const beside = defineModule({ name: "beside", replicaSafe: true, takes: [] }, (m) => [
		m.provide(frameStore).by(() => frames.frames),
		m.provide(transparencyLog).by(() => book.as("w1")),
		m.provide(passkeyStore).by(() => credentials as PasskeyStore),
		m.provide(approvalStore).by(() => statements),
		m
			.provide(issuer)
			.by(() => ({ url: "https://issuer.example", endpointOrigin: "https://issuer.example" })),
		m.contribute(statementItems).by(() => creationItems),
		m.contribute(statementItems).by(() => possessionItems),
		m.contribute(statementItems).by(() => ({ purpose: "authorization", names: [], by: "beside" })),
		m.contribute(operationKinds).by(() => keyChangeKind),
		m.contribute(stances).by(() => ({
			promise: "front-compromise-new-authorization",
			holds: true,
			by: "beside",
		})),
	]);
	const app = await assemble({
		modules: [
			beside,
			// The state's families, as refresh owns them in a deployment.
			familiesOwning,
			rateLimitStandIn,
			keysModule,
			testHolder(),
			transparencyModule,
			webauthnModule,
			passkeysModule,
			approvalsModule,
		],
		config: {
			...kernelConfig(),
			...keysConfig(),
			...webauthnConfig(),
			passkeys: given.passkeys ?? {},
		},
		runtime: quietRuntime({ clock: { now } }),
	});
	const settled: string[] = [];
	const known = await app.get(passkeys);
	const keyChange = keyChangesOver({
		registrations: await app.get(registrations),
		transparency: await app.get(transparency),
		passkeys: {
			settle: async (subject) => {
				settled.push(subject);
				return known.settle(subject);
			},
			publicKeyOf: (id) => known.publicKeyOf(id),
		},
		digest: book.as("w1").digest,
		pause: async () => {},
		looks: 3,
		now,
		log: book.as("w1"),
	});
	const parts = {
		approvals: await app.get(approvals),
		registrations: await app.get(registrations),
		held: await app.get(heldKeys),
		passkeys: known,
		ceremonies: await app.get(ceremonies),
		revocation: { check: async () => (revoked ? ("revoked" as const) : ("valid" as const)) },
		keyChange,
	};
	const registration = registrationOver(parts);
	const cer = parts.ceremonies;
	const auth = softwareAuthenticator();
	const client = { origin: testOrigin };

	/** A creation for `subject`, a first key's as the mail's side issues it unless told, and its screen. */
	const created = async (
		subject = "s1",
		basis: "first-key" | "passkey-add" | "sign-up" = "first-key",
		given: { readonly evidence?: string; readonly shown?: ReturnType<typeof screen> } = {},
	) => {
		const shown = given.shown ?? screen();
		const handle = freshHandle(randomBytes);
		const issued = await parts.approvals.issue({
			purpose: "creation",
			items: {
				// A sign-up's names its account in `user_name` alone.
				...(basis === "sign-up" ? {} : { account: "a***@example.com" }),
				basis,
				evidence: given.evidence ?? sha256("token"),
				...(basis === "first-key" ? { ct_hash: sha256("ct") } : {}),
				subject,
				kg: 0,
				options: {
					user_id: handle,
					...(basis === "sign-up" ? { user_name: "Example 3fa9c1" } : {}),
					rp_id: "rp.example",
					exclude_credentials: [],
					algorithms: [-7, -8],
				},
			},
			screen: shown.keys,
			by: subject,
		});
		if (issued.kind !== "issued") throw new Error(issued.reason);
		return { ...issued, handle, ...shown };
	};
	type Created = Awaited<ReturnType<typeof created>>;
	/** The screen's `create()` over the creation, its response's JSON text. */
	const made = (c: Created, a = auth) => {
		const options = cer.creation(
			sha256(challengeInput(c.statement, "create")),
			{ handle: c.handle, name: "s" },
			[],
			"required",
		);
		return JSON.stringify(a.create(options as never, client));
	};
	/** The register continuation of `body`, signed by the creation's screen. */
	const continued = (c: Created, body: string, seq = 1) => ({
		statement: c.statement,
		hash: c.hash,
		seq,
		body,
		sig: c.signs(continuations.of("register", c.hash, seq, sha256(body))),
	});
	/** The new key's assertion over a possession, as the screen's `get()` answers it. */
	const asserted = (
		possession: string,
		credential: Credential,
		a = auth,
		flags?: (f: number) => number,
	) =>
		JSON.stringify(
			a.get(
				cer.request(sha256(challengeInput(possession, "get")), [credential], "required") as never,
				client,
				flags ? { flags } : {},
			),
		);
	return {
		app,
		frames,
		book,
		parts,
		registration,
		settled,
		created,
		made,
		continued,
		asserted,
		revoke: (on = true) => {
			revoked = on;
		},
		advance: (ms: number) => {
			clock += ms;
			frames.clock.set(frames.clock.now() + ms);
		},
	};
}
