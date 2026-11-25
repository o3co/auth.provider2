import {
	createDecipheriv,
	createECDH,
	createHash,
	createHmac,
	generateKeyPairSync,
	type KeyObject,
	randomBytes,
	sign,
} from "node:crypto";
import { issuer } from "@mod/issuer";
import { assemble, defineModule, kernelConfig, type Module, Unavailable } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { keys } from "@mod/keys";
import keysModule from "@mod/keys/module";
import { keysConfig, testHolder } from "@mod/keys/testing";
import {
	type PasskeyStore,
	passkeyChanges,
	passkeyStore,
	type StoredCredential,
} from "@mod/passkeys";
import passkeysModule from "@mod/passkeys/module";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import { payloads } from "@mod/sdk-core-wire";
import {
	frameStore,
	operationKinds,
	type StateOwner,
	stateOwners,
	transparencyLog,
} from "@mod/transparency";
import transparencyModule from "@mod/transparency/module";
import { logBook, memoryFrames } from "@mod/transparency/testing";
import type { Flow } from "@mod/transparency-wire";
import { ceremonies, freshHandle } from "@mod/webauthn";
import webauthnModule from "@mod/webauthn/module";
import { softwareAuthenticator, testOrigin, webauthnConfig } from "@mod/webauthn/testing";
import {
	type ApprovalStore,
	approvalPart,
	approvalStore,
	approvals,
	type Screen,
	type StoredStatement,
	statementItems,
} from "../../src/contract.ts";
import approvalsModule from "../../src/module.ts";

export const sha256 = (data: string) => createHash("sha256").update(data).digest("base64url");

/**
 * Statements' records in memory, under a clock a test moves, failing on demand as a store that cannot
 * tell, and running a test's hook once before the next change of a record (another call's write
 * between a read and a change, or a fault there).
 */
export function memoryStatements(now: () => number) {
	const kept = new Map<string, { value: StoredStatement; until: number }>();
	let failing = false;
	const hooks = new Map<string, () => Promise<void>>();
	const live = (hash: string) => {
		if (failing) throw new Unavailable("store");
		const entry = kept.get(hash);
		return entry && now() < entry.until ? entry : undefined;
	};
	const store: ApprovalStore = {
		async create(hash, record, lifetimeMs) {
			if (live(hash)) return "exists";
			kept.set(hash, { value: structuredClone(record), until: now() + lifetimeMs });
			return "created";
		},
		read: async (hash) => structuredClone(live(hash)?.value),
		async change(hash, change) {
			const hook = hooks.get(hash);
			hooks.delete(hash);
			if (hook) await hook();
			const entry = live(hash);
			if (!entry) return undefined;
			const next = change(structuredClone(entry.value));
			const before = entry.value;
			if (next) kept.set(hash, { value: structuredClone(next.value), until: entry.until });
			return { before, after: (kept.get(hash) as { value: StoredStatement }).value };
		},
	};
	return {
		store,
		value: (hash: string) => kept.get(hash)?.value as unknown as Record<string, unknown>,
		fail: (on: boolean) => {
			failing = on;
		},
		beforeChange: (hash: string, hook: () => Promise<void>) => {
			hooks.set(hash, hook);
		},
	};
}

/** Credential records in memory. */
function memoryCredentials() {
	const kept = new Map<string, StoredCredential>();
	const store: PasskeyStore = {
		async create(id, record) {
			if (kept.has(id)) return "exists";
			kept.set(id, structuredClone(record));
			return "created";
		},
		read: async (id) => structuredClone(kept.get(id)),
		async change(id, change) {
			const record = kept.get(id);
			if (!record) return undefined;
			const next = change(structuredClone(record));
			if (next) kept.set(id, structuredClone(next.value));
			return { before: record, after: kept.get(id) as StoredCredential };
		},
	};
	return { store, kept };
}

/** The owner of the families, which approvals does not hold. */
const familiesOwner: StateOwner = {
	name: "families",
	holds: ["families"],
	parts: ["families"],
	records: () => [{ part: "families", name: "state" }],
	read: () => ({ families: {} }),
	write: () => [undefined],
};

/** A purpose's item names, as sdk-core-wire's schema holds them. */
const itemNames = (purpose: "authorization" | "creation" | "possession") =>
	Object.keys(
		{
			authorization: payloads.statement.shape.approval,
			creation: payloads.creation.shape.creation,
			possession: payloads.possession.shape.possession,
		}[purpose].shape,
	);

/** Every item of the three purposes, filled by a test's module. */
const filler = defineModule({ name: "filler", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(statementItems).by(() => ({
		purpose: "authorization",
		names: itemNames("authorization"),
		by: "filler",
	})),
	m
		.contribute(statementItems)
		.by(() => ({ purpose: "creation", names: itemNames("creation"), by: "filler" })),
	m.contribute(statementItems).by(() => ({
		purpose: "possession",
		names: itemNames("possession"),
		by: "filler",
	})),
]);

/** The families' owner and the key change's writer, which a composition with approvals has beside it. */
const beside = defineModule({ name: "beside", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(stateOwners).by(() => familiesOwner),
	m.contribute(operationKinds).by(() => ({ ...passkeyChanges, bundle: false })),
]);

/** The screen's two keys, their private halves kept for the test. */
export function screenKeys() {
	const enc = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const sig = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const point = enc.publicKey.export({ format: "jwk" });
	const raw = Buffer.concat([
		Buffer.from([4]),
		Buffer.from(point.x as string, "base64url"),
		Buffer.from(point.y as string, "base64url"),
	]);
	const { x, y } = sig.publicKey.export({ format: "jwk" }) as { x: string; y: string };
	const screen: Screen = {
		eEnc: raw.toString("base64url"),
		eSig: { kty: "EC", crv: "P-256", x, y },
	};
	const signs = (input: string) =>
		sign("sha256", Buffer.from(input), { key: sig.privateKey, dsaEncoding: "ieee-p1363" }).toString(
			"base64url",
		);
	return { screen, encKey: enc.privateKey, signs };
}

/** approvals composed with keys, passkeys, webauthn and transparency, over memory. */
export async function world(
	p: {
		readonly passkeys?: Record<string, unknown>;
		readonly approvals?: Record<string, unknown>;
		readonly modules?: readonly Module[];
		readonly items?: Module;
	} = {},
) {
	let clock = 1_800_000_000_000;
	const now = () => clock;
	const frames = memoryFrames(["passkeys", approvalPart, "families"]);
	const book = logBook(now);
	const log = book.as("w1");
	const statements = memoryStatements(now);
	const credentials = memoryCredentials();
	const fakes = defineModule({ name: "fakes", replicaSafe: true, takes: [] }, (m) => [
		m.provide(frameStore).by(() => frames.frames),
		m.provide(transparencyLog).by(() => log),
		m.provide(passkeyStore).by(() => credentials.store),
		m.provide(approvalStore).by(() => statements.store),
		m
			.provide(issuer)
			.by(() => ({ url: "https://issuer.example", endpointOrigin: "https://issuer.example" })),
	]);
	const app = await assemble({
		modules: [
			fakes,
			p.items ?? filler,
			beside,
			rateLimitStandIn,
			keysModule,
			testHolder(),
			transparencyModule,
			webauthnModule,
			passkeysModule,
			approvalsModule,
			...(p.modules ?? []),
		],
		config: {
			...kernelConfig(),
			...keysConfig(),
			...webauthnConfig(),
			passkeys: p.passkeys ?? {},
			approvals: p.approvals ?? {},
		},
		runtime: quietRuntime({ clock: { now } }),
	});
	const cer = await app.get(ceremonies);
	const auth = softwareAuthenticator();
	const client = { origin: testOrigin };
	/** A key active for `subject`, planted as a Step and a settle would leave it. */
	const plant = async (subject: string) => {
		const c = randomBytes(32).toString("base64url");
		const handle = freshHandle(randomBytes);
		const options = cer.creation(c, { handle, name: subject }, []);
		const attested = await cer.attest(auth.create(options as never, client), c, handle);
		if (attested.kind !== "attested") throw new Error(attested.reason);
		const k = attested.credential;
		credentials.kept.set(k.id, {
			subject,
			signCount: k.signCount,
			active: true,
			details: { userHandle: k.userHandle, backupEligible: false, backedUp: false },
		} as unknown as StoredCredential);
		const flow: Flow = { of: "subject", id: subject };
		const key = { credential: k.id, publicKey: k.publicKey, chain: [], position: 1, acceptedAt: 0 };
		frames.put(flow, { part: "passkeys", name: "keys" }, { keyGeneration: 0, keys: { r0: key } });
		return k;
	};
	/** An assertion over `challenge` by any discoverable credential, its flags as given. */
	const assert = (challenge: string, flags?: (f: number) => number) =>
		// Sent with spaces a re-encoding would drop: its bytes, as sent, are what is hashed.
		JSON.stringify(
			auth.get(cer.request(challenge, [], "required") as never, client, flags ? { flags } : {}),
			null,
			1,
		);
	return {
		app,
		approvals: await app.get(approvals),
		keys: await app.get(keys),
		frames,
		book,
		statements,
		plant,
		assert,
		advance: (ms: number) => {
			clock += ms;
		},
	};
}

/** HPKE's base mode opened (RFC 9180: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM), as the screen opens. */
export function openSealed(
	key: KeyObject,
	sealed: { readonly enc: string; readonly ct: string },
	info: string,
	aad: string,
): string {
	const hmac = (k: Buffer, data: Buffer) => createHmac("sha256", k).update(data).digest();
	const i2osp = (n: number, w: number) => Buffer.from(n.toString(16).padStart(w * 2, "0"), "hex");
	const kemId = Buffer.concat([Buffer.from("KEM"), i2osp(0x10, 2)]);
	const hpkeId = Buffer.concat([Buffer.from("HPKE"), i2osp(0x10, 2), i2osp(1, 2), i2osp(1, 2)]);
	const v1 = Buffer.from("HPKE-v1");
	const extract = (suite: Buffer, salt: Buffer, label: string, ikm: Buffer) =>
		hmac(
			salt.length > 0 ? salt : Buffer.alloc(32),
			Buffer.concat([v1, suite, Buffer.from(label), ikm]),
		);
	const expand = (suite: Buffer, prk: Buffer, label: string, ctx: Buffer, n: number) =>
		hmac(
			prk,
			Buffer.concat([i2osp(n, 2), v1, suite, Buffer.from(label), ctx, Buffer.from([1])]),
		).subarray(0, n);
	const jwk = key.export({ format: "jwk" });
	const ecdh = createECDH("prime256v1");
	ecdh.setPrivateKey(Buffer.from(jwk.d as string, "base64url"));
	const enc = Buffer.from(sealed.enc, "base64url");
	const pkR = Buffer.concat([
		Buffer.from([4]),
		Buffer.from(jwk.x as string, "base64url"),
		Buffer.from(jwk.y as string, "base64url"),
	]);
	const none = Buffer.alloc(0);
	const eae = extract(kemId, none, "eae_prk", ecdh.computeSecret(enc));
	const shared = expand(kemId, eae, "shared_secret", Buffer.concat([enc, pkR]), 32);
	const context = Buffer.concat([
		Buffer.from([0]),
		extract(hpkeId, none, "psk_id_hash", none),
		extract(hpkeId, none, "info_hash", Buffer.from(info)),
	]);
	const secret = extract(hpkeId, shared, "secret", none);
	const decipher = createDecipheriv(
		"aes-128-gcm",
		expand(hpkeId, secret, "key", context, 16),
		expand(hpkeId, secret, "base_nonce", context, 12),
	);
	const ct = Buffer.from(sealed.ct, "base64url");
	decipher.setAAD(Buffer.from(aad));
	decipher.setAuthTag(ct.subarray(ct.length - 16));
	return Buffer.concat([
		decipher.update(ct.subarray(0, ct.length - 16)),
		decipher.final(),
	]).toString("utf8");
}
