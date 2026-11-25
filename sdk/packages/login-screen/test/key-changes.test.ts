import { hpke, keyThumbprintInput, purposes, typs } from "@mod/sdk-core-wire";
import { logTyps } from "@mod/transparency-wire";
import { describe, expect, it, vi } from "vitest";
import { digest, utf8 } from "../src/bytes.ts";
import { firstKey } from "../src/first-key.ts";
import { sealTo } from "../src/hpke.ts";
import { type KeyChangeChecks, keyChanges } from "../src/key-changes.ts";
import { screenKeys } from "../src/keys.ts";
import { management } from "../src/management.ts";
import { signCompact, signingKey } from "./fixtures.ts";

const issuer = "https://id.example";
const now = 1_000_000_000;
type Key = Awaited<ReturnType<typeof signingKey>>;

/** A set's signed object as its JSON text: one signature per key given, under the purpose's typ. */
async function setSigned(payload: unknown, signers: readonly Key[], typ: string) {
	const signatures = [];
	let body = "";
	for (const key of signers) {
		const [protectedPart = "", payloadPart = "", signature = ""] = (
			await signCompact(key, payload, { typ })
		).split(".");
		body = payloadPart;
		signatures.push({ protected: protectedPart, signature });
	}
	return JSON.stringify({ payload: body, signatures });
}
const publicOf = (key: Key) => {
	const { kty, crv, x, y } = key.jwk;
	return { kid: key.kid, key: { kty, crv, x, y } };
};
const setOf = (purpose: "status" | "stateOf", keys: readonly Key[], required = 1) => ({
	v: 1,
	version: 1,
	purpose,
	keys: keys.map(publicOf),
	required,
});

async function world() {
	const ring = await signingKey("ES256", "core-1");
	const log = await signingKey("ES256", "log-1");
	const statusKey = await signingKey("ES256", "status-1");
	const stateKey = await signingKey("ES256", "state-1");
	const keys = await screenKeys();
	const sealing = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
		"deriveBits",
	])) as CryptoKeyPair;
	const sealingKey = new Uint8Array(await crypto.subtle.exportKey("raw", sealing.publicKey));
	const checks: KeyChangeChecks = {
		level: "log",
		log: [log.jwk],
		statusSigners: setOf("status", [statusKey]),
		stateOfSigners: setOf("stateOf", [stateKey]),
		maxAge: 60_000,
		now,
		skew: 1_000,
	};
	const flow = { of: "subject", id: "sub-1" };
	const receiptOf = (h: string, evidence: string, over: Record<string, unknown> = {}) =>
		signCompact(
			log,
			{
				v: 1,
				iss: "https://log.example",
				id: "rec-3",
				writer: { role: "core", instance: "i-1", image: "img", generation: 1 },
				kind: "keyChange",
				flow,
				position: 3,
				shard: "s1",
				n: 5,
				acceptedAt: now - 10_000,
				plaintextDigest: h,
				keyChange: { statement: h, evidence },
				...over,
			},
			{ typ: logTyps.receipt },
		);
	const statusOf = (over: Record<string, unknown> = {}, signers = [statusKey]) =>
		setSigned(
			{
				v: 1,
				version: 1,
				shards: { s1: { watermark: 10, generation: 1, state: "running" } },
				deny: [],
				...over,
			},
			signers,
			logTyps.status,
		);
	const result = (position: number, id: string) => ({
		position,
		id,
		verdict: "verified",
		outcome: "took",
	});
	const stateOfOf = (
		keysHeld: Record<string, unknown>,
		over: Record<string, unknown> = {},
		signers = [stateKey],
	) =>
		setSigned(
			{
				v: 1,
				flow,
				position: 3,
				state: { keyGeneration: 0, keys: keysHeld },
				results: [result(1, "rec-1"), result(2, "rec-2"), result(3, "rec-3")],
				...over,
			},
			signers,
			logTyps.stateOf,
		);
	/** The completion the Core seals to E_enc under the purpose and the statement's hash. */
	const sealed = async (purpose: string, h: string, payload: Record<string, unknown>) =>
		sealTo(
			Buffer.from(keys.eEnc, "base64url"),
			utf8(hpke.info.completion),
			utf8(hpke.completionAad(purpose as "first-key", h)),
			utf8(
				await signCompact(
					ring,
					{ v: 1, iss: issuer, iat: 1, exp: 2, purpose, ...payload },
					{ typ: typs.completion },
				),
			),
		);
	const options = (c: KeyChangeChecks = checks) => ({ ring: [ring.jwk], keys, issuer, checks: c });
	return {
		ring,
		log,
		statusKey,
		stateKey,
		keys,
		sealingKey,
		checks,
		receiptOf,
		statusOf,
		stateOfOf,
		result,
		sealed,
		options,
	};
}

/** A delete sent under a passkey-manage statement, and the completion the Core would answer it with. */
async function deleted() {
	const w = await world();
	const statement = await signCompact(
		w.ring,
		{
			v: 1,
			iss: issuer,
			sid: "st-1",
			iat: 1,
			exp: 2,
			e_enc: w.keys.eEnc,
			e_sig: w.keys.eSig,
			nonce: "n1",
			purpose: purposes.passkeyManage,
		},
		{ typ: typs.statement },
	);
	const read = await management.read(statement, {
		ring: [w.ring.jwk],
		keys: w.keys,
		issuer,
		purpose: "passkey-manage",
	});
	if ("error" in read) throw new Error(read.error);
	const made = await management.continuation(
		read.manage,
		"delete",
		1,
		{ credential_id: "AQID" },
		w,
	);
	if ("error" in made) throw new Error(made.error);
	const h = await digest(statement);
	const source = { delete: made.sent } as const;
	const change = { op: "delete", credential_id: "AQID" };
	const completion = async (over: Record<string, unknown> = {}) =>
		w.sealed("passkey-manage", h, {
			change,
			receipt: await w.receiptOf(h, made.sent.bodyHash),
			status: await w.statusOf(),
			stateOf: await w.stateOfOf({ k2: { credential: "BAUG" } }),
			...over,
		});
	return { ...w, read, made, h, source, change, completion };
}

describe("keyChanges.read: a delete", () => {
	it("takes the change once the log holds it: its receipt, its age, the status and the stateOf", async () => {
		const d = await deleted();
		const taken = await keyChanges.read(d.source, await d.completion(), d.options());
		expect(taken).toMatchObject({ change: d.change, receipt: { id: "rec-3", kind: "keyChange" } });
	});

	it("reads the completion alone where the caller names L0", async () => {
		const d = await deleted();
		const sealed = await d.sealed("passkey-manage", d.h, { change: d.change });
		expect(await keyChanges.read(d.source, sealed, d.options({ level: "L0" }))).toEqual({
			change: d.change,
		});
	});

	it("refuses log inputs that do not hold: no log key, a set unread, a clock not finite, a key of the Core ring among them", async () => {
		const d = await deleted();
		const sealed = await d.completion();
		const bad: KeyChangeChecks[] = [
			{ ...d.checks, log: [] },
			{ ...d.checks, statusSigners: { purpose: "status" } },
			{ ...d.checks, now: Number.NaN },
			{ ...d.checks, maxAge: -1 },
			{ ...d.checks, log: [d.ring.jwk] },
			{ ...d.checks, stateOfSigners: setOf("stateOf", [d.ring]) },
		];
		for (const checks of bad)
			expect(await keyChanges.read(d.source, sealed, d.options(checks))).toEqual({
				error: "checks",
			});
	});

	it("refuses a completion of another change, and a source not sent here or a rename's", async () => {
		const d = await deleted();
		const other = await d.completion({ change: { op: "delete", credential_id: "BAUG" } });
		expect(await keyChanges.read(d.source, other, d.options())).toEqual({ error: "change" });
		const sealed = await d.completion();
		expect(await keyChanges.read({ delete: { ...d.made.sent } }, sealed, d.options())).toEqual({
			error: "source",
		});
		const renamed = await management.continuation(
			d.read.manage,
			"rename",
			2,
			{ credential_id: "AQID", label: "x" },
			d,
		);
		if ("error" in renamed) throw new Error(renamed.error);
		expect(await keyChanges.read({ delete: renamed.sent }, sealed, d.options())).toEqual({
			error: "source",
		});
	});

	it("refuses a receipt missing, not the log's, accepted later than now, of another kind, digest or flow, or too old", async () => {
		const d = await deleted();
		const evidence = d.made.sent.bodyHash;
		const stranger = await signingKey("ES256", "log-1");
		for (const [receipt, error] of [
			[undefined, "receipt"],
			[(await d.receiptOf(d.h, evidence)).replace(/\.[^.]+$/, `.${"A".repeat(86)}`), "receipt"],
			[await d.receiptOf(d.h, evidence, { acceptedAt: now + 5_000 }), "receipt"],
			[await d.receiptOf(d.h, evidence, { kind: "start", keyChange: undefined }), "kind"],
			[await d.receiptOf(d.h, await digest("other")), "digest"],
			[await d.receiptOf(await digest("other"), evidence), "digest"],
			[await d.receiptOf(d.h, evidence, { flow: { of: "client", id: "c1" } }), "flow"],
			[await d.receiptOf(d.h, evidence, { acceptedAt: now - 120_000 }), "tooOld"],
		] as const) {
			const sealed = await d.completion({ receipt });
			expect(await keyChanges.read(d.source, sealed, d.options()), error).toEqual({ error });
		}
		const theirs = await signCompact(stranger, {}, { typ: logTyps.receipt });
		expect(
			await keyChanges.read(d.source, await d.completion({ receipt: theirs }), d.options()),
		).toEqual({ error: "receipt" });
	});

	it("asks for a fetch, with the receipt, where the status or the stateOf is missing, unread or behind, and takes the one fetched", async () => {
		const d = await deleted();
		const bare = await d.completion({ status: undefined, stateOf: undefined });
		expect(await keyChanges.read(d.source, bare, d.options())).toMatchObject({
			retry: "status",
			receipt: { id: "rec-3", flow: { of: "subject", id: "sub-1" }, position: 3 },
		});
		const stranger = await signingKey("ES256", "status-1");
		const unread = await d.completion({ status: await d.statusOf({}, [stranger]) });
		expect(await keyChanges.read(d.source, unread, d.options())).toMatchObject({ retry: "status" });
		const noState = await d.completion({ stateOf: undefined });
		expect(await keyChanges.read(d.source, noState, d.options())).toMatchObject({
			retry: "stateOf",
		});
		const unsigned = await d.completion({
			stateOf: await d.stateOfOf({ k2: { credential: "BAUG" } }, {}, [d.statusKey]),
		});
		expect(await keyChanges.read(d.source, unsigned, d.options())).toMatchObject({
			retry: "stateOf",
		});
		const behind = await d.completion({
			status: await d.statusOf({
				shards: { s1: { watermark: 4, generation: 1, state: "running" } },
			}),
		});
		expect(await keyChanges.read(d.source, behind, d.options())).toMatchObject({
			retry: "notYetChecked",
		});
		const early = await d.completion({
			stateOf: await d.stateOfOf(
				{},
				{ position: 2, results: [d.result(1, "rec-1"), d.result(2, "rec-2")] },
			),
		});
		expect(await keyChanges.read(d.source, early, d.options())).toMatchObject({
			retry: "stateBehind",
		});
		const fetched = {
			...d.checks,
			status: await d.statusOf(),
			stateOf: await d.stateOfOf({ k2: { credential: "BAUG" } }),
		};
		expect(await keyChanges.read(d.source, bare, d.options(fetched))).toMatchObject({
			change: d.change,
		});
	});

	it("refuses a status or a stateOf fetched and not read, rather than asking again", async () => {
		const d = await deleted();
		const sealed = await d.completion();
		expect(
			await keyChanges.read(d.source, sealed, d.options({ ...d.checks, status: "{}" })),
		).toEqual({ error: "status" });
		expect(
			await keyChanges.read(d.source, sealed, d.options({ ...d.checks, stateOf: "{}" })),
		).toEqual({ error: "stateOf" });
	});

	it("refuses a record the status denies, and keeps refusing it whatever older status is given", async () => {
		const d = await deleted();
		const denying = await d.completion({
			status: await d.statusOf({ version: 2, deny: ["rec-3"] }),
		});
		expect(await keyChanges.read(d.source, denying, d.options())).toEqual({ error: "denied" });
		expect(await keyChanges.read(d.source, await d.completion(), d.options())).toEqual({
			error: "denied",
		});
	});

	it("takes no status or stateOf older than one read before for the same change", async () => {
		const d = await deleted();
		const newer = await d.completion({
			status: await d.statusOf({ version: 3 }),
			stateOf: await d.stateOfOf(
				{ k2: { credential: "BAUG" } },
				{
					position: 4,
					results: [d.result(1, "r1"), d.result(2, "r2"), d.result(3, "rec-3"), d.result(4, "r4")],
				},
			),
		});
		expect(await keyChanges.read(d.source, newer, d.options())).toHaveProperty("change");
		expect(await keyChanges.read(d.source, await d.completion(), d.options())).toMatchObject({
			retry: "status",
		});
		const newStatus = await d.completion({ status: await d.statusOf({ version: 3 }) });
		expect(await keyChanges.read(d.source, newStatus, d.options())).toMatchObject({
			retry: "stateOf",
		});
	});

	it("keeps a refusal that a read of the same change beside this one gave, and remembers a status read before its watermark", async () => {
		const d = await deleted();
		// The same version: only the page's holding, read again before success, tells the two apart.
		const denying = await d.completion({ status: await d.statusOf({ deny: ["rec-3"] }) });
		const stateOf = await d.stateOfOf({ k2: { credential: "BAUG" } });
		const plain = await d.completion({ stateOf });
		// The plain read is held at its stateOf's signature, past its status and before its last
		// reading of the page's holding, until the denying read has refused: the order is the test's.
		const { payload, signatures } = JSON.parse(stateOf) as {
			payload: string;
			signatures: { protected: string }[];
		};
		const held = `${signatures[0]?.protected}.${payload}`;
		let reached: () => void = () => {};
		const atGate = new Promise<void>((resolve) => {
			reached = resolve;
		});
		let release: () => void = () => {};
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		const verify = crypto.subtle.verify.bind(crypto.subtle);
		const spy = vi
			.spyOn(crypto.subtle, "verify")
			.mockImplementation(async (algorithm, key, signature, data) => {
				if (new TextDecoder().decode(data as Uint8Array) === held) {
					reached();
					await gate;
				}
				return verify(algorithm, key, signature, data);
			});
		try {
			const one = keyChanges.read(d.source, plain, d.options());
			await atGate;
			expect(await keyChanges.read(d.source, denying, d.options())).toEqual({ error: "denied" });
			release();
			expect(await one).toEqual({ error: "denied" });
		} finally {
			release();
			spy.mockRestore();
		}
		expect(await keyChanges.read(d.source, plain, d.options())).toEqual({ error: "denied" });
		const e = await deleted();
		const unchecked = await e.completion({
			status: await e.statusOf({
				version: 5,
				shards: { s1: { watermark: 4, generation: 1, state: "running" } },
			}),
		});
		expect(await keyChanges.read(e.source, unchecked, e.options())).toMatchObject({
			retry: "notYetChecked",
		});
		expect(await keyChanges.read(e.source, await e.completion(), e.options())).toMatchObject({
			retry: "status",
		});
	});

	it("reads the checks as they were given, whatever the caller changes while it reads", async () => {
		const d = await deleted();
		const sealed = await d.completion({
			receipt: await d.receiptOf(d.h, d.made.sent.bodyHash, { acceptedAt: now - 120_000 }),
		});
		const statusSigners = setOf("status", [d.statusKey]);
		const checks = { ...d.checks, statusSigners };
		const reading = keyChanges.read(d.source, sealed, d.options(checks));
		(checks as { now: number }).now = now - 100_000;
		statusSigners.keys[0] = { kid: "status-1", key: publicOf(d.ring).key };
		expect(await reading).toEqual({ error: "tooOld" });
	});

	it("verifies by the signer sets as they were given, a set changed while it reads reaching nothing", async () => {
		const d = await deleted();
		const sealed = await d.completion();
		const statusSigners = setOf("status", [d.statusKey]);
		const stateOfSigners = setOf("stateOf", [d.stateKey]);
		const reading = keyChanges.read(
			d.source,
			sealed,
			d.options({ ...d.checks, statusSigners, stateOfSigners }),
		);
		const stranger = await signingKey("ES256", "x-1");
		statusSigners.keys[0] = publicOf(stranger);
		stateOfSigners.keys.splice(0, 1, publicOf(stranger));
		expect(await reading).toMatchObject({ change: d.change });
	});

	it("keeps a refusal for the change whatever source is made again for it, and refuses a log that is no list", async () => {
		const d = await deleted();
		const sealed = await d.completion({
			stateOf: await d.stateOfOf({ k1: { credential: "AQID" } }),
		});
		expect(await keyChanges.read(d.source, sealed, d.options())).toEqual({ error: "key" });
		const again = await management.continuation(
			d.read.manage,
			"delete",
			1,
			{ credential_id: "AQID" },
			d,
		);
		if ("error" in again) throw new Error(again.error);
		expect(
			await keyChanges.read({ delete: again.sent }, await d.completion(), d.options()),
		).toEqual({ error: "key" });
		expect(
			await keyChanges.read(
				d.source,
				await d.completion(),
				d.options({ ...d.checks, log: {} as never }),
			),
		).toEqual({ error: "checks" });
	});

	it("refuses a stateOf of another flow, where the record did not take, of a state unread, or still holding the key, and keeps refusing what the log's objects gave", async () => {
		const held = { k2: { credential: "BAUG" } };
		const results = (d: Awaited<ReturnType<typeof deleted>>, last: Record<string, unknown>) => ({
			results: [d.result(1, "rec-1"), d.result(2, "rec-2"), { ...d.result(3, "rec-3"), ...last }],
		});
		const cases: readonly (readonly [
			(d: Awaited<ReturnType<typeof deleted>>) => Promise<string>,
			string,
		])[] = [
			[(d) => d.stateOfOf(held, { flow: { of: "subject", id: "sub-2" } }), "flow"],
			[(d) => d.stateOfOf(held, results(d, { id: "rec-x" })), "result"],
			[(d) => d.stateOfOf(held, results(d, { verdict: "held" })), "result"],
			[(d) => d.stateOfOf(held, results(d, { outcome: "didNotTake" })), "result"],
			[(d) => d.stateOfOf({ k2: {} }), "state"],
			[(d) => d.stateOfOf({ k1: { credential: "AQID" } }), "key"],
		];
		for (const [make, error] of cases) {
			const d = await deleted();
			const sealed = await d.completion({ stateOf: await make(d) });
			expect(await keyChanges.read(d.source, sealed, d.options()), error).toEqual({ error });
			if (error !== "flow")
				expect(
					await keyChanges.read(d.source, await d.completion(), d.options()),
					`${error} again`,
				).toEqual({ error });
		}
		const d = await deleted();
		const unsupported = await d.completion({
			stateOf: await d.stateOfOf(held, results(d, { verdict: "unsupported" })),
		});
		expect(await keyChanges.read(d.source, unsupported, d.options())).toHaveProperty("change");
	});

	it("refuses checks of no level it knows, before reading anything", async () => {
		const d = await deleted();
		const sealed = await d.completion();
		for (const checks of [
			{ ...d.checks, level: "L1" },
			{ ...d.checks, level: undefined, now: Number.NaN },
			undefined,
		])
			expect(
				await keyChanges.read(d.source, sealed, { ...d.options(), checks: checks as never }),
				JSON.stringify(checks),
			).toEqual({ error: "checks" });
	});
});

describe("keyChanges.read: a key added", () => {
	/** A first key's possession, read as the screen reads it, and the new key's assertion. */
	async function added() {
		const w = await world();
		const options = { ring: [w.ring.jwk], sealingKey: w.sealingKey, keys: w.keys, issuer };
		const sent = await firstKey.mail(
			{ token: "tok", identifier: "a@example", code: "123456" },
			"n".repeat(43),
			options,
		);
		if ("error" in sent) throw new Error(sent.error);
		const sign = (payload: unknown) => signCompact(w.ring, payload, { typ: typs.statement });
		const common = {
			v: 1,
			iss: issuer,
			sid: "st-1",
			iat: 1,
			exp: 2,
			e_enc: w.keys.eEnc,
			e_sig: w.keys.eSig,
		};
		const creationCompact = await sign({
			...common,
			nonce: "cn",
			purpose: purposes.creation,
			creation: {
				account: "a***@example",
				evidence: await digest("first-key-token\u0000tok"),
				ct_hash: sent.mail.ctHash,
				subject: "sub-1",
				kg: 0,
				options: {
					user_id: "dXNlcg",
					rp_id: "id.example",
					exclude_credentials: [],
					algorithms: [-7],
				},
			},
		});
		const creation = await firstKey.readCreation(creationCompact, sent.mail, options);
		if ("error" in creation) throw new Error(creation.error);
		const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
			"sign",
		]);
		const { crv, kty, x, y } = await crypto.subtle.exportKey("jwk", pair.publicKey);
		const jkt = await digest(keyThumbprintInput({ crv, kty, x, y }) ?? "");
		const possessionCompact = await sign({
			...common,
			nonce: "pn",
			purpose: purposes.possession,
			possession: {
				creation_hash: await digest(creationCompact),
				key_jkt: jkt,
				credential_id: "BAUG",
				reservation_id: "r-1",
			},
		});
		const possession = await firstKey.readPossession(
			possessionCompact,
			creation.creation,
			{
				id: "BAUG",
				spki: new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey)),
				alg: -7,
			},
			options,
		);
		if ("error" in possession) throw new Error(possession.error);
		const assertion = utf8("the new key's assertion");
		const h = await digest(possessionCompact);
		const change = { op: "add", credential_id: "BAUG", key_jkt: jkt };
		const completion = async (over: Record<string, unknown> = {}, purpose = "first-key") =>
			w.sealed(purpose, h, {
				change,
				receipt: await w.receiptOf(h, await digest(assertion)),
				status: await w.statusOf(),
				stateOf: await w.stateOfOf({ k1: { credential: "BAUG" } }),
				...over,
			});
		const source = { add: possession.possession, assertion } as const;
		return { ...w, h, change, completion, source };
	}

	it("takes a passkey-add's addition through its approval, creation and possession, under its own purpose", async () => {
		const w = await world();
		const common = {
			v: 1,
			iss: issuer,
			sid: "st-1",
			iat: 1,
			exp: 2,
			e_enc: w.keys.eEnc,
			e_sig: w.keys.eSig,
		};
		const sign = (payload: unknown) => signCompact(w.ring, payload, { typ: typs.statement });
		const statement = await sign({ ...common, nonce: "an", purpose: purposes.passkeyAdd });
		const options = { ring: [w.ring.jwk], keys: w.keys, issuer };
		const read = await management.read(statement, { ...options, purpose: "passkey-add" });
		if ("error" in read) throw new Error(read.error);
		const approvalAssertion = utf8("the approving assertion");
		const ha = await digest(statement);
		const creationCompact = await sign({
			...common,
			nonce: "cn",
			purpose: purposes.creation,
			creation: {
				account: "a***@example",
				basis: "passkey-add",
				evidence: ha,
				subject: "sub-1",
				kg: 0,
				options: {
					user_id: "dXNlcg",
					rp_id: "id.example",
					exclude_credentials: [],
					algorithms: [-7],
				},
			},
		});
		const approved = await sealTo(
			Buffer.from(w.keys.eEnc, "base64url"),
			utf8(hpke.info.completion),
			utf8(hpke.completionAad("passkey-add", ha)),
			utf8(
				await signCompact(
					w.ring,
					{
						v: 1,
						iss: issuer,
						t_hash: ha,
						assertion_hash: await digest(approvalAssertion),
						purpose: purposes.passkeyAdd,
						creation: creationCompact,
						iat: 1,
						exp: 2,
					},
					{ typ: typs.completion },
				),
			),
		);
		const finished = await management.finish(read.manage, approved, {
			...options,
			assertion: approvalAssertion,
		});
		if (!("creation" in finished)) throw new Error(JSON.stringify(finished));
		const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
			"sign",
		]);
		const { crv, kty, x, y } = await crypto.subtle.exportKey("jwk", pair.publicKey);
		const jkt = await digest(keyThumbprintInput({ crv, kty, x, y }) ?? "");
		const possessionCompact = await sign({
			...common,
			nonce: "pn",
			purpose: purposes.possession,
			possession: {
				creation_hash: await digest(creationCompact),
				key_jkt: jkt,
				credential_id: "BAUG",
				reservation_id: "r-1",
			},
		});
		const possession = await firstKey.readPossession(
			possessionCompact,
			finished.creation,
			{
				id: "BAUG",
				spki: new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey)),
				alg: -7,
			},
			options,
		);
		if ("error" in possession) throw new Error(possession.error);
		const assertion = utf8("the new key's assertion");
		const h = await digest(possessionCompact);
		const change = { op: "add", credential_id: "BAUG", key_jkt: jkt };
		const sealed = await w.sealed("passkey-add", h, {
			change,
			receipt: await w.receiptOf(h, await digest(assertion)),
			status: await w.statusOf(),
			stateOf: await w.stateOfOf({ k1: { credential: "BAUG" } }),
		});
		const source = { add: possession.possession, assertion };
		expect(await keyChanges.read(source, sealed, w.options())).toMatchObject({ change });
		// Under the first key's purpose it does not open: the path is the creation's.
		const asFirst = await w.sealed("first-key", h, { change });
		expect(await keyChanges.read(source, asFirst, w.options())).toEqual({ error: "open" });
	});

	it("takes a first key's addition once the log holds it, the state holding the new key", async () => {
		const a = await added();
		expect(await keyChanges.read(a.source, await a.completion(), a.options())).toMatchObject({
			change: a.change,
		});
	});

	it("refuses another path's purpose, another subject's flow, another assertion, and a state without the key", async () => {
		const a = await added();
		const other = await a.completion({ purpose: "passkey-add" });
		expect(await keyChanges.read(a.source, other, a.options())).toEqual({ error: "purpose" });
		const elsewhere = await a.completion({
			receipt: await a.receiptOf(a.h, await digest(a.source.assertion), {
				flow: { of: "subject", id: "sub-2" },
			}),
		});
		expect(await keyChanges.read(a.source, elsewhere, a.options())).toEqual({ error: "flow" });
		const assertion = utf8("another assertion");
		expect(
			await keyChanges.read({ ...a.source, assertion }, await a.completion(), a.options()),
		).toEqual({ error: "digest" });
		const gone = await a.completion({ stateOf: await a.stateOfOf({}) });
		expect(await keyChanges.read(a.source, gone, a.options())).toEqual({ error: "key" });
	});
});
