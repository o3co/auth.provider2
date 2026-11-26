import { describe, expect, it } from "vitest";
import {
	appendRefusals,
	flows,
	judgments,
	logTyps,
	opIds,
	recordKinds,
	schemas,
	sealing,
	signers,
	speaks,
	statusWords,
	tokens,
} from "../src/contract.ts";

const d = (c: string) => c.repeat(43);
const jws = "aGVhZA.Ym9keQ.c2ln";
const subject = { of: "subject", id: "sub-1" } as const;
const core = { role: "core", instance: "i-1", image: `sha256:${"a".repeat(64)}`, generation: 1 };
const ecKey = { kty: "EC", crv: "P-256", x: "eA", y: "eQ" } as const;

const bundleRequest = {
	v: 1,
	kind: "bundle",
	flow: subject,
	prev: 4,
	op: "op-1",
	stage: 2,
	last: true,
	registryVersion: 3,
	configVersion: 2,
	plaintextDigest: d("p"),
	preimage: [
		{ key: "mk-1", enc: "ZW5j", ciphertext: "Y3Q" },
		{ key: "mk-2", enc: "ZW5k", ciphertext: "Y3R" },
	],
	tokens: [
		{ frame: "accessToken", digest: d("a") },
		{ frame: "idToken", digest: d("i") },
		{ frame: "family", digest: d("f") },
	],
};
const placed = {
	id: "r-5",
	writer: core,
	position: 5,
	shard: "s1",
	n: 17,
	acceptedAt: 1_700_000_000_123,
};
const { prev: _p, preimage: _s, ...bundleFields } = bundleRequest;
const bundleRecord = {
	...bundleFields,
	...placed,
	sealedTo: [
		{ key: "mk-1", ciphertextHash: d("c") },
		{ key: "mk-2", ciphertextHash: d("e") },
	],
	keySetVersion: 2,
};
const denialRecord = {
	v: 1,
	id: "r-6",
	writer: { role: "monitor", key: "mon-1" },
	kind: "denial",
	flow: subject,
	position: 6,
	shard: "s1",
	n: 18,
	acceptedAt: 1_700_000_000_200,
	op: "deny-1",
	stage: 1,
	last: true,
	plaintextDigest: d("q"),
	signed: jws,
};
const tick = {
	v: 1,
	id: "r-7",
	writer: { role: "log" },
	kind: "tick",
	shard: "ps",
	n: 3,
	acceptedAt: 9,
};
const receipt = {
	v: 1,
	iss: "https://log.example",
	id: "r-5",
	writer: core,
	kind: "bundle",
	flow: subject,
	position: 5,
	shard: "s1",
	n: 17,
	acceptedAt: 1_700_000_000_123,
	plaintextDigest: d("p"),
	token: { frame: "idToken", digest: d("i") },
};

const ok = (schema: { safeParse(x: unknown): { success: boolean } }, value: unknown) =>
	expect(schema.safeParse(value).success, JSON.stringify(value)).toBe(true);
const no = (schema: { safeParse(x: unknown): { success: boolean } }, value: unknown) =>
	expect(schema.safeParse(value).success, JSON.stringify(value)).toBe(false);

describe("the conditional append a writer sends", () => {
	it("reads a Core writer's record: kind, flow and previous position, operation and stage, versions, the preimage sealed to a monitor key, and one digest per token", () => {
		ok(schemas.appendRequest, bundleRequest);
	});

	it("refuses an unconditional flow given a previous position, and a conditional one without", () => {
		no(schemas.appendRequest, { ...bundleRequest, prev: undefined });
		const { prev: _, ...noPrev } = bundleRequest;
		no(schemas.appendRequest, noPrev);
		const { tokens: _t, ...start } = { ...noPrev, kind: "start", stage: 1, last: false };
		ok(schemas.appendRequest, { ...start, flow: { of: "client", id: "rp-1" } });
		no(schemas.appendRequest, { ...start, flow: { of: "client", id: "rp-1" }, prev: 0 });
	});

	it("holds a Core record to a sealed preimage and another writer's to its signed body", () => {
		no(schemas.appendRequest, { ...bundleRequest, signed: jws });
		const { preimage: _, ...unsealed } = bundleRequest;
		no(schemas.appendRequest, unsealed);
		const {
			id: _i,
			writer: _w,
			position: _po,
			shard: _sh,
			n: _n,
			acceptedAt: _a,
			...denial
		} = denialRecord;
		ok(schemas.appendRequest, { ...denial, prev: 5 });
		no(schemas.appendRequest, { ...denial, prev: 5, preimage: bundleRequest.preimage });
	});

	it("holds token digests to a bundle, a frame named once, and an abandonment to the op id it derives", () => {
		const { tokens: _, ...noTokens } = bundleRequest;
		no(schemas.appendRequest, noTokens);
		no(schemas.appendRequest, {
			...bundleRequest,
			tokens: [bundleRequest.tokens[0], bundleRequest.tokens[0]],
		});
		no(schemas.appendRequest, { ...bundleRequest, kind: "start" });
		const abandons = { op: "op-1", attempt: 1, digest: d("p") };
		const abandon = {
			...noTokens,
			kind: "abandonment",
			stage: 1,
			abandons,
			op: opIds.abandonment("op-1", 1),
		};
		ok(schemas.appendRequest, abandon);
		no(schemas.appendRequest, { ...abandon, op: "op-9" });
		no(schemas.appendRequest, { ...noTokens, kind: "start", abandons });
	});

	it("keeps a Core writer off a reset's and a stop's op ids, and an abandonment's op id to an abandonment", () => {
		for (const op of ["reset:A", "stop:1", opIds.reset("A".repeat(22)), opIds.stop(2)])
			no(schemas.appendRequest, { ...bundleRequest, op });
		no(schemas.appendRequest, { ...bundleRequest, op: "abandonment:1:o1" });
		ok(schemas.appendRequest, { ...bundleRequest, op: "resets:1" });
		expect(opIds.reset("abc")).toBe("reset:abc");
	});

	it("holds key change digests to a key change, and approval digests to an approval, each kind its own", () => {
		const { tokens: _, ...noTokens } = bundleRequest;
		const keyChange = { statement: d("p"), evidence: d("a") };
		const approval = { statement: d("t"), assertion: d("s"), code: d("c") };
		ok(schemas.appendRequest, { ...noTokens, kind: "keyChange", keyChange });
		ok(schemas.appendRequest, { ...noTokens, kind: "keyChange" });
		ok(schemas.appendRequest, { ...noTokens, kind: "approval", approval });
		no(schemas.appendRequest, { ...noTokens, kind: "approval", keyChange });
		no(schemas.appendRequest, { ...noTokens, kind: "keyChange", approval });
		no(schemas.appendRequest, { ...noTokens, kind: "keyChange", keyChange, approval });
		no(schemas.appendRequest, { ...noTokens, kind: "approval", keyChange, approval });
		no(schemas.appendRequest, { ...bundleRequest, keyChange });
		no(schemas.appendRequest, { ...noTokens, kind: "start", stage: 1, last: false, keyChange });
		no(schemas.appendRequest, {
			...noTokens,
			kind: "keyChange",
			keyChange: { ...keyChange, code: d("c") },
		});
		no(schemas.appendRequest, { ...noTokens, kind: "keyChange", keyChange: { statement: d("p") } });
	});

	it("holds evidence elements to a client's start, each a digest named once", () => {
		const { prev: _, tokens: _t, ...noPrev } = bundleRequest;
		const start = {
			...noPrev,
			kind: "start",
			stage: 1,
			last: false,
			flow: { of: "client", id: "rp-1" },
		};
		const elements = [d("x"), d("y")];
		ok(schemas.appendRequest, { ...start, elements });
		no(schemas.appendRequest, { ...start, elements: [] });
		no(schemas.appendRequest, { ...start, elements: [d("x"), d("x")] });
		no(schemas.appendRequest, { ...start, elements: ["short"] });
		no(schemas.appendRequest, { ...start, flow: subject, prev: 4, elements });
		no(schemas.appendRequest, { ...bundleRequest, flow: start.flow, prev: undefined, elements });
		const { prev: _q, preimage: _s, ...fields } = { ...start, prev: 0 };
		const record = { ...fields, ...placed, sealedTo: bundleRecord.sealedTo, keySetVersion: 2 };
		ok(schemas.record, { ...record, elements });
		no(schemas.record, { ...record, flow: subject, elements });
	});

	it("refuses a field it does not know, a kind the log writes, and malformed digests and positions", () => {
		no(schemas.appendRequest, { ...bundleRequest, extra: 1 });
		no(schemas.appendRequest, {
			...bundleRequest,
			preimage: [{ ...bundleRequest.preimage[0], tag: 1 }],
		});
		no(schemas.appendRequest, { ...bundleRequest, preimage: [] });
		no(schemas.appendRequest, {
			...bundleRequest,
			preimage: [bundleRequest.preimage[0], bundleRequest.preimage[0]],
		});
		no(schemas.appendRequest, { ...bundleRequest, kind: "tick" });
		no(schemas.appendRequest, { ...bundleRequest, plaintextDigest: "short" });
		no(schemas.appendRequest, { ...bundleRequest, prev: -1 });
		no(schemas.appendRequest, { ...bundleRequest, stage: 0 });
		no(schemas.appendRequest, { ...bundleRequest, v: 2 });
	});
});

describe("the log's answer to an append", () => {
	it("refuses an accepted answer whose record id is __proto__", () => {
		no(schemas.appendAnswer, {
			v: 1,
			result: "accepted",
			id: "__proto__",
			position: 5,
			shard: "s1",
			n: 17,
			acceptedAt: 1,
			receipts: [jws, jws, jws],
		});
	});

	it("accepts with the record's id, position, shard, sequence number, acceptance time and one receipt per token", () => {
		ok(schemas.appendAnswer, {
			v: 1,
			result: "accepted",
			id: "r-5",
			position: 5,
			shard: "s1",
			n: 17,
			acceptedAt: 1,
			receipts: [jws, jws, jws],
		});
		no(schemas.appendAnswer, {
			v: 1,
			result: "accepted",
			id: "r-5",
			position: 5,
			shard: "s1",
			n: 17,
			acceptedAt: 1,
			receipts: [],
		});
	});

	it("refuses by one word, with the shard's key set, where it has one, only on keyNotInSet", () => {
		for (const refusal of appendRefusals) {
			const answer = { v: 1, result: "refused", refusal };
			if (refusal === "keyNotInSet") {
				ok(schemas.appendAnswer, answer);
				ok(schemas.appendAnswer, {
					...answer,
					keySet: { v: 1, version: 2, keys: [{ kid: "mk-2", key: ecKey }] },
				});
			} else ok(schemas.appendAnswer, answer);
		}
		no(schemas.appendAnswer, {
			v: 1,
			result: "refused",
			refusal: "prevMismatch",
			keySet: { v: 1, version: 2, keys: [{ kid: "mk-2", key: ecKey }] },
		});
		no(schemas.appendAnswer, { v: 1, result: "refused", refusal: "busy" });
	});

	it("names every refusal kernel-spec KE-L02 names", () => {
		for (const word of [
			"prevMismatch",
			"sameIdOther",
			"temporary",
			"stopped",
			"lateBundle",
			"keyNotInSet",
			"holdLimit",
			"kindNotAllowed",
			"credInvalid",
			"abandoned",
			"evidenceUsed",
		]) {
			expect(appendRefusals).toContain(word);
		}
	});
});

describe("a committed record", () => {
	it("reads a Core record with its writer from the credential, the key-set version the log checked and the ciphertext hash", () => {
		ok(schemas.record, bundleRecord);
		no(schemas.record, { ...bundleRecord, keySetVersion: undefined });
		const { sealedTo: _, ...noHash } = bundleRecord;
		no(schemas.record, noHash);
		no(schemas.record, {
			...bundleRecord,
			sealedTo: [bundleRecord.sealedTo[0], bundleRecord.sealedTo[0]],
		});
	});

	it("reads another writer's record by its signed body, and the log's tick", () => {
		ok(schemas.record, denialRecord);
		ok(schemas.record, tick);
		no(schemas.record, { ...denialRecord, sealedTo: bundleRecord.sealedTo });
	});

	it("refuses a record whose id is __proto__: the state names its items by record ids, and a store refuses that key", () => {
		no(schemas.record, { ...bundleRecord, id: "__proto__" });
		no(schemas.record, { ...tick, id: "__proto__" });
		// A flow's id is no record's: a subject of that name is read.
		ok(schemas.record, { ...bundleRecord, flow: { of: "subject", id: "__proto__" } });
	});

	it("refuses a kind its writer may not write, and a field it does not know", () => {
		no(schemas.record, { ...denialRecord, writer: core });
		no(schemas.record, { ...bundleRecord, writer: { role: "monitor", key: "mon-1" } });
		no(schemas.record, { ...bundleRecord, extra: true });
		no(schemas.record, { ...tick, op: "x" });
		const { tokens: _tk, ...noTokens } = bundleRecord;
		const keyChange = { statement: d("p"), evidence: d("a") };
		const approval = { statement: d("t"), assertion: d("s"), code: d("c") };
		ok(schemas.record, { ...noTokens, kind: "keyChange", keyChange });
		no(schemas.record, { ...noTokens, kind: "approval", keyChange });
		no(schemas.record, { ...noTokens, kind: "keyChange", approval });
		no(schemas.record, { ...noTokens, kind: "keyChange", keyChange, approval });
		no(schemas.record, { ...noTokens, kind: "approval", keyChange, approval });
		no(schemas.record, { ...bundleRecord, keyChange });
		no(schemas.record, { ...tick, keyChange });
		const keySetRecord = { ...denialRecord, kind: "keySet", flow: { of: "monitor", id: "s1" } };
		ok(schemas.record, keySetRecord);
		no(schemas.record, { ...keySetRecord, flow: { of: "monitor", id: "s2" } });
		no(schemas.record, { ...bundleRecord, writer: { ...core, generation: 0 } });
	});
});

describe("receipts, judgments, checkpoints, status and stateOf", () => {
	it("reads a receipt per token, and one of an approval binding what the screen checks", () => {
		ok(schemas.receipt, receipt);
		no(schemas.receipt, { ...receipt, id: "__proto__" });
		const { token: _, ...approval } = { ...receipt, kind: "approval" };
		ok(schemas.receipt, {
			...approval,
			approval: { statement: d("t"), assertion: d("s"), code: d("c") },
		});
		no(schemas.receipt, { ...approval, token: receipt.token });
		const keyChange = { statement: d("p"), evidence: d("a") };
		ok(schemas.receipt, { ...approval, kind: "keyChange", keyChange });
		no(schemas.receipt, { ...approval, keyChange });
		no(schemas.receipt, { ...receipt, keyChange });
		no(schemas.receipt, {
			...approval,
			kind: "approval",
			keyChange,
			approval: { statement: d("t"), assertion: d("s"), code: d("c") },
		});
		no(schemas.receipt, {
			...approval,
			kind: "keyChange",
			approval: { statement: d("t"), assertion: d("s"), code: d("c") },
		});
		const { token: _t, ...bare } = receipt;
		no(schemas.receipt, bare);
		no(schemas.receipt, { ...receipt, token: { frame: "refreshToken", digest: d("r") } });
		no(schemas.receipt, { ...receipt, extra: 1 });
	});

	it("reads a judgment's verdict and outcome, and refuses other words", () => {
		const judgment = {
			v: 1,
			id: "r-5",
			flow: subject,
			position: 5,
			shard: "s1",
			n: 17,
			verdict: "verified",
			outcome: "took",
		};
		for (const verdict of judgments.verdicts) ok(schemas.judgment, { ...judgment, verdict });
		for (const outcome of judgments.outcomes) ok(schemas.judgment, { ...judgment, outcome });
		no(schemas.judgment, { ...judgment, verdict: "確かめた" });
		no(schemas.judgment, { ...judgment, id: "__proto__" });
		no(schemas.judgment, { ...judgment, reason: "J7" });
	});

	it("reads a checkpoint whose not-accepted ids are always there, even empty, with the forged among them and their generations", () => {
		const checkpoint = { v: 1, shard: "s1", watermark: 17, deny: [], counted: [], forged: [] };
		ok(schemas.checkpoint, checkpoint);
		const forged = { ...checkpoint, deny: ["r-1", "r-2"], forged: [{ id: "r-1", generation: 2 }] };
		ok(schemas.checkpoint, forged);
		no(schemas.checkpoint, { ...forged, forged: [{ id: "r-3", generation: 2 }] });
		no(schemas.checkpoint, { ...forged, forged: [forged.forged[0], forged.forged[0]] });
		no(schemas.checkpoint, { ...forged, forged: [{ id: "r-1", generation: 0 }] });
		const { forged: _f, ...noForged } = checkpoint;
		no(schemas.checkpoint, noForged);
		ok(schemas.checkpoint, { ...checkpoint, ext: { stage3: { at: 1 } } });
		no(schemas.checkpoint, { ...checkpoint, stage3: 1 });
		const { deny: _, ...noDeny } = checkpoint;
		no(schemas.checkpoint, noDeny);
		no(schemas.checkpoint, { ...checkpoint, deny: ["r-1", "r-1"] });
		no(schemas.checkpoint, { ...checkpoint, deny: ["__proto__"] });
		no(schemas.checkpoint, { ...checkpoint, counted: ["__proto__"] });
	});

	it("reads a status: its version, each shard's watermark and generation state, and ids alone", () => {
		const status = {
			v: 1,
			version: 4,
			shards: { s1: { watermark: 17, generation: 1, state: "running" } },
			deny: ["r-2"],
		};
		ok(schemas.status, status);
		no(schemas.status, { ...status, shards: { s1: { ...status.shards.s1, state: "paused" } } });
		no(schemas.status, { ...status, reasons: [{ id: "r-2", reason: "forged" }] });
		ok(schemas.status, { ...status, ext: { kmsCheckedTo: 3, later: "unknown" } });
		ok(schemas.statusReasons, { v: 1, version: 4, reasons: [{ id: "r-2", reason: "forged" }] });
		no(schemas.statusReasons, { v: 1, version: 4, reasons: [{ id: "r-2", reason: "lost" }] });
		no(schemas.status, { ...status, deny: ["__proto__"] });
		no(schemas.statusReasons, {
			v: 1,
			version: 4,
			reasons: [{ id: "__proto__", reason: "forged" }],
		});
	});

	it("reads stateOf: the flow, a position, the state, and each position's verdict and outcome", () => {
		const stateOf = {
			v: 1,
			flow: subject,
			position: 5,
			state: { families: [] },
			results: [
				{ position: 1, id: "r-1", verdict: "verified", outcome: "took" },
				{ position: 2, id: "r-2", verdict: "held", outcome: "didNotTake" },
			],
		};
		ok(schemas.stateOf, { ...stateOf, position: 2 });
		const [first, second] = stateOf.results;
		no(schemas.stateOf, {
			...stateOf,
			position: 2,
			results: [first, { ...second, id: "__proto__" }],
		});
		ok(schemas.stateOf, { ...stateOf, position: 0, results: [] });
		no(schemas.stateOf, stateOf);
		no(schemas.stateOf, {
			...stateOf,
			position: 2,
			results: [stateOf.results[1], stateOf.results[0]],
		});
		no(schemas.stateOf, {
			...stateOf,
			position: 2,
			results: [stateOf.results[0], stateOf.results[0]],
		});
	});
});

describe("the generation flow and the publisher's records", () => {
	it("reads a stop instruction, and a restart approval or the install approval", () => {
		ok(schemas.bodies.stopInstruction, { v: 1, installation: "inst-1", generation: 1 });
		const restart = {
			v: 1,
			installation: "inst-1",
			ringKey: d("k"),
			prev: 2,
			from: 1,
			evidence: d("e"),
		};
		ok(schemas.bodies.restartApproval, restart);
		ok(schemas.bodies.restartApproval, { v: 1, installation: "inst-1", ringKey: d("k") });
		no(schemas.bodies.restartApproval, { ...restart, evidence: undefined });
		no(schemas.bodies.restartApproval, { ...restart, extra: 1 });
	});

	it("reads the Core ring key record and a monitor key set", () => {
		ok(schemas.bodies.coreRingKey, { v: 1, kid: "ring-2", key: ecKey });
		ok(schemas.bodies.keySet, { v: 1, version: 2, keys: [{ kid: "mk-1", key: ecKey }] });
		no(schemas.bodies.keySet, {
			v: 1,
			version: 2,
			keys: [
				{ kid: "mk-1", key: ecKey },
				{ kid: "mk-1", key: ecKey },
			],
		});
	});

	it("holds a signer set to its required count, with stop by one and restart by two of three or more", () => {
		const key = (kid: string) => ({ kid, key: ecKey });
		ok(schemas.signerSet, {
			v: 1,
			version: 1,
			purpose: "stopInstruction",
			keys: [key("a")],
			required: 1,
		});
		no(schemas.signerSet, { v: 1, purpose: "stopInstruction", keys: [key("a")], required: 1 });
		no(schemas.signerSet, {
			v: 1,
			version: 1,
			purpose: "stopInstruction",
			keys: [key("a"), key("b")],
			required: 2,
		});
		ok(schemas.signerSet, {
			v: 1,
			version: 1,
			purpose: "restartApproval",
			keys: [key("a"), key("b"), key("c")],
			required: 2,
		});
		no(schemas.signerSet, {
			v: 1,
			version: 1,
			purpose: "restartApproval",
			keys: [key("a"), key("b")],
			required: 2,
		});
		ok(schemas.signerSet, {
			v: 1,
			version: 1,
			purpose: "stateOf",
			keys: [key("a"), key("b")],
			required: 2,
		});
		no(schemas.signerSet, { v: 1, version: 1, purpose: "stateOf", keys: [key("a")], required: 2 });
		no(schemas.signerSet, {
			v: 1,
			version: 1,
			purpose: "stateOf",
			keys: [key("a"), key("a")],
			required: 1,
		});
		expect(signers.restartApproval).toEqual({ required: 2, least: 3 });
		expect(signers.resetInstruction).toEqual({ required: 1, least: 1 });
		ok(schemas.signerSet, {
			v: 1,
			version: 1,
			purpose: "resetInstruction",
			keys: [key("a")],
			required: 1,
		});
		no(schemas.signerSet, {
			v: 1,
			version: 1,
			purpose: "resetInstruction",
			keys: [key("a"), key("b")],
			required: 2,
		});
	});

	it("reads a preimage: the root it names, its parent and the evidence bundle", () => {
		ok(schemas.preimage, {
			v: 1,
			root: "r-1",
			parent: "r-4",
			evidence: [{ form: "token", value: "eyJ" }],
			content: { family: "f-1" },
		});
		no(schemas.preimage, { v: 1, evidence: [{ form: "photo", value: "x" }], content: {} });
		for (const form of ["continuation", "completion"]) {
			ok(schemas.preimage, { v: 1, evidence: [{ form, value: "eyJ" }], content: {} });
		}
		no(schemas.preimage, {
			v: 1,
			evidence: [{ form: "resetInstruction", value: "eyJ" }],
			content: {},
		});
	});
});

describe("a record no Core writer writes, read with its verified body", () => {
	const boundary = {
		...denialRecord,
		kind: "erasureBoundary",
		op: "erase-1",
	};
	const body = { v: 1, flow: subject, op: "erase-1", prev: 5 };

	it("binds an erasure boundary's and a tombstone's body to the envelope's flow, op and previous position", () => {
		ok(schemas.signedRecord, { record: boundary, body });
		ok(schemas.signedRecord, { record: { ...boundary, kind: "tombstone" }, body });
		no(schemas.signedRecord, {
			record: boundary,
			body: { ...body, flow: { of: "subject", id: "sub-2" } },
		});
		no(schemas.signedRecord, { record: boundary, body: { ...body, op: "erase-2" } });
		no(schemas.signedRecord, { record: boundary, body: { ...body, prev: 4 } });
		no(schemas.signedRecord, { record: boundary, body: { v: 1 } });
	});

	it("binds a reset boundary's body to the envelope, its op derived from its instruction's id", () => {
		const b64 = (text: string) => Buffer.from(text).toString("base64url");
		const jws = (payload: string) => `${b64('{"alg":"ES256"}')}.${b64(payload)}.c2ln`;
		const instruction = jws(JSON.stringify({ subject: "sub-1", id: "A".repeat(22) }));
		const reset = { ...denialRecord, kind: "resetBoundary", op: opIds.reset("A".repeat(22)) };
		const resetBody = { v: 1, flow: subject, op: reset.op, prev: 5, set: 1, instruction };
		ok(schemas.signedRecord, { record: reset, body: resetBody });
		no(schemas.signedRecord, {
			record: { ...reset, op: "reset:B" },
			body: { ...resetBody, op: "reset:B" },
		});
		no(schemas.signedRecord, { record: reset, body: { ...resetBody, prev: 4 } });
		for (const envelope of [{ stage: 2 }, { last: false }, { flow: { of: "client", id: "sub-1" } }])
			no(schemas.signedRecord, { record: { ...reset, ...envelope }, body: resetBody });
		no(schemas.signedRecord, { record: reset, body: { ...resetBody, set: 0 } });
		no(schemas.signedRecord, { record: reset, body: { ...resetBody, instruction: "a.b" } });
		const { set: _, ...noSet } = resetBody;
		no(schemas.signedRecord, { record: reset, body: noSet });
		for (const payload of ['{"id":1}', "{}", "[]", "not json", '{"id":"A","id":"B"}'])
			no(schemas.signedRecord, {
				record: { ...reset, op: "reset:A" },
				body: { ...resetBody, op: "reset:A", instruction: jws(payload) },
			});
		const bad = `${b64("{}")}.${Buffer.from([0x7b, 0x22, 0xc0, 0x80, 0x22, 0x7d]).toString("base64url")}.c2ln`;
		no(schemas.signedRecord, { record: reset, body: { ...resetBody, instruction: bad } });
		const multi = jws(JSON.stringify({ subject: "主体", id: "A".repeat(22) }));
		ok(schemas.signedRecord, { record: reset, body: { ...resetBody, instruction: multi } });
		expect(recordKinds.monitor).toContain("resetBoundary");
		expect([logTyps.resetBoundary, logTyps.resetInstruction]).toEqual([
			"reset-boundary+jwt",
			"reset-instruction+jwt",
		]);
	});

	it("holds every other body to its kind's schema, a stop to its derived op id and a restart to its position", () => {
		ok(schemas.signedRecord, { record: denialRecord, body: { v: 1, registration: "r-1" } });
		no(schemas.signedRecord, { record: denialRecord, body: { v: 1, registration: "r-1", x: 1 } });
		const gen = { of: "generation", id: "inst-1" } as const;
		const stop = {
			...denialRecord,
			writer: { role: "human", keys: ["h-1"] },
			kind: "stopInstruction",
			flow: gen,
			op: opIds.stop(1),
		};
		ok(schemas.signedRecord, {
			record: stop,
			body: { v: 1, installation: "inst-1", generation: 1 },
		});
		no(schemas.signedRecord, {
			record: stop,
			body: { v: 1, installation: "inst-1", generation: 2 },
		});
		const restart = { ...stop, kind: "restartApproval", op: "restart-1", position: 3 };
		const approval = {
			v: 1,
			installation: "inst-1",
			ringKey: d("k"),
			prev: 2,
			from: 1,
			evidence: d("e"),
		};
		ok(schemas.signedRecord, { record: restart, body: approval });
		no(schemas.signedRecord, { record: restart, body: { ...approval, prev: 1 } });
		no(schemas.signedRecord, { record: bundleRecord, body: {} });
	});
});

describe("the builders", () => {
	it("derives a stop's op id from the generation it names, and an abandonment's from the op and attempt, each one way", () => {
		expect(opIds.stop(2)).not.toBe(opIds.stop(3));
		expect(opIds.abandonment("a", 1)).not.toBe(opIds.abandonment("a", 2));
		expect(opIds.abandonment("a:1", 1)).not.toBe(opIds.abandonment("a", 11));
	});

	it("builds a token's digest input from its texts without its receipt claim, the same whatever the key order", () => {
		const one = tokens.digestInput(
			'{"alg":"ES256","typ":"JWT"}',
			`{"sub":"s","aud":"a","txr":"${jws}"}`,
		);
		const two = tokens.digestInput('{ "typ": "JWT", "alg": "ES256" }', '{"aud":"a","sub":"s"}');
		expect("input" in one && one.input).toBe("input" in two && two.input);
		expect(JSON.stringify(one)).not.toContain(jws);
	});

	it("refuses a token text with a key named twice at any depth, a number it cannot hold, or no object", () => {
		const header = '{"alg":"ES256"}';
		for (const claims of [
			'{"sub":"a","sub":"b"}',
			'{"sub":"a","\\u0073ub":"b"}',
			'{"x":{"k":1,"y":[{"k":1,"k":2}]}}',
			'{"n":1e400}',
			'["sub"]',
			'{"sub":',
		]) {
			expect("error" in tokens.digestInput(header, claims), claims).toBe(true);
		}
		expect("error" in tokens.digestInput('{"alg":"a","alg":"b"}', "{}")).toBe(true);
	});

	it("reads keys inside strings and escapes as text, not as keys", () => {
		for (const text of [
			'{"a":"\\"a\\":1,","b":"{\\"a\\":2}"}',
			'{"a\\\\":1,"a":2}',
			'{"a":{"b":1},"b":{"a":1}}',
			'{"q":"}","a":1,"r":"{","s":"\\\\"}',
		]) {
			const read = tokens.parse(text);
			expect("value" in read, text).toBe(true);
		}
		expect(tokens.parse('{"a":"x","a":"x"}')).toEqual({ error: "duplicate_key:a" });
	});

	it("binds a sealed preimage to its flow, op and stage", () => {
		expect(sealing.aad(subject, "op-1", 1)).not.toBe(sealing.aad(subject, "op-1", 2));
		expect(sealing.aad(subject, "op-1", 1)).not.toBe(
			sealing.aad({ of: "client", id: "sub-1" }, "op-1", 1),
		);
	});
});

describe("the words", () => {
	const all = (x: unknown): unknown[] =>
		Array.isArray(x)
			? x.flatMap(all)
			: x && typeof x === "object"
				? Object.values(x).flatMap(all)
				: [x];

	it("speaks wire version 1, and names each word once", () => {
		expect(speaks).toEqual([1]);
		const kindWords = all(recordKinds);
		expect(new Set(kindWords).size).toBe(kindWords.length);
		for (const list of [
			appendRefusals,
			judgments.verdicts,
			judgments.outcomes,
			statusWords.shardStates,
			statusWords.denyReasons,
			tokens.frames,
			flows.units,
		]) {
			expect(new Set(list).size).toBe(list.length);
		}
		const typWords = Object.values(logTyps);
		expect(new Set(typWords).size).toBe(typWords.length);
		for (const typ of typWords) expect(typ).toMatch(/^[a-z-]+(\+jwt)?$/);
		expect(logTyps.stopInstruction).not.toMatch(/\+jwt$/);
		expect(logTyps.restartApproval).not.toMatch(/\+jwt$/);
	});

	it("holds every constant frozen", () => {
		const frozen = (x: unknown, path: string): void => {
			if (!x || typeof x !== "object" || "safeParse" in x) return;
			expect(Object.isFrozen(x), path).toBe(true);
			for (const [k, v] of Object.entries(x)) frozen(v, `${path}.${k}`);
		};
		const values = {
			speaks,
			logTyps,
			recordKinds,
			flows,
			appendRefusals,
			judgments,
			statusWords,
			tokens,
			sealing,
			signers,
			opIds,
			schemas,
		};
		for (const [name, value] of Object.entries(values)) frozen(value, name);
		expect(Object.isFrozen(schemas.bodies)).toBe(true);
	});

	it("names a typ for every signed object, the generation flow's two kinds among them", () => {
		for (const name of [
			"receipt",
			"judgment",
			"checkpoint",
			"status",
			"statusReasons",
			"stateOf",
			"stopInstruction",
			"restartApproval",
			"coreRingKey",
			"keySet",
			"signerSet",
		]) {
			expect(logTyps).toHaveProperty(name);
		}
		expect(recordKinds.human).toEqual(["stopInstruction", "restartApproval"]);
		expect(flows.unconditional).toEqual(["client"]);
	});
});
