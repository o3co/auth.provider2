import { createHash, createPublicKey, generateKeyPairSync, randomBytes, verify } from "node:crypto";
import { passkeyGenerations } from "@mod/passkeys";
import { challengeInput } from "@mod/sdk-core-wire";
import type { Contact } from "@mod/users";
import type { Credential } from "@mod/webauthn";
import { softwareAuthenticator, testOrigin } from "@mod/webauthn/testing";
import { describe, expect, it } from "vitest";
import { type CreationAsk, creationOver } from "../../creation/creation.ts";
import { screen, sha256, stack } from "../../registration/test/stack.ts";
import { approvalOver } from "../approval.ts";

/** An RS256 key's COSE_Key, base64url, as a passkey of one holds it: CTAP2's canonical form (kty 3, alg -257, n, e). */
const rs256 = (() => {
	const jwk = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({
		format: "jwk",
	});
	const n = Buffer.from(jwk.n ?? "", "base64url");
	const e = Buffer.from(jwk.e ?? "", "base64url");
	const head = Buffer.from("a401030339010020590100", "hex");
	return Buffer.concat([head, n, Buffer.from([0x21, 0x40 + e.length]), e]).toString("base64url");
})();

const payloadOf = (jws: string) =>
	JSON.parse(Buffer.from(jws.split(".")[1] ?? "", "base64url").toString("utf8"));

/** A subject `s1` holding one key, made through its first key's path; and a passkey-add's approval over it. */
async function world(
	contacts: readonly Contact[] = [{ kind: "email", value: "alice@example.com" }],
	passkeys?: Record<string, unknown>,
) {
	const w = await stack(passkeys ? { passkeys } : {});
	const auth = softwareAuthenticator();
	const c = await w.created();
	const registered = await w.registration.register(w.continued(c, w.made(c, auth)));
	if (registered.kind !== "possession") throw new Error(registered.kind);
	const items = payloadOf(registered.statement).possession;
	const pending = (await w.parts.held.of("s1")).pending;
	if (!pending) throw new Error("none pending");
	const key: Credential = {
		id: items.credential_id,
		publicKey: pending.publicKey,
		signCount: 0,
		userHandle: c.handle,
		backupEligible: false,
		backedUp: false,
	};
	const assertion = w.asserted(registered.statement, key, auth);
	const finished = await w.registration.finish({ statement: registered.statement, assertion });
	if (finished.kind !== "completed") throw new Error(finished.kind);
	const asked: CreationAsk[] = [];
	let full = false;
	const create = creationOver({
		approvals: w.parts.approvals,
		ceremonies: w.parts.ceremonies,
		held: {
			of: async (subject) => ({
				...(await w.parts.held.of(subject)),
				...(full ? { full: true as const } : {}),
			}),
		},
		generations: await w.app.get(passkeyGenerations),
		revocation: w.parts.revocation,
		random: (n) => randomBytes(n),
	});
	let publicKeyOf = w.parts.passkeys.publicKeyOf;
	/** Each passkey-add's record and contacts asked for, as an RS256 refusal must ask neither. */
	const reads = { passkeyAddOf: 0, contactsOf: 0 };
	const approval = approvalOver({
		approvals: {
			...w.parts.approvals,
			passkeyAddOf: (hash) => {
				reads.passkeyAddOf += 1;
				return w.parts.approvals.passkeyAddOf(hash);
			},
		},
		passkeys: { publicKeyOf: (id) => publicKeyOf(id) },
		users: {
			contactsOf: async () => {
				reads.contactsOf += 1;
				return contacts;
			},
		},
		create: async (ask) => {
			asked.push(ask);
			return create(ask);
		},
	});
	/** The approving key's assertion over a statement, as the screen's `get()` answers it. */
	const approve = (statement: string) => {
		const options = w.parts.ceremonies.request(
			sha256(challengeInput(statement, "get")),
			[],
			"required",
		);
		return JSON.stringify(auth.get(options as never, { origin: testOrigin }, {}, key.id));
	};
	const started = async () => {
		const s = await approval.start({ purpose: "passkey-add", screen: screen().keys, by: "src" });
		if (s.kind !== "statement") throw new Error(s.reason);
		return s.statement;
	};
	return {
		w,
		key,
		approval,
		asked,
		reads,
		approve,
		started,
		replaceKeyLookup: (f: typeof publicKeyOf) => {
			publicKeyOf = f;
		},
		/** The subject read as holding the most keys it may, or not. */
		fill: (on: boolean) => {
			full = on;
		},
	};
}

describe("a passkey-add's or a passkey-manage's approval", () => {
	it("signs a passkey-add or a passkey-manage for the screen", async () => {
		const { approval } = await world();
		for (const purpose of ["passkey-add", "passkey-manage"] as const) {
			const started = await approval.start({ purpose, screen: screen().keys, by: "src" });
			if (started.kind !== "statement") throw new Error(started.reason);
			expect(payloadOf(started.statement)).toMatchObject({ purpose });
		}
	});

	it("completes a passkey-manage by the approving key with its subject's keys, kept and answered alike", async () => {
		const { approval, approve, asked, w, key, replaceKeyLookup } = await world();
		const started = await approval.start({
			purpose: "passkey-manage",
			screen: screen().keys,
			by: "src",
		});
		if (started.kind !== "statement") throw new Error(started.reason);
		const assertion = approve(started.statement);
		const finished = await approval.finish({ statement: started.statement, assertion });
		expect(finished).toMatchObject({ kind: "completed", enc: expect.any(String) });
		// No creation is made for it; asked again, past its life, the one kept.
		expect(asked).toEqual([]);
		w.advance(5 * 60_000 + 1000);
		expect(await approval.finish({ statement: started.statement, assertion })).toEqual(finished);
		// One whose approving key is gone since it was used is answered no list.
		const other = await approval.start({
			purpose: "passkey-manage",
			screen: screen().keys,
			by: "src",
		});
		if (other.kind !== "statement") throw new Error(other.reason);
		replaceKeyLookup(async (id) => (id === key.id ? undefined : w.parts.passkeys.publicKeyOf(id)));
		expect(
			await approval.finish({ statement: other.statement, assertion: approve(other.statement) }),
		).toEqual({
			kind: "refused",
			reason: "approver",
		});
	});

	it("completes it by the approving key with the creation it bases, for that key's subject", async () => {
		const { approval, asked, approve, started, w } = await world();
		const statement = await started();
		const assertion = approve(statement);
		const finished = await approval.finish({ statement, assertion });
		expect(finished).toMatchObject({ kind: "completed", enc: expect.any(String) });
		const hash = sha256(statement);
		const ask = asked[0];
		if (ask?.basis !== "passkey-add") throw new Error("no passkey-add's creation asked");
		const approving = ask.approverKey;
		// The key named is the one the approval's assertion verifies under, checked apart from how the
		// Core reads it: its signature over the authenticator data and the client data's SHA-256.
		const { response } = JSON.parse(assertion);
		const signed = Buffer.concat([
			Buffer.from(response.authenticatorData, "base64url"),
			createHash("sha256").update(Buffer.from(response.clientDataJSON, "base64url")).digest(),
		]);
		const jwk: Record<string, string> = { kty: approving.kty, crv: approving.crv, x: approving.x };
		if (approving.y !== undefined) jwk.y = approving.y;
		const named = createPublicKey({ key: jwk, format: "jwk" });
		expect(verify("sha256", signed, named, Buffer.from(response.signature, "base64url"))).toBe(
			true,
		);
		expect(asked).toEqual([
			expect.objectContaining({
				subject: "s1",
				account: "a***@example.com",
				basis: "passkey-add",
				// The approving key, as its JWK (V30): the record's parent, the screen's own key.
				approverKey: approving,
				evidence: hash,
				screen: expect.objectContaining({ eEnc: payloadOf(statement).e_enc }),
			}),
		]);
		// Asked again, even past the statement's life, the one kept is answered, no creation made again.
		w.advance(5 * 60_000 + 1000);
		expect(await approval.finish({ statement, assertion })).toEqual(finished);
		expect(asked).toHaveLength(1);
	});

	it("bases no creation on an RS256 approving key, or one that does not read (V30)", async () => {
		const { approval, asked, reads, approve, started, w, key, replaceKeyLookup } = await world();
		const as = (publicKey: string) => async (id: string) => {
			const held = await w.parts.passkeys.publicKeyOf(id);
			return held && id === key.id ? { ...held, publicKey } : held;
		};
		replaceKeyLookup(as(rs256));
		const one = await started();
		expect(await approval.finish({ statement: one, assertion: approve(one) })).toEqual({
			kind: "refused",
			reason: "approver-algorithm",
		});
		// Refused before the passkey-add's record or the subject's contacts are read.
		expect(reads).toEqual({ passkeyAddOf: 0, contactsOf: 0 });
		replaceKeyLookup(as("AAAA"));
		const two = await started();
		expect(await approval.finish({ statement: two, assertion: approve(two) })).toEqual({
			kind: "refused",
			reason: "approver",
		});
		expect(asked).toEqual([]);
	});

	it("checks the approving key before every list made: a finish sent again, or after one that fell, is refused alike", async () => {
		const { approval, approve, w, key, replaceKeyLookup } = await world();
		const gone = async (id: string) =>
			id === key.id ? undefined : w.parts.passkeys.publicKeyOf(id);
		const start = async () => {
			const s = await approval.start({
				purpose: "passkey-manage",
				screen: screen().keys,
				by: "src",
			});
			if (s.kind !== "statement") throw new Error(s.reason);
			return { statement: s.statement, assertion: approve(s.statement) };
		};
		// Refused `approver`, then the same finish again.
		const one = await start();
		replaceKeyLookup(gone);
		expect(await approval.finish(one)).toEqual({ kind: "refused", reason: "approver" });
		expect(await approval.finish(one)).toEqual({ kind: "refused", reason: "approver" });
		// No list was kept for it.
		const hash = sha256(one.statement);
		expect(
			await w.parts.approvals.completePasskeyManage({ hash, assertion: one.assertion }),
		).toEqual({ kind: "refused", reason: "unknown" });
		// Used by a finish that fell before its list, its key gone since.
		replaceKeyLookup(w.parts.passkeys.publicKeyOf);
		const two = await start();
		await w.parts.approvals.use(two);
		replaceKeyLookup(gone);
		expect(await approval.finish(two)).toEqual({ kind: "refused", reason: "approver" });
		replaceKeyLookup(w.parts.passkeys.publicKeyOf);
		expect(await approval.finish(two)).toMatchObject({ kind: "completed" });
	});

	it("bases no creation for a subject holding the most keys it may, and one once it holds fewer", async () => {
		const { approval, approve, started, fill } = await world();
		const statement = await started();
		const assertion = approve(statement);
		fill(true);
		expect(await approval.finish({ statement, assertion })).toEqual({
			kind: "refused",
			reason: "full",
		});
		fill(false);
		expect(await approval.finish({ statement, assertion })).toMatchObject({ kind: "completed" });
	});

	it("reads the subject full from its keys as passkeys holds them", async () => {
		const { approval, approve, started, asked } = await world(undefined, { "max-credentials": 1 });
		const statement = await started();
		expect(await approval.finish({ statement, assertion: approve(statement) })).toEqual({
			kind: "refused",
			reason: "full",
		});
		expect(asked).toHaveLength(1);
	});

	it("answers two finishes at once alike, and completes one used before with nothing kept", async () => {
		const { approval, approve, started, w } = await world();
		const statement = await started();
		const assertion = approve(statement);
		const [one, two] = await Promise.all([
			approval.finish({ statement, assertion }),
			approval.finish({ statement, assertion }),
		]);
		expect(one).toMatchObject({ kind: "completed" });
		expect(two).toEqual(one);
		// Used already, by this assertion, its completion not kept: completed by the finish that follows.
		const later = await started();
		const shown = approve(later);
		await w.parts.approvals.use({ statement: later, assertion: shown });
		expect(await approval.finish({ statement: later, assertion: shown })).toMatchObject({
			kind: "completed",
		});
	});

	it("refuses a used statement sent with another assertion", async () => {
		const { approval, approve, started } = await world();
		const statement = await started();
		await approval.finish({ statement, assertion: approve(statement) });
		expect(await approval.finish({ statement, assertion: approve(statement) })).toEqual({
			kind: "refused",
			reason: "assertion",
		});
	});

	it("asks a creation of an account no address names with no account, the creation naming it", async () => {
		const { approval, asked, approve, started } = await world([]);
		const statement = await started();
		await approval.finish({ statement, assertion: approve(statement) });
		expect(asked[0]).toMatchObject({ basis: "passkey-add", subject: "s1" });
		expect(asked[0]).not.toHaveProperty("account");
	});

	it("bases no creation on a statement of another purpose sent here, and uses it not", async () => {
		const { approval, approve, asked, w } = await world();
		const other = await w.created();
		expect(
			await approval.finish({ statement: other.statement, assertion: approve(other.statement) }),
		).toEqual({ kind: "refused", reason: "purpose" });
		expect(await w.parts.approvals.usedOf(other.hash)).toBeUndefined();
		expect(asked).toEqual([]);
	});

	it("bases none on a key removed since it approved, or registered again", async () => {
		const { approval, approve, asked, started, replaceKeyLookup, key } = await world();
		const statement = await started();
		replaceKeyLookup(async (id) =>
			id === key.id
				? { subject: "s1", publicKey: key.publicKey, registration: "later" }
				: undefined,
		);
		expect(await approval.finish({ statement, assertion: approve(statement) })).toEqual({
			kind: "refused",
			reason: "approver",
		});
		expect(asked).toEqual([]);
	});

	it("bases none on a statement used past its life", async () => {
		const { approval, approve, started, w } = await world();
		const statement = await started();
		const assertion = approve(statement);
		w.advance(5 * 60_000 + 1000);
		expect(await approval.finish({ statement, assertion })).toEqual({
			kind: "refused",
			reason: "expired",
		});
	});
});

describe("a passkey-add's finish, over approvals as it answers", () => {
	it("stops at the completion's `purpose` for an authorization's statement, using it never", async () => {
		const called: string[] = [];
		const refusing = async () => {
			called.push("completePasskeyAdd");
			return { kind: "refused", reason: "purpose" } as const;
		};
		const approval = approvalOver({
			approvals: {
				issue: async () => {
					throw new Error("not asked");
				},
				use: async () => {
					called.push("use");
					throw new Error("not asked");
				},
				passkeyAddOf: async () => undefined,
				completePasskeyAdd: refusing,
				completePasskeyManage: async () => {
					throw new Error("not asked");
				},
			},
			passkeys: { publicKeyOf: async () => undefined },
			users: { contactsOf: async () => [] },
			create: async () => {
				throw new Error("not asked");
			},
		});
		expect(await approval.finish({ statement: "t.of.authorization", assertion: "{}" })).toEqual({
			kind: "refused",
			reason: "purpose",
		});
		expect(called).toEqual(["completePasskeyAdd"]);
	});
});
