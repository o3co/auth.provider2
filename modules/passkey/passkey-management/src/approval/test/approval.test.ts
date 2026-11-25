import { randomBytes } from "node:crypto";
import { passkeyGenerations } from "@mod/passkeys";
import { challengeInput } from "@mod/sdk-core-wire";
import type { Contact } from "@mod/users";
import type { Credential } from "@mod/webauthn";
import { softwareAuthenticator, testOrigin } from "@mod/webauthn/testing";
import { describe, expect, it } from "vitest";
import { type CreationAsk, creationOver } from "../../creation/creation.ts";
import { screen, sha256, stack } from "../../registration/test/stack.ts";
import { approvalOver } from "../approval.ts";

const payloadOf = (jws: string) =>
	JSON.parse(Buffer.from(jws.split(".")[1] ?? "", "base64url").toString("utf8"));

/** A subject `s1` holding one key, made through its first key's path; and a passkey-add's approval over it. */
async function world(
	contacts: readonly Contact[] = [{ kind: "email", value: "alice@example.com" }],
) {
	const w = await stack();
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
	const create = creationOver({
		approvals: w.parts.approvals,
		ceremonies: w.parts.ceremonies,
		held: w.parts.held,
		generations: await w.app.get(passkeyGenerations),
		revocation: w.parts.revocation,
		random: (n) => randomBytes(n),
	});
	let publicKeyOf = w.parts.passkeys.publicKeyOf;
	const approval = approvalOver({
		approvals: w.parts.approvals,
		passkeys: { publicKeyOf: (id) => publicKeyOf(id) },
		users: { contactsOf: async () => contacts },
		create: async (ask) => {
			asked.push(ask);
			return create(ask);
		},
		deployment: "Example",
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
		approve,
		started,
		replaceKeyLookup: (f: typeof publicKeyOf) => {
			publicKeyOf = f;
		},
	};
}

describe("a passkey-add's approval", () => {
	it("signs a passkey-add for the screen, and no passkey-manage yet", async () => {
		const { approval } = await world();
		const started = await approval.start({
			purpose: "passkey-add",
			screen: screen().keys,
			by: "src",
		});
		if (started.kind !== "statement") throw new Error(started.reason);
		expect(payloadOf(started.statement)).toMatchObject({ purpose: "passkey-add" });
		expect(
			await approval.start({ purpose: "passkey-manage", screen: screen().keys, by: "src" }),
		).toEqual({ kind: "refused", reason: "purpose" });
	});

	it("completes it by the approving key with the creation it bases, for that key's subject", async () => {
		const { approval, asked, approve, started, w } = await world();
		const statement = await started();
		const assertion = approve(statement);
		const finished = await approval.finish({ statement, assertion });
		expect(finished).toMatchObject({ kind: "completed", enc: expect.any(String) });
		const hash = sha256(statement);
		expect(asked).toEqual([
			expect.objectContaining({
				subject: "s1",
				account: "a***@example.com",
				basis: "passkey-add",
				evidence: hash,
				screen: expect.objectContaining({ eEnc: payloadOf(statement).e_enc }),
			}),
		]);
		// Asked again, even past the statement's life, the one kept is answered, no creation made again.
		w.advance(5 * 60_000 + 1000);
		expect(await approval.finish({ statement, assertion })).toEqual(finished);
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

	it("names an account no address names in `userName`, by the deployment and a mark of its subject", async () => {
		const { approval, asked, approve, started } = await world([]);
		const statement = await started();
		await approval.finish({ statement, assertion: approve(statement) });
		expect(asked[0]).toMatchObject({ userName: expect.stringMatching(/^Example [0-9a-f]{6}$/) });
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
			},
			passkeys: { publicKeyOf: async () => undefined },
			users: { contactsOf: async () => [] },
			create: async () => {
				throw new Error("not asked");
			},
			deployment: "Example",
		});
		expect(await approval.finish({ statement: "t.of.authorization", assertion: "{}" })).toEqual({
			kind: "refused",
			reason: "purpose",
		});
		expect(called).toEqual(["completePasskeyAdd"]);
	});
});
