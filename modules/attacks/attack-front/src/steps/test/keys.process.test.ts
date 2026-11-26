import { answers, challengeOf, management, screenKeys } from "@sdk/login-screen";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readyWithinMs } from "../../../test/core/launch.ts";
import { browser } from "../../../test/roles/browser.ts";
import { stopped } from "../../../test/roles/screen.ts";
import { resealedDelete, thiefBody, thiefSealer } from "./thief.ts";
import { origin, screenOrigin, type World, world } from "./world.ts";

// The compromised Front's steps on a person's keys (the design note's §2): passkey-add, passkey-manage.

let w: World;
beforeAll(async () => {
	w = await world(["rp-keys"]);
}, readyWithinMs + 10_000);
afterAll(async () => {
	await w?.stop();
});

describe("a person's keys through an honest Front", () => {
	it("adds a key approved by one held, deletes the first by the second, and keeps the last", async () => {
		const person = await w.person();
		const front = await w.front();
		// The new key on the person's other device, whose screen approves with it after.
		const device = browser(screenOrigin);
		const added = await person.screen.addKey(front, person.credential, device);
		if (stopped(added)) throw new Error(`add: ${JSON.stringify(added)}`);
		const other = w.screenOf(device);
		const deleted = await other.deleteKey(front, added.credential, person.credential);
		expect(deleted).toEqual({ deleted: true });
		const last = await other.deleteKey(front, added.credential, added.credential);
		expect(last).toMatchObject({ kept: { refused: "last" } });
	});
});

/** The reasons the Core's log gives its stage refusals, `access_denied` alone on the wire. */
const refusalsLogged = () =>
	w.core
		.lines()
		.filter((line) => line.event === "passkey-management.continue_refused")
		.map((line) => `${line.fields.stage}:${line.fields.reason}`);
/** The stage refusals the Core logs while `step` runs, waited for as the log comes apart from the wire. */
async function loggedDuring(step: () => Promise<unknown>, count: number) {
	const before = refusalsLogged().length;
	await step();
	await w.core.lineWhere(() => refusalsLogged().length >= before + count);
	return refusalsLogged().slice(before);
}

describe("the compromised Front on a person's keys", () => {
	/** A person with a second key on another device, and that device's screen. */
	const twoKeys = async () => {
		const person = await w.person();
		const device = browser(screenOrigin);
		const honest = await w.front();
		const added = await person.screen.addKey(honest, person.credential, device);
		if (stopped(added)) throw new Error(`add: ${JSON.stringify(added)}`);
		return { person, device, other: w.screenOf(device), second: added.credential };
	};

	it("F-16: passkey-add's register stage given another key is refused by the Core (the screen's E_sig covers the body)", async () => {
		const person = await w.person();
		const front = await w.front();
		const thief = browser(screenOrigin);
		// The Front puts a credential of its own into the register stage, the screen's signature kept.
		front.rewrite({
			messages: {
				continue: async (message) =>
					message.stage === 0
						? { ...message, body: await thiefBody(thief, message.statement) }
						: message,
			},
		});
		let added: unknown;
		const logged = await loggedDuring(async () => {
			added = await person.screen.addKey(front, person.credential, browser(screenOrigin));
		}, 1);
		expect(added).toMatchObject({
			stopped: "core",
			at: "/continue register",
			answered: { body: { error: "access_denied" } },
		});
		// Its reason, the Core's log alone: the screen's signature, not over this body.
		expect(logged).toEqual(["register:signature"]);
	});

	it("F-16b: passkey-add's completion swapped for the Front's own approval's, sealed to this screen's key, fails to open: its additional data is the statement's hash", async () => {
		const person = await w.person();
		// The Front's own account: a person of its own, with a passkey of its own.
		const own = await w.person();
		const front = await w.front();
		const elsewhere = await w.front();
		const keys = await screenKeys();
		let theirs: { statement: string; assertion: string; body: unknown } | undefined;
		front.rewrite({
			messages: {
				// As the screen's start goes by, the Front starts an approval of its own naming the screen's
				// public keys (all the wire shows of them), and approves it with its own passkey.
				approvalStart: async (message) => {
					const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
					const started = await elsewhere.post({
						path: "/approval/start",
						body: {
							purpose: "passkey-add",
							eEnc: b64(message.eEnc),
							eSigX: b64(message.eSigX),
							eSigY: b64(message.eSigY),
						},
					});
					const statement = answers.read("statement", started.body) ?? "";
					const assertion = own.browser.get({
						challenge: await challengeOf(statement, "get"),
						rpId: new URL(screenOrigin).hostname,
						allowCredentials: [
							{ type: "public-key", id: Buffer.from(own.credential, "base64url") },
						],
						userVerification: "required",
					});
					const finished = await elsewhere.post({
						path: "/approval/finish",
						body: { statement, assertion },
					});
					theirs = { statement, assertion, body: finished.body };
					return message;
				},
			},
			replies: {
				approvalFinish: (reply) => {
					const swapped = elsewhere.seen().findLast((r) => r.kind === "approvalFinish")?.reply;
					return swapped ?? reply;
				},
			},
		});
		const approved = await person.screen.approveManagement(
			front,
			"passkey-add",
			person.credential,
			keys,
		);
		expect(approved).toMatchObject({ stopped: "sdk", at: "management.finish", error: "open" });
		// The control: the completion swapped in is sealed to this screen's key, and opens under the
		// hash of the statement it completes. Only the additional data's hash told the two apart.
		if (theirs === undefined) throw new Error("no completion of the Front's own");
		const sdk = { ring: w.core.ring, issuer: origin };
		const read = await management.read(theirs.statement, { ...sdk, keys, purpose: "passkey-add" });
		if ("error" in read) throw new Error(read.error);
		const sealed = answers.read("sealed", theirs.body);
		if (sealed === undefined) throw new Error("no sealed completion");
		const done = await management.finish(read.manage, sealed, {
			...sdk,
			keys,
			assertion: new TextEncoder().encode(theirs.assertion),
		});
		expect(done).toHaveProperty("creation");
	});

	it("F-17: a delete's sealed body altered or sent under another sequence is refused by the Core", async () => {
		const { other, second, person } = await twoKeys();
		// Its ciphertext altered: the Core's opening fails.
		const altered = await w.front();
		altered.rewrite({
			messages: {
				continue: (message) => {
					if (message.stage !== 1) return message;
					const ct = Uint8Array.from(message.ct);
					ct[0] = (ct[0] ?? 0) ^ 1;
					return { ...message, ct };
				},
			},
		});
		expect(
			await loggedDuring(async () => {
				expect(await other.deleteKey(altered, second, person.credential)).toMatchObject({
					stopped: "core",
					at: "/continue delete",
				});
			}, 1),
		).toEqual(["delete:sealed"]);
		// Sent under another sequence: the seal is bound to it.
		const moved = await w.front();
		moved.rewrite({
			messages: { continue: (message) => (message.stage === 1 ? { ...message, seq: 2 } : message) },
		});
		expect(
			await loggedDuring(async () => {
				expect(await other.deleteKey(moved, second, person.credential)).toMatchObject({
					stopped: "core",
					at: "/continue delete",
				});
			}, 1),
		).toEqual(["delete:sealed"]);
		// The same delete through an honest Front takes: the alterations alone were refused.
		const honest = await w.front();
		expect(await other.deleteKey(honest, second, person.credential)).toEqual({ deleted: true });
	});

	it("F-17: a delete the Front seals anew for another key, its additional data right, is refused: only E_sig signs the body", async () => {
		const { other, second, person } = await twoKeys();
		const sealer = await thiefSealer();
		try {
			const thief = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
				"sign",
			]);
			/** A Front putting, in place of the screen's delete of the first key, its own of the second. */
			const swapping = async (signer: CryptoKey) => {
				const front = await w.front();
				front.rewrite({
					messages: {
						continue: async (message) =>
							message.stage === 1
								? resealedDelete(sealer, w.sealingKey, message, second, signer)
								: message,
					},
				});
				return front;
			};
			const resealed = await loggedDuring(async () => {
				expect(
					await other.deleteKey(await swapping(thief.privateKey), second, person.credential),
				).toMatchObject({ stopped: "core", at: "/continue delete" });
			}, 1);
			expect(resealed).toEqual(["delete:sealed"]);
			// The control: the same sealing, signed by the screen's own E_sig, is one the Core takes (the
			// screen then refuses an answer of a body it did not send). Only the signature was refused.
			const keys = await screenKeys();
			const signed = await other.deleteKey(
				await swapping(keys.signing.privateKey),
				second,
				person.credential,
				keys,
			);
			expect(signed).toMatchObject({ stopped: "sdk", at: "keyChanges.read" });
		} finally {
			await sealer.stop();
		}
	});

	it("F-17: a delete's answer is of one length whether the key went or was kept", async () => {
		const { other, second, person } = await twoKeys();
		const lengthOf = async (approver: string, target: string, expected: unknown) => {
			const front = await w.front();
			expect(await other.deleteKey(front, approver, target)).toMatchObject(expected as object);
			const answer = front.seen().findLast((r) => r.kind === "continue")?.reply;
			if (answer?.outcome !== "ok") throw new Error("no delete's answer");
			return answer.message.body.length;
		};
		const went = await lengthOf(second, person.credential, { deleted: true });
		// The last key: kept, and answered as long.
		const kept = await lengthOf(second, second, { kept: expect.anything() });
		expect(kept).toBe(went);
	});

	it("F-17: the keys list a passkey-manage answers is of one length whatever the count of keys", async () => {
		const lengths: number[] = [];
		for (const count of [1, 2]) {
			const person = await w.person();
			const front = await w.front();
			if (count === 2) {
				const added = await person.screen.addKey(front, person.credential, browser(screenOrigin));
				if (stopped(added)) throw new Error(JSON.stringify(added));
			}
			const listed = await person.screen.approveManagement(
				front,
				"passkey-manage",
				person.credential,
			);
			if (stopped(listed)) throw new Error(JSON.stringify(listed));
			expect((listed.done as { keys: readonly unknown[] }).keys).toHaveLength(count);
			const answer = front.seen().findLast((r) => r.kind === "approvalFinish")?.reply;
			if (answer?.outcome !== "ok") throw new Error("no answer");
			lengths.push(answer.message.body.length);
		}
		expect(lengths[0]).toBe(lengths[1]);
	});

	it("F-20: a refresh of a family whose root key was deleted is refused", async () => {
		const { person, other, second } = await twoKeys();
		const rp = w.rps[0] as World["rps"][number];
		const front = await w.front();
		const { session, s } = await w.started(person, rp, front);
		const approved = await person.screen.approve(front, s, [person.credential]);
		if (stopped(approved)) throw new Error(JSON.stringify(approved));
		const asked = await front.post(rp.token(session, approved.code));
		const tokens = await front.post(rp.token(session, approved.code, asked.dpopNonce));
		const { refresh_token } = tokens.body as { refresh_token: string };
		// Before the deletion, the family refreshes.
		expect((await front.post(rp.refresh(session, refresh_token, asked.dpopNonce))).status).toBe(
			200,
		);
		expect(await other.deleteKey(front, second, person.credential)).toEqual({ deleted: true });
		const after = await front.post(rp.refresh(session, refresh_token, asked.dpopNonce));
		expect(after.wire?.outcome).toBe("refused");
		expect(after.body).toEqual({
			error: "invalid_grant",
			error_description: "invalid refresh token",
		});
	});
});
