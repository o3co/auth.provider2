import { continuation } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import { screenKeys, sha256, world } from "../../../test/fixtures/world.ts";

type World = Awaited<ReturnType<typeof world>>;
const creationItems = {
	account: "a***@example",
	evidence: "ev",
	ct_hash: "ct",
	subject: "s1",
	kg: 0,
	options: {
		user_id: "u",
		rp_id: "rp.example",
		exclude_credentials: [],
		algorithms: [-7 as const],
	},
};
const possessionOf = (creation: string) => ({
	creation_hash: creation,
	key_jkt: "kZ8n9mX3tQ2vB7cY4wR1sE6uA0pL5dH9jF2gK8hN3oM",
	credential_id: "cred",
	reservation_id: "res",
});

/** A creation of `items`, continued by register number `seq` into a possession, that possession used. */
async function made(w: World, items: object = creationItems) {
	const keys = screenKeys();
	const c = await w.approvals.issue({
		purpose: "creation",
		items: items as never,
		screen: keys.screen,
		by: "s",
	});
	if (c.kind !== "issued") throw new Error(c.reason);
	const register = async (seq: number, body: string) => {
		const signature = keys.signs(continuation.of("register", c.hash, seq, sha256(body)));
		let made = "";
		await w.approvals.continue({
			hash: c.hash,
			seq,
			body,
			signature,
			step: async () => {
				const p = await w.approvals.issue({
					purpose: "possession",
					items: possessionOf(c.hash),
					screen: keys.screen,
					by: "s",
				});
				if (p.kind !== "issued") throw new Error(p.reason);
				made = p.statement;
				return { statement: p.statement };
			},
		});
		return { possession: made, hash: sha256(made), signature };
	};
	return { c, keys, register };
}

describe("a used possession's key change, as kept", () => {
	it("gives its creation and the continuation that made it, past expiry, to its records' end", async () => {
		const w = await world();
		const { c, keys, register } = await made(w);
		const p = await register(1, "b1");
		// Not used yet: none.
		expect(await w.approvals.keptChangeOf(p.hash)).toBeUndefined();
		await w.approvals.use({ statement: p.possession, verification: "v1" });
		const kept = {
			creation: { statement: c.statement, items: creationItems, screen: keys.screen },
			continuation: { seq: 1, body: "b1", signature: p.signature },
		};
		expect(await w.approvals.keptChangeOf(p.hash)).toEqual(kept);
		// Past the creation's expiry: as kept; its records gone: none.
		w.advance(5 * 60_000 + 1000);
		expect(await w.approvals.keptChangeOf(p.hash)).toEqual(kept);
		w.advance(60_000);
		expect(await w.approvals.keptChangeOf(p.hash)).toBeUndefined();
	});

	it("gives none for a possession this generation's ring does not verify", async () => {
		const w = await world();
		const { register } = await made(w);
		const p = await register(1, "b1");
		await w.approvals.use({ statement: p.possession, verification: "v1" });
		const [head, body] = p.possession.split(".");
		await w.statements.store.change(p.hash, (r) => ({
			value: {
				...(r as object),
				jws: `${head}.${body}.${Buffer.alloc(64).toString("base64url")}`,
			} as never,
		}));
		expect(await w.approvals.keptChangeOf(p.hash)).toBeUndefined();
	});

	it("gives none for a possession its creation's last continuation did not make, or any other statement", async () => {
		const w = await world();
		const { c, register } = await made(w);
		const first = await register(1, "b1");
		await w.approvals.use({ statement: first.possession, verification: "v1" });
		await register(2, "b2");
		expect(await w.approvals.keptChangeOf(first.hash)).toBeUndefined();
		expect(await w.approvals.keptChangeOf(c.hash)).toBeUndefined();
		expect(await w.approvals.keptChangeOf("unknown")).toBeUndefined();
	});

	it("gives the passkey-add a creation rests on, used, as its evidence", async () => {
		const w = await world();
		const key = await w.plant("s1");
		const add = await w.approvals.issue({
			purpose: "passkey-add",
			items: {},
			screen: screenKeys().screen,
			by: "src",
		});
		if (add.kind !== "issued") throw new Error(add.reason);
		const assertion = w.assert(add.challenge);
		await w.approvals.use({ statement: add.statement, assertion });
		const { ct_hash: _, account: __, ...rest } = creationItems;
		const items = { ...rest, account: "a***@example", basis: "passkey-add", evidence: add.hash };
		const { register } = await made(w, items);
		const p = await register(1, "b1");
		await w.approvals.use({ statement: p.possession, verification: "v1" });
		expect(await w.approvals.keptChangeOf(p.hash)).toMatchObject({
			evidence: {
				statement: add.statement,
				assertion,
				subject: "s1",
				credential: key.id,
				registration: "r0",
			},
		});
	});

	it("gives none once the passkey-add it rests on, issued first, has its record gone", async () => {
		const w = await world();
		await w.plant("s1");
		const add = await w.approvals.issue({
			purpose: "passkey-add",
			items: {},
			screen: screenKeys().screen,
			by: "src",
		});
		if (add.kind !== "issued") throw new Error(add.reason);
		await w.approvals.use({ statement: add.statement, assertion: w.assert(add.challenge) });
		w.advance(4 * 60_000);
		const { ct_hash: _, account: __, ...rest } = creationItems;
		const items = { ...rest, account: "a***@example", basis: "passkey-add", evidence: add.hash };
		const { register } = await made(w, items);
		const p = await register(1, "b1");
		await w.approvals.use({ statement: p.possession, verification: "v1" });
		expect(await w.approvals.keptChangeOf(p.hash)).toBeDefined();
		// The passkey-add's record ends a minute past its expiry; the possession's lives on.
		w.advance(2 * 60_000 + 1000);
		expect(await w.statements.store.read(p.hash)).toBeDefined();
		expect(await w.approvals.keptChangeOf(p.hash)).toBeUndefined();
	});

	it("gives a sign-up's T as signed, and none for a passkey-add another subject used", async () => {
		const w = await world();
		const t = await w.approvals.issue({
			purpose: "authorization",
			items: {
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
			},
			screen: screenKeys().screen,
			by: "src",
		});
		if (t.kind !== "issued") throw new Error(t.reason);
		const { ct_hash: _, account: __, ...rest } = creationItems;
		const signUp = {
			...rest,
			options: { ...rest.options, user_name: "Example" },
			basis: "sign-up",
			evidence: t.hash,
		};
		const one = await made(w, signUp);
		const p = await one.register(1, "b1");
		await w.approvals.use({ statement: p.possession, verification: "v1" });
		expect(await w.approvals.keptChangeOf(p.hash)).toMatchObject({ evidence: t.statement });
		// A passkey-add s1 used, named by a creation for s2: none.
		await w.plant("s1");
		const add = await w.approvals.issue({
			purpose: "passkey-add",
			items: {},
			screen: screenKeys().screen,
			by: "src",
		});
		if (add.kind !== "issued") throw new Error(add.reason);
		await w.approvals.use({ statement: add.statement, assertion: w.assert(add.challenge) });
		const other = {
			...rest,
			subject: "s2",
			account: "a***@example",
			basis: "passkey-add",
			evidence: add.hash,
		};
		const two = await made(w, other);
		const q = await two.register(1, "b1");
		await w.approvals.use({ statement: q.possession, verification: "v1" });
		expect(await w.approvals.keptChangeOf(q.hash)).toBeUndefined();
	});
});
