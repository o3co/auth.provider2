import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
	canonicalText,
	hpke,
	itemsFromJar,
	jarClaims,
	payloads,
	purposes,
} from "../src/contract.ts";

// C9: the readers of what the screen sends the Core and the Core seals to the screen.
const seed = Number(process.env.WIRE_FUZZ_SEED ?? 20261127);
const numRuns = Number(process.env.WIRE_FUZZ_CASES ?? 2000);
const isObject = (v: unknown): v is Record<string, unknown> =>
	typeof v === "object" && v !== null && !Array.isArray(v);
/** Whether a value holds a null at any depth, walked here apart from the wire's. */
const holdsNull = (v: unknown): boolean =>
	v === null || (typeof v === "object" && Object.values(v as object).some(holdsNull));
/** A JSON value as JSON reads it back: no -0, no undefined, no other prototype. */
const readBack = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

const jar = {
	iss: "rp-1",
	aud: "https://id.example",
	iat: 1,
	exp: 61,
	jti: "j-1",
	client_id: "rp-1",
	redirect_uri: "https://rp.example/cb",
	response_type: "code",
	response_mode: "form_post",
	state: "s",
	scope: "openid",
	nonce: "n",
	code_challenge: "c",
	code_challenge_method: "S256",
	dpop_jkt: "k",
};
const approval = payloads.statement.shape.approval;
const shapeOrder = Object.keys(approval.shape) as (keyof typeof approval.shape)[];

/** The reference's reading of a JAR, written apart from `itemsFromJar`: its precedence, its projection. */
function reference(payload: Record<string, unknown>, hash: string) {
	const allowed: readonly string[] = [...jarClaims.items, ...jarClaims.envelope];
	const unknown = Object.keys(payload).find((k) => !allowed.includes(k));
	if (unknown !== undefined) return { error: `unknown_item:${unknown}` };
	const missing = jarClaims.required.find(
		(k) => typeof payload[k] !== "string" || payload[k] === "",
	);
	if (missing !== undefined) return { error: `missing_item:${missing}` };
	const items: Record<string, unknown> = { jar_hash: hash };
	for (const k of jarClaims.items) if (payload[k] !== undefined) items[k] = payload[k];
	if (payload.claims !== undefined) {
		const claims = payload.claims;
		items.claims = isObject(claims)
			? Object.fromEntries(
					Object.entries(claims).map(([m, asked]) => [
						m,
						(m === "id_token" || m === "userinfo") && isObject(asked)
							? Object.fromEntries(Object.entries(asked).map(([n, r]) => [n, r === null ? {} : r]))
							: asked,
					]),
				)
			: claims;
	}
	// The first item, in T's own order, its rule refuses, each rule written out here apart from T's schema.
	const text = (v: unknown) => typeof v === "string" && v !== "";
	const optionalText = (v: unknown) => v === undefined || text(v);
	const rules: Record<string, (v: unknown) => boolean> = {
		client_id: text,
		redirect_uri: text,
		response_type: (v) => v === "code",
		response_mode: (v) => v === "form_post",
		state: text,
		scope: text,
		resource: optionalText,
		claims: (v) => v === undefined || (isObject(v) && !holdsNull(v)),
		nonce: text,
		code_challenge: text,
		code_challenge_method: (v) => v === "S256",
		dpop_jkt: text,
		jar_hash: text,
		request_uri: optionalText,
	};
	if (Object.keys(rules).sort().join() !== [...shapeOrder].sort().join())
		throw new Error("T's items and the rules part");
	const bad = shapeOrder.find((k) => !(rules[k as string] as (v: unknown) => boolean)(items[k]));
	return bad === undefined ? { items } : { error: `item:${String(bad)}` };
}

/** Claims of each kind: asked in the default manner, with constraints, with a null left, of no object's form. */
const claims = fc.oneof(
	fc.record({
		id_token: fc.dictionary(
			fc.constantFrom("email", "name", "acr"),
			fc.oneof(fc.constant(null), fc.record({ essential: fc.boolean() })),
		),
	}),
	fc.record({
		userinfo: fc.record({ email: fc.constant(null) }),
		other: fc.jsonValue().map(readBack),
	}),
	fc.record({ id_token: fc.record({ email: fc.record({ value: fc.constant(null) }) }) }),
	fc.constantFrom(5, "x", true, [], [{ id_token: {} }], null, {}),
);
/** A JAR's payload changed one to three times as a relying party may write one. */
const payload = fc
	.array(
		fc.oneof(
			fc.tuple(
				fc.constant("add"),
				fc.constantFrom("authorization_details", "__proto__", "", "x", "request", "prompt"),
				fc.jsonValue().map(readBack),
			),
			fc.tuple(
				fc.constant("drop"),
				fc.constantFrom(...jarClaims.required, "nonce", "dpop_jkt"),
				fc.constant(undefined),
			),
			fc.tuple(
				fc.constant("set"),
				fc.constantFrom(...jarClaims.items),
				fc.constantFrom(
					"",
					1,
					null,
					"query",
					"plain",
					"token",
					"x",
					"code",
					"form_post",
					"S256",
					[],
					{},
					true,
				),
			),
			fc.tuple(fc.constant("claims"), fc.constant("claims"), claims),
		),
		{ maxLength: 3 },
	)
	.map((changes) => {
		const out: [string, unknown][] = Object.entries(jar);
		for (const [op, k, v] of changes) {
			const at = out.findIndex(([name]) => name === k);
			if (op === "drop") {
				if (at >= 0) out.splice(at, 1);
			} else if (at >= 0) out[at] = [k, v];
			else out.push([k, v]);
		}
		// Built by entries, so a member named __proto__ is the payload's own.
		return Object.fromEntries(out) as Record<string, unknown>;
	});

describe("the items T approves, from any JAR's payload", () => {
	it("are what a reference written apart reads: an unknown claim first, then a missing item, then T's first refused item, else the projection", () => {
		const seen = { unknown: 0, missing: 0, item: 0, claimsNull: 0, claimsForm: 0, ok: 0 };
		fc.assert(
			fc.property(payload, fc.string({ minLength: 1, maxLength: 8 }), (p, hash) => {
				const got = itemsFromJar(p, hash);
				const expected = reference(p, hash);
				expect(got).toEqual(expected);
				if ("items" in got) {
					seen.ok++;
					// No null at any depth in T's claims, and its claims an object where given.
					expect(holdsNull(got.items.claims)).toBe(false);
					if (got.items.claims !== undefined) expect(isObject(got.items.claims)).toBe(true);
				} else if (got.error.startsWith("unknown_item:")) seen.unknown++;
				else if (got.error.startsWith("missing_item:")) seen.missing++;
				else if (got.error === "item:claims")
					isObject(p.claims) ? seen.claimsNull++ : seen.claimsForm++;
				else seen.item++;
			}),
			{ seed, numRuns },
		);
		for (const [what, n] of Object.entries(seen)) expect(n, what).toBeGreaterThan(0);
	});

	it("are the same, to the byte, whatever the order of a payload's members at any depth", () => {
		const shuffled = (v: unknown, order: number): unknown =>
			Array.isArray(v)
				? v.map((x) => shuffled(x, order))
				: isObject(v)
					? Object.fromEntries(
							Object.entries(v)
								.map((e, i) => [e, ((i + 1) * 2654435761 * (order + 1)) % 1009] as const)
								.sort(([, x], [, y]) => x - y)
								.map(([e]) => e)
								.map(([k, x]) => [k, shuffled(x, order + 1)]),
						)
					: v;
		fc.assert(
			fc.property(claims.filter(isObject), fc.nat(), (c, order) => {
				const p = { ...jar, claims: readBack(c) };
				const one = itemsFromJar(p, "h");
				const two = itemsFromJar(shuffled(p, order) as Record<string, unknown>, "h");
				expect("items" in two).toBe("items" in one);
				if ("items" in one && "items" in two)
					expect(canonicalText(two.items)).toBe(canonicalText(one.items));
			}),
			{ seed, numRuns },
		);
	});
});

describe("the canonical text both sides hash", () => {
	it("is JSON, read back as the value, the same written again, whatever its members' order", () => {
		fc.assert(
			fc.property(fc.jsonValue().map(readBack), (v) => {
				const text = canonicalText(v);
				expect(JSON.parse(text)).toEqual(v);
				expect(canonicalText(JSON.parse(text))).toBe(text);
				const reversed = JSON.parse(JSON.stringify(v), (_, x) =>
					isObject(x) ? Object.fromEntries(Object.entries(x).reverse()) : x,
				);
				expect(canonicalText(reversed)).toBe(text);
			}),
			{ seed, numRuns },
		);
		// -0 is written 0 and read back +0.
		expect(canonicalText(-0)).toBe("0");
	});
});

describe("a padded completion", () => {
	const jws = fc
		.tuple(
			fc.stringMatching(/^[A-Za-z0-9_-]{1,40}$/, { size: "max" }),
			fc.stringMatching(/^[A-Za-z0-9_-]{1,400}$/, { size: "max" }),
			fc.stringMatching(/^[A-Za-z0-9_-]{1,90}$/, { size: "max" }),
		)
		.map(([a, b, c]) => `${a}.${b}.${c}`);
	it("is a bucket's length, a compact JWS then spaces alone, read back as it was; a change off that form refused", () => {
		const changes = [" ", "\t", "\n", "\u00a0", "\u2028", "\ufeff", "\u3000", "x", ""];
		fc.assert(
			fc.property(jws, fc.nat(1000), fc.nat(), fc.nat(changes.length - 1), (j, longest, at, c) => {
				const text = hpke.paddedCompletion(j, longest);
				if (text === undefined) return;
				expect(hpke.completionBuckets as readonly number[]).toContain(text.length);
				expect(hpke.unpaddedCompletion(text)).toBe(j);
				const i = at % text.length;
				const changed = `${text.slice(0, i)}${changes[c]}${text.slice(i + 1)}`;
				const read = hpke.unpaddedCompletion(changed);
				// Read only where it is a bucket's length, a compact JWS then spaces alone.
				if (read !== undefined) expect(changed).toBe(read.padEnd(changed.length, " "));
				// Classified apart: a bucket's length, a compact JWS, then spaces alone; else refused.
				let end = changed.length;
				while (end > 0 && changed[end - 1] === " ") end--;
				const jwsPart = changed.slice(0, end);
				const expected =
					(hpke.completionBuckets as readonly number[]).includes(changed.length) &&
					/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(jwsPart)
						? jwsPart
						: undefined;
				expect(read, JSON.stringify(changed.slice(Math.max(0, i - 2), i + 2))).toBe(expected);
			}),
			{ seed, numRuns: Math.max(100, Math.floor(numRuns / 7)) },
		);
		for (const n of hpke.completionBuckets) {
			expect(hpke.unpaddedCompletion(" ".repeat(n))).toBeUndefined();
			expect(hpke.unpaddedCompletion(`a.b.${"c".repeat(n - 4)}`)).toBe(`a.b.${"c".repeat(n - 4)}`);
		}
	});
});

describe("the payloads' schemas", () => {
	const key = { kty: "EC", crv: "P-256", x: "x", y: "y" };
	const read = itemsFromJar({ ...jar, claims: { id_token: { email: {} } } }, "h");
	if (!("items" in read)) throw new Error(read.error);
	const point = Buffer.concat([Buffer.of(4), Buffer.alloc(64, 7)]).toString("base64url");
	const common = {
		v: 1,
		iss: "https://id.example",
		sid: "c-1",
		iat: 1,
		exp: 2,
		e_enc: "e",
		e_sig: key,
		nonce: "n",
	};
	/** A passkey's thumbprint: passkey-key-wire's vector ES256's `jkt`. */
	const jkt = "f8S_bSDLrCv5BxMRxT99d2bFk8QDVQQl4bOAWUvTvCM";
	const approved = {
		v: 1,
		iss: "https://id.example",
		iat: 1,
		exp: 2,
		t_hash: "E".repeat(43),
		assertion_hash: "A".repeat(43),
	};
	const creation = {
		...common,
		purpose: purposes.creation,
		creation: {
			account: "a***",
			evidence: "ev",
			ct_hash: "ct",
			subject: "s-1",
			kg: 0,
			options: { user_id: "u", rp_id: "id.example", exclude_credentials: [], algorithms: [-7, -8] },
		},
	};
	const valid: readonly [
		string,
		{ safeParse(x: unknown): { success: boolean; data?: unknown } },
		Record<string, unknown>,
	][] = [
		[
			"statement",
			payloads.statement,
			{
				v: 1,
				iss: "https://id.example",
				sid: "t-1",
				iat: 1,
				exp: 2,
				e_enc: "e",
				e_sig: key,
				purpose: purposes.authorization,
				approval: read.items,
			},
		],
		[
			"completion",
			payloads.completion,
			{ v: 1, iss: "i", t_hash: "t", assertion_hash: "a", code: "c", iat: 1, exp: 2 },
		],
		["startPlain", payloads.startPlain, { identifier: "a@x.example", password: "p" }],
		["mailPlain", payloads.mailPlain, { token: "t", identifier: "a", code: "c" }],
		["answers.statement", payloads.answers.statement, { statement: "a.b.c" }],
		[
			"answers.sealed",
			payloads.answers.sealed,
			{ sealed: { enc: point, ct: Buffer.alloc(17, 9).toString("base64url") } },
		],
		["answers.nonce", payloads.answers.nonce, { nonce: "A".repeat(43) }],
		[
			"answers.authorization",
			payloads.answers.authorization,
			{ statement: "eyJh.eyJi.c2ln", challenge: "A".repeat(43), create: false },
		],
		["codePlain", payloads.codePlain, { code: "c" }],
		["passkeyAdd", payloads.passkeyAdd, { ...common, purpose: purposes.passkeyAdd }],
		["passkeyManage", payloads.passkeyManage, { ...common, purpose: purposes.passkeyManage }],
		["creation", payloads.creation, creation],
		[
			"possession",
			payloads.possession,
			{
				...common,
				purpose: purposes.possession,
				possession: { creation_hash: "c", key_jkt: jkt, credential_id: "cr", reservation_id: "r" },
			},
		],
		[
			"completions.passkeyAdd",
			payloads.completions.passkeyAdd,
			{ ...approved, purpose: "passkey-add", creation: "a.b.c" },
		],
		[
			"completions.passkeyManage",
			payloads.completions.passkeyManage,
			{
				...approved,
				purpose: "passkey-manage",
				keys: [{ credential_id: "c1", label: "Laptop", created_at: 0 }],
			},
		],
		[
			"completions.keyChange",
			payloads.completions.keyChange,
			{
				v: 1,
				iss: "https://id.example",
				iat: 1,
				exp: 2,
				purpose: "first-key",
				change: { op: "add", credential_id: "c1", key_jkt: jkt },
			},
		],
	];
	/** Every object path in a value, the value itself the first. */
	const paths = (v: unknown, at: string[] = []): string[][] =>
		isObject(v)
			? [at, ...Object.entries(v).flatMap(([k, x]) => paths(x, [...at, k]))]
			: Array.isArray(v)
				? v.flatMap((x, i) => paths(x, [...at, String(i)]))
				: [];
	const inserted = (v: unknown, at: string[], name: string, value: unknown): unknown =>
		at.length === 0
			? Object.fromEntries([...Object.entries(v as Record<string, unknown>), [name, value]])
			: Array.isArray(v)
				? v.map((x, i) => (String(i) === at[0] ? inserted(x, at.slice(1), name, value) : x))
				: Object.fromEntries(
						Object.entries(v as Record<string, unknown>).map(([k, x]) => [
							k,
							k === at[0] ? inserted(x, at.slice(1), name, value) : x,
						]),
					);

	it("take bytes in their one spelling and of their length alone, by a reading of Buffer written apart: a point, a ciphertext, a nonce", () => {
		const ct = Buffer.alloc(17, 9).toString("base64url");
		const spelt = (t: string) =>
			/^[A-Za-z0-9_-]*$/.test(t) && Buffer.from(t, "base64url").toString("base64url") === t;
		const length = (t: string) => Buffer.from(t, "base64url").length;
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
		const spareFlipped = (t: string) =>
			t === "" ? t : `${t.slice(0, -1)}${alphabet[alphabet.indexOf(t.slice(-1)) ^ 1]}`;
		const exactBytes = (n: number) =>
			fc
				.uint8Array({ minLength: n, maxLength: n })
				.map((b) => Buffer.from(b).toString("base64url"));
		const text = fc.oneof(
			fc
				.uint8Array({ minLength: 0, maxLength: 80, size: "max" })
				.map((b) => Buffer.from(b).toString("base64url")),
			// At and past each field's length: 15 to 17 bytes, 31 to 33, 64 to 66 of any first byte; and
			// each of those with its last character's lowest bit flipped.
			fc.constantFrom(15, 16, 17, 31, 32, 33, 64, 65, 66).chain(exactBytes),
			fc.constantFrom(16, 17, 18, 32, 65).chain(exactBytes).map(spareFlipped),
			fc.uint8Array({ minLength: 64, maxLength: 66 }).map((b) => {
				const c = new Uint8Array(b);
				c[0] = 4;
				return Buffer.from(c).toString("base64url");
			}),
			fc.stringMatching(/^[A-Za-z0-9_=+/-]{0,90}$/, { size: "max" }),
		);
		fc.assert(
			fc.property(text, (t) => {
				const asPoint = spelt(t) && length(t) === 65 && Buffer.from(t, "base64url")[0] === 4;
				expect(
					payloads.answers.sealed.safeParse({ sealed: { enc: t, ct } }).success,
					`enc ${t}`,
				).toBe(asPoint);
				expect(
					payloads.answers.sealed.safeParse({ sealed: { enc: point, ct: t } }).success,
					`ct ${t}`,
				).toBe(spelt(t) && length(t) >= 16);
				expect(payloads.answers.nonce.safeParse({ nonce: t }).success, `nonce ${t}`).toBe(
					spelt(t) && length(t) === 32,
				);
			}),
			{ seed, numRuns },
		);
	});

	it("take each valid payload as it is, and refuse a member it does not name at every depth, but within T's claims", () => {
		for (const [name, schema, value] of valid) {
			const taken = schema.safeParse(value);
			expect(taken.success, name).toBe(true);
			expect(taken.data, name).toEqual(value);
			for (const at of paths(value)) {
				for (const extra of ["x", "__proto__", "constructor"]) {
					const changed = inserted(value, at, extra, 1);
					const underClaims = at.join(".").startsWith("approval.claims");
					const got = schema.safeParse(changed);
					expect(got.success, `${name} ${at.join(".")} ${extra}`).toBe(underClaims);
					if (got.success) expect(got.data).toEqual(changed);
				}
			}
		}
	});
});
