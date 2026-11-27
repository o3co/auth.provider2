import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { clientSecret } from "@mod/clients/testing";
import { testRequest } from "@mod/http/testing";
import { takesUnused } from "@mod/kernel/testing";
import { pkcs1v15Deprecated } from "@mod/keys";
import { describe, expect, it } from "vitest";
import { clientAssertion } from "../src/contract.ts";
import { assertionType } from "../src/method/method.ts";
import { section } from "../src/section.ts";
import { composed, type Header } from "./composed.ts";

const now = 1_800_000_000_000;
const {
	recorded,
	lastWarned,
	ecPair,
	ec,
	ed,
	rsa,
	jwk,
	boot,
	claims,
	sign,
	signedWithSecret,
	asked,
	posted,
	presenting,
	outcome,
	tried,
} = composed(() => now);

describe("private_key_jwt", () => {
	it("names the asymmetric algorithms an assertion may be signed with: by default FAPI 2.0's, any other only where named [oidc-discovery-3-ad]", async () => {
		const { c } = await boot();
		expect(c.signingAlgorithms()).toEqual(["ES256", "PS256", "EdDSA"]);
		const named = await boot({
			keys: [jwk(rsa.publicKey, { kid: "r", alg: "PS256" })],
			settings: { algorithms: ["RS256", "PS256", "RS256"] },
		});
		expect(named.c.signingAlgorithms()).toEqual(["RS256", "PS256"]);
		// The contract names the same ones, for a request object verified by it too.
		expect((await boot()).app.get(clientAssertion).algorithms).toEqual(["ES256", "PS256", "EdDSA"]);
		expect(named.app.get(clientAssertion).algorithms).toEqual(["RS256", "PS256"]);
		for (const algorithms of [[], ["HS256"], ["none"]]) {
			expect(section.safeParse({ algorithms }).success, String(algorithms)).toBe(false);
		}
	});

	it("warns at each start of every registered client accepting a loose audience, by its id", async () => {
		const warned = () =>
			recorded
				.lines()
				.filter((line) => line.event === "client-assertion.accept_loose_audience")
				.map(({ level, fields }) => ({ level, fields }));
		const before = warned().length;
		const { app } = await boot({ loose: ["app:twin"] });
		expect(warned()).toHaveLength(before);
		await app.start();
		expect(warned().slice(before)).toEqual([{ level: "warn", fields: { client: "app:twin" } }]);
		await app.stop();
		const strict = await boot();
		await strict.app.start();
		expect(warned()).toHaveLength(before + 1);
		await strict.app.stop();
	});

	it("warns at every start where RS256, RS384 or RS512 is named, naming them, in keys' words, and not where none is", async () => {
		const warned = () =>
			recorded.lines().filter((line) => line.event === "client-assertion.pkcs1v15_deprecated");
		const before = warned().length;
		await boot();
		await boot({ settings: { algorithms: ["ES256", "PS256", "PS384", "PS512"] } });
		await boot({ settings: { algorithms: ["ES384", "ES512", "EdDSA"] } });
		expect(warned()).toHaveLength(before);
		for (const algorithms of [
			["ES256", "RS256"],
			["RS384"],
			["PS256", "RS512", "RS256"],
			["RS256", "RS384", "RS512", "RS384"],
		] as const)
			await boot({ settings: { algorithms: [...algorithms] } });
		expect(
			warned()
				.slice(before)
				.map((line) => line.fields),
		).toEqual([
			{ algorithms: "RS256", reason: pkcs1v15Deprecated },
			{ algorithms: "RS384", reason: pkcs1v15Deprecated },
			{ algorithms: "RS512 RS256", reason: pkcs1v15Deprecated },
			// All three, one written twice: each once, as the section keeps them.
			{ algorithms: "RS256 RS384 RS512", reason: pkcs1v15Deprecated },
		]);
		expect(
			warned()
				.slice(before)
				.every((line) => line.level === "warn"),
		).toBe(true);
	});

	it("verifies with the one key the header picks, by asymmetric algorithms only [rfc7523-3-u] [rfc7521-5.2-n] [rfc8414-2-i]", async () => {
		const { c } = await boot({
			keys: [jwk(ec.publicKey, { kid: "ec" }), jwk(ed.publicKey), jwk(rsa.publicKey, { kid: "r" })],
		});
		const by = (key: KeyObject, header: Header) => tried(c, {}, {}, key, header);
		expect(await by(ec.privateKey, { alg: "ES256", kid: "ec" })).toBe("app");
		expect(await by(ec.privateKey, { alg: "ES256" })).toBe("app");
		expect(await by(ed.privateKey, { alg: "EdDSA" })).toBe("app");
		// PS256 is taken by default, RS256 only where named; named, a key naming one is read under it alone.
		expect(await by(rsa.privateKey, { alg: "RS256" })).toBe("bad_credentials");
		expect(await by(rsa.privateKey, { alg: "PS256", kid: "r" })).toBe("app");
		const withPss = await boot({
			keys: [jwk(rsa.publicKey, { kid: "r", alg: "PS256" })],
			settings: { algorithms: ["RS256", "PS256"] },
		});
		expect(await tried(withPss.c, {}, {}, rsa.privateKey, { alg: "PS256", kid: "r" })).toBe("app");
		expect(await by(rsa.privateKey, { alg: "RS256", kid: "ec" })).toBe("bad_credentials");
		const p384 = generateKeyPairSync("ec", { namedCurve: "P-384" });
		expect(await by(p384.privateKey, { alg: "ES384" })).toBe("bad_credentials");
		expect(await outcome(c, presenting(await signedWithSecret()))).toBe("bad_credentials");
		const twin = await boot({ keys: [jwk(ec.publicKey), jwk(ecPair().publicKey)] });
		expect(await tried(twin.c, {}, {}, ec.privateKey, { alg: "ES256" })).toBe("bad_credentials");
		expect(lastWarned()).toBe("more than one key fits");
		// A key's own alg, and an EC key's curve, narrow the choice.
		const pinned = await boot({
			keys: [jwk(rsa.publicKey, { alg: "RS256" })],
			settings: { algorithms: ["RS256", "PS256"] },
		});
		const rs = (alg: string) => tried(pinned.c, {}, {}, rsa.privateKey, { alg });
		expect(await rs("RS256")).toBe("app");
		expect(await rs("PS256")).toBe("bad_credentials");
		const p521 = generateKeyPairSync("ec", { namedCurve: "P-521" });
		const curves = await boot({
			keys: [jwk(ec.publicKey), jwk(p384.publicKey), jwk(p521.publicKey)],
			settings: { algorithms: ["ES256", "ES384", "ES512"] },
		});
		expect(await tried(curves.c, {}, {}, ec.privateKey, { alg: "ES256" })).toBe("app");
		// Named, keys of P-384 and P-521 naming no alg are read under their own curve's.
		expect(await tried(curves.c, {}, {}, p384.privateKey, { alg: "ES384" })).toBe("app");
		expect(await tried(curves.c, {}, {}, p521.privateKey, { alg: "ES512" })).toBe("app");
	});

	it("reads each client key under one algorithm, its own alg or the one the operator takes for its kind, and warns at each start of one read under none, by its place", async () => {
		const both = { algorithms: ["RS256" as const, "PS256" as const] };
		const unread = () =>
			recorded
				.lines()
				.filter((line) => line.event === "client-assertion.key_unread")
				.map(({ level, fields }) => ({ level, fields }));
		/** What one start of the composition booted so warns of, with its clients. */
		const started = async (options: Parameters<typeof boot>[0]) => {
			const before = unread().length;
			const { app, c } = await boot(options);
			expect(unread()).toHaveLength(before);
			await app.start();
			await app.stop();
			return { c, warned: unread().slice(before) };
		};
		// Each of the two clients registered with the keys, by each one's place.
		const byClient = (keys: string[]) =>
			["app", "app:twin"].flatMap((client) =>
				keys.map((key) => ({ level: "warn", fields: { client, key } })),
			);
		// RS256 and PS256 both taken: a key naming no alg is read under neither.
		const unnamed = await started({ keys: [jwk(rsa.publicKey, { kid: "r" })], settings: both });
		expect(unnamed.warned).toEqual(byClient(["keys.0"]));
		expect(await tried(unnamed.c, {}, {}, rsa.privateKey, { alg: "RS256", kid: "r" })).toBe(
			"bad_credentials",
		);
		// A key naming its alg is read under that one alone.
		const named = await started({
			keys: [jwk(rsa.publicKey, { kid: "r", alg: "RS256" })],
			settings: both,
		});
		expect(named.warned).toEqual([]);
		const namedBy = (alg: string) => tried(named.c, {}, {}, rsa.privateKey, { alg, kid: "r" });
		expect(await namedBy("RS256")).toBe("app");
		expect(await namedBy("PS256")).toBe("bad_credentials");
		// A key whose alg the operator does not take is read under none; every such key is named.
		const several = await started({
			keys: [
				jwk(rsa.publicKey, { kid: "r", alg: "RS512" }),
				jwk(ec.publicKey, { kid: "ec" }),
				jwk(rsa.publicKey, { kid: "r2" }),
			],
			settings: { algorithms: ["RS256", "PS256", "ES256"] },
		});
		expect(several.warned).toEqual(byClient(["keys.0", "keys.2"]));
		// One taken for its kind, a key naming no alg is read under it; by default an RSA key is read under PS256.
		const rs256 = { algorithms: ["RS256" as const] };
		expect(
			(await started({ keys: [jwk(rsa.publicKey, { kid: "r" })], settings: rs256 })).warned,
		).toEqual([]);
		expect((await started({ keys: [jwk(rsa.publicKey, { kid: "r" })] })).warned).toEqual([]);
		// ES384 is not taken by default: a P-384 key naming no alg is read under none.
		const p384 = generateKeyPairSync("ec", { namedCurve: "P-384" });
		expect((await started({ keys: [jwk(p384.publicKey, { kid: "p" })] })).warned).toEqual(
			byClient(["keys.0"]),
		);
	});

	it("answers a request with only half of an assertion as malformed, and refuses one of a type not taken here [rfc7521-4.2-a] [rfc7521-4.2-b] [oidc-core-9-q] [rfc6749-2.3-b]", async () => {
		const { c } = await boot();
		expect(await outcome(c, asked({ client_assertion_type: assertionType }))).toBe(
			"malformed_credentials",
		);
		expect(await outcome(c, asked({ client_assertion: await sign(claims()) }))).toBe(
			"malformed_credentials",
		);
		expect(await outcome(c, presenting(""))).toBe("malformed_credentials");
		expect(await outcome(c, asked({ client_assertion: "" }))).toBe("malformed_credentials");
		expect(await outcome(c, asked({ client_assertion: "", client_id: "app" }))).toBe(
			"malformed_credentials",
		);
		const other = {
			client_assertion_type: "urn:unsupported",
			client_assertion: await sign(claims()),
		};
		expect(await outcome(c, asked(other))).toBe("bad_credentials");
		expect(lastWarned()).toBe("assertion type");
		// Nor does another method take it: not a public client by its id, not a client by its secret.
		expect(await outcome(c, asked({ ...other, client_id: "pub" }))).toBe("wrong_method");
		const secret = { client_id: "post", client_secret: clientSecret("post") };
		expect(await outcome(c, asked({ ...other, ...secret }))).toBe("multiple_methods");
	});

	it("marks as the assertion's the refusal of an assertion beside another method, or of half of one", async () => {
		const { c } = await boot();
		const secret = { client_id: "post", client_secret: clientSecret("post") };
		const beside = asked({
			client_assertion_type: assertionType,
			client_assertion: await sign(claims()),
			...secret,
		});
		expect(await c.authenticate(beside)).toMatchObject({
			kind: "refused",
			reason: "multiple_methods",
			assertion: true,
		});
		expect(await c.authenticate(asked({ client_assertion_type: assertionType }))).toMatchObject({
			kind: "refused",
			reason: "malformed_credentials",
			assertion: true,
		});
	});

	it("marks two methods beside an assertion that is no string in JSON, challenging for Basic", async () => {
		const { c } = await boot();
		const basic = `Basic ${Buffer.from(`post:${clientSecret("post")}`).toString("base64")}`;
		const request = testRequest({
			method: "POST",
			headers: new Map([["authorization", basic]]),
			json: { client_id: "post", client_secret: clientSecret("post"), client_assertion: 7 },
		});
		expect(await c.authenticate(request)).toEqual({
			kind: "refused",
			reason: "multiple_methods",
			assertion: true,
			challenges: ['Basic realm="client"'],
		});
	});

	it("leaves unmarked a client id given twice or as no string with no assertion, malformed as another method finds it", async () => {
		const { c } = await boot();
		const secret = clientSecret("post");
		for (const request of [
			asked({ client_id: ["post", "post"], client_secret: secret }),
			posted({ client_id: 7, client_secret: secret }),
		]) {
			expect(await c.authenticate(request)).toEqual({
				kind: "refused",
				reason: "malformed_credentials",
				challenges: [],
			});
		}
	});

	it("answers each method with and without an assertion beside it, whatever the client_id beside them", async () => {
		const { c } = await boot();
		const basicHeader = `Basic ${Buffer.from(`basic:${clientSecret("basic")}`).toString("base64")}`;
		/** The client_id: none, one, sent twice, or in JSON not a string. */
		const shapes = ["absent", "one", "twice", "mistyped"] as const;
		/** What a refusal two methods or malformed credentials gives: marked as the assertion's or not. */
		const refusal = (
			reason: "multiple_methods" | "malformed_credentials",
			challenges: readonly string[] = [],
			assertion = false,
		) => ({ kind: "refused", reason, challenges, ...(assertion ? { assertion: true } : {}) });
		const malformed = refusal("malformed_credentials");
		const besideBasic = refusal("multiple_methods", ['Basic realm="client"'], true);
		const besidePost = refusal("multiple_methods", [], true);
		type Expected = string | ReturnType<typeof refusal>;
		const cases: [string, string | undefined, Record<string, unknown>, boolean, Expected[]][] = [
			// Each row: the method, its Authorization header, its body, an assertion beside it, then the
			// outcome for each client_id shape in order.
			["Basic", basicHeader, {}, false, ["basic", "basic", malformed, malformed]],
			[
				"post",
				undefined,
				{ client_secret: clientSecret("post") },
				false,
				[malformed, "post", malformed, malformed],
			],
			[
				"none",
				undefined,
				{},
				false,
				[{ kind: "refused", reason: "no_credentials" } as never, "pub", malformed, malformed],
			],
			["Basic", basicHeader, {}, true, [besideBasic, besideBasic, besideBasic, besideBasic]],
			[
				"post",
				undefined,
				{ client_secret: clientSecret("post") },
				true,
				[besidePost, besidePost, besidePost, besidePost],
			],
			[
				"the assertion alone",
				undefined,
				{},
				true,
				[
					"app",
					"app",
					refusal("malformed_credentials", [], true),
					refusal("malformed_credentials", [], true),
				],
			],
		];
		const idOf: Record<string, string> = { Basic: "basic", post: "post", none: "pub" };
		for (const [name, header, body, withAssertion, expected] of cases) {
			const id = withAssertion && name === "the assertion alone" ? "app" : (idOf[name] ?? "app");
			for (const [at, shape] of shapes.entries()) {
				// A fresh one each time: an assertion is taken once.
				const assertion = withAssertion
					? { client_assertion_type: assertionType, client_assertion: await sign(claims()) }
					: {};
				const ids = {
					absent: {},
					one: { client_id: id },
					twice: { client_id: [id, id] },
					mistyped: { client_id: 7 },
				}[shape];
				const headers = new Map(header ? [["authorization", header]] : []);
				const fields = { ...body, ...assertion, ...ids };
				const request =
					shape === "mistyped"
						? testRequest({ method: "POST", headers, json: fields })
						: testRequest({
								method: "POST",
								headers,
								form: new Map(Object.entries(fields).map(([k, v]) => [k, [v].flat().map(String)])),
							});
				const result = await c.authenticate(request);
				const got = result.kind === "authenticated" ? result.client.id : result;
				const want = expected[at];
				const label = `${name}${withAssertion ? " beside an assertion" : ""}, client_id ${shape}`;
				if (typeof want === "string") expect(got, label).toBe(want);
				else expect(got, label).toMatchObject(want as object);
				if (typeof want !== "string" && !("assertion" in (want as object)))
					expect(got, label).not.toHaveProperty("assertion");
			}
		}
	});

	it("leaves a request with no part of an assertion to the other methods, and claims one with either part [rfc6749-2.3-b]", async () => {
		const { c } = await boot();
		const secret = { client_id: "post", client_secret: clientSecret("post") };
		expect(await outcome(c, asked(secret))).toBe("post");
		expect(await outcome(c, asked({ client_id: "pub" }))).toBe("pub");
		const typed = { ...secret, client_assertion_type: assertionType };
		expect(await outcome(c, asked(typed))).toBe("multiple_methods");
		const carried = { ...secret, client_assertion: await sign(claims()) };
		expect(await outcome(c, asked(carried))).toBe("multiple_methods");
	});

	it("is used only by clients registered for it [oidc-core-3.1.3.1-a]", async () => {
		const other = await boot({ method: "client_secret_post" });
		expect(await tried(other.c)).toBe("wrong_method");
		const none = await boot({ keys: [] });
		expect(await tried(none.c)).toBe("bad_credentials");
	});

	it("takes the operator's lifetime cap and clock allowance within their bounds, in whole seconds written with their unit", () => {
		const takes = (settings: Record<string, unknown>) => section.safeParse(settings).success;
		for (const fits of ["1s", "1d"]) expect(takes({ "max-lifetime": fits })).toBe(true);
		for (const fits of ["0s", "5m"]) expect(takes({ "clock-skew": fits })).toBe(true);
		for (const not of ["0s", "86401s", "1500ms", 3600, "3600"]) {
			expect(takes({ "max-lifetime": not }), String(not)).toBe(false);
		}
		for (const not of ["301s", "500ms", 30])
			expect(takes({ "clock-skew": not }), String(not)).toBe(false);
		expect(section.parse({})).toEqual({
			"max-lifetime": 3600,
			"clock-skew": 30,
			algorithms: ["ES256", "PS256", "EdDSA"],
		});
		expect(takes({ other: 1 })).toBe(false);
	});
});

it("takes all it names", async () => {
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused((await boot()).input))["client-assertion"]).toBeUndefined();
});
