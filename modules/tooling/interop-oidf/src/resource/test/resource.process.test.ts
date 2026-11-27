import {
	constants,
	createHash,
	generateKeyPairSync,
	type KeyObject,
	randomUUID,
	sign,
} from "node:crypto";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { stopAll } from "../../lifecycle/lifecycle.ts";
import { dpopKey, type ProofChange } from "../../rp/test/rp.ts";
import { type Answered, type At, ask } from "../../scene/test/ask.ts";
import { type SignedIn, signedIn } from "../../screen/test/signed-in.ts";
import { type Resource, startResource, thumbprintOf } from "./resource.ts";

const b64u = (bytes: Uint8Array | string) => Buffer.from(bytes).toString("base64url");
const sha256 = (text: string) => createHash("sha256").update(text).digest();
const now = () => Math.floor(Date.now() / 1000);
const partOf = (jws: string, at: 0 | 1) =>
	JSON.parse(Buffer.from(jws.split(".")[at] ?? "", "base64url").toString("utf8")) as Record<
		string,
		unknown
	>;

/** A JWS signed under `alg` by `key` (ES256, PS256 or EdDSA), as the harness makes one. */
function signed(alg: string, key: KeyObject, header: object, claims: object): string {
	const input = `${b64u(JSON.stringify({ alg, ...header }))}.${b64u(JSON.stringify(claims))}`;
	const signature =
		alg === "ES256"
			? sign("sha256", Buffer.from(input), { key, dsaEncoding: "ieee-p1363" })
			: alg === "PS256"
				? sign("sha256", Buffer.from(input), {
						key,
						padding: constants.RSA_PKCS1_PSS_PADDING,
						saltLength: 32,
					})
				: sign(null, Buffer.from(input), key);
	return `${input}.${b64u(signature)}`;
}

/** A key pair of a kind, its public JWK as a proof writes it. */
function pairOf(kind: "P-256" | "P-384" | "RSA-2048" | "RSA-1024" | "Ed25519" | "Ed448") {
	const pair =
		kind === "P-256" || kind === "P-384"
			? generateKeyPairSync("ec", { namedCurve: kind })
			: kind === "RSA-2048" || kind === "RSA-1024"
				? generateKeyPairSync("rsa", { modulusLength: kind === "RSA-2048" ? 2048 : 1024 })
				: kind === "Ed25519"
					? generateKeyPairSync("ed25519")
					: generateKeyPairSync("ed448");
	return {
		privateKey: pair.privateKey,
		jwk: pair.publicKey.export({ format: "jwk" }) as Record<string, unknown>,
	};
}

let dir = "";
let signedUp: SignedIn | undefined;
/** The resource taking the provider's tokens. */
let resource: Resource | undefined;
/** A resource taking tokens the harness signs, of a made-up issuer: for the token's own checks. */
let crafted: Resource | undefined;
let token = "";
let proofOf: (htm: string, htu: string, accessToken: string, change?: ProofChange) => string = () =>
	"";

const craftedIssuer = "https://issuer.crafted.invalid";
const craftedAudience = "https://resource.crafted.invalid";
const craftedKey = pairOf("P-256");

const started = () => {
	if (signedUp === undefined || resource === undefined || crafted === undefined)
		throw new Error("the setup did not start");
	return { signedUp, resource, crafted };
};
const atOf = (r: Resource): At => ({ origin: new URL(r.url).origin, certificate: r.certificate });
const url = () => started().resource.url;

/** A call at a resource, its headers as given. */
const call = (
	headers: Readonly<Record<string, string>>,
	path = "/resource",
	at: Resource = started().resource,
) => ask(atOf(at), path, { method: "GET", headers });

/** A call with the provider's token and a proof of the session's key, made wrong by `change` where given. */
const proved = (change?: ProofChange, htu = url()) =>
	call({ authorization: `DPoP ${token}`, dpop: proofOf("GET", htu, token, change) });

/** The answer is the refusal named, and the resource kept it so. */
const refusedAs = (
	answer: Answered,
	status: number,
	error: string,
	description: string,
	at: Resource = started().resource,
) => {
	expect(answer.status).toBe(status);
	expect(answer.json).toEqual({ error, error_description: description });
	expect(String(answer.headers["www-authenticate"])).toBe(
		`DPoP error="${error}", error_description="${description}", algs="ES256 PS256 EdDSA"`,
	);
	expect(at.refused().at(-1)).toEqual({ status, error, description });
};

/** The claims changed, the header kept. */
const claims =
	(changed: Readonly<Record<string, unknown>>): ProofChange =>
	(parts) => ({ header: parts.header, claims: { ...parts.claims, ...changed } });

/** The header changed, the claims kept. */
const header =
	(
		changed: (parts: Parameters<ProofChange>[0]) => Readonly<Record<string, unknown>>,
	): ProofChange =>
	(parts) => ({ header: { ...parts.header, ...changed(parts) }, claims: parts.claims });

/** A token the harness signs for the crafted resource, bound to `jkt`, its claims and header changed. */
const craftedToken = (
	jkt: string | undefined,
	changed: Readonly<Record<string, unknown>> = {},
	head: Readonly<Record<string, unknown>> = {},
) =>
	signed(
		"ES256",
		craftedKey.privateKey,
		{ typ: "at+jwt", kid: "crafted", ...head },
		{
			iss: craftedIssuer,
			aud: craftedAudience,
			sub: "crafted",
			exp: now() + 300,
			...(jkt !== undefined && { cnf: { jkt } }),
			...changed,
		},
	);

/** A proof by a pair under `alg`, for the crafted resource's URL and a token. */
const proofBy = (pair: ReturnType<typeof pairOf>, alg: string, accessToken: string) =>
	signed(
		alg,
		pair.privateKey,
		{ typ: "dpop+jwt", jwk: pair.jwk },
		{
			jti: randomUUID(),
			htm: "GET",
			htu: started().crafted.url,
			iat: now(),
			ath: b64u(sha256(accessToken)),
		},
	);

/** A call at the crafted resource with a token and a proof by `pair` under `alg`. */
const craftedCall = (accessToken: string, pair = craftedKey, alg = "ES256") =>
	call(
		{ authorization: `DPoP ${accessToken}`, dpop: proofBy(pair, alg, accessToken) },
		"/resource",
		started().crafted,
	);

beforeAll(async () => {
	dir = await mkdtemp(join(tmpdir(), "interop-oidf-resource-"));
	for (const own of ["provider", "crafted"]) await mkdir(join(dir, own));
	signedUp = await signedIn({
		clientId: "rp-resource",
		redirectUri: "https://rp.example.invalid/cb",
	});
	const { scene, at } = signedUp;
	resource = await startResource({
		host: "localhost",
		listen: "127.0.0.1",
		dir: join(dir, "provider"),
		issuer: () => scene.issuer,
		// The audience a token has where no `resource` is asked: the issuer (pinned below).
		audience: () => scene.issuer,
		jwks: async () => (await at("/jwks.json", {})).json.keys as Readonly<Record<string, unknown>>[],
	});
	crafted = await startResource({
		host: "localhost",
		listen: "127.0.0.1",
		dir: join(dir, "crafted"),
		issuer: () => craftedIssuer,
		audience: () => craftedAudience,
		jwks: async () => [
			{ ...craftedKey.jwk, kid: "crafted", use: "sig", alg: "ES256" },
			{ ...craftedKey.jwk, kid: "crafted-enc", use: "enc" },
			{ ...craftedKey.jwk, kid: "crafted-ps", alg: "PS256" },
		],
	});
	const { session, tokens } = await signedUp.login();
	token = String(tokens.access_token);
	proofOf = (htm, htu, accessToken, change) =>
		session.proof(htm, htu, undefined, accessToken, change);
}, 180_000);

afterAll(async () => {
	// The resources first (they read the scene's keys), the scene next, the directory (their certificates) last.
	const problems = await stopAll([
		async () => (dir === "" ? undefined : rm(dir, { recursive: true, force: true })),
		async () => signedUp?.stop(),
		async () => resource?.stop(),
		async () => crafted?.stop(),
	]);
	if (problems.length > 0) throw new AggregateError(problems, "the resource's test did not stop");
}, 30_000);

describe("the provider's token, as the resource meets it", () => {
	it("is an at+jwt for the issuer, the audience where no resource is asked", () => {
		expect(partOf(token, 0).typ).toBe("at+jwt");
		expect(partOf(token, 1).aud).toBe(started().signedUp.scene.issuer);
	});
});

describe("the resource takes the provider's DPoP-bound access token with a proof of its key", () => {
	it("answers a call with the token's subject, and a Date header", async () => {
		const answer = await proved();
		expect(answer.status).toBe(200);
		expect(typeof answer.json.sub).toBe("string");
		expect(Number.isNaN(Date.parse(String(answer.headers.date)))).toBe(false);
	});

	it("takes the scheme in any case, and more than one space after it", async () => {
		const loud = await call({ authorization: `dPoP ${token}`, dpop: proofOf("GET", url(), token) });
		expect(loud.status).toBe(200);
		const spaced = await call({
			authorization: `DPoP   ${token}`,
			dpop: proofOf("GET", url(), token),
		});
		expect(spaced.status).toBe(200);
	});

	it("takes the proof's typ in any case, and with application/", async () => {
		for (const typ of ["DPoP+JWT", "application/dpop+jwt"])
			expect((await proved(header(() => ({ typ })))).status).toBe(200);
	});

	it("compares htu without the call's query or the proof's, nor a fragment (RFC 9449 §4.3)", async () => {
		const queried = await call(
			{ authorization: `DPoP ${token}`, dpop: proofOf("GET", url(), token) },
			"/resource?x=1",
		);
		expect(queried.status).toBe(200);
		expect((await proved(undefined, `${url()}?y=2#part`)).status).toBe(200);
	});

	it("compares htu's scheme and host in any case", async () => {
		const loud = url().replace("https://localhost", "HTTPS://LOCALHOST");
		expect(loud).not.toBe(url());
		expect((await proved(undefined, loud)).status).toBe(200);
	});

	it("takes a proof made half a minute away, either way (iat within 60 s)", async () => {
		for (const iat of [now() - 30, now() + 30])
			expect((await proved(claims({ iat }))).status).toBe(200);
	});

	it("does not spend a refused proof's jti", async () => {
		const proof = proofOf("GET", url(), token);
		expect((await call({ authorization: `Bearer ${token}`, dpop: proof })).status).toBe(401);
		expect((await call({ authorization: `DPoP ${token}`, dpop: proof })).status).toBe(200);
	});

	it("echoes the interaction id it is sent", async () => {
		const answer = await call({
			authorization: `DPoP ${token}`,
			dpop: proofOf("GET", url(), token),
			"x-fapi-interaction-id": "c770aef3-6784-41f7-8e0e-ff5f97bddb3a",
		});
		expect(answer.status).toBe(200);
		expect(answer.headers["x-fapi-interaction-id"]).toBe("c770aef3-6784-41f7-8e0e-ff5f97bddb3a");
	});
});

describe("the resource refuses a call that sends no DPoP-bound token", () => {
	it("answers a call with no credentials by the challenge alone (RFC 6750 §3.1)", async () => {
		const answer = await call({});
		expect(answer.status).toBe(401);
		expect(answer.headers["www-authenticate"]).toBe('DPoP algs="ES256 PS256 EdDSA"');
		expect(answer.text).toBe("");
		expect(started().resource.refused().at(-1)).toEqual({ status: 401 });
	});

	it("refuses a token in the query (RFC 6750 §2.3 is not taken)", async () => {
		const answer = await call({}, `/resource?access_token=${token}`);
		expect(answer.status).toBe(400);
		expect(answer.json).toEqual({
			error: "invalid_request",
			error_description: "a token in the query",
		});
	});

	it("refuses a Bearer token", async () => {
		const answer = await call({
			authorization: `Bearer ${token}`,
			dpop: proofOf("GET", url(), token),
		});
		refusedAs(answer, 401, "invalid_token", "a DPoP-bound token, sent as DPoP");
	});

	it("refuses a token with no proof", async () => {
		refusedAs(
			await call({ authorization: `DPoP ${token}` }),
			401,
			"invalid_dpop_proof",
			"no DPoP proof",
		);
	});

	it("refuses a token not the provider's", async () => {
		const [head = "", body = ""] = token.split(".");
		const forged = `${head}.${body}.${b64u("not a signature")}`;
		const answer = await call({
			authorization: `DPoP ${forged}`,
			dpop: proofOf("GET", url(), forged),
		});
		refusedAs(answer, 401, "invalid_token", "the token's signature");
	});

	it("answers no other path", async () => {
		const other = url().replace("/resource", "/other");
		const answer = await call(
			{ authorization: `DPoP ${token}`, dpop: proofOf("GET", other, token) },
			"/other",
		);
		expect(answer.status).toBe(404);
	});
});

describe("the resource checks the token itself (RFC 9068 §4, a token the harness signs)", () => {
	const jkt = () => thumbprintOf(craftedKey.jwk);
	const refusedToken = async (accessToken: string, description: string) =>
		refusedAs(await craftedCall(accessToken), 401, "invalid_token", description, started().crafted);

	it("takes a token of its issuer, for its audience, bound to the proof's key", async () => {
		expect((await craftedCall(craftedToken(jkt()))).status).toBe(200);
		expect((await craftedCall(craftedToken(jkt(), { aud: ["x", craftedAudience] }))).status).toBe(
			200,
		);
	});

	it("refuses a token of another type (an ID token's JWT)", async () => {
		await refusedToken(craftedToken(jkt(), {}, { typ: "JWT" }), "the token's typ");
	});

	it("refuses a token by a key not published, or naming none", async () => {
		await refusedToken(craftedToken(jkt(), {}, { kid: "another" }), "the token's key");
		await refusedToken(craftedToken(jkt(), {}, { kid: undefined }), "the token's key");
	});

	it("refuses a token by a published key not for signing, or for another algorithm", async () => {
		await refusedToken(craftedToken(jkt(), {}, { kid: "crafted-enc" }), "the token's key");
		await refusedToken(craftedToken(jkt(), {}, { kid: "crafted-ps" }), "the token's key");
	});

	it("refuses a token whose segment is not as its bytes encode, though signed (RFC 7515 App. C)", async () => {
		const [head = "", body = ""] = craftedToken(jkt()).split(".");
		// The header's JSON padded with spaces to whole quads, then a letter added, which Node's decoder drops.
		const json = Buffer.from(head, "base64url").toString("utf8");
		const quads = b64u(`${json}${" ".repeat((3 - (Buffer.byteLength(json) % 3)) % 3)}`);
		expect(quads.length % 4).toBe(0);
		const input = `${quads}A.${body}`;
		const signature = sign("sha256", Buffer.from(input), {
			key: craftedKey.privateKey,
			dsaEncoding: "ieee-p1363",
		});
		await refusedToken(`${input}.${b64u(signature)}`, "the token is no JWS");
	});

	it("refuses a token of another issuer", async () => {
		await refusedToken(craftedToken(jkt(), { iss: "https://other.invalid" }), "the token's issuer");
	});

	it("refuses a token for another audience, or whose list holds other than strings", async () => {
		await refusedToken(
			craftedToken(jkt(), { aud: "https://other.invalid" }),
			"the token's audience",
		);
		await refusedToken(craftedToken(jkt(), { aud: [42, craftedAudience] }), "the token's audience");
	});

	it("refuses a token expired, or not yet valid", async () => {
		await refusedToken(craftedToken(jkt(), { exp: now() - 1 }), "the token has expired");
		await refusedToken(craftedToken(jkt(), { nbf: now() + 3600 }), "the token is not yet valid");
	});

	it("refuses a token bound to no key", async () => {
		await refusedToken(craftedToken(undefined), "the token is bound to no key");
	});
});

describe("the resource takes a proof under each algorithm FAPI 2.0 takes, by the key it takes", () => {
	for (const [kind, alg] of [
		["RSA-2048", "PS256"],
		["Ed25519", "EdDSA"],
	] as const)
		it(`takes ${alg} by ${kind}`, async () => {
			const pair = pairOf(kind);
			const answer = await craftedCall(craftedToken(thumbprintOf(pair.jwk)), pair, alg);
			expect(answer.status).toBe(200);
		});

	for (const [kind, alg] of [
		["P-384", "ES256"],
		["Ed448", "EdDSA"],
		["RSA-1024", "PS256"],
	] as const)
		it(`refuses ${alg} by ${kind} (FAPI 2.0 §5.4.1)`, async () => {
			const pair = pairOf(kind);
			const answer = await craftedCall(craftedToken(thumbprintOf(pair.jwk)), pair, alg);
			refusedAs(answer, 401, "invalid_dpop_proof", "the proof's algorithm", started().crafted);
		});
});

describe("the resource refuses a proof that does not prove this call by the token's key", () => {
	it("refuses a proof by another key", async () => {
		const other = dpopKey().proof("GET", url(), undefined, token);
		const answer = await call({ authorization: `DPoP ${token}`, dpop: other });
		refusedAs(answer, 401, "invalid_token", "the proof is not of the token's key");
	});

	it("refuses a proof naming the token's key, signed by another", async () => {
		const ownKey = partOf(proofOf("GET", url(), token), 0).jwk;
		const other = dpopKey().proof(
			"GET",
			url(),
			undefined,
			token,
			header(() => ({ jwk: ownKey })),
		);
		const answer = await call({ authorization: `DPoP ${token}`, dpop: other });
		refusedAs(answer, 401, "invalid_dpop_proof", "the proof's signature");
	});

	it("refuses a proof not a JWS: a bad segment, an extension it does not know, an alg not a string", async () => {
		const proof = proofOf("GET", url(), token);
		const bad = await call({ authorization: `DPoP ${token}`, dpop: `${proof}!` });
		refusedAs(bad, 401, "invalid_dpop_proof", "the proof is no JWS");
		// 86 letters and three more: one left over a quad, bits Node's decoder drops.
		const extra = await call({ authorization: `DPoP ${token}`, dpop: `${proof}AAA` });
		refusedAs(extra, 401, "invalid_dpop_proof", "the proof is no JWS");
		// The last letter's unused bits set: the same bytes, a letter no encoder writes (RFC 4648 §3.5).
		const last = proof.at(-1) ?? "A";
		const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
		const twin = `${proof.slice(0, -1)}${letters[letters.indexOf(last) ^ 1]}`;
		expect(Buffer.from(twin.split(".")[2] ?? "", "base64url")).toEqual(
			Buffer.from(proof.split(".")[2] ?? "", "base64url"),
		);
		const bits = await call({ authorization: `DPoP ${token}`, dpop: twin });
		refusedAs(bits, 401, "invalid_dpop_proof", "the proof is no JWS");
		for (const changed of [header(() => ({ crit: ["exp"] })), header(() => ({ alg: ["ES256"] }))])
			refusedAs(await proved(changed), 401, "invalid_dpop_proof", "the proof is no JWS");
	});

	it("refuses a proof of another token (ath)", async () => {
		const answer = await call({
			authorization: `DPoP ${token}`,
			dpop: proofOf("GET", url(), "another"),
		});
		refusedAs(answer, 401, "invalid_dpop_proof", "the proof's ath");
	});

	it("refuses a proof of another method (htm)", async () => {
		refusedAs(await proved(claims({ htm: "PUT" })), 401, "invalid_dpop_proof", "the proof's htm");
	});

	it("refuses a proof of another URL (htu)", async () => {
		const answer = await proved(undefined, url().replace("/resource", "/other"));
		refusedAs(answer, 401, "invalid_dpop_proof", "the proof's htu");
	});

	it("refuses a proof made two minutes away, either way (iat)", async () => {
		for (const iat of [now() - 120, now() + 120])
			refusedAs(await proved(claims({ iat })), 401, "invalid_dpop_proof", "the proof's iat");
	});

	it("takes a proof once (jti)", async () => {
		const proof = proofOf("GET", url(), token);
		expect((await call({ authorization: `DPoP ${token}`, dpop: proof })).status).toBe(200);
		const again = await call({ authorization: `DPoP ${token}`, dpop: proof });
		refusedAs(again, 401, "invalid_dpop_proof", "the proof was used already");
	});

	it("refuses a proof whose key is a private one", async () => {
		const answer = await proved(header((parts) => ({ jwk: parts.privateJwk })));
		refusedAs(answer, 401, "invalid_dpop_proof", "the proof's key is private");
	});

	it("refuses a proof under alg none", async () => {
		const answer = await proved(header(() => ({ alg: "none" })));
		refusedAs(answer, 401, "invalid_dpop_proof", "the proof's algorithm");
	});

	it("refuses a proof of another typ", async () => {
		refusedAs(
			await proved(header(() => ({ typ: "jwt" }))),
			401,
			"invalid_dpop_proof",
			"the proof's typ",
		);
	});

	it("refuses two proofs", async () => {
		const answer = await call({
			authorization: `DPoP ${token}`,
			dpop: `${proofOf("GET", url(), token)}, ${proofOf("GET", url(), token)}`,
		});
		refusedAs(answer, 401, "invalid_dpop_proof", "more than one proof");
	});
});

describe("the provider's apps, through a login to a signed token, every Core call relayed by the Front", () => {
	it("ran held by the permission model in audit, reaching nothing its grants do not cover, to its stop", async () => {
		const { scene } = started().signedUp;
		// Stopped first, so each server's drain is in what it wrote; the scene's stop is once, its later calls nothing.
		await scene.stop();
		const servers = scene
			.outputs()
			.filter(({ name }) => name === "nextgen-core" || name === "nextgen-front");
		expect(servers.map(({ name }) => name)).toEqual(["nextgen-core", "nextgen-front"]);
		for (const { name, out } of servers)
			expect(out, name).toContain('{"event":"app-permissions.held","mode":"audit"}');
		// Anywhere in a line: stdout and stderr arrive in one text, an event line may follow a log line's part.
		const events = scene
			.outputs()
			.flatMap(({ out }) => out.split("\n"))
			.filter((line) => line.includes('"event":"app-permissions.event"'));
		expect(events, scene.output()).toEqual([]);
	});
});
