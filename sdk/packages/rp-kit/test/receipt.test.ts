import { logTyps, type ReceiptCheck, tokens } from "@mod/transparency-wire";
import { describe, expect, it } from "vitest";
import { digest } from "../src/bytes.ts";
import { checkReceipt } from "../src/receipt.ts";
import { signCompact, signingKey } from "./fixtures.ts";

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
const subject = { of: "subject", id: "sub-1" } as const;
const now = 1_000_000;

/** A status signed by the keys given, as JWS JSON General Serialization. */
async function statusOf(
	signers: readonly Awaited<ReturnType<typeof signingKey>>[],
	body: unknown,
	header: Record<string, unknown> = {},
) {
	const payload = b64(body);
	const signatures = await Promise.all(
		signers.map(async (key) => {
			const compact = await signCompact(key, body, { typ: logTyps.status, ...header });
			const [protectedPart, , signature] = compact.split(".");
			return { protected: protectedPart, signature };
		}),
	);
	return JSON.stringify({ payload, signatures });
}

async function world(
	options: {
		receipt?: Record<string, unknown>;
		status?: Record<string, unknown>;
		claims?: Record<string, unknown>;
		signers?: number;
		frame?: "idToken" | "accessToken";
	} = {},
) {
	const log = await signingKey("ES256", "log-1");
	const s = [
		await signingKey("ES256", "st-a"),
		await signingKey("ES256", "st-b"),
		await signingKey("ES256", "st-c"),
	];
	const headerText = JSON.stringify({ alg: "ES256", typ: "JWT", kid: "iss-1" });
	const baseClaims = {
		iss: "https://id.example",
		sub: "sub-1",
		aud: "c1",
		exp: 2_000_000_000,
		...options.claims,
	};
	const input = tokens.digestInput(headerText, JSON.stringify(baseClaims));
	if ("error" in input) throw new Error(input.error);
	const receiptBody = {
		v: 1,
		iss: "log",
		id: "r-1",
		writer: { role: "core", instance: "i", image: "img", generation: 1 },
		kind: "bundle",
		flow: subject,
		position: 3,
		shard: "s1",
		n: 7,
		acceptedAt: now - 1000,
		plaintextDigest: await digest("p"),
		token: { frame: options.frame ?? "idToken", digest: await digest(input.input) },
		...options.receipt,
	};
	const txr = await signCompact(log, receiptBody, { typ: logTyps.receipt });
	const claims = { ...baseClaims, txr };
	const claimsText = JSON.stringify(claims);
	const unsigned = `${Buffer.from(headerText).toString("base64url")}.${Buffer.from(claimsText).toString("base64url")}`;
	const token = `${unsigned}.sig`;
	const statusBody = {
		v: 1,
		version: 4,
		shards: { s1: { watermark: 10, generation: 1, state: "running" } },
		deny: [],
		ext: {},
		...options.status,
	};
	const status = await statusOf(s.slice(0, options.signers ?? 2), statusBody);
	const strip = ({ alg: _a, kid: _k, ...jwk }: JsonWebKey & { kid?: string }) => jwk;
	const check: ReceiptCheck = {
		token,
		frame: "idToken",
		flow: subject,
		status,
		logKeys: [strip(log.jwk) as never],
		statusSigners: {
			v: 1,
			version: 4,
			purpose: "status",
			keys: s.map((key) => ({ kid: key.kid, key: strip(key.jwk) as never })),
			required: 2,
		},
		now,
		skew: 100,
		maxAge: 5000,
	};
	return { check, s, log, statusBody, receiptBody };
}

describe("checkReceipt (R16, R17)", () => {
	it("takes a token whose receipt is the log's, of its digest, frame and flow, recent, and checked by a status enough of its set signed", async () => {
		const { check, receiptBody } = await world();
		expect(await checkReceipt(check)).toEqual({ receipt: receiptBody });
	});

	it("names noReceipt for a token without its receipt, and receipt for one the log did not sign", async () => {
		const plain = await world();
		const [h, c] = plain.check.token.split(".");
		const claims = JSON.parse(Buffer.from(c ?? "", "base64url").toString());
		delete claims.txr;
		const bare = `${h}.${b64(claims)}.sig`;
		expect(await checkReceipt({ ...plain.check, token: bare })).toEqual({ fault: "noReceipt" });
		for (const token of [
			`${plain.check.token}.x`,
			plain.check.token.split(".").slice(0, 2).join("."),
		])
			expect(await checkReceipt({ ...plain.check, token }), token).toEqual({ fault: "noReceipt" });
		const stranger = await signingKey("ES256", "log-1");
		const { alg: _a, kid: _k, ...jwk } = stranger.jwk;
		expect(await checkReceipt({ ...plain.check, logKeys: [jwk as never] })).toEqual({
			fault: "receipt",
		});
	});

	it("names digest for a receipt of other bytes, kind for one of another frame or no bundle, flow for another flow", async () => {
		expect(
			await checkReceipt(
				(await world({ receipt: { token: { frame: "idToken", digest: await digest("x") } } }))
					.check,
			),
		).toEqual({ fault: "digest" });
		expect(await checkReceipt((await world({ frame: "accessToken" })).check)).toEqual({
			fault: "kind",
		});
		expect(
			await checkReceipt(
				(await world({ receipt: { flow: { of: "subject", id: "sub-2" } } })).check,
			),
		).toEqual({ fault: "flow" });
	});

	it("names tooOld for a receipt older than maxAge allows, the receiver's clock skew aside", async () => {
		const old = await world({ receipt: { acceptedAt: now - 5200 } });
		expect(await checkReceipt(old.check)).toEqual({ fault: "tooOld" });
		const edge = await world({ receipt: { acceptedAt: now - 5050 } });
		expect(await checkReceipt(edge.check)).toHaveProperty("receipt");
	});

	it("names tooOld where a time it is given is not a finite number, failing closed", async () => {
		const w = await world();
		for (const field of ["now", "skew", "maxAge"] as const)
			for (const value of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])
				expect(await checkReceipt({ ...w.check, [field]: value }), `${field} ${value}`).toEqual({
					fault: "tooOld",
				});
	});

	it("names receipt for a receipt accepted after now, the skew aside, which would stretch its life", async () => {
		const later = await world({ receipt: { acceptedAt: now + 101 } });
		expect(await checkReceipt(later.check)).toEqual({ fault: "receipt" });
		const edge = await world({ receipt: { acceptedAt: now + 100 } });
		expect(await checkReceipt(edge.check)).toHaveProperty("receipt");
		const both = await world({
			receipt: { acceptedAt: now + 101, flow: { of: "subject", id: "sub-2" } },
		});
		expect(await checkReceipt(both.check)).toEqual({ fault: "receipt" });
	});

	it("names status for a status fewer than its set's required signed, or that does not read", async () => {
		expect(await checkReceipt((await world({ signers: 1 })).check)).toEqual({ fault: "status" });
		const w = await world();
		expect(await checkReceipt({ ...w.check, status: "{}" })).toEqual({ fault: "status" });
		expect(
			await checkReceipt({
				...w.check,
				statusSigners: { ...w.check.statusSigners, purpose: "checkpoint" },
			}),
		).toEqual({ fault: "status" });
	});

	it("names status for a set that is not the wire's, one requiring no signature among them", async () => {
		const w = await world({ signers: 0 });
		for (const required of [0, Number.NaN, 1.5])
			expect(
				await checkReceipt({
					...w.check,
					statusSigners: { ...w.check.statusSigners, required },
				}),
				String(required),
			).toEqual({ fault: "status" });
	});

	it("counts one key named under two kids as one signer", async () => {
		const w = await world();
		const [a] = w.s;
		if (!a) throw new Error("a signer");
		const twin = { ...a, kid: "st-a2" };
		const keys = [
			...w.check.statusSigners.keys,
			{ ...w.check.statusSigners.keys[0], kid: "st-a2" },
		];
		expect(
			await checkReceipt({
				...w.check,
				status: await statusOf([a, twin], w.statusBody),
				statusSigners: { ...w.check.statusSigners, keys: keys as never },
			}),
		).toEqual({ fault: "status" });
	});

	it("names notYetChecked for a record past its shard's watermark, or a shard the status lacks", async () => {
		expect(
			await checkReceipt(
				(
					await world({
						status: { shards: { s1: { watermark: 6, generation: 1, state: "running" } } },
					})
				).check,
			),
		).toEqual({ fault: "notYetChecked" });
		expect(await checkReceipt((await world({ status: { shards: {} } })).check)).toEqual({
			fault: "notYetChecked",
		});
	});

	it("names notYetChecked for a shard named as what every object answers, which the status does not name", async () => {
		for (const shard of ["constructor", "toString", "valueOf", "hasOwnProperty"])
			expect(
				await checkReceipt((await world({ receipt: { shard, n: 999 } })).check),
				shard,
			).toEqual({ fault: "notYetChecked" });
	});

	it("names denied for a record in the not-accepted ids", async () => {
		expect(await checkReceipt((await world({ status: { deny: ["r-1"] } })).check)).toEqual({
			fault: "denied",
		});
	});
});
