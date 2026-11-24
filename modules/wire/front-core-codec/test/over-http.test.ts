import { overHttp, type RequestKind, requests } from "@mod/front-core-wire";
import { describe, expect, it } from "vitest";
import { carriedOf, decodeRequest, messageOf, operationAt } from "../src/contract.ts";
import { fuzzer } from "../src/testing.ts";

const seed = Number(process.env.WIRE_FUZZ_SEED ?? 20261124);
const cases = Number(process.env.WIRE_FUZZ_CASES ?? 2000);
const { pick, validFrame } = fuzzer(seed);
const kinds = Object.keys(requests) as RequestKind[];
const values = (entries: Record<string, string | string[]>) =>
	new Map(Object.entries(entries).map(([k, v]) => [k, [v].flat()]));
const carried = (
	body: Record<string, string | string[]>,
	headers: Record<string, string> = {},
	source?: string,
) => ({
	values: values(body),
	headers: new Map(Object.entries(headers)),
	...(source === undefined ? {} : { source }),
});

describe("an operation over HTTP", () => {
	it("reads back every message it carries, as the Core rebuilds what the Front read", () => {
		for (let i = 0; i < cases; i++) {
			const kind = pick(kinds);
			const decoded = decodeRequest(validFrame(kind));
			if (!decoded.ok) throw new Error("a valid frame");
			const { message } = decoded.value;
			const sent = carriedOf(kind, message as never);
			const read = messageOf(kind, sent);
			expect(read, kind).toEqual({ ok: true, message });
			expect(operationAt("POST", overHttp.operations[kind].path, sent.values)).toBe(kind);
		}
	});

	it("reads a code's exchange from the token endpoint's form, the DPoP proof from its header", () => {
		const read = messageOf(
			"token",
			carried(
				{
					grant_type: "authorization_code",
					code: "abc",
					redirect_uri: "https://rp.example/cb",
					code_verifier: "v".repeat(43),
					client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
					client_assertion: "a.b.c",
				},
				{ dpop: "d.e.f" },
				"203.0.113.7",
			),
		);
		expect(read).toEqual({
			ok: true,
			message: {
				source: "203.0.113.7",
				grantType: 1,
				code: "abc",
				redirectUri: "https://rp.example/cb",
				codeVerifier: "v".repeat(43),
				clientAssertionType: 1,
				clientAssertion: "a.b.c",
				clientId: "",
				authorizationDetails: 0,
				dpop: "d.e.f",
			},
		});
	});

	it("reads any other grant or assertion type as `other`, and authorization details as sent or not", () => {
		const read = messageOf(
			"token",
			carried({ grant_type: "password", client_assertion_type: "x", authorization_details: "[]" }),
		);
		expect(read.ok && read.message).toMatchObject({
			grantType: 0,
			clientAssertionType: 0,
			authorizationDetails: 1,
		});
		const rebuilt = carriedOf("token", read.ok ? read.message : ({} as never));
		expect(rebuilt.values.get("grant_type")).toEqual(["other"]);
		expect(rebuilt.values.has("client_id")).toBe(false);
	});

	it("tells the Core a pushed request named a request_uri, which it must refuse, keeping the name in what it rebuilds", () => {
		const form = {
			request: "a.b.c",
			client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			client_assertion: "d.e.f",
		};
		const sent = messageOf("par", carried({ ...form, request_uri: "urn:x" }));
		expect(sent.ok && sent.message).toMatchObject({ requestUriSent: 1, authorizationDetails: 0 });
		const rebuilt = carriedOf("par", sent.ok ? sent.message : ({} as never));
		expect(rebuilt.values.has("request_uri")).toBe(true);
		const plain = messageOf("par", carried(form));
		expect(plain.ok && plain.message).toMatchObject({ requestUriSent: 0 });
		expect(
			carriedOf("par", plain.ok ? plain.message : ({} as never)).values.has("request_uri"),
		).toBe(false);
	});

	it("carries the declared source apart from the request, never reading it from the body or a header", () => {
		const read = messageOf(
			"loginFinish",
			carried(
				{ statement: "a.b.c", assertion: "x", source: "198.51.100.1" },
				{ source: "198.51.100.2" },
			),
		);
		expect(read.ok && read.message.source).toBe("");
		const declared = messageOf(
			"loginFinish",
			carried({ statement: "a.b.c", assertion: "x" }, {}, "2001:db8::1"),
		);
		expect(declared.ok && declared.message.source).toBe("2001:db8::1");
		const rebuilt = carriedOf("loginFinish", {
			source: "2001:db8::1",
			statement: "a.b.c",
			assertion: "x",
		});
		expect([rebuilt.source, rebuilt.values.has("source"), rebuilt.headers.has("source")]).toEqual([
			"2001:db8::1",
			false,
			false,
		]);
	});

	it("picks the refresh by its grant type at the shared path, and nothing for another method or path", () => {
		expect(operationAt("POST", "/oauth/token", values({ grant_type: "refresh_token" }))).toBe(
			"refresh",
		);
		expect(operationAt("POST", "/oauth/token", values({ grant_type: "authorization_code" }))).toBe(
			"token",
		);
		expect(
			operationAt("POST", "/oauth/token", values({ grant_type: ["refresh_token", "x"] })),
		).toBe("token");
		expect(operationAt("GET", "/oauth/token", values({}))).toBeUndefined();
		expect(operationAt("POST", "/oauth/token/", values({}))).toBeUndefined();
		const rebuilt = carriedOf("refresh", {
			source: "",
			refreshToken: "r",
			scope: "",
			clientAssertionType: 1,
			clientAssertion: "a.b.c",
			clientId: "",
			authorizationDetails: 0,
			dpop: "",
		});
		expect([...rebuilt.values.keys()][0]).toBe("grant_type");
		expect(rebuilt.values.get("grant_type")).toEqual(["refresh_token"]);
		expect(rebuilt.source).toBeUndefined();
	});

	it("refuses a repeated name, an unknown enum text, and bytes not in canonical base64url, naming the field", () => {
		expect(messageOf("loginFinish", carried({ statement: ["a", "b"] }))).toEqual({
			ok: false,
			field: "statement",
			error: "fieldSyntax",
		});
		expect(messageOf("firstKeyNonce", carried({ stage: "later" }))).toEqual({
			ok: false,
			field: "stage",
			error: "enumRange",
		});
		expect(messageOf("firstKeyContinue", carried({ seq: "01" }))).toMatchObject({
			field: "seq",
			error: "enumRange",
		});
		for (const eEnc of ["AB+/", "AB==", "AC", "A"]) {
			expect(messageOf("loginStart", carried({ eEnc })), eEnc).toMatchObject({
				field: "eEnc",
				error: "fieldSyntax",
			});
		}
		expect(messageOf("loginStart", carried({ eEnc: "AA" }))).toMatchObject({ ok: true });
		expect(messageOf("loginFinish", carried({ statement: "fieldSyntax" }))).toMatchObject({
			ok: true,
			message: { statement: "fieldSyntax" },
		});
	});
});
