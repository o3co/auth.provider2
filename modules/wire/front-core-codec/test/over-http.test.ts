import { type FieldSpec, overHttp, type RequestKind, requests } from "@mod/front-core-wire";
import { describe, expect, it } from "vitest";
import {
	type Carried,
	carriedOf,
	decodeRequest,
	encodeRequest,
	messageOf,
	operationAt,
	requestOf,
	WireEncodeError,
} from "../src/contract.ts";
import { fuzzer } from "../src/testing.ts";

const seed = Number(process.env.WIRE_FUZZ_SEED ?? 20261124);
const cases = Number(process.env.WIRE_FUZZ_CASES ?? 2000);
const { int, pick, validFrame, mutate } = fuzzer(seed);
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
	mistyped: new Set<string>(),
	...(source === undefined ? {} : { source }),
});

describe("an operation over HTTP", () => {
	it(
		"reads back every message it carries, as the Core rebuilds what the Front read",
		() => {
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
		},
		Math.max(5000, cases * 4),
	);

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
		expect(messageOf("continue", carried({ stage: "rename", seq: "01" }))).toMatchObject({
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

	it("holds a read request's every field to its spec, as the encoder does: missing, sized or spelt outside it, named", () => {
		const nonce = "A".repeat(43);
		const sealed = {
			nonce,
			eEnc: Buffer.alloc(65, 4).toString("base64url"),
			eSigX: Buffer.alloc(32, 1).toString("base64url"),
			eSigY: Buffer.alloc(32, 2).toString("base64url"),
			enc: Buffer.alloc(65, 4).toString("base64url"),
			ct: Buffer.alloc(17, 3).toString("base64url"),
		};
		const kind = operationAt("POST", "/first-key/start", values(sealed));
		if (!kind) throw new Error("the first key's start");
		// Every message carried and read back is within its spec.
		for (let i = 0; i < cases; i++) {
			const k = pick(kinds);
			const decoded = decodeRequest(validFrame(k));
			if (!decoded.ok) throw new Error("a valid frame");
			expect(requestOf(k, carriedOf(k, decoded.value.message as never)).ok).toBe(true);
		}
		expect(requestOf(kind, carried(sealed)).ok).toBe(true);
		const { ct: _, ...missing } = sealed;
		for (const [body, field, error] of [
			[missing, "ct", "fieldLength"],
			[{ ...sealed, eEnc: Buffer.alloc(64).toString("base64url") }, "eEnc", "fieldLength"],
			[{ ...sealed, ct: Buffer.alloc(2049).toString("base64url") }, "ct", "fieldLength"],
			[{ ...sealed, nonce: "A".repeat(42) }, "nonce", "fieldLength"],
			[{ ...sealed, nonce: `${"A".repeat(42)}+` }, "nonce", "fieldSyntax"],
		] as const) {
			// messageOf leaves each of these to the encoder; requestOf refuses it, naming the field.
			expect(messageOf(kind, carried(body)).ok, field).toBe(true);
			expect(requestOf(kind, carried(body)), field).toEqual({ ok: false, field, error });
		}
	});

	it("refuses an enum's number past its count, never wrapped to a byte within it", () => {
		const decoded = decodeRequest(validFrame("continue"));
		if (!decoded.ok) throw new Error("a valid frame");
		const sent = carriedOf("continue", decoded.value.message as never);
		for (const seq of ["17", "255", "256", "257", "272"]) {
			const values = new Map(sent.values);
			values.set("seq", [seq]);
			expect(requestOf("continue", { ...sent, values }), seq).toEqual({
				ok: false,
				field: "seq",
				error: "enumRange",
			});
		}
	});

	it("refuses a text with a lone surrogate, never checked as the bytes of U+FFFD", () => {
		const decoded = decodeRequest(validFrame("continue"));
		if (!decoded.ok) throw new Error("a valid frame");
		const sent = carriedOf("continue", decoded.value.message as never);
		for (const body of ["\ud800", "a\udfffb", "\udc00\ud800"]) {
			const values = new Map(sent.values);
			values.set("body", [body]);
			expect(requestOf("continue", { ...sent, values })).toEqual({
				ok: false,
				field: "body",
				error: "fieldSyntax",
			});
		}
		// A surrogate pair is one character, well formed.
		const values = new Map(sent.values);
		values.set("body", ["\ud83d\ude00"]);
		expect(requestOf("continue", { ...sent, values }).ok).toBe(true);
	});

	it("refuses a value carried as no text, never throwing, whatever its type claims", () => {
		const decoded = decodeRequest(validFrame("continue"));
		if (!decoded.ok) throw new Error("a valid frame");
		const sent = carriedOf("continue", decoded.value.message as never);
		for (const [name, value] of [
			["ct", 5],
			["sig", { toString: () => "AAAA" }],
			["body", 7],
			["seq", 1],
		] as const) {
			const values = new Map(sent.values) as Map<string, unknown>;
			values.set(name, [value]);
			const carried = { ...sent, values } as never;
			expect(messageOf("continue", carried), name).toEqual({
				ok: false,
				field: name,
				error: "fieldSyntax",
			});
			expect(requestOf("continue", carried), name).toEqual({
				ok: false,
				field: name,
				error: "fieldSyntax",
			});
		}
	});

	it("refuses a field the body sent as no text, never reading it as absent, and ignores any other name", () => {
		const decoded = decodeRequest(validFrame("continue"));
		if (!decoded.ok) throw new Error("a valid frame");
		const sent = carriedOf("continue", decoded.value.message as never);
		for (const name of ["body", "sig", "enc", "ct", "statement"]) {
			const values = new Map(sent.values);
			values.delete(name);
			const carried = { ...sent, values, mistyped: new Set([name]) };
			const refused = { ok: false, field: name, error: "fieldSyntax" };
			expect(messageOf("continue", carried), name).toEqual(refused);
			expect(requestOf("continue", carried), name).toEqual(refused);
		}
		// A name the wire gives no field under, sent as no text, is ignored, as an unknown text is.
		expect(requestOf("continue", { ...sent, mistyped: new Set(["extra", "source"]) }).ok).toBe(
			true,
		);
		// None named, as before.
		expect(requestOf("continue", { ...sent, mistyped: new Set() }).ok).toBe(true);
	});
});

// C9: what the Front reads from a browser or a client (`messageOf`, then the encoder) and the Core's
// routes read (`requestOf`), given HTTP no honest client need send.
describe("an operation over HTTP from a hostile sender", () => {
	const side = (kind: RequestKind) => overHttp.operations[kind];
	const specs = (kind: RequestKind) => requests[kind].fields as readonly FieldSpec[];
	const nameOf = (kind: RequestKind, field: string) => side(kind).bodyNames?.[field] ?? field;
	/** The fields read from the body, by their HTTP names: neither a header's nor the declared source. */
	const bodyFields = (kind: RequestKind) =>
		specs(kind).filter(
			(f) => f.name !== overHttp.declaredSource && !side(kind).headerNames?.[f.name],
		);
	const headerFields = (kind: RequestKind) =>
		specs(kind).filter((f) => side(kind).headerNames?.[f.name]);
	const allNames = (kind: RequestKind) =>
		new Set([
			...specs(kind).map((f) => nameOf(kind, f.name)),
			...specs(kind).map((f) => f.name),
			...Object.values(side(kind).headerNames ?? {}),
			...(side(kind).discriminator ? [side(kind).discriminator?.name as string] : []),
		]);
	const edge = [
		"",
		"a".repeat(5000),
		"\ud800",
		"\u0000",
		"AA==",
		"A+/",
		"017",
		"-1",
		"1e3",
		"17",
		"other",
		"unknown-text",
		"Ä",
		"a b",
		"A".repeat(43),
		"constructor",
		"__proto__",
		"toString",
		"0",
		"1",
		"AUTHORIZATION_CODE",
		"Refresh_Token",
		" refresh_token",
	];
	const text = () =>
		int(2) === 0
			? pick(edge)
			: Array.from({ length: int(12) }, () => String.fromCharCode(32 + int(95))).join("");
	const valid = (kind: RequestKind) => {
		const decoded = decodeRequest(validFrame(kind));
		if (!decoded.ok) throw new Error("a valid frame");
		return carriedOf(kind, decoded.value.message as never);
	};
	/** One to three changes to a carried request, of the kinds a sender can make. */
	function hostile(kind: RequestKind): Carried {
		const base = valid(kind);
		const values = new Map([...base.values].map(([k, v]) => [k, [...v]]));
		const headers = new Map(base.headers);
		const mistyped = new Set<string>();
		let source = base.source;
		const bodyNames = [...values.keys()];
		const names = [...allNames(kind), "x", "source", "x-forwarded-for"];
		for (let k = 1 + int(3); k > 0; k--) {
			const name = pick(bodyNames.length > 0 && int(3) > 0 ? bodyNames : names);
			switch (int(10)) {
				case 0:
					values.delete(name);
					break;
				case 1:
					values.set(name, [...(values.get(name) ?? [text()]), text()]);
					break;
				case 2: {
					const to = pick(names);
					values.set(to, values.get(name) ?? [text()]);
					values.delete(name);
					break;
				}
				case 3:
					values.set(pick(["x", "y", "__proto__", "constructor"]), [text()]);
					break;
				case 4:
					values.set(name, [text()]);
					break;
				case 5: {
					const header = pick([
						...Object.values(side(kind).headerNames ?? {}),
						...Object.values(side(kind).headerNames ?? {}).map((h) => `x-${h}`),
						"dpop",
						"x-forwarded-for",
					]);
					int(2) === 0 ? headers.delete(header) : headers.set(header, text());
					break;
				}
				case 6:
					mistyped.add(name);
					break;
				case 7:
					source = pick([undefined, "", "203.0.113.9", "名前", text()]);
					break;
				case 9: {
					// An enum's own texts in another case, or a name every object answers to, at that very field.
					const named = specs(kind).filter(
						(f) => f.type === "enum" && side(kind).enumTexts?.[f.name],
					);
					const f = named.length > 0 ? pick(named) : undefined;
					const texts = f ? Object.keys(side(kind).enumTexts?.[f.name]?.texts ?? {}) : [];
					if (f && texts.length > 0) {
						const t = pick(texts);
						values.set(nameOf(kind, f.name), [
							pick([
								t.toUpperCase(),
								`${t[0]?.toUpperCase()}${t.slice(1)}`,
								` ${t}`,
								"constructor",
								"__proto__",
								"toString",
							]),
						]);
					}
					break;
				}
				case 8: {
					// A decimal enum's number past its count: read by messageOf, refused by the encoder and requestOf.
					const decimal = specs(kind).filter(
						(f) => f.type === "enum" && !side(kind).enumTexts?.[f.name],
					);
					const f = decimal.length > 0 ? pick(decimal) : undefined;
					if (f)
						values.set(nameOf(kind, f.name), [
							pick([String(f.values ?? 1), "17", "99", "255", "256", "272", "999"]),
						]);
					break;
				}
			}
		}
		return { values, headers, mistyped, ...(source === undefined ? {} : { source }) };
	}
	function random(kind: RequestKind): Carried {
		const names = [...allNames(kind), "x"];
		return {
			values: new Map(
				Array.from({ length: int(6) }, () => [
					pick(names),
					Array.from({ length: 1 + int(2) }, text),
				]),
			),
			headers: new Map(
				Array.from({ length: int(3) }, () => [
					pick([...Object.values(side(kind).headerNames ?? {}), "x"]),
					text(),
				]),
			),
			mistyped: new Set(Array.from({ length: int(2) }, () => pick(names))),
			...(int(2) === 0 ? { source: text() } : {}),
		};
	}

	/**
	 * The message an HTTP request carries, read apart from the codec, from `overHttp` alone: each field
	 * in its spec's order, the declared source from the Front's own member, a header's field from its
	 * header (absent read as empty), a body field by its HTTP name (sent twice, or as no text, refused),
	 * an enum by its texts' own names (any other `other`, or refused where none is) or plain decimal,
	 * bytes by their one base64url spelling.
	 */
	function reference(kind: RequestKind, sent: Carried) {
		const message: Record<string, unknown> = Object.create(null);
		for (const f of specs(kind)) {
			const no = (error: string) => ({ ok: false, field: f.name, error });
			if (f.name === overHttp.declaredSource) {
				message[f.name] = sent.source ?? "";
				continue;
			}
			const header = side(kind).headerNames?.[f.name];
			let text: string;
			if (header !== undefined) text = sent.headers.get(header) ?? "";
			else {
				const name = nameOf(kind, f.name);
				if (sent.mistyped.has(name)) return no("fieldSyntax");
				const got = sent.values.get(name) ?? [];
				if (got.length > 1) return no("fieldSyntax");
				text = got[0] ?? "";
			}
			if (f.type === "enum") {
				const texts = side(kind).enumTexts?.[f.name];
				const named = texts && Object.entries(texts.texts).find(([t]) => t === text);
				const value = texts
					? named
						? named[1]
						: texts.other
					: /^(0|[1-9][0-9]{0,2})$/.test(text)
						? Number(text)
						: undefined;
				if (value === undefined) return no("enumRange");
				message[f.name] = value;
			} else if (f.type === "bytes") {
				const bytes = /^[A-Za-z0-9_-]*$/.test(text) ? Buffer.from(text, "base64url") : undefined;
				if (bytes === undefined || bytes.toString("base64url") !== text) return no("fieldSyntax");
				message[f.name] = new Uint8Array(bytes);
			} else message[f.name] = text;
		}
		return { ok: true, message };
	}

	it(
		"reads what a reference written apart from the codec reads, for any request a sender makes",
		() => {
			for (let i = 0; i < cases * 4; i++) {
				const kind = pick(kinds);
				const sent = int(4) === 0 ? random(kind) : hostile(kind);
				expect(messageOf(kind, sent), `${kind} case ${i}`).toEqual(reference(kind, sent));
			}
		},
		Math.max(5000, cases * 4),
	);

	it(
		"never throws, takes only what the encoder sends and the Core reads back, refuses by a field it names and a field's code, and the encoder refuses as requestOf does",
		() => {
			const seen = { messageOnly: 0, encoderToo: 0, encoderEnum: 0, accepted: 0 };
			const codes = new Set<string>();
			const fieldCodes = ["fieldSyntax", "enumRange", "fieldLength"];
			for (let i = 0; i < cases * 4; i++) {
				const kind = pick(kinds);
				const sent = int(4) === 0 ? random(kind) : hostile(kind);
				const read = messageOf(kind, sent);
				const held = requestOf(kind, sent);
				if (!held.ok) {
					expect(specs(kind).map((f) => f.name)).toContain(held.field);
					expect(fieldCodes).toContain(held.error);
					codes.add(held.error);
				}
				if (!read.ok) {
					seen.messageOnly++;
					expect(held).toEqual(read);
					continue;
				}
				// The declared source comes from the Front's own member alone, whatever the body and headers say.
				if (specs(kind).some((f) => f.name === overHttp.declaredSource))
					expect((read.message as { source: string }).source).toBe(sent.source ?? "");
				// The Front encodes what messageOf read; the encoder refuses exactly what requestOf refuses.
				let frame: Uint8Array | undefined;
				try {
					frame = encodeRequest(kind, 7, read.message as never);
				} catch (error) {
					if (!(error instanceof WireEncodeError)) throw error;
					seen.encoderToo++;
					if (error.code === "enumRange") seen.encoderEnum++;
					expect(held).toEqual({ ok: false, field: error.field, error: error.code });
					continue;
				}
				expect(held).toEqual(read);
				seen.accepted++;
				const decoded = decodeRequest(frame);
				expect(decoded.ok && decoded.value.message).toEqual(read.message);
			}
			for (const [what, n] of Object.entries(seen)) expect(n, what).toBeGreaterThan(0);
			for (const code of fieldCodes) expect(codes, code).toContain(code);
		},
		Math.max(5000, cases * 4),
	);

	it("reads a body field sent twice or as no text as refused, and a header's field, the declared source or a name it does not know, in the body, as nothing", () => {
		for (const kind of kinds) {
			const base = valid(kind);
			const before = messageOf(kind, base);
			for (const f of bodyFields(kind)) {
				const name = nameOf(kind, f.name);
				const twice = new Map(base.values).set(name, ["a", "b"]);
				expect(messageOf(kind, { ...base, values: twice }), `${kind} ${name} twice`).toEqual({
					ok: false,
					field: f.name,
					error: "fieldSyntax",
				});
				expect(
					messageOf(kind, { ...base, mistyped: new Set([name]) }),
					`${kind} ${name} mistyped`,
				).toEqual({
					ok: false,
					field: f.name,
					error: "fieldSyntax",
				});
			}
			// A header's field, its header absent, is read as empty: never from the body, under any name.
			for (const f of headerFields(kind)) {
				const header = side(kind).headerNames?.[f.name] as string;
				const headers = new Map(base.headers);
				headers.delete(header);
				// Nor from a header of another name.
				const other = new Map(headers).set(`x-${header}`, "a.b.c");
				const elsewhereRead = messageOf(kind, { ...base, headers: other });
				expect(
					elsewhereRead.ok && (elsewhereRead.message as Record<string, unknown>)[f.name],
					`${kind} ${f.name} x-`,
				).toBe("");
				for (const name of new Set([nameOf(kind, f.name), f.name, header])) {
					const read = messageOf(kind, {
						...base,
						headers,
						values: new Map(base.values).set(name, ["a.b.c"]),
					});
					expect(
						read.ok && (read.message as Record<string, unknown>)[f.name],
						`${kind} ${f.name} under ${name}`,
					).toBe("");
				}
			}
			const elsewhere = [
				...headerFields(kind).map((f) => nameOf(kind, f.name)),
				overHttp.declaredSource,
				"x-unknown",
				"__proto__",
			].filter((n) => !bodyFields(kind).some((f) => nameOf(kind, f.name) === n));
			for (const name of elsewhere) {
				const added = new Map(base.values).set(name, ["a", "b"]);
				expect(messageOf(kind, { ...base, values: added }), `${kind} ${name}`).toEqual(before);
				expect(
					messageOf(kind, { ...base, mistyped: new Set([name]) }),
					`${kind} ${name} mistyped`,
				).toEqual(before);
			}
		}
	});

	it("picks an operation only for its method and path, one sharing a path by its value sent exactly once", () => {
		const paths = [...new Set(kinds.map((k) => side(k).path)), "/other", "/oauth/token/"];
		const shared = kinds.filter((k) => side(k).discriminator);
		for (let i = 0; i < cases; i++) {
			const method = pick(["POST", "POST", "GET", "PUT"]);
			const path = pick(paths);
			const values = new Map<string, string[]>();
			for (const k of shared) {
				const d = side(k).discriminator as { name: string; value: string };
				if (int(2) === 0)
					values.set(
						d.name,
						Array.from({ length: 1 + int(2) }, () => pick([d.value, "x"])),
					);
			}
			const at = kinds.filter((k) => side(k).path === path);
			const once = at.find((k) => {
				const d = side(k).discriminator;
				const got = d && values.get(d.name);
				return got?.length === 1 && got[0] === d?.value;
			});
			const expected =
				method !== "POST" ? undefined : (once ?? at.find((k) => !side(k).discriminator));
			expect(
				operationAt(method, path, values),
				`${method} ${path} ${JSON.stringify([...values])}`,
			).toBe(expected);
		}
		// The token endpoint's three, by a table written out: its value exactly once, POST in capitals alone.
		const at = (method: string, grant?: readonly string[]) =>
			operationAt(method, "/oauth/token", new Map(grant ? [["grant_type", grant]] : []));
		expect(at("POST")).toBe("token");
		expect(at("POST", ["authorization_code"])).toBe("token");
		expect(at("POST", ["refresh_token"])).toBe("refresh");
		expect(at("POST", ["client_credentials"])).toBe("clientCredentials");
		expect(at("POST", ["refresh_token", "refresh_token"])).toBe("token");
		expect(at("POST", ["refresh_token", "client_credentials"])).toBe("token");
		expect(at("POST", [" refresh_token"])).toBe("token");
		expect(at("POST", ["REFRESH_TOKEN"])).toBe("token");
		expect(at("post", ["refresh_token"])).toBeUndefined();
		expect(at("Post")).toBeUndefined();
		// Each operation sharing a path is reached by its value, the others by none.
		for (const k of shared) {
			const d = side(k).discriminator as { name: string; value: string };
			expect(operationAt("POST", side(k).path, new Map([[d.name, [d.value]]]))).toBe(k);
			expect(operationAt("POST", side(k).path, new Map([[d.name, [d.value, d.value]]]))).not.toBe(
				k,
			);
		}
	});

	it(
		"reads back, as the Core rebuilds it, every frame the Core's decoder takes, mutated ones among them",
		() => {
			const taken = new Map<RequestKind, number>();
			let mutants = 0;
			for (let i = 0; i < cases * 4; i++) {
				const kind = pick(kinds);
				const pristine = int(4) === 0;
				const frame = pristine ? validFrame(kind) : mutate(validFrame(kind));
				const decoded = decodeRequest(frame);
				if (!decoded.ok) continue;
				const { kind: read, message } = decoded.value;
				if (!pristine) {
					mutants++;
					taken.set(read, (taken.get(read) ?? 0) + 1);
				}
				expect(requestOf(read, carriedOf(read, message as never)), read).toEqual({
					ok: true,
					message,
				});
			}
			// Mutants the decoder took, apart from the valid frames: each kind more than twice.
			expect(mutants).toBeGreaterThan(0);
			for (const kind of kinds) expect(taken.get(kind) ?? 0, kind).toBeGreaterThan(2);
		},
		Math.max(5000, cases * 4),
	);
});
