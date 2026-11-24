import { describe, expect, it } from "vitest";
import { overHttp, type RequestKind, refusals, requests } from "../src/contract.ts";

const operations = Object.entries(overHttp.operations) as [
	RequestKind,
	(typeof overHttp.operations)[RequestKind],
][];
const fieldNames = (kind: RequestKind) => requests[kind].fields.map((f) => f.name as string);

describe("each operation over HTTP", () => {
	it("is named for every operation, and for nothing else", () => {
		expect(Object.keys(overHttp.operations).sort()).toEqual(Object.keys(requests).sort());
	});

	it("is a POST to a path of this server, its body a form or a JSON object, its success a 2xx", () => {
		for (const [kind, side] of operations) {
			expect(side.path, kind).toMatch(/^\/[a-z0-9/-]+$/);
			expect(["form", "json"], kind).toContain(side.body);
			const success = side.successStatus ?? 200;
			expect(success >= 200 && success < 300, kind).toBe(true);
		}
	});

	it("carries first in every operation the source the Front declares, never in the request itself", () => {
		for (const [kind, side] of operations) {
			expect(requests[kind].fields[0], kind).toEqual({
				name: overHttp.declaredSource,
				type: "visible",
				min: 0,
				max: 45,
			});
			for (const named of [side.bodyNames, side.headerNames, side.enumTexts]) {
				expect(Object.keys(named ?? {}), kind).not.toContain(overHttp.declaredSource);
			}
		}
	});

	it("names only its own fields, each carried once: in the body or in a lower-case header", () => {
		for (const [kind, side] of operations) {
			const own = fieldNames(kind).filter((f) => f !== overHttp.declaredSource);
			for (const key of [
				...Object.keys(side.bodyNames ?? {}),
				...Object.keys(side.headerNames ?? {}),
				...Object.keys(side.enumTexts ?? {}),
			]) {
				expect(own, `${kind}.${key}`).toContain(key);
			}
			for (const header of Object.values(side.headerNames ?? {}))
				expect(header).toMatch(/^[a-z-]+$/);
			const inBody = own
				.filter((f) => !Object.hasOwn(side.headerNames ?? {}, f))
				.map((f) => side.bodyNames?.[f] ?? f);
			const all = [...inBody, ...(side.discriminator ? [side.discriminator.name] : [])];
			expect(new Set(all).size, kind).toBe(all.length);
		}
	});

	it("carries an enum as text only within the values its field holds, never naming `other`", () => {
		for (const [kind, side] of operations) {
			for (const [name, texts] of Object.entries(side.enumTexts ?? {})) {
				const spec = requests[kind].fields.find((f) => f.name === name) as { values?: number };
				const values = [
					...Object.values(texts.texts),
					...(texts.other === undefined ? [] : [texts.other]),
				];
				for (const v of values)
					expect(v >= 0 && v < (spec.values ?? 0), `${kind}.${name}`).toBe(true);
				expect(Object.keys(texts.texts)).not.toContain("other");
			}
		}
	});

	it("tells apart the operations sharing a path: each but one by a value of its own", () => {
		const byPath = Map.groupBy(operations, ([, side]) => side.path);
		for (const [path, sharing] of byPath) {
			expect(sharing.filter(([, side]) => !side.discriminator).length, path).toBe(1);
			const whens = sharing.flatMap(([, side]) =>
				side.discriminator ? [`${side.discriminator.name}=${side.discriminator.value}`] : [],
			);
			expect(new Set(whens).size, path).toBe(whens.length);
		}
	});

	it("names the answer's form of every operation the screen calls, and of no other; by an enum field, one form per value", () => {
		for (const [kind, side] of operations) {
			expect(side.answer !== undefined, kind).toBe(side.crossOrigin !== undefined);
			const answer = side.answer;
			if (typeof answer !== "object") continue;
			const spec = requests[kind].fields.find((f) => f.name === answer.by) as
				| { type: string; values?: number }
				| undefined;
			expect(spec?.type, kind).toBe("enum");
			expect(answer.forms.length, kind).toBe(spec?.values);
		}
		expect(overHttp.operations.continue.answer).toEqual({
			by: "stage",
			forms: ["statement", "sealed", "sealed"],
		});
	});

	it("opens the screen's key operations by §C's names, their stages and purposes as text", () => {
		const ops = overHttp.operations;
		expect(
			[ops.firstKeyRecover, ops.approvalStart, ops.approvalFinish, ops.continue, ops.keyFinish].map(
				(side) => [side.path, side.answer],
			),
		).toEqual([
			["/first-key/recover", "statement"],
			["/approval/start", "statement"],
			["/approval/finish", "sealed"],
			["/continue", ops.continue.answer],
			["/key/finish", "sealed"],
		]);
		expect(ops.approvalStart.enumTexts?.purpose?.texts).toEqual({
			"passkey-add": 0,
			"passkey-manage": 1,
		});
		expect(ops.continue.enumTexts?.stage?.texts).toEqual({ register: 0, delete: 1, rename: 2 });
		expect(requests.continue.fields.map((f) => f.name)).toEqual([
			"source",
			"statement",
			"stage",
			"seq",
			"body",
			"sig",
		]);
		expect(requests.continue.fields.find((f) => f.name === "seq")).toMatchObject({ values: 17 });
		expect(requests.continue.fields.find((f) => f.name === "statement")).toMatchObject({
			max: 8192,
		});
		expect(requests.firstKeyRecover.fields.map((f) => [f.name, f.min, f.max])).toEqual([
			["source", 0, 45],
			["nonce", 43, 43],
			["digest", 43, 43],
			["sig", 64, 64],
		]);
	});

	it("answers a refusal with the status its word names, words of the wire alone", () => {
		for (const word of Object.keys(overHttp.statuses)) expect(refusals).toContain(word);
		expect(overHttp.statuses).toMatchObject({
			invalid_client: 401,
			server_error: 500,
			rate_limited: 429,
			too_many_attempts: 429,
		});
	});

	it("takes a pushed authorization request at the PAR endpoint by RFC 9126's names, from the client's server, answering 201", () => {
		const par = overHttp.operations.par;
		expect(par).toMatchObject({ path: "/oauth/par", body: "form", successStatus: 201 });
		expect(par).not.toHaveProperty("crossOrigin");
		expect(par.bodyNames).toEqual({
			clientAssertionType: "client_assertion_type",
			clientAssertion: "client_assertion",
			clientId: "client_id",
			authorizationDetails: "authorization_details",
			requestUriSent: "request_uri",
		});
		expect(par.headerNames).toEqual({ dpop: "dpop" });
		expect(par.enumTexts?.requestUriSent).toEqual({ texts: { "": 0 }, other: 1 });
		expect(requests.par.fields.map((f) => f.name)).toEqual([
			"source",
			"request",
			"clientAssertionType",
			"clientAssertion",
			"clientId",
			"authorizationDetails",
			"requestUriSent",
			"dpop",
		]);
		expect(requests.par.fields.find((f) => f.name === "request")?.min).toBe(1);
	});

	it("lets the login's start carry its JAR by value or a PAR's reference, either of length 0 on the wire", () => {
		const fields = Object.fromEntries(requests.loginStart.fields.map((f) => [f.name, f]));
		expect(fields.request).toMatchObject({ type: "jws", min: 0 });
		expect(fields.requestUri).toMatchObject({ type: "visible", min: 0, max: 512 });
	});

	it("is frozen to the leaves", () => {
		const frozen = (value: unknown): boolean =>
			typeof value !== "object" || value === null
				? true
				: Object.isFrozen(value) && Object.values(value).every(frozen);
		expect(frozen(overHttp)).toBe(true);
	});
});
