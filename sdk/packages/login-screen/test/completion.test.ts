import { hpke, typs } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import { digest, utf8 } from "../src/bytes.ts";
import { readCompletion } from "../src/completion.ts";
import { sealTo } from "../src/hpke.ts";
import { screenKeys } from "../src/keys.ts";
import { signCompact, signingKey } from "./fixtures.ts";

const issuer = "https://id.example";
const aad = utf8("completion-aad");
const statement = "h.t.s";
const assertion = utf8('{"assertion":1}');

async function world(change: Record<string, unknown> = {}, header: Record<string, unknown> = {}) {
	const ring = await signingKey("ES256", "core-1");
	const keys = await screenKeys();
	const payload = {
		v: 1,
		iss: issuer,
		t_hash: await digest(statement),
		assertion_hash: await digest(assertion),
		code: "code-1",
		iat: 1,
		exp: 2,
		...change,
	};
	const jws = await signCompact(ring, payload, { typ: typs.completion, ...header });
	const point = Buffer.from(keys.eEnc, "base64url");
	const sealed = await sealTo(point, utf8(hpke.info.completion), aad, utf8(jws));
	const options = { keys, ring: [ring.jwk], issuer, aad, statement, assertion };
	return { sealed, options, payload, point };
}

describe("readCompletion", () => {
	it("opens the completion sealed to the screen and reads its code, bound to T and the assertion", async () => {
		const { sealed, options, payload } = await world();
		expect(await readCompletion(sealed, options)).toEqual({ completion: payload });
	});

	it("opens nothing sealed under another info or additional data", async () => {
		const { options, point } = await world();
		const ring = await signingKey("ES256", "core-1");
		const jws = await signCompact(ring, {}, { typ: typs.completion });
		for (const [info, data] of [
			[hpke.info.firstKeyCode, aad],
			[hpke.info.completion, utf8("other")],
		] as const) {
			const sealed = await sealTo(point, utf8(info), data, utf8(jws));
			expect(await readCompletion(sealed, options)).toEqual({ error: "open" });
		}
	});

	it("refuses one bound to another T or another assertion", async () => {
		for (const [change, error] of [
			[{ t_hash: "other" }, "statement"],
			[{ assertion_hash: "other" }, "assertion"],
			[{ iss: "https://other.example" }, "issuer"],
		] as const) {
			const { sealed, options } = await world(change);
			expect(await readCompletion(sealed, options), error).toEqual({ error });
		}
	});

	it("refuses one of T's typ, or of a shape the schema refuses", async () => {
		const typed = await world({}, { typ: typs.statement });
		expect(await readCompletion(typed.sealed, typed.options)).toEqual({ error: "typ" });
		const extra = await world({ extra: 1 });
		expect(await readCompletion(extra.sealed, extra.options)).toEqual({ error: "payload" });
	});

	it("refuses one signed by a key not in the ring", async () => {
		const { sealed, options } = await world();
		const other = await signingKey("ES256", "core-1");
		expect(await readCompletion(sealed, { ...options, ring: [other.jwk] })).toEqual({
			error: "signature",
		});
	});
});
