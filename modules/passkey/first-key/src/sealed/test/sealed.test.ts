import { createHash } from "node:crypto";
import type { Keys } from "@mod/keys";
import { firstKey, hpke, payloads } from "@mod/sdk-core-wire";
import { expect, it } from "vitest";
import { screenPoints } from "../../../test/fixtures/screen.ts";
import { openSealed, type SealedRequest } from "../../sealed/sealed.ts";

const bytes = (n: number, fill: number) => new Uint8Array(n).fill(fill);
const request: SealedRequest = {
	nonce: "N".repeat(43),
	...screenPoints(),
	enc: bytes(65, 3),
	ct: bytes(40, 5),
};
const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64url");

/** The Core's opening as a stand-in: what it was asked, and the text it opens to. */
function opening(answer: Awaited<ReturnType<Keys["open"]>>) {
	const asked: { info: string; aad: string }[] = [];
	const keys: Pick<Keys, "open"> = {
		open: async (_, info, aad) => {
			asked.push({ info, aad: new TextDecoder().decode(aad) });
			return answer;
		},
	};
	return { keys, asked };
}
const plainOf = (value: unknown) => ({
	kind: "opened" as const,
	plaintext: new TextEncoder().encode(JSON.stringify(value)),
});

it("opens under its stage's info and additional data: the stage, nonce and screen's keys", async () => {
	const { keys, asked } = opening(plainOf({ identifier: "alice", password: "pw" }));
	const opened = await openSealed(keys, "start", request, payloads.startPlain);
	const eSig = { kty: "EC", crv: "P-256", x: b64(request.eSigX), y: b64(request.eSigY) } as const;
	expect(asked).toEqual([
		{
			info: hpke.info.firstKeyRequest,
			aad: firstKey.aad("start", request.nonce, b64(request.eEnc), eSig),
		},
	]);
	expect(opened).toEqual({
		kind: "opened",
		plain: { identifier: "alice", password: "pw" },
		digest: createHash("sha256").update(request.enc).update(request.ct).digest("base64url"),
		screen: { eEnc: b64(request.eEnc), eSig },
	});
});

it("answers unopened for text of no shape its stage takes, and passes the holder's withdrawal on", async () => {
	for (const text of [{ identifier: "alice", extra: 1 }, { token: "t" }, "plain"]) {
		const { keys } = opening(plainOf(text));
		expect(await openSealed(keys, "start", request, payloads.startPlain)).toEqual({
			kind: "unopened",
		});
	}
	const notJson = { kind: "opened" as const, plaintext: new Uint8Array([0xff, 0xfe]) };
	expect(await openSealed(opening(notJson).keys, "mail", request, payloads.mailPlain)).toEqual({
		kind: "unopened",
	});
	// Screen keys of no point are not opened, the holder never asked.
	for (const keysOf of [{ eEnc: bytes(65, 4) }, { eSigX: bytes(32, 1) }]) {
		const { keys, asked } = opening(plainOf({ identifier: "alice" }));
		const odd = { ...request, ...keysOf };
		expect(await openSealed(keys, "start", odd, payloads.startPlain)).toEqual({ kind: "unopened" });
		expect(asked).toEqual([]);
	}
	for (const answer of [{ kind: "unopened" }, { kind: "withdrawn" }] as const) {
		expect(await openSealed(opening(answer).keys, "mail", request, payloads.mailPlain)).toEqual(
			answer,
		);
	}
});
