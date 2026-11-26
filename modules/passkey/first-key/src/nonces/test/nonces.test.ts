import { randomBytes } from "node:crypto";
import { expect, it } from "vitest";
import { memoryKept } from "../../../test/fixtures/kept.ts";
import type { StoredNonce } from "../../contract.ts";
import { noncesOver } from "../../nonces/nonces.ts";

function nonces() {
	const kept = memoryKept<StoredNonce>();
	const over = noncesOver({
		store: kept.store,
		random: (n) => randomBytes(n),
		lifetimeMs: 120_000,
	});
	return { ...over, advance: kept.advance };
}

it("issues each stage's nonce as 32 random bytes, a fresh one each time", async () => {
	const n = nonces();
	const [a, b] = [await n.issue("start"), await n.issue("start")];
	expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
	expect(a).not.toBe(b);
});

it("binds a nonce to the first request that uses it, and answers that request again alone", async () => {
	const n = nonces();
	const nonce = await n.issue("mail");
	expect(await n.use(nonce, "mail", "d1")).toBe("first");
	expect(await n.use(nonce, "mail", "d1")).toBe("again");
	expect(await n.use(nonce, "mail", "d2")).toBe("refused");
});

it("refuses a nonce unknown, of another stage, or past its life", async () => {
	const n = nonces();
	expect(await n.use("none", "mail", "d")).toBe("refused");
	const start = await n.issue("start");
	expect(await n.use(start, "mail", "d")).toBe("refused");
	const late = await n.issue("mail");
	n.advance(120_000);
	expect(await n.use(late, "mail", "d")).toBe("refused");
});

it("binds a nonce to one of two requests sent at once", async () => {
	const n = nonces();
	const nonce = await n.issue("mail");
	const uses = await Promise.all([n.use(nonce, "mail", "d1"), n.use(nonce, "mail", "d2")]);
	expect(uses.toSorted()).toEqual(["first", "refused"]);
});
