import { isUnavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import { firstKeyCreations } from "../../contract.ts";
import type { Created, CreationAsk } from "../../creation/creation.ts";
import { firstKeyCreationsOver } from "../keying.ts";
import { keyWorld, payloadOf, screen, sha256 } from "./world.ts";

const ask = {
	subject: "s1",
	identifier: "alice@example.com",
	ctHash: "ct",
	evidence: "ev",
	screen: { eEnc: "E", eSig: { kty: "EC", crv: "P-256", x: "x", y: "y" } },
	since: 1,
} as const;

function over(made: Created) {
	const asked: CreationAsk[] = [];
	const told: string[] = [];
	const creations = firstKeyCreationsOver(
		async (a) => {
			asked.push(a);
			return made;
		},
		(reason) => told.push(reason),
	);
	return { creations, asked, told };
}

it("asks a first key's creation with the identifier masked, and answers it issued", async () => {
	const issued = { kind: "issued", statement: "s", hash: "h", challenge: "c" } as const;
	const o = over(issued);
	expect(await o.creations.create(ask)).toEqual(issued);
	expect(o.asked).toEqual([
		expect.objectContaining({ account: "a***@example.com", basis: "first-key", ctHash: "ct" }),
	]);
	expect(o.told).toEqual([]);
});

it("answers revoked and full in its own words, telling nothing", async () => {
	for (const reason of ["revoked", "full"] as const) {
		const o = over({ kind: "refused", reason });
		expect(await o.creations.create(ask)).toEqual({ kind: "refused", reason });
		expect(o.told).toEqual([]);
	}
});

it("tells approvals' other refusals by their reason alone, then throws: items a fault, the rest unavailable", async () => {
	const items = over({ kind: "refused", reason: "items" });
	await expect(items.creations.create(ask)).rejects.toThrow(TypeError);
	expect(items.told).toEqual(["items"]);
	for (const reason of ["limited", "busy", "withdrawn", "long"] as const) {
		const o = over({ kind: "refused", reason });
		await expect(o.creations.create(ask), reason).rejects.toSatisfy(isUnavailable);
		// The reason's word alone: never the identifier or the subject.
		expect(o.told).toEqual([reason]);
	}
});

it("makes a first key's creation for the subject its token binds, its account the identifier masked", async () => {
	const w = await keyWorld();
	const s = await screen();
	const made = await (await w.app.get(firstKeyCreations)).create({
		subject: "s1",
		identifier: "alice@example.com",
		ctHash: sha256("sealed"),
		evidence: sha256("token"),
		screen: { eEnc: s.eEnc, eSig: s.eSig },
		since: w.now(),
	});
	if (made.kind !== "issued") throw new Error(made.reason);
	const items = payloadOf(made.statement).creation;
	expect(items).toMatchObject({
		basis: "first-key",
		account: "a***@example.com",
		evidence: sha256("token"),
		ct_hash: sha256("sealed"),
		subject: "s1",
	});
	// Its account shown, it is named no other way.
	expect(items.options).not.toHaveProperty("user_name");
});
