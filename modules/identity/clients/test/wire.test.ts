import { requests } from "@mod/front-core-wire";
import { expect, it } from "vitest";
import { clientRecord } from "../src/registry/registry.ts";

it("takes as a client id exactly what the Front's wire carries in every `clientId`", () => {
	const specs = Object.values(requests).flatMap((op) =>
		op.fields.filter((f) => f.name === "clientId"),
	);
	expect(specs.length).toBeGreaterThan(0);
	const named = (id: string) =>
		clientRecord.safeParse({ id, kind: "public", method: "none" }).success;
	for (const spec of specs) {
		// Its bounds are the wire's: the longest it takes is the field's longest, the shortest fits
		// (a field of length 0 is the id not sent, never an id).
		expect(spec.type).toBe("visible");
		expect(spec.max).toBe(64);
		expect(spec.min).toBeLessThanOrEqual(1);
	}
	expect(named("!")).toBe(true);
	expect(named("")).toBe(false);
	expect(named("!".repeat(64))).toBe(true);
	expect(named("~".repeat(64))).toBe(true);
	expect(named("a".repeat(65))).toBe(false);
	// The wire's visible bytes are 0x21 to 0x7e: each it takes, and none outside.
	for (let c = 0; c < 0x100; c++) {
		expect(named(String.fromCharCode(c)), c.toString(16)).toBe(c >= 0x21 && c <= 0x7e);
	}
});
