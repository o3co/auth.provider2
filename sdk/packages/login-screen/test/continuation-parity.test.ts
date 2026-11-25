import { continuations } from "@mod/continuation-wire";
import { canonicalText, continuation } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";

// While sdk-core-wire's continuation and continuation-wire both stand, the same inputs give the same
// bytes from each: the screen moved to continuation-wire and the Core moves one module at a time.
// Taken out with sdk-core-wire's continuation.
describe("sdk-core-wire's continuation and continuation-wire, while both stand", () => {
	const sig = `${"A".repeat(85)}A`;
	const bodies = {
		delete: [{ credential_id: "AQID" }, { credential_id: "A".repeat(1364) }],
		rename: [
			{ credential_id: "AQID", label: "鍵" },
			{ label: "😀".repeat(64), credential_id: "BAUG" },
		],
	} as const;

	it("names every stage sdk-core-wire names, and the same sealed stages", () => {
		// continuation-wire may name more (sign-up comes there alone); each old one keeps its place.
		expect(continuations.stages.slice(0, continuation.stages.length)).toEqual([
			...continuation.stages,
		]);
		expect([...continuations.sealed]).toEqual([...continuation.sealed]);
		expect(continuations.plainBytes).toBe(continuation.plainBytes);
	});

	it("gives the same signed input, additional data, plaintext and body text", () => {
		for (const stage of continuation.stages)
			expect(continuations.of(stage, "h", 3, "b")).toBe(continuation.of(stage, "h", 3, "b"));
		for (const stage of continuation.sealed) {
			expect(continuations.aad(stage, "h", 2)).toBe(continuation.aad(stage, "h", 2));
			for (const body of bodies[stage]) {
				const plain = continuation.plainOf(stage, body, sig);
				expect(continuations.plainOf(stage, body, sig)).toBe(plain);
				expect(continuations.readPlain(stage, plain ?? "")).toEqual(
					continuation.readPlain(stage, plain ?? ""),
				);
				expect(continuations.bodyText(stage, body)).toBe(canonicalText(body));
			}
		}
	});

	it("signs by the same rule, its name aside, and reads none of the same texts", () => {
		expect({ ...continuations.signature, over: undefined }).toEqual({
			...continuation.signature,
			over: undefined,
		});
		expect(continuations.signature.over).toBe("UTF-8 of continuations.of");
		const plain = continuation.plainOf("delete", { credential_id: "AQID" }, sig) ?? "";
		const pad = (text: string) =>
			`${text}${" ".repeat(continuation.plainBytes - new TextEncoder().encode(text).length)}`;
		for (const [stage, text] of [
			["delete", plain.slice(0, -1)],
			["delete", `${plain} `],
			["delete", pad(`{"sig":"${sig}","body":{"credential_id":"AQID"}}`)],
			["rename", plain],
		] as const)
			expect(continuations.readPlain(stage, text)).toEqual(continuation.readPlain(stage, text));
	});

	it("takes and refuses the same bodies", () => {
		const labels = ["Laptop", "", "x".repeat(64), "x".repeat(65), "a‮b", "a\nb", "\ud800"];
		for (const label of labels) {
			const body = { credential_id: "AQID", label };
			expect(continuations.bodies.rename.safeParse(body).success, label).toBe(
				continuation.bodies.rename.safeParse(body).success,
			);
		}
		for (const id of ["AQID", "A", "A=", "a+b", "A".repeat(1364), "A".repeat(1365)])
			expect(continuations.bodies.delete.safeParse({ credential_id: id }).success, id).toBe(
				continuation.bodies.delete.safeParse({ credential_id: id }).success,
			);
	});
});
