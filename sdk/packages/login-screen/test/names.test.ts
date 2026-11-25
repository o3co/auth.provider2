import { continuations } from "@mod/continuation-wire";
import { overHttp } from "@mod/front-core-wire";
import { payloads, purposes } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";

/** An enum's texts in the order of the values they give. */
const wordsOf = (texts: Readonly<Record<string, number>>) =>
	Object.entries(texts)
		.sort(([, a], [, b]) => a - b)
		.map(([word]) => word);

const operations = Object.entries(overHttp.operations);

// front-core-wire names each answer's form and carries a continuation's stage and an approval's
// purpose as texts; sdk-core-wire holds the forms and the purposes, continuation-wire the stages. None
// depends on another (G2), so a package reading them all holds the names to agree.
describe("the names front-core-wire, sdk-core-wire and continuation-wire share", () => {
	it("names, for every operation the screen calls, a form sdk-core-wire's answers hold", () => {
		const named = operations.flatMap(([, http]) =>
			http.answer === undefined
				? []
				: typeof http.answer === "string"
					? [http.answer]
					: http.answer.forms,
		);
		expect(named.length).toBeGreaterThan(0);
		for (const form of named) expect(Object.hasOwn(payloads.answers, form), form).toBe(true);
	});

	it("gives a form for each value of the enum an answer is decided by, in the enum's order", () => {
		for (const [name, http] of operations) {
			if (http.answer === undefined || typeof http.answer === "string") continue;
			const texts = http.enumTexts?.[http.answer.by]?.texts;
			expect(texts, name).toBeDefined();
			expect(wordsOf(texts ?? {}), name).toHaveLength(http.answer.forms.length);
		}
	});

	it("carries continue's stages as continuation-wire's, a sealed stage answered sealed and every other a statement", () => {
		const http = overHttp.operations.continue;
		const stages = wordsOf(http.enumTexts?.stage?.texts ?? {});
		expect(stages).toEqual([...continuations.stages]);
		const forms = typeof http.answer === "string" ? [] : (http.answer?.forms ?? []);
		expect(
			stages.map((stage) =>
				(continuations.sealed as readonly string[]).includes(stage) ? "sealed" : "statement",
			),
		).toEqual(forms);
	});

	it("carries an approval's purposes as sdk-core-wire's", () => {
		const texts = overHttp.operations.approvalStart.enumTexts?.purpose?.texts ?? {};
		expect(wordsOf(texts)).toEqual([purposes.passkeyAdd, purposes.passkeyManage]);
	});

	it("names a rename's answer by a stage continuation-wire holds", () => {
		const continued = payloads.completions.passkeyManage.shape.continued.unwrap().shape.stage;
		expect((continuations.stages as readonly string[]).includes(continued.value)).toBe(true);
		expect((continuations.sealed as readonly string[]).includes(continued.value)).toBe(true);
	});

	it("holds a rename's label to the rule the keys' list holds a label to", () => {
		const labels = [
			"Laptop",
			"鍵",
			"",
			"x".repeat(64),
			"x".repeat(65),
			"a\u202eb",
			"a\nb",
			"\ud800",
		];
		for (const label of labels) {
			const renamed = continuations.bodies.rename.safeParse({ credential_id: "AQID", label });
			const row = { credential_id: "AQID", label, created_at: 1 };
			const listed = payloads.completions.passkeyManage.shape.keys.safeParse([row]);
			expect(renamed.success, JSON.stringify(label)).toBe(listed.success);
		}
	});
});
