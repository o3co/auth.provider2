import { overHttp } from "@mod/front-core-wire";
import { continuation, payloads, purposes } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";

/** An enum's texts in the order of the values they give. */
const wordsOf = (texts: Readonly<Record<string, number>>) =>
	Object.entries(texts)
		.sort(([, a], [, b]) => a - b)
		.map(([word]) => word);

const operations = Object.entries(overHttp.operations);

// front-core-wire names each answer's form, and sdk-core-wire holds the forms; neither depends on
// the other (G2), so a package reading both holds the names to agree.
describe("the names front-core-wire and sdk-core-wire share", () => {
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

	it("carries continue's stages as sdk-core-wire's, a sealed stage answered sealed and register a statement", () => {
		const http = overHttp.operations.continue;
		const stages = wordsOf(http.enumTexts?.stage?.texts ?? {});
		expect(stages).toEqual([...continuation.stages]);
		const forms = typeof http.answer === "string" ? [] : (http.answer?.forms ?? []);
		expect(
			stages.map((stage) =>
				(continuation.sealed as readonly string[]).includes(stage) ? "sealed" : "statement",
			),
		).toEqual(forms);
	});

	it("carries an approval's purposes as sdk-core-wire's", () => {
		const texts = overHttp.operations.approvalStart.enumTexts?.purpose?.texts ?? {};
		expect(wordsOf(texts)).toEqual([purposes.passkeyAdd, purposes.passkeyManage]);
	});
});
