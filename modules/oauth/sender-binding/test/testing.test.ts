import { expect, it } from "vitest";
import { requirementSection } from "../src/requirement.ts";
import { senderBindingFor } from "../src/testing.ts";

it("gives a test client's sections the requirement this module reads, under its own section's name", () => {
	const sections = senderBindingFor({ required: true, kinds: ["dpop"] });
	expect(Object.keys(sections)).toEqual([requirementSection.name]);
	const read = requirementSection.schema["~standard"].validate(sections[requirementSection.name]);
	expect(read).toEqual({ value: { required: true, kinds: ["dpop"] } });
});
