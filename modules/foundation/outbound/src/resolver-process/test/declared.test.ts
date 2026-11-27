import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { section } from "../../module.ts";

// The launcher reads no schema: outbound holds its own declaration of where its helpers start true to it.
const manifest = JSON.parse(
	readFileSync(join(import.meta.dirname, "..", "..", "..", "package.json"), "utf8"),
);

it("declares its child processes where resolution is helper: a key of its section, one of the key's values, not its default", () => {
	const when = manifest.permissions.child.when as { key: string; is: string };
	expect(Object.keys(section.shape)).toContain(when.key);
	const parsed = section.parse({ [when.key]: when.is });
	expect(parsed[when.key as keyof typeof parsed]).toBe(when.is);
	expect(section.parse({})[when.key as keyof typeof parsed]).not.toBe(when.is);
	// And its forks are the helper's, which the condition is for.
	expect(Object.values(manifest.forks)).toContain("src/resolver-process/helper.mjs");
});
