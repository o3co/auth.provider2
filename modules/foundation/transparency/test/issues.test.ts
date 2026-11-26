import { schemas } from "@mod/transparency-wire";
import { expect, it } from "vitest";
import { issuePaths } from "../src/issues.ts";

const pathsOf = (v: unknown) => {
	const read = schemas.record.safeParse(v);
	return read.success ? [] : issuePaths(read.error.issues);
};

it("tells a union's paths by its nearest branch, and an unknown discriminator at its own path", () => {
	const tick = { v: 1, id: "t1", writer: { role: "log" }, kind: "tick", shard: "s1", n: 1 };
	expect(pathsOf({ ...tick, acceptedAt: "soon" })).toEqual(["acceptedAt"]);
	expect(pathsOf({ ...tick, acceptedAt: 1, writer: { role: "who" } })).toEqual(["writer.role"]);
	// Never the answer's own ids, values or key names.
	const told = pathsOf({ ...tick, acceptedAt: 1, "secret-key": "secret-value", id: "" }).join();
	expect(told).not.toMatch(/secret/);
});
