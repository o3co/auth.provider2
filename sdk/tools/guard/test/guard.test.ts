import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { sdkViolations } from "../src/guard.ts";

/** A repository with the provider's modules and the sdk's packages, from file paths to contents. */
function repo(files: Readonly<Record<string, string>>): string {
	const root = mkdtempSync(join(tmpdir(), "sdk-guard-"));
	for (const [path, content] of Object.entries(files)) {
		mkdirSync(dirname(join(root, path)), { recursive: true });
		writeFileSync(join(root, path), content);
	}
	return join(root, "sdk");
}

const manifest = (name: string, extra: Record<string, unknown> = {}) =>
	JSON.stringify({ name, type: "module", ...extra });
const supply = [
	'packages:\n  - "modules/*/*"\nminimumReleaseAge: 1440\ntrustPolicy: no-downgrade\noverrides:\n  "a@1": "1.0.1"\n',
	'packages:\n  - "packages/*"\nminimumReleaseAge: 1440\ntrustPolicy: no-downgrade\noverrides:\n  "a@1": "1.0.1"\n',
] as const;
const provider = {
	"package.json": manifest("root", { packageManager: "pnpm@1.0.0" }),
	"pnpm-workspace.yaml": supply[0],
	"sdk/package.json": manifest("sdk", { packageManager: "pnpm@1.0.0" }),
	"sdk/pnpm-workspace.yaml": supply[1],
	"modules/wire/a-wire/package.json": manifest("@mod/a-wire", { kind: "protocol" }),
	"modules/wire/a-wire/src/contract.ts": "export const a = 1;\n",
	"modules/foundation/keys/package.json": manifest("@mod/keys", { kind: "foundation" }),
	"modules/foundation/keys/src/contract.ts": "export const k = 1;\n",
};
const linkTo = (dir: string) => `link:../../../modules/${dir}`;
const sdkPackage = (deps: Record<string, string>, source: string, test = "") => ({
	"sdk/packages/one/package.json": manifest("@sdk/one", { dependencies: deps }),
	"sdk/packages/one/src/contract.ts": source,
	...(test ? { "sdk/packages/one/test/one.test.ts": test } : {}),
});

describe("sdkViolations", () => {
	it("passes a package that imports its own files and a protocol package it depends on", () => {
		const root = repo({
			...provider,
			...sdkPackage(
				{ "@mod/a-wire": linkTo("wire/a-wire") },
				'import { a } from "@mod/a-wire";\nimport { b } from "./b.ts";\nexport const c = a + b;\n',
				'import { expect, it } from "vitest";\nimport { readFileSync } from "node:fs";\nit("x", () => expect(1).toBe(1));\n',
			),
			"sdk/packages/one/src/b.ts": "export const b = 2;\n",
		});
		expect(sdkViolations(root)).toEqual([]);
	});

	it("refuses a dependency on a provider package whose kind is not protocol", () => {
		const root = repo({
			...provider,
			...sdkPackage({ "@mod/keys": linkTo("foundation/keys") }, "export const c = 1;\n"),
		});
		expect(sdkViolations(root).map((f) => f.id)).toEqual(["S1"]);
	});

	it("refuses a dependency that is no link to a provider package, a third party's too", () => {
		const root = repo({ ...provider, ...sdkPackage({ jose: "6.0.0" }, "export const c = 1;\n") });
		expect(sdkViolations(root).map((f) => f.id)).toEqual(["S1"]);
	});

	it("refuses a link whose target names another package than the dependency", () => {
		const root = repo({
			...provider,
			...sdkPackage({ "@mod/b-wire": linkTo("wire/a-wire") }, "export const c = 1;\n"),
		});
		expect(sdkViolations(root).map((f) => f.id)).toEqual(["S1"]);
	});

	it("refuses shipped code importing a package it does not depend on, node's builtins too", () => {
		for (const source of [
			'import { k } from "@mod/keys";\nexport const c = k;\n',
			'import { readFileSync } from "node:fs";\nexport const c = readFileSync;\n',
			'export const c = await import("@sdk/two");\n',
			'export { k } from "@mod/keys";\n',
			'import type { K } from "@mod/keys";\nexport type C = K;\n',
		]) {
			const root = repo({ ...provider, ...sdkPackage({}, source) });
			expect(
				sdkViolations(root).map((f) => f.id),
				source,
			).toEqual(["S2"]);
		}
	});

	it("refuses a relative import that leaves its package", () => {
		const root = repo({
			...provider,
			...sdkPackage(
				{},
				'import { k } from "../../../../modules/foundation/keys/src/contract.ts";\nexport const c = k;\n',
			),
		});
		expect(sdkViolations(root).map((f) => f.id)).toEqual(["S2"]);
	});

	it("refuses a test importing a package beside vitest, node's builtins and the dependencies", () => {
		const root = repo({
			...provider,
			...sdkPackage(
				{},
				"export const c = 1;\n",
				'import { it } from "vitest";\nimport { k } from "@mod/keys";\nit("x", () => k);\n',
			),
		});
		expect(sdkViolations(root).map((f) => f.id)).toEqual(["S2"]);
	});

	it("checks each dependency field apart, optional ones too", () => {
		for (const field of ["optionalDependencies", "devDependencies", "peerDependencies"]) {
			const root = repo({
				...provider,
				"sdk/packages/one/package.json": manifest("@sdk/one", {
					dependencies: { "@mod/a-wire": linkTo("wire/a-wire") },
					[field]: { "@mod/a-wire": linkTo("foundation/keys") },
				}),
				"sdk/packages/one/src/contract.ts": "export const c = 1;\n",
			});
			expect(
				sdkViolations(root).map((f) => f.id),
				field,
			).toEqual(["S1"]);
		}
	});

	it("refuses a link to a protocol manifest that is no package of the provider's workspace", () => {
		const root = repo({
			...provider,
			"modules/wire/a-wire/fake/package.json": manifest("@mod/fake", { kind: "protocol" }),
			...sdkPackage({ "@mod/fake": linkTo("wire/a-wire/fake") }, "export const c = 1;\n"),
		});
		expect(sdkViolations(root).map((f) => f.id)).toEqual(["S1"]);
	});

	it("refuses a dependency's subpath, and a name a plain object inherits", () => {
		for (const source of [
			'import { k } from "@mod/a-wire/../../foundation/keys/src/contract.ts";\nexport const c = k;\n',
			'import x from "constructor";\nexport const c = x;\n',
		]) {
			const root = repo({
				...provider,
				...sdkPackage({ "@mod/a-wire": linkTo("wire/a-wire") }, source),
			});
			expect(
				sdkViolations(root).map((f) => f.id),
				source,
			).toEqual(["S2"]);
		}
	});

	it("reads every script extension, and triple-slash references in shipped code", () => {
		for (const [file, source] of [
			["src/x.cts", 'import { k } from "@mod/keys";\n'],
			["src/x.cjs", 'const k = require("@mod/keys");\n'],
			["src/x.tsx", 'import { k } from "@mod/keys";\n'],
			["src/x.jsx", 'import { k } from "@mod/keys";\n'],
			["src/x.ts", '/// <reference types="node" />\nexport const c = 1;\n'],
			["src/x.ts", '/// <reference lib="webworker" />\nexport const c = 1;\n'],
			[
				"src/x.ts",
				'/// <reference path="../../../../modules/foundation/keys/src/contract.ts" />\n',
			],
		] as const) {
			const root = repo({
				...provider,
				...sdkPackage({}, "export const c = 1;\n"),
				[`sdk/packages/one/${file}`]: source,
			});
			expect(
				sdkViolations(root).map((f) => f.id),
				`${file}: ${source}`,
			).toEqual(["S2"]);
		}
	});

	it("counts as tests the package's test directory and *.test files alone", () => {
		const root = repo({
			...provider,
			...sdkPackage({}, 'export { r } from "./test/node.ts";\n'),
			"sdk/packages/one/src/test/node.ts":
				'import { readFileSync } from "node:fs";\nexport const r = readFileSync;\n',
		});
		expect(sdkViolations(root)).toEqual([
			{ id: "S2", place: "packages/one/src/test/node.ts", what: "imports node:fs" },
		]);
	});

	it("reads files and directories whose names start with a dot", () => {
		for (const path of ["src/.hidden.ts", "src/.dir/x.ts"]) {
			const root = repo({
				...provider,
				...sdkPackage({}, `export { k } from "./${path.slice(4)}";\n`),
				[`sdk/packages/one/${path}`]: 'export { k } from "@mod/keys";\n',
			});
			expect(
				sdkViolations(root).map((f) => f.id),
				path,
			).toEqual(["S2"]);
		}
	});

	it("refuses a symlink in a package", () => {
		const root = repo({ ...provider, ...sdkPackage({}, "export const c = 1;\n") });
		symlinkSync(join(root, "..", "modules"), join(root, "packages", "one", "src", "provider"));
		expect(sdkViolations(root).map((f) => f.id)).toEqual(["S2"]);
	});

	it("refuses a supply rule or a pnpm pin that differs from the provider's workspace", () => {
		for (const [path, content] of [
			["sdk/pnpm-workspace.yaml", supply[1].replace("1440", "60")],
			["sdk/pnpm-workspace.yaml", supply[1].replace("trustPolicy: no-downgrade\n", "")],
			["sdk/pnpm-workspace.yaml", supply[1].replace('"1.0.1"', '"1.0.0"')],
			["sdk/package.json", manifest("sdk", { packageManager: "pnpm@2.0.0" })],
		] as const) {
			const root = repo({
				...provider,
				...sdkPackage({}, "export const c = 1;\n"),
				[path]: content,
			});
			expect(
				sdkViolations(root).map((f) => f.id),
				content,
			).toEqual(["S3"]);
		}
	});

	it("names the place and what went over", () => {
		const root = repo({
			...provider,
			...sdkPackage({}, 'import { k } from "@mod/keys";\nexport const c = k;\n'),
		});
		expect(sdkViolations(root)).toEqual([
			{ id: "S2", place: "packages/one/src/contract.ts", what: "imports @mod/keys" },
		]);
	});
});
