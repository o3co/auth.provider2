import { describe, expect, it } from "vitest";
import {
	appPermissionsOf,
	homeOf,
	lookupsAbove,
	nodeSettings,
	type ProcessPermissions,
	permissionsProblems,
	valuesAt,
} from "../src/contract.ts";

describe("a package's permissions", () => {
	it("takes each form, and an empty declaration (code alone)", () => {
		expect(permissionsProblems({})).toEqual([]);
		expect(
			permissionsProblems({
				read: {
					keys: ["certificate-file", "keys.*.file"],
					paths: [
						{ path: "/proc/self/limits", kind: "file" },
						{ path: "/proc/self/fd", kind: "dir" },
					],
					env: [
						{ name: "AWS_CONFIG_FILE", default: "~/.aws/config", home: true },
						{ name: "AWS_WEB_IDENTITY_TOKEN_FILE" },
					],
				},
				write: { keys: ["path"], beside: ["path"] },
				child: { when: { key: "resolution", is: "helper" } },
			}),
		).toEqual([]);
	});

	it("names each problem: an unknown member, a key path that is none, a relative path, a kind, a variable's name, a condition", () => {
		expect(permissionsProblems([])).toEqual(["permissions is an object"]);
		expect(
			permissionsProblems({
				files: [],
				read: {
					keys: ["*.file", "Upper", 1],
					paths: [{ path: "etc/hosts", kind: "link" }],
					env: [{ name: "lower" }],
				},
				write: { beside: "path" },
				child: { when: { key: "a.*", is: 1 } },
			}),
		).toEqual([
			"permissions.files is no member",
			"permissions.read.keys[0] is no key path",
			"permissions.read.keys[1] is no key path",
			"permissions.read.keys[2] is no key path",
			"permissions.read.paths[0].path is an absolute path",
			"permissions.read.paths[0].kind is file or dir",
			"permissions.read.env[0].name is a variable's name",
			"permissions.write.beside is a list",
			"permissions.child.when.key is a key of the section",
			"permissions.child.when.is is a value",
		]);
		expect(permissionsProblems({ child: {} })).toEqual(["permissions.child names when"]);
	});
});

describe("an app's permissions.json", () => {
	const process = { code: ["/app"], declared: [], network: false };
	it("reads version 1 with its processes, and says what is wrong otherwise", () => {
		expect(appPermissionsOf(JSON.stringify({ v: 1, processes: { start: process } }))).toEqual({
			permissions: { v: 1, processes: { start: process } },
		});
		expect(appPermissionsOf("{")).toEqual({ problems: ["permissions.json is no JSON"] });
		expect(appPermissionsOf('{"v":2,"processes":{}}')).toEqual({
			problems: ["permissions.json is version 1 with its processes"],
		});
		const bad = {
			start: {
				code: ["app"],
				network: "yes",
				declared: [{ package: "@p", section: "p", forks: 0, permissions: { x: 1 } }],
			},
		};
		expect(appPermissionsOf(JSON.stringify({ v: 1, processes: bad }))).toEqual({
			problems: [
				"start.code is a list of absolute directories",
				"start.network is true or false",
				"start.declared[0].forks is true or false",
				"start.declared[0]: permissions.x is no member",
			],
		});
	});
});

describe("Node's settings for a process", () => {
	it("takes the home directory as the AWS SDK does: HOME, USERPROFILE, HOMEDRIVE and HOMEPATH, then the system's", () => {
		expect(homeOf({ HOME: "/h", USERPROFILE: "/u" }, "/sys", "/")).toBe("/h");
		expect(homeOf({ HOME: "", USERPROFILE: "/u", HOMEPATH: "p" }, "/sys", "/")).toBe("/u");
		expect(homeOf({ HOMEDRIVE: "D:", HOMEPATH: "\\me" }, "/sys", "\\")).toBe("D:\\me");
		expect(homeOf({ HOMEPATH: "\\me" }, "/sys", "\\")).toBe("C:\\\\me");
		expect(homeOf({}, "/sys", "/")).toBe("/sys");
	});
	it("reads a key path's strings, each element of a list at *, nothing else", () => {
		const section = {
			file: "/a",
			keys: [{ file: "k1" }, { inline: "pem" }, { file: "" }, { file: 3 }],
		};
		expect(valuesAt(section, "file")).toEqual(["/a"]);
		expect(valuesAt(section, "keys.*.file")).toEqual(["k1"]);
		expect(valuesAt(undefined, "file")).toEqual([]);
		expect(valuesAt({ file: { not: "a string" } }, "file")).toEqual([]);
	});

	it("names every node_modules above a root, never the ancestor itself", () => {
		expect(lookupsAbove("/w/app")).toEqual(["/w/node_modules", "/node_modules"]);
	});

	const held: ProcessPermissions = {
		code: [],
		network: true,
		declared: [
			{
				package: "@mod/core-wire",
				section: "core-wire",
				forks: false,
				permissions: {
					read: { keys: ["certificate-file", "keys.*.file"] },
					write: { keys: ["out"] },
				},
			},
			{
				package: "@mod/keys-kms",
				section: "kms",
				forks: false,
				permissions: {
					read: {
						paths: [{ path: "/proc/self/limits", kind: "file" }],
						env: [
							{ name: "AWS_CONFIG_FILE", default: "~/.aws/config" },
							{ name: "AWS_WEB_IDENTITY_TOKEN_FILE" },
							{ name: "TOKEN_RELATIVE" },
						],
					},
				},
			},
			{
				package: "@mod/outbound",
				section: "outbound",
				forks: true,
				permissions: { child: { when: { key: "resolution", is: "helper" } } },
			},
		],
	};
	const inputs = {
		mode: "enforce" as const,
		tree: {
			"core-wire": { "certificate-file": "certs/core.pem", keys: [{ file: "/k/1.pem" }] },
			outbound: {},
		},
		reads: { read: ["config/application.conf"], probed: ["/w/app/config/local.conf"] },
		env: { TOKEN_RELATIVE: "token" },
		home: "/home/app",
		cwd: "/w/app",
		appRoot: "/w/app",
		allowsNet: true,
	};

	it("grants its code, the lookups above it, the configuration's reads and probes, the files its packages name, and the network; never a write", () => {
		const settings = nodeSettings(held, inputs);
		expect(settings).toEqual({
			argv: [
				"--permission",
				"--allow-fs-read=/w/app",
				"--allow-fs-read=/w/node_modules",
				"--allow-fs-read=/node_modules",
				"--allow-fs-read=/w/app/config/application.conf",
				"--allow-fs-read=/w/app/config/local.conf",
				"--allow-fs-read=/w/app/certs/core.pem",
				"--allow-fs-read=/k/1.pem",
				"--allow-fs-read=/proc/self/limits",
				"--allow-fs-read=/home/app/.aws/config",
				"--allow-fs-read=/w/app/token",
				"--allow-net",
			],
			childFor: [],
		});
		expect(JSON.stringify(settings)).not.toMatch(/allow-fs-write/);
	});

	it("audits with the same grants, holds nothing off, and leaves the network out where Node takes no flag for it", () => {
		const audit = nodeSettings(held, { ...inputs, mode: "audit" });
		expect("argv" in audit && audit.argv[0]).toBe("--permission-audit");
		expect(nodeSettings(held, { ...inputs, mode: "off" })).toEqual({ argv: [], childFor: [] });
		const noNet = nodeSettings(held, { ...inputs, allowsNet: false });
		expect("argv" in noNet && noNet.argv.includes("--allow-net")).toBe(false);
	});

	it("grants child processes where a package's forks start one: always with no condition, else where its key is set to the value, never where unset", () => {
		const childOf = (outbound: unknown, permissions = held.declared[2]?.permissions ?? {}) => {
			const process = { ...held, declared: [{ ...held.declared[2], permissions } as never] };
			const settings = nodeSettings(process, { ...inputs, tree: { outbound } });
			return "argv" in settings
				? [settings.argv.includes("--allow-child-process"), settings.childFor]
				: settings;
		};
		expect(childOf({ resolution: "helper" })).toEqual([true, ["@mod/outbound"]]);
		expect(childOf({ resolution: "in-process" })).toEqual([false, []]);
		expect(childOf({})).toEqual([false, []]);
		expect(childOf(undefined)).toEqual([false, []]);
		expect(childOf({}, {})).toEqual([true, ["@mod/outbound"]]);
	});

	it("refuses a value Node cannot take as a grant, one holding * or ,, naming where it came from, never the path", () => {
		for (const bad of ["/k/*.pem", "/k/a,b.pem"]) {
			const tree = { "core-wire": { "certificate-file": bad } };
			expect(nodeSettings(held, { ...inputs, tree })).toEqual({
				refused: {
					where: "core-wire.certificate-file",
					reason: "names a path holding * or ,, which Node cannot grant",
				},
			});
		}
		expect(nodeSettings(held, { ...inputs, env: { TOKEN_RELATIVE: "a*b" } })).toMatchObject({
			refused: { where: "TOKEN_RELATIVE" },
		});
	});

	it("reads a variable's ~/ as its reader does: the home directory where it says so and in the default, else literally", () => {
		const of = (home: boolean | undefined, env: Record<string, string>) => {
			const reading = {
				...held,
				declared: [
					{
						package: "@t/files",
						section: "files",
						forks: false,
						permissions: {
							read: {
								env: [
									{ name: "FILE", default: "~/default", ...(home === undefined ? {} : { home }) },
								],
							},
						},
					},
				],
			};
			const settings = nodeSettings(reading, { ...inputs, env });
			return "argv" in settings
				? settings.argv.filter((flag) => flag.includes("default") || flag.includes("set"))
				: settings;
		};
		expect(of(true, { FILE: "~/set" })).toEqual(["--allow-fs-read=/home/app/set"]);
		expect(of(undefined, { FILE: "~/set" })).toEqual(["--allow-fs-read=/w/app/~/set"]);
		expect(of(false, {})).toEqual(["--allow-fs-read=/home/app/default"]);
	});

	it("holds a dotted condition key by its path in the section", () => {
		const nested = {
			...held,
			declared: [
				{
					package: "@t/nested",
					section: "nested",
					forks: true,
					permissions: { child: { when: { key: "resolver.mode", is: "helper" } } },
				},
			],
		};
		const of = (tree: unknown) => {
			const settings = nodeSettings(nested, { ...inputs, tree });
			return "childFor" in settings ? settings.childFor : settings;
		};
		expect(of({ nested: { resolver: { mode: "helper" } } })).toEqual(["@t/nested"]);
		expect(of({ nested: { resolver: { mode: "in-process" } } })).toEqual([]);
		expect(of({ nested: {} })).toEqual([]);
	});
});
