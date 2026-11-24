import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { testServer } from "@mod/http-server/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, BootRefused, defineModule, kernelConfig } from "@mod/kernel";
import { expect, it } from "vitest";
import { senderBinding, senderBindings } from "../src/contract.ts";
import senderBindingModule from "../src/module.ts";

/** A kind a client may ask for ahead by `parameter`, taking a value of letters alone. */
const kind = (member: string, parameter?: string) =>
	defineModule({ name: `binding-${member}`, replicaSafe: true, takes: [] }, (m) => [
		m.contribute(senderBindings).by(() => ({
			member,
			tokenType: member.toUpperCase(),
			...(parameter
				? {
						requested: {
							parameter,
							confirmationOf: (value: string) => (/^[a-z]+$/.test(value) ? value : undefined),
						},
					}
				: {}),
			read: async () => ({ kind: "absent" as const }),
		})),
	]);

const reader = async (...kinds: ReturnType<typeof kind>[]) => {
	const app = await assemble({
		modules: [http, testServer(), issuerModule, senderBindingModule, ...kinds],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": "https://issuer.example" }),
			...issuerConfig(),
		},
	});
	return app.get(senderBinding);
};
const params =
	(given: Record<string, string>) =>
	(name: string): string | undefined =>
		given[name];

it("reads the binding an authorization request asks for ahead, by the parameter its kind names", async () => {
	const b = await reader(kind("one", "one_key"), kind("two"));
	expect(b.requestedOf(params({}))).toEqual({ kind: "none" });
	expect(b.requestedOf(params({ one_key: "abc", two_key: "def" }))).toEqual({
		kind: "requested",
		binding: { member: "one", confirmation: "abc", tokenType: "ONE" },
	});
});

it("refuses a value not in its kind's form, naming the parameter, and two kinds asked at once", async () => {
	const b = await reader(kind("one", "one_key"), kind("two", "two_key"));
	expect(b.requestedOf(params({ one_key: "ABC" }))).toEqual({
		kind: "malformed",
		parameter: "one_key",
	});
	expect(b.requestedOf(params({ one_key: "" }))).toEqual({
		kind: "malformed",
		parameter: "one_key",
	});
	expect(b.requestedOf(params({ one_key: "abc", two_key: "def" }))).toEqual({
		kind: "multiple_bindings",
	});
});

it("refuses boot where two kinds are asked for by one parameter", async () => {
	await expect(reader(kind("one", "key"), kind("two", "key"))).rejects.toBeInstanceOf(BootRefused);
});
