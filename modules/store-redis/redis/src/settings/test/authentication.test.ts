import { expect, it } from "vitest";
import { authenticationProblems } from "../settings.ts";

const spaces = [
	{ name: "signed", guarantees: ["authenticated"] as const },
	{ name: "plain", guarantees: ["durable"] as const },
];

it("refuses authenticated spaces unless the operator states the store authenticates nothing, naming them", () => {
	expect(authenticationProblems(spaces, undefined)).toEqual([
		"no Redis store tells a write made outside the provider apart, which the authenticated guarantee of these spaces needs (set redis.authentication to none to accept it): signed",
	]);
	expect(authenticationProblems(spaces, "none")).toEqual([]);
	expect(authenticationProblems([spaces[1] as (typeof spaces)[number]], undefined)).toEqual([]);
});
