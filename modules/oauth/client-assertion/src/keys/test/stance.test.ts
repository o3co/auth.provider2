import type { Client } from "@mod/clients";
import { expect, it } from "vitest";
import { type ClientKeys, keysStance } from "../keys.ts";

/** A registered client whose client-assertion section holds the fields given. */
const client = (id: string, keys: Partial<ClientKeys> = {}) =>
	({
		id,
		section: () => ({ keys: [], "accept-loose-audience": false, ...keys }),
	}) as unknown as Client;

it("holds the client token's promise where every registered client's keys are written in and none takes a loose audience", () => {
	expect(keysStance([client("a"), client("b")])).toEqual({
		promise: "front-compromise-client-token",
		holds: true,
		by: "client-assertion",
	});
	expect(keysStance([]).holds).toBe(true);
});

it("breaks it for a registered client naming a jwks-uri, or taking a loose audience, by its place and field, never its id", () => {
	const fetched = keysStance([
		client("a"),
		client("far", { "jwks-uri": "http://keys.example/jwks" }),
	]);
	expect(fetched).toMatchObject({
		holds: false,
		by: "client-assertion",
		setting: "clients.registered.1.sections.client-assertion.jwks-uri",
	});
	const loose = keysStance([client("loose", { "accept-loose-audience": true })]);
	expect(loose).toMatchObject({
		holds: false,
		setting: "clients.registered.0.sections.client-assertion.accept-loose-audience",
	});
	expect(JSON.stringify([fetched, loose])).not.toMatch(/far|loose"|keys\.example/);
});

it("names the first registered client weakening it, whichever field it sets", () => {
	const stance = keysStance([
		client("a", { "accept-loose-audience": true }),
		client("b", { "jwks-uri": "https://keys.example/jwks" }),
	]);
	expect(stance.setting).toBe(
		"clients.registered.0.sections.client-assertion.accept-loose-audience",
	);
});
