import { type Grant, grantServers } from "@mod/grants";
import { promiseNames } from "@mod/promises";
import { expect, it } from "vitest";
import { clientSubjectStance, keyHoldStance } from "../stance.ts";

const grant = (grantType: string, subjectKind?: Grant["subjectKind"]) => ({
	grantType,
	...(subjectKind === undefined ? {} : { subjectKind }),
});

it("holds no client subject token where every grant composed declares a person's", () => {
	expect(clientSubjectStance([grant("urn:test:a", "user"), grant("urn:test:b", "user")])).toEqual({
		promise: promiseNames.noClientSubjectToken,
		holds: true,
		by: "token-endpoint",
	});
});

it("breaks it for a grant that declares the client's own, naming the grant and the module serving it", () => {
	expect(grantServers.client_credentials).toBe("client-credentials");
	expect(
		clientSubjectStance([grant("urn:test:a", "user"), grant("client_credentials", "client")]),
	).toEqual({
		promise: promiseNames.noClientSubjectToken,
		holds: false,
		by: "token-endpoint",
		reason:
			"client_credentials (client-credentials) issues a token whose subject is the client, on its key alone, with no user's approval at its root",
	});
});

it("breaks it for a grant that declares no subject kind, never counting it as held", () => {
	expect(clientSubjectStance([grant("urn:test:silent"), grant("urn:test:b", "user")])).toEqual({
		promise: promiseNames.noClientSubjectToken,
		holds: false,
		by: "token-endpoint",
		reason: "urn:test:silent declares no subject kind",
	});
});

const held = (grantType: string, keyHold?: Grant["keyHold"]) => ({
	grantType,
	...(keyHold === undefined ? {} : { keyHold }),
});

it("holds the client token's promise where every grant composed declares how it holds a client's tokens to a key, saying each", () => {
	const stance = keyHoldStance([
		held("authorization_code", "authorization"),
		held("refresh_token", "family"),
		held("client_credentials", "assertion"),
	]);
	expect(stance).toMatchObject({
		promise: promiseNames.clientToken,
		holds: true,
		by: "token-endpoint",
	});
	expect(stance.reason).toMatch(
		/authorization_code.*authorization.*refresh_token.*family.*client_credentials.*assertion/s,
	);
	expect(keyHoldStance([]).holds).toBe(true);
});

it("breaks it for a grant that declares no hold, or a value no hold is, naming the grant", () => {
	const stance = keyHoldStance([
		held("authorization_code", "authorization"),
		held("urn:test:silent"),
	]);
	expect(stance).toMatchObject({
		promise: promiseNames.clientToken,
		holds: false,
		by: "token-endpoint",
	});
	expect(stance.reason).toMatch(/urn:test:silent/);
	expect(stance.reason).not.toMatch(/authorization_code/);
});

it("counts a stray value as no hold, never as one", () => {
	for (const stray of [null, false, "none", ""])
		expect(keyHoldStance([{ grantType: "x", keyHold: stray as never }]).holds, String(stray)).toBe(
			false,
		);
});
