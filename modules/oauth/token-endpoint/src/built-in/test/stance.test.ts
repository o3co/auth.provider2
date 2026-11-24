import { type Grant, grantServers } from "@mod/grants";
import { promiseNames } from "@mod/promises";
import { expect, it } from "vitest";
import { clientSubjectStance } from "../stance.ts";

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
