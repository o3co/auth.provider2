import type { Selection } from "@mod/claims-selection";
import type { Client } from "@mod/clients";
import { describe, expect, it } from "vitest";
import { claimsPinning, claimsRefusal } from "../claims.ts";

const client = { id: "c1" } as Client;
const none: Selection = {
	idToken: { names: [], constraints: [] },
	userinfo: { names: [], constraints: [] },
};

/** The pinning over a selection that answers what it was asked, recording each call. */
function pinning() {
	const calls: unknown[][] = [];
	const p = claimsPinning({
		select: async (...args) => {
			calls.push(args);
			return none;
		},
		keepForCode: async (...args) => {
			calls.push(args);
		},
	});
	return { p, calls };
}

describe("an OpenID request's claims", () => {
	it("are refused at ② where malformed or asked without openid, and taken otherwise", () => {
		expect(claimsRefusal(undefined, false)).toBeUndefined();
		expect(claimsRefusal({ id_token: { email: null } }, true)).toBeUndefined();
		expect(claimsRefusal({ id_token: { email: null } }, false)).toMatch(/openid/);
		expect(claimsRefusal({ id_token: 3 }, true)).toMatch(/malformed/);
	});

	it("select what the person agreed to in T: its scope's words and the names its claims asked", async () => {
		const { p, calls } = pinning();
		const claims = { id_token: { email: null }, userinfo: { name: null, email: null } };
		expect(await p.select(client, "alice", ["openid", "email"], claims, undefined)).toEqual({
			kind: "selected",
			selection: none,
		});
		expect(calls[0]?.[3]).toEqual({ scopes: ["openid", "email"], names: ["email", "name"] });
		expect(await p.select(client, "alice", ["openid"], undefined, undefined)).toEqual({
			kind: "none",
		});
	});

	it("answer a sub asked of another subject, and an essential acr the login does not meet", async () => {
		const { p } = pinning();
		const sub = { id_token: { sub: { value: "bob" } } };
		expect(await p.select(client, "alice", ["openid"], sub, undefined)).toEqual({
			kind: "otherSubject",
		});
		const essential = (values: string[]) => ({
			id_token: { acr: { essential: true, ...(values.length > 0 ? { values } : {}) } },
		});
		const asked = async (claims: unknown, acr?: string) =>
			(await p.select(client, "alice", ["openid"], claims, acr)).kind;
		expect(await asked(essential(["urn:a"]), "urn:a")).toBe("selected");
		expect(await asked(essential(["urn:b"]), "urn:a")).toBe("acrUnmet");
		expect(await asked(essential([]), undefined)).toBe("acrUnmet");
		expect(await asked(essential([]), "urn:a")).toBe("selected");
		// One not essential is voluntary: the login answers it as it can.
		expect(await asked({ id_token: { acr: { values: ["urn:b"] } } }, undefined)).toBe("selected");
	});

	it("are kept for the code as claims-selection keeps them", async () => {
		const { p, calls } = pinning();
		await p.keep("digest", none, 60_000, "alice");
		expect(calls).toEqual([["digest", none, 60_000, "alice"]]);
	});
});
