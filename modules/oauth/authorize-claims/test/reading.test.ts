import type { Selection } from "@mod/claims-selection";
import type { Client } from "@mod/clients";
import { describe, expect, it } from "vitest";
import { claimsReading, claimsRefusal } from "../src/reading.ts";

const client = { id: "c1" } as Client;
const none: Selection = {
	idToken: { names: [], constraints: [] },
	userinfo: { names: [], constraints: [] },
};

/** The reading over a selection that answers what it was asked, recording each call. */
function reading() {
	const calls: unknown[][] = [];
	const r = claimsReading({
		select: async (...args) => {
			calls.push(args);
			return none;
		},
		keepForCode: async (...args) => {
			calls.push(args);
		},
	});
	return { r, calls };
}

describe("an OpenID request's claims", () => {
	it("are refused at ② where malformed or asked without openid, and taken otherwise", () => {
		expect(claimsRefusal(undefined, false)).toBeUndefined();
		expect(claimsRefusal({ id_token: { email: null } }, true)).toBeUndefined();
		expect(claimsRefusal({ id_token: { email: null } }, false)).toMatch(/openid/);
		expect(claimsRefusal({ id_token: 3 }, true)).toMatch(/malformed/);
		expect(reading().r.refusal).toBe(claimsRefusal);
	});

	it("select what the person agreed to in T, kept for the code as claims-selection keeps it", async () => {
		const { r, calls } = reading();
		const claims = { id_token: { email: null }, userinfo: { name: null, email: null } };
		const picked = await r.select(client, "alice", ["openid", "email"], claims, undefined);
		expect(calls[0]?.[3]).toEqual({ scopes: ["openid", "email"], names: ["email", "name"] });
		if (picked.kind !== "selected") throw new Error(`picked ${picked.kind}`);
		await picked.keep("digest", 60_000, "alice");
		expect(calls[1]).toEqual(["digest", none, 60_000, "alice"]);
		expect(await r.select(client, "alice", ["openid"], undefined, undefined)).toEqual({
			kind: "none",
		});
		expect(calls).toHaveLength(2);
	});

	it("answer a sub asked of another subject, and an essential acr the login does not meet", async () => {
		const { r } = reading();
		const sub = { id_token: { sub: { value: "bob" } } };
		expect(await r.select(client, "alice", ["openid"], sub, undefined)).toEqual({
			kind: "otherSubject",
		});
		const essential = (values: string[]) => ({
			id_token: { acr: { essential: true, ...(values.length > 0 ? { values } : {}) } },
		});
		const asked = async (claims: unknown, acr?: string) =>
			(await r.select(client, "alice", ["openid"], claims, acr)).kind;
		expect(await asked(essential(["urn:a"]), "urn:a")).toBe("selected");
		expect(await asked(essential(["urn:b"]), "urn:a")).toBe("acrUnmet");
		expect(await asked(essential([]), undefined)).toBe("acrUnmet");
		expect(await asked(essential([]), "urn:a")).toBe("selected");
		// One not essential is voluntary: the login answers it as it can.
		expect(await asked({ id_token: { acr: { values: ["urn:b"] } } }, undefined)).toBe("selected");
	});

	it("read malformed past ② are no request the start let through", async () => {
		await expect(reading().r.select(client, "alice", ["openid"], [], undefined)).rejects.toThrow(
			TypeError,
		);
	});
});
