import { describe, expect, it } from "vitest";
import { registryWire } from "../src/contract.ts";

const client = {
	id: "rp-1",
	kind: "confidential",
	method: "private_key_jwt",
	sections: { "redirect-uris": { uris: ["https://rp.example/cb"] } },
};
const version = { v: 1, version: 3, issuedAt: 1_700_000_000, clients: [client] };

describe("a version of the client registry, as the publisher signs it", () => {
	it("reads a version: the wire's version, a version number that only grows, when it was issued, and the clients", () => {
		expect(registryWire.version.safeParse(version).success).toBe(true);
		expect(registryWire.version.safeParse({ ...version, clients: [] }).success).toBe(true);
	});

	it("refuses a version number that is not a positive whole number, and a wire version it does not speak", () => {
		for (const bad of [0, -1, 1.5]) {
			expect(
				registryWire.version.safeParse({ ...version, version: bad }).success,
				String(bad),
			).toBe(false);
		}
		expect(registryWire.version.safeParse({ ...version, v: 2 }).success).toBe(false);
	});

	it("refuses a client without its id, kind or method, and a kind that is neither public nor confidential", () => {
		const without = (key: string) =>
			Object.fromEntries(Object.entries(client).filter(([k]) => k !== key));
		for (const key of ["id", "kind", "method"]) {
			expect(
				registryWire.version.safeParse({ ...version, clients: [without(key)] }).success,
				key,
			).toBe(false);
		}
		expect(
			registryWire.version.safeParse({ ...version, clients: [{ ...client, kind: "trusted" }] })
				.success,
		).toBe(false);
	});

	it("refuses two clients under one id, as a version names each client once", () => {
		expect(registryWire.version.safeParse({ ...version, clients: [client, client] }).success).toBe(
			false,
		);
	});

	it("refuses a field it does not know, so a version means one thing to every reader", () => {
		expect(registryWire.version.safeParse({ ...version, extra: true }).success).toBe(false);
		expect(
			registryWire.version.safeParse({ ...version, clients: [{ ...client, extra: 1 }] }).success,
		).toBe(false);
	});

	it("names the type its signature carries, and the wire versions it speaks", () => {
		expect(registryWire.typ).toBe("registry+jwt");
		expect(registryWire.speaks).toEqual([1]);
	});

	it("holds every word frozen", () => {
		expect(Object.isFrozen(registryWire)).toBe(true);
		expect(Object.isFrozen(registryWire.speaks)).toBe(true);
	});
});
