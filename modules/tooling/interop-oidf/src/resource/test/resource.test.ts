import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { thumbprint } from "../../rp/test/rp.ts";
import { thumbprintOf } from "./resource.ts";

describe("thumbprintOf (RFC 7638)", () => {
	it("gives RFC 7638 §3.1's thumbprint of its RSA key", () => {
		const n =
			"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
		expect(thumbprintOf({ kty: "RSA", n, e: "AQAB", alg: "RS256", kid: "2011-04-29" })).toBe(
			"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
		);
	});

	it("gives RFC 8037 A.3's thumbprint of its Ed25519 key", () => {
		expect(
			thumbprintOf({
				kty: "OKP",
				crv: "Ed25519",
				x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
			}),
		).toBe("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
	});

	it("gives an EC key's thumbprint as the RP's own reckoning does", () => {
		const { x = "", y = "" } = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({
			format: "jwk",
		});
		expect(thumbprintOf({ kty: "EC", crv: "P-256", x, y })).toBe(thumbprint({ x, y }));
	});

	it("gives none for a key of another type, or missing a member", () => {
		expect(thumbprintOf({ kty: "oct", k: "AAAA" })).toBeUndefined();
		expect(thumbprintOf({ kty: "EC", crv: "P-256", x: "AAAA" })).toBeUndefined();
	});
});
