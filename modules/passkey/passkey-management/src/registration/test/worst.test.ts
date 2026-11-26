import { generateKeyPairSync } from "node:crypto";
import { requests } from "@mod/front-core-wire";
import { rsaModulusCeiling } from "@mod/keys/testing";
import { expect, it } from "vitest";
import { masked } from "../../account.ts";
import { screen, sha256, stack } from "./stack.ts";

// The statements a key's path makes at their largest, against the Front's wire (worker-2's wire-fit
// survey, §A.2 and §A.3): signed here by a 2048-bit RSA key, their signature's part grown to the
// largest key keys takes (its ceiling), as a statement's length is its parts' (header, payload and
// signature, each base64url, joined by dots). An RSA key of that size takes seconds to make.
const chars = (bytes: number) => Math.ceil((bytes * 4) / 3);
const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
const largest = (statement: string) =>
	statement.length - chars(2048 / 8) + chars(rsaModulusCeiling / 8);
const maxOf = (kind: "continue" | "keyFinish") =>
	requests[kind].fields.find((field) => field.name === "statement")?.max ?? 0;
/** A credential id of the most bytes webauthn takes, 1023, base64url. */
const longId = (n: number) => `${String(n).padStart(4, "0")}${"A".repeat(1360)}`;

// Each item at its longest once JSON escapes it, as its owner bounds it: a subject of 255 visible ASCII
// characters (users), each a quote, which JSON writes in two; an account masked from users' longest
// identifier (255 bytes, no character JSON writes as \uXXXX), quotes again; an RP id of a domain's
// longest name (webauthn); the handle and the reservation at their fixed sizes.
const worstSubject = '"'.repeat(255);
const worstAccount = masked(`"@${'"'.repeat(253)}`);
const worstRpId = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(58)}.rp`;

const worst = () =>
	stack({ core: { kid: "k".repeat(128), key: rsa }, issuer: `https://${"i".repeat(248)}` });

it("fits a creation excluding fifteen credentials of 1023 bytes under the largest Core key within the continue's statement", async () => {
	const s = await worst();
	const shown = screen();
	const issued = await s.parts.approvals.issue({
		purpose: "creation",
		items: {
			account: worstAccount,
			basis: "first-key",
			evidence: sha256("token"),
			ct_hash: sha256("ct"),
			subject: worstSubject,
			// The key generation at its longest, as an integer the JSON writes.
			kg: Number.MAX_SAFE_INTEGER,
			options: {
				// webauthn's freshHandle: 32 random bytes.
				user_id: "u".repeat(43),
				rp_id: worstRpId,
				exclude_credentials: Array.from({ length: 15 }, (_, n) => longId(n)),
				algorithms: [-7, -8, -257],
			},
		},
		screen: shown.keys,
		by: worstSubject,
	});
	if (issued.kind !== "issued") throw new Error(issued.reason);
	const length = largest(issued.statement);
	// Past the 8192 it had, within the operation's statement now.
	expect(length).toBeGreaterThan(8192);
	expect(length).toBeLessThanOrEqual(maxOf("continue"));
});

it("fits a possession of a 1023-byte credential under the largest Core key within the key's finish's statement", async () => {
	const s = await worst();
	const shown = screen();
	const issued = await s.parts.approvals.issue({
		purpose: "possession",
		items: {
			creation_hash: sha256("creation"),
			key_jkt: sha256("key"),
			credential_id: longId(0),
			// passkeys' reservation: 16 random bytes.
			reservation_id: "r".repeat(22),
		},
		screen: shown.keys,
		by: worstSubject,
	});
	if (issued.kind !== "issued") throw new Error(issued.reason);
	const length = largest(issued.statement);
	expect(length).toBeGreaterThan(4096);
	expect(length).toBeLessThanOrEqual(maxOf("keyFinish"));
});
