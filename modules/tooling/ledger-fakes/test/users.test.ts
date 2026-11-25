import { ledgerRoutes } from "@mod/ledger-wire";
import { describe, expect, it } from "vitest";
import { type LedgerCall, usersLedger } from "../src/contract.ts";

const alice = {
	identifier: "alice",
	password: "right",
	subject: "u-1",
	email: "a@x.example",
	emailVerified: true,
};

/** A lookup's answer for a user it does not know, saying so. */
const notFound = { status: 404, json: { error: "not_found" } };

const caller =
	(ledger: ReturnType<typeof usersLedger>) =>
	(path: string, body: unknown, credential = ledger.credential): LedgerCall => ({
		method: "POST",
		path,
		headers: { authorization: `Bearer ${credential}` },
		body: JSON.stringify(body),
	});

describe("a fake ledger speaking users-http's calls", () => {
	const ledger = usersLedger([alice]);
	const call = caller(ledger);

	it("serves its calls at one origin, under a credential of its own", () => {
		// Every route ledger-wire names, at the origin: a call the wire adds is served there too.
		expect(ledger.urls("http://127.0.0.1:1")).toEqual(
			Object.fromEntries(
				Object.entries(ledgerRoutes.users).map(([call, path]) => [
					call,
					`http://127.0.0.1:1${path}`,
				]),
			),
		);
		expect(ledger.urls("http://127.0.0.1:1").verify).toBe("http://127.0.0.1:1/verify");
		expect(ledger.credential).toMatch(/^[0-9a-f]{64}$/);
	});

	it("makes an identifierless subject for a key once, the same for that key after, found by subject", () => {
		const key = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
		const made = ledger.answer(call("/create-identifierless", { key }));
		expect(made?.status).toBe(201);
		const id = (made?.json as { id: string } | undefined)?.id;
		expect(ledger.answer(call("/create-identifierless", { key }))).toEqual(made);
		const other = ledger.answer(call("/create-identifierless", { key: key.replace("4", "5") }));
		expect((other?.json as { id: string } | undefined)?.id).not.toBe(id);
		expect(ledger.answer(call("/subject", { subject: id }))).toEqual({ json: { id } });
		expect(ledger.answer(call("/create-identifierless", { key: "short" }))).toEqual({
			status: 400,
		});
	});

	it("verifies the right password, and says no such user to a wrong one", () => {
		const user = { id: "u-1", username: "alice", email: "a@x.example", emailVerified: true };
		expect(ledger.answer(call("/verify", { email: "alice", password: "right" }))).toEqual({
			json: user,
		});
		expect(ledger.answer(call("/verify", { email: "alice", password: "wrong" }))).toEqual(notFound);
	});

	it("looks a user up by subject and by identifier, in the shape users-http reads", () => {
		const user = { id: "u-1", username: "alice", email: "a@x.example", emailVerified: true };
		expect(ledger.answer(call("/subject", { subject: "u-1" }))).toEqual({ json: user });
		expect(ledger.answer(call("/subject", { subject: "u-2" }))).toEqual(notFound);
		expect(ledger.answer(call("/identifier", { email: "alice" }))).toEqual({ json: user });
		expect(ledger.answer(call("/identifier", { email: "bob" }))).toEqual(notFound);
	});

	it("answers a bare 404 to its calls without its credential, which says no user is not known, and nothing to a call not its own", () => {
		expect(ledger.answer(call("/verify", { email: "alice", password: "right" }, "other"))).toEqual({
			status: 404,
		});
		expect(ledger.answer(call("/elsewhere", {}))).toBeUndefined();
	});
});

describe("a fake ledger creating subjects", () => {
	it("creates a subject for a new identifier, answered 201, and finds it after", () => {
		const ledger = usersLedger([]);
		const call = caller(ledger);
		const made = ledger.answer(call("/create", { email: "bob" }));
		expect(made?.status).toBe(201);
		const { id } = (made?.json ?? {}) as { id?: string };
		expect(id).toMatch(/^.+$/);
		expect(ledger.answer(call("/identifier", { email: "bob" }))).toEqual({
			json: { id, username: "bob" },
		});
		expect(ledger.answer(call("/subject", { subject: id }))).toEqual({
			json: { id, username: "bob" },
		});
	});

	it("answers 409 naming the identifier taken where it has a subject already, and makes none", () => {
		const ledger = usersLedger([alice]);
		const call = caller(ledger);
		expect(ledger.answer(call("/create", { email: "alice" }))).toEqual({
			status: 409,
			json: { error: "exists" },
		});
		expect(ledger.answer(call("/identifier", { email: "alice" }))?.json).toMatchObject({
			id: "u-1",
		});
	});

	it("verifies no password for a subject it created", () => {
		const ledger = usersLedger([]);
		const call = caller(ledger);
		ledger.answer(call("/create", { email: "bob" }));
		expect(ledger.answer(call("/verify", { email: "bob", password: "" }))).toEqual(notFound);
	});
});
