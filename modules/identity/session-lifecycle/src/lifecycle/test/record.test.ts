import { expect, it } from "vitest";
import type { StoredSession } from "../../store.ts";
import { closedFrom, fromStored, type SessionRecord, toStored } from "../record.ts";

const at = 1_800_000_000_000;
const stored = (value: Record<string, unknown>) => value as unknown as StoredSession;
const open = {
	format: 1,
	state: "open",
	subject: "alice",
	amr: ["pwd"],
	authenticatedAt: at - 60_000,
	openedAt: at,
	endsAt: at + 3_600_000,
};

it("reads a record of its own format as it is", () => {
	expect(fromStored(stored(open))).toEqual(open);
	const unknown = { ...open, authenticatedAt: at, authenticatedAtUnknown: true };
	expect(fromStored(stored(unknown))).toEqual(unknown);
});

it("reads nothing of another format, or of a shape it does not know", () => {
	for (const value of [
		{ ...open, format: 2 },
		{ ...open, endsAt: undefined },
		{ ...open, extra: 1 },
		{ format: 1, state: "closed" },
		{ format: 1, state: "closed", subject: "alice", openedAt: at, endsAt: at, amr: [] },
		null,
	]) {
		expect(fromStored(stored(value as Record<string, unknown>)), JSON.stringify(value)).toBe(
			undefined,
		);
	}
});

it("closes a record to its subject, opening and end, dropping a login's attributes, amr and times", () => {
	const closing = {
		...open,
		state: "closing",
		attributes: { source: "idp", values: { email: "a@example.com" } },
		closingSince: at + 2000,
		retryAt: at + 3000,
	};
	const read = fromStored(stored(closing));
	expect(read).toMatchObject({ state: "closing", attributes: closing.attributes });
	const closed = closedFrom(read as SessionRecord);
	expect(closed).toEqual({
		format: 1,
		state: "closed",
		subject: "alice",
		openedAt: at,
		endsAt: at + 3_600_000,
	});
	expect(fromStored(toStored(closed))).toEqual(closed);
	expect(closedFrom(closed)).toEqual(closed);
});
