import type { Mail, Message } from "@mod/mail";
import type { Users, Verified } from "@mod/users";
import { describe, expect, it } from "vitest";
import { masked } from "../src/account.ts";
import { issuingOver } from "../src/issuing/issuing.ts";

const passed = {
	subject: "s-alice",
	identifier: "alice@example.com",
	code: "12345678",
	startedAt: 500,
};

function issuing(p: {
	holds?: boolean;
	marked?: boolean;
	contacts?: string[];
	read?: Verified;
	sent?: "sent" | "limited";
}) {
	const order: string[] = [];
	const sent: Message[] = [];
	const users: Pick<Users, "contactsOf" | "bySubject"> = {
		contactsOf: async () => (p.contacts ?? []).map((value) => ({ kind: "email", value })),
		bySubject: async () => p.read ?? { kind: "none" },
	};
	const mail: Mail = {
		send: async (message) => {
			order.push("send");
			sent.push(message);
			return p.sent ?? "sent";
		},
	};
	const run = issuingOver({
		passkeys: {
			settle: async () => {
				order.push("settle");
				return p.holds ?? false;
			},
		},
		held: {
			of: async () => {
				order.push("held");
				return { credentials: [], marked: p.marked ?? false };
			},
		},
		users,
		issue: async (subject, code, since) => {
			order.push(`issue ${subject} ${code} ${since}`);
			return { token: "TOKEN", until: 901_000 };
		},
		mail,
		link: "https://login.example/first-key",
		lifetimeMs: 900_000,
	});
	return { run, order, sent };
}

describe("a start's job", () => {
	it("settles the keys first, and does nothing more where the subject holds a key", async () => {
		const { run, order } = issuing({ holds: true, contacts: ["a@example.com"] });
		expect(await run(passed)).toBe("holds");
		expect(order).toEqual(["settle"]);
		// A mark left after the settle holds too, as a first key's reservation reads it.
		const marked = issuing({ marked: true, contacts: ["a@example.com"] });
		expect(await marked.run(passed)).toBe("holds");
		expect(marked.order).toEqual(["settle", "held"]);
	});

	it("sends to the contact verified last, the token written before the mail, the link carrying it in the fragment", async () => {
		const { run, order, sent } = issuing({ contacts: ["new@example.com", "old@example.com"] });
		expect(await run(passed)).toBe("sent");
		expect(order).toEqual(["settle", "held", "issue s-alice 12345678 500", "send"]);
		expect(sent).toEqual([
			{
				purpose: "first-key",
				to: "new@example.com",
				values: {
					link: "https://login.example/first-key#TOKEN",
					account: "a***@example.com",
					minutes: "15",
				},
				expiresAt: 901_000,
			},
		]);
	});

	it("takes the ledger's email where it is verified, and issues no token where no address is", async () => {
		const user = (attributes: Record<string, unknown>): Verified => ({
			kind: "user",
			user: { subject: "s-alice", attributes },
		});
		const verified = issuing({ read: user({ email: "l@example.com", email_verified: true }) });
		expect(await verified.run(passed)).toBe("sent");
		expect(verified.sent[0]?.to).toBe("l@example.com");
		for (const read of [user({ email: "l@example.com" }), user({}), undefined]) {
			const none = issuing(read ? { read } : {});
			expect(await none.run(passed)).toBe("unreachable");
			expect(none.order).toEqual(["settle", "held"]);
		}
	});

	it("answers limited where mail's limits refuse it", async () => {
		expect(await issuing({ contacts: ["a@example.com"], sent: "limited" }).run(passed)).toBe(
			"limited",
		);
	});
});

it("masks an identifier to its first character, and an address's domain", () => {
	expect(masked("alice@example.com")).toBe("a***@example.com");
	expect(masked("alice")).toBe("a***");
	expect(masked("あいう")).toBe("あ***");
});
