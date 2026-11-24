import { erasers } from "@mod/erasure-extensions";
import { defineModule, setting } from "@mod/kernel";
import { secretCheckers } from "@mod/secret-hash";
import { z } from "zod";
import { ledgers, users, usersImport } from "./contract.ts";
import { usersImporter } from "./imports/imports.ts";
import { contributedSource } from "./ledger/contributed.ts";
import { contactSubjectOf, ledgerUsers } from "./ledger.ts";
import { record, registeredUsers } from "./registered.ts";
import { contactStore } from "./store.ts";
import { usersEraser } from "./stores/eraser.ts";
import { portsRefused } from "./stores/ports.ts";
import { identifierWaits } from "./waits/waits.ts";

/** Identifiers match exactly; this form, folding case fully ("straße", "STRASSE", "STRAẞE"), only finds look-alikes. */
const confusable = (identifier: string) =>
	identifier.normalize("NFKC").trim().toLowerCase().toUpperCase();
const distinct = (values: string[]) => new Set(values).size === values.length;
const waitMs = (fallback: string) =>
	setting
		.duration("ms")
		.pipe(
			z
				.number()
				.int()
				.min(1)
				.max(2 ** 31 - 1),
		)
		.prefault(fallback);

const waits = z
	.strictObject({
		after: z
			.number()
			.int()
			.min(0)
			.prefault(3)
			.describe(
				"Failed checks of one identifier, until they are forgotten, before its checks wait.",
			),
		first: waitMs("1s").describe("The first wait; each further failure doubles it."),
		longest: waitMs("30s").describe("The longest wait."),
		forget: waitMs("15m").describe(
			"How long an identifier goes with no failure before its failures are forgotten.",
		),
	})
	.refine((w) => w.first <= w.longest, { message: "first is longer than longest", path: ["first"] })
	.prefault({})
	.describe(
		"How failed password checks of one identifier make its next checks wait, in this process.",
	);

const section = z
	.strictObject({
		registered: z
			.array(record)
			.prefault([])
			.describe("The users the settings register, each with its identifier and password hash."),
		waits,
	})
	.refine((s) => distinct(s.registered.map((r) => confusable(r.identifier))), {
		message:
			"identifiers are duplicated or differ only in case, Unicode normal form, or leading/trailing whitespace",
		path: ["registered"],
	})
	.refine((s) => distinct(s.registered.map((r) => r.subject ?? r.identifier)), {
		message: "two identifiers map to the same subject",
		path: ["registered"],
	});

export default defineModule(
	{
		name: "users",
		// Safe on many instances given the same registered users on each (deployment-guarantees, Several
		// instances); the rest it keeps is behind the store's interfaces or an outside ledger.
		replicaSafe: true,
		section,
		takes: [secretCheckers, contactStore, ledgers],
	},
	(m) => [
		// Its build takes only its stores and collects no `probes`, as an eraser's must (erasure-extensions).
		m
			.contribute(erasers)
			.by(async (c) =>
				usersEraser(await c.get(contactStore), async (key, value) => contactSubjectOf(key, value)),
			),
		m.provide(users).by(async (c) => {
			const [ledger, ...more] = await c.collect(ledgers);
			if (more.length > 0) return c.refuse("users", "more than one user ledger is contributed");
			if (ledger && c.section.registered.length > 0) {
				return c.refuse(
					"users.registered",
					"users are registered while a user ledger is contributed: take users.registered out, the ledger holding the users",
				);
			}
			// This assembly's checkers, which share its limit on checks under way.
			const checkers = await c.get(secretCheckers);
			const answering = ledger
				? contributedSource(ledger, c.log)
				: registeredUsers(c.section.registered, (inUse) => checkers.checkerOf(inUse));
			const { after, first, longest, forget } = c.section.waits;
			const waited = identifierWaits(
				{ after, firstMs: first, longestMs: longest, forgetMs: forget },
				{
					now: () => c.clock.monotonic?.() ?? c.clock.now(),
					pause: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
				},
			);
			// Every check of a password waits as its identifier's run of failures says, whoever answers.
			const source = {
				...answering,
				verify: (identifier: string, password: string) =>
					waited.run(identifier, () => answering.verify(identifier, password)),
			};
			const contacts = await c.get(contactStore);
			const ports = portsRefused(contacts);
			if (ports !== undefined) return c.refuse("users", ports);
			return ledgerUsers(source, contacts);
		}),
		// users' build refused more than one ledger, and one beside registered users.
		m.provide(usersImport).by(async (c) => {
			const [ledger] = await c.collect(ledgers);
			const keep = ledger ? contributedSource(ledger, c.log).keep : undefined;
			return usersImporter(await c.get(users), keep);
		}),
	],
);
