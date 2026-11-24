import { erasers } from "@mod/erasure-extensions";
import { defineModule, setting } from "@mod/kernel";
import { secretCheckers } from "@mod/secret-hash";
import { z } from "zod";
import { ledgers, type UpstreamNames, upstreamNames, users } from "./contract.ts";
import { contributedSource } from "./ledger/contributed.ts";
import { contactSubjectOf, ledgerUsers } from "./ledger.ts";
import { keptLinks } from "./links/kept.ts";
import { ledgerLinks } from "./links/ledger.ts";
import { linkSubjectOf } from "./links/reading.ts";
import { isNameKey, nameSubjectOf, namesKept } from "./names/elsewhere.ts";
import { issuersJudged, namesRefused } from "./names/names.ts";
import { nameRecordsOver } from "./names/records.ts";
import { keyOf, record, registeredUsers } from "./registered.ts";
import { contactStore, linkStore } from "./store.ts";
import { type ErasureReadings, usersEraser } from "./stores/eraser.ts";
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
			.describe("Failed checks of one identifier in a row before its checks wait."),
		first: waitMs("1s").describe("The first wait; each further failure doubles it."),
		longest: waitMs("30s").describe("The longest wait."),
		forget: waitMs("15m").describe(
			"How long a run of failures stays quiet before it is forgotten.",
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
		"issuer-moved": z
			.array(
				z.strictObject({
					idp: z.string().min(1).describe("The IdP name whose issuer moves."),
					from: z.string().min(1).describe("The issuer kept for the name."),
					to: z.string().min(1).describe("The issuer now declared for the name."),
				}),
			)
			.prefault([])
			.describe(
				"The moves of an IdP name to another issuer the operator states, its links going with it; every assembly no module refuses applies it and warns while one is listed.",
			),
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
	})
	.refine((s) => distinct(s.registered.flatMap((r) => r.upstream.map(keyOf))), {
		message: "an upstream identity is linked to more than one user",
		path: ["registered"],
	});

/** Each registered link through an IdP no module declares a name for: nothing would ever look it up. */
function undeclaredLinks(
	registered: z.output<typeof section>["registered"],
	declarations: readonly UpstreamNames[],
) {
	const declared = new Set(declarations.flatMap((d) => d.names.map((n) => n.name)));
	return registered.flatMap((user, i) =>
		user.upstream.flatMap((link, j) =>
			declared.has(link.idp)
				? []
				: [
						{
							where: `users.registered.${i}.upstream.${j}.idp`,
							reason: "no module declares this IdP name",
						},
					],
		),
	);
}

/** Each space's reading by the module that owns its records: a name's key is names', any other the link's. */
const erasureReadings: ErasureReadings = {
	links: async (key, value) => (isNameKey(key) ? nameSubjectOf(value) : linkSubjectOf(value)),
	contacts: async (key, value) => contactSubjectOf(key, value),
	namesKept,
};

export default defineModule(
	{
		name: "users",
		// Safe on many instances given the same registered users on each (deployment-guarantees, Several
		// instances); the rest it keeps is behind the store's interfaces or an outside ledger.
		replicaSafe: true,
		section,
		takes: [secretCheckers, contactStore, ledgers, linkStore, upstreamNames],
	},
	(m) => [
		// Its build takes only its stores and collects no `probes`, as an eraser's must (erasure-extensions).
		m
			.contribute(erasers)
			.by(async (c) =>
				usersEraser(await c.get(linkStore), await c.get(contactStore), erasureReadings),
			),
		m.provide(users).by(async (c) => {
			const declarations = await c.collect(upstreamNames);
			const refused = namesRefused(declarations);
			if (refused.length > 0) return c.refuse("users", refused.join("; "));
			const undeclared = undeclaredLinks(c.section.registered, declarations);
			if (undeclared.length > 0) return c.refuseAll(undeclared);
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
			const links = await c.get(linkStore);
			const contacts = await c.get(contactStore);
			const ports = portsRefused(links, contacts);
			if (ports !== undefined) return c.refuse("users", ports);
			const moved = c.section["issuer-moved"];
			const across = await issuersJudged(declarations, moved, nameRecordsOver(links), c.log);
			if (across.refusals.length > 0) return c.refuseAll(across.refusals);
			// Written only once no module refuses this boot, so a refused one changes nothing kept.
			c.onBuilt(async () => {
				const refusals = await across.settle();
				if (refusals.length > 0) c.refuseAll(refusals);
			});
			// A ledger that looks users up by upstream identity has the last word on links: none is written.
			const linking = ledger?.byUpstream ? ledgerLinks(source) : keptLinks(source, links);
			return ledgerUsers(source, linking, contacts);
		}),
	],
);
