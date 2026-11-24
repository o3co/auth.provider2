import { erasers } from "@mod/erasure-extensions";
import { defineModule } from "@mod/kernel";
import { closingParticipants, type Sessions, sessionRules, sessions } from "@mod/session";
import { revocationFollowers, subjectRevocation } from "@mod/subject-revocation";
import { attributesUnder } from "./attributes.ts";
import { sessionEraser } from "./erasure/eraser.ts";
import { portsRefused } from "./erasure/ports.ts";
import { lifecycleOver } from "./lifecycle/lifecycle.ts";
import { membersOf } from "./lifecycle/listing/listing.ts";
import { section } from "./section.ts";
import { closingList, sessionStore, sessionsPerSubject, subjectSessions } from "./store.ts";

export default defineModule(
	{
		name: "session-lifecycle",
		section,
		replicaSafe: true,
		takes: [closingList, sessionStore, subjectSessions, closingParticipants, subjectRevocation],
	},
	(m) => [
		m.provide(sessionsPerSubject).by((c) => c.section["sessions-per-subject"]),
		m.provide(sessions).by(async (c): Promise<Sessions> => {
			const kept = await c.get(sessionStore);
			const listed = await c.get(subjectSessions);
			const parted = portsRefused(kept, listed);
			if (parted !== undefined) return c.refuse("session-lifecycle", parted);
			// Kept elsewhere, as session's seam: none composed is refused, never taken as no participant.
			const [closing] = await c.collect(closingParticipants);
			if (!closing) {
				return c.refuse(closingParticipants.label, "needs exactly one contribution (0)");
			}
			const sweepMs = c.section["sweep-interval"] * 1000;
			const lifecycle = lifecycleOver({
				kept,
				closings: await c.get(closingList),
				listed,
				revocation: await c.get(subjectRevocation),
				closing,
				clock: c.clock,
				random: c.random,
				log: c.log,
				sweepMs,
				attributes: attributesUnder(c.section.attributes),
			});
			c.every(sweepMs, lifecycle.sweep);
			const { open, close, entryOf, subjectOf } = lifecycle;
			return { open, close, entryOf, subjectOf };
		}),
		// Its build takes only its two stores, collecting no probes: the erasure gate collects erasers.
		m
			.contribute(erasers)
			.by(async (c) =>
				sessionEraser(await c.get(sessionStore), await c.get(subjectSessions), c.clock),
			),
		m.contribute(revocationFollowers).by(async (c) => {
			const listed = { members: membersOf(await c.get(subjectSessions)) };
			const lateSessions = c.late(sessions);
			return {
				name: "session-lifecycle",
				follow: (subject) =>
					sessionRules.closeListed(subject, listed, (handle) => lateSessions().close(handle)),
			};
		}),
	],
);
