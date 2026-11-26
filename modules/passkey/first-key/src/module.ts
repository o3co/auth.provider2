import { routes } from "@mod/http";
import { type BuildContext, contract, defineModule } from "@mod/kernel";
import { mailPurposes } from "@mod/mail";
import { type Counter, counter, instruments } from "@mod/metrics";
import { evidence, evidenceKinds, promiseNames, stances } from "@mod/promises";
import { firstKeyEvidence, firstKeyMail } from "./contract.ts";
import { type Evidence, evidenceOver, inboxKind, undeclared } from "./evidence/evidence.ts";
import { pathOf, pathTakes } from "./path/path.ts";
import { type Settings, section } from "./section.ts";

type Context = BuildContext<Settings>;

/** The kinds composed asked of a start, as the path's rule takes them together. */
const firstKeyChecks = contract<Evidence>("first-key.checks");
/** A start's jobs dropped, never run: past the bound under way, or outside start and stop. */
const droppedJobs = contract<Counter>("first-key.dropped");
/** The routes of the first key's path, made once from its parts. */
const firstKeyPath = contract<Awaited<ReturnType<typeof pathOf>>>("first-key.path");

// Holds nothing of its own past a start's job: its nonces and tokens are in their stores.
export default defineModule(
	{
		name: "first-key",
		section,
		replicaSafe: true,
		takes: [firstKeyEvidence, evidence, ...pathTakes],
	},
	(m) => [
		// A first key's path is outside the new authorization's claim (P1): it breaks none of it.
		m.contribute(stances).by(() => ({
			promise: promiseNames.newAuthorization,
			holds: true,
			by: "first-key",
		})),
		// Its mail's wording is a template's, which a deployment replaces with its own module.
		m.contribute(mailPurposes).by(() => ({ purpose: firstKeyMail.purpose })),
		// The inbox, the path's own kind; alone where no other is composed or one absent on all may pass.
		m.contribute(evidenceKinds).by(async (c) => {
			const composed = await c.collect(firstKeyEvidence);
			const alone = composed.length === 0 || c.section["inbox-only-when-absent"];
			return inboxKind(c.section["token-lifetime"] * 1000, alone);
		}),
		m.provide(firstKeyChecks).by(async (c) => {
			const composed = await c.collect(firstKeyEvidence);
			// A kind composed that no module declares to promises would pass unseen by those who rely on it.
			const missing = undeclared(composed, (await c.get(evidence)).kinds());
			if (missing.length > 0)
				return c.refuse(
					"first-key",
					`a kind of a first key's evidence is composed undeclared, or declared past: ${missing.join(", ")}`,
				);
			return evidenceOver(composed, c.section["inbox-only-when-absent"]);
		}),
		m.provide(droppedJobs).by(() =>
			counter({
				name: "auth_first_key_jobs_dropped_total",
				help: "A first key's start jobs dropped since boot, never run: past the bound under way, or outside start and stop.",
				labels: {},
			}),
		),
		m.contribute(instruments).by((c) => c.get(droppedJobs)),
		m.provide(firstKeyPath).by(async (c: Context) => {
			const dropped = await c.get(droppedJobs);
			return pathOf(c, { evidence: await c.get(firstKeyChecks), dropped: () => dropped.add({}) });
		}),
		m.contribute(routes).by(async (c) => (await c.get(firstKeyPath)).nonce),
		m.contribute(routes).by(async (c) => (await c.get(firstKeyPath)).start),
		m.contribute(routes).by(async (c) => (await c.get(firstKeyPath)).mail),
		m.contribute(routes).by(async (c) => (await c.get(firstKeyPath)).recover),
	],
);
