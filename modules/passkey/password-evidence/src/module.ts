import { firstKeyEvidence } from "@mod/first-key";
import { defineModule } from "@mod/kernel";
import { evidenceKinds, trustedNames } from "@mod/promises";
import { users } from "@mod/users";
import { kind, passwordEvidence } from "./evidence.ts";

// It holds a start's check until its end; an end told in another process finds none, and the check
// stays a failure, so several instances are safe.
export default defineModule(
	{ name: "password-evidence", replicaSafe: true, takes: [users] },
	(m) => [
		m.contribute(firstKeyEvidence).by(async (c) => passwordEvidence(await c.get(users))),
		m.contribute(evidenceKinds).by(async (c) => {
			const { count, windowMs } = (await c.get(users)).failedChecks;
			return {
				kind,
				by: "password-evidence",
				trusts: [trustedNames.password],
				strength: { kind: "guesses", guesses: { count, windowMs } },
			};
		}),
	],
);
