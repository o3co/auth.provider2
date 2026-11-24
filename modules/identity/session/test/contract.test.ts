import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { revocations } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { expect, it } from "vitest";
import { closingParticipants, sessions } from "../src/contract.ts";
import {
	failStandInListing,
	openedOf,
	type SessionsPlace,
	sessionStandIn,
	sessionsContract,
	standInListingCap,
} from "../src/testing.ts";

/** A place over the stand-in, with a participant whose work can be made to fail, or with none. */
async function placeOver(participant = true): Promise<SessionsPlace> {
	let now = 1_800_000_000_000;
	let failing = false;
	const closed: string[] = [];
	const around = defineModule({ name: "around", replicaSafe: false, takes: [] }, (m) => [
		m.contribute(closingParticipants).by(() => ({
			closing: async (session) => {
				if (failing) return [{ participant: "test", kind: "Error" }];
				closed.push(session.context.subject);
				return [];
			},
		})),
	]);
	const app = await assemble({
		modules: [sessionStandIn, subjectRevocationStandIn, ...(participant ? [around] : [])],
		config: kernelConfig(),
		runtime: quietRuntime({ clock: { now: () => now } }),
	});
	return {
		sessions: app.get(sessions),
		now: () => now,
		advance: (ms) => {
			now += ms;
		},
		revokeSubject: (subject) => app.get(revocations).record(subject),
		closed,
		failClosing: (on) => {
			failing = on;
		},
		listingCap: standInListingCap,
		failNextListing: () => failStandInListing(app.get(sessions)),
	};
}

sessionsContract("the stand-in, over subject-revocation's stand-in", () => placeOver());

it("takes no participant contributed as none, and closes at once", async () => {
	const place = await placeOver(false);
	const facts = {
		subject: "alice",
		amr: ["pwd"],
		authenticatedAt: place.now(),
		provenSince: place.now(),
		endsAt: place.now() + 60_000,
	};
	const done = openedOf(await place.sessions.open(facts));
	expect((await place.sessions.close(done.session.id)).kind).toBe("closed");
	expect((await place.sessions.entryOf(done.session.id)).kind).toBe("absent");
});

it("takes every handle its stand-in's takes name, the seam collected though none is contributed", async () => {
	const modules = [sessionStandIn, subjectRevocationStandIn];
	expect((await takesUnused({ modules, config: kernelConfig() })).session).toBeUndefined();
});
