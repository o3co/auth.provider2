import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { closingParticipants, sessions } from "@mod/session";
import { type SessionsPlace, sessionsContract } from "@mod/session/testing";
import { revocations } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import sessionLifecycle from "../src/module.ts";
import { sessionLifecycleConfig } from "../src/testing.ts";
import { memoryStores } from "./stores.ts";

const listingCap = 50;

/** A place over session-lifecycle, with the participant the contract test expects. */
async function place(): Promise<SessionsPlace> {
	let now = 1_800_000_000_000;
	let failing = false;
	const closed: string[] = [];
	const stores = memoryStores();
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
		modules: [sessionLifecycle, stores.module, subjectRevocationStandIn, around],
		config: {
			...kernelConfig(),
			...sessionLifecycleConfig({ "sessions-per-subject": listingCap }),
		},
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
		listingCap,
		failNextListing: () => stores.down.listed.failNext("add"),
	};
}

sessionsContract(
	"session-lifecycle over the records stand-in and subject-revocation's stand-in",
	place,
);
