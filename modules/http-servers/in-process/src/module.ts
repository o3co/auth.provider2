import { httpServers, marks, policies, routes } from "@mod/http";
import { nodeHttpServer } from "@mod/http-server";
import { defineModule } from "@mod/kernel";
import { promiseNames, stances } from "@mod/promises";

/** Why a Core in the Front's process breaks both promises a compromised Front must not break. */
const reason =
	"the Core runs in the Front's process: whoever takes the Front takes the Core with it, its checks and the use of its keys, so a login needs no passkey and a token no client's key";

// Safe on many instances: each serves its own listener and holds nothing else.
export default defineModule(
	{ name: "in-process", replicaSafe: true, takes: [marks, policies, routes] },
	(m) => [
		m.contribute(httpServers).by(async (c) => {
			const built = nodeHttpServer({
				routes: await c.collect(routes),
				rules: await c.collect(policies),
				marks: await c.collect(marks),
			});
			return built.kind === "refused" ? c.refuseAll(built.refusals) : built.server;
		}),
		m.contribute(stances).by(() => ({
			promise: promiseNames.newAuthorization,
			holds: false,
			by: "in-process",
			reason,
		})),
		m.contribute(stances).by(() => ({
			promise: promiseNames.clientToken,
			holds: false,
			by: "in-process",
			reason,
		})),
	],
);
