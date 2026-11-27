import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readyWithinMs } from "../../../pattern/test/launch.ts";
import { stopped } from "../../../roles/test/screen.ts";
import { type World, world } from "../../test/world.ts";

// A Core taking a login's request pushed alone (par's pushed-only; FAPI 2.0's F4): a JAR by value is
// refused at ②, a started pushed JAR resent by value among them, the metadata says so, and a pushed
// login completes.

let w: World;
beforeAll(async () => {
	w = await world(["rp-par-only"], { pushedOnly: true });
}, readyWithinMs + 10_000);
afterAll(async () => {
	await w?.stop();
});

const rp = () => w.rps[0] as World["rps"][number];
/** ②'s refusal of a JAR by value where it is not taken: its word and its cause. */
const notTaken = { error: "invalid_request", error_description: "a request by value is not taken" };

describe("a Core taking pushed requests alone", () => {
	it("publishes that it requires pushed requests and takes no request parameter", () => {
		expect(w.core.metadata).toMatchObject({
			require_pushed_authorization_requests: true,
			request_parameter_supported: false,
		});
	});

	it("refuses a JAR by value at ②, and completes a login pushed", async () => {
		const person = await w.person();
		const front = await w.front();
		const byValue = rp().authorization();
		expect(await person.screen.start(front, rp().clientId, byValue.jar)).toMatchObject({
			stopped: "core",
			at: "/login/start",
			answered: { body: notTaken },
		});
		const session = rp().authorization();
		const pushed = await front.post(rp().par(session.jar));
		expect(pushed.status).toBe(201);
		const uri = (pushed.body as { request_uri: string }).request_uri;
		const s = await person.screen.startPushed(front, rp().clientId, uri);
		if (stopped(s)) throw new Error(JSON.stringify(s));
		// The JAR started pushed, resent by value under the same screen keys: refused, not given the kept T.
		expect(await person.screen.start(front, rp().clientId, session.jar, s.keys)).toMatchObject({
			stopped: "core",
			answered: { body: notTaken },
		});
		const callback = await person.screen.approve(front, s, [person.credential]);
		if (stopped(callback)) throw new Error(JSON.stringify(callback));
		expect(rp().callbackFaults(callback, session)).toEqual([]);
	});
});
