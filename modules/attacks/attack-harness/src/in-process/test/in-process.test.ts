import { promiseNames } from "@mod/promises";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readyWithinMs } from "../../pattern/test/launch.ts";
import { honestRelay } from "../../relay/relay.ts";
import type { RelyingParty } from "../../roles/test/rp.ts";
import { stopped } from "../../roles/test/screen.ts";
import { type InProcess, inProcess, testClock } from "./in-process.ts";

const clock = testClock();
let core: InProcess;
beforeAll(async () => {
	core = await inProcess({ clientIds: ["rp-here"] }, honestRelay, clock);
}, readyWithinMs + 10_000);
afterAll(() => core?.stop());

describe("a Core in the test's process", () => {
	it("is judged at its start to hold claims 1 and 2, and not claim 3: its log and the log's judgment run in it", () => {
		const held = (promise: string) => core.judged.find((j) => j.promise === promise)?.held;
		expect(held(promiseNames.newAuthorization)).toBe(true);
		expect(held(promiseNames.clientToken)).toBe(true);
		expect(held(promiseNames.coreContained)).toBe(false);
	});

	it("signs a person up through its world, the keys' owner holding their key, the log their record judged as an honest one", async () => {
		const who = await core.world.person();
		const key = await core.keysRead.keyOf(who.credential);
		if (key === undefined) throw new Error("no key");
		const flow = { of: "subject", id: key.subject } as const;
		expect((await core.keysRead.heldBy(key.subject)).credentials).toEqual([who.credential]);
		const head = await core.writer.head(flow);
		expect(head).toBeGreaterThan(0);
		// At L0 no monitor confirms: an honest record on a subject's flow is unsupported, and takes.
		expect(await core.writer.at(flow, head)).toMatchObject({
			kind: "keyChange",
			judged: { verdict: "unsupported", outcome: "took" },
		});
		expect(await core.writer.at(flow, head + 1)).toBeUndefined();
		expect(await core.keysRead.keyOf("no-such-credential")).toBeUndefined();
	});

	it("opens only what was sealed to it, and offers no reset where passkey-reset is not composed", async () => {
		const junk = Buffer.alloc(65, 4).toString("base64url");
		expect(await core.opener.open({ enc: junk, ct: junk }, "delete", "h", 1)).toBe("unopened");
		expect(core.setup).toBeUndefined();
	});

	it("runs on the test's clock, the roles on the same: a JAR an hour ahead of the real time starts", async () => {
		clock.advance(60 * 60_000);
		const who = await core.world.person();
		const rp = core.world.rps[0] as RelyingParty;
		const front = await core.world.front();
		const { s } = await core.world.started(who, rp, front);
		expect(stopped(s)).toBe(false);
		// T was signed by the Core at the test's time, an hour past the real one.
		const iat = (s.t.statement as { iat: number }).iat;
		expect(iat * 1000).toBeGreaterThan(Date.now() + 59 * 60_000);
		expect(() => clock.advance(-1)).toThrow(RangeError);
	});
});
