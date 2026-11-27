import type { WireReply } from "@mod/front-core-codec";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readyWithinMs } from "../../pattern/test/launch.ts";
import type { Started as Session } from "../../roles/test/rp.ts";
import { type Started, stopped } from "../../roles/test/screen.ts";
import { provider, type World, world } from "./world.ts";

// The person refuses on the screen: the page POSTs access_denied to T's redirect_uri with T's state and
// issuer, every value T's; the screen role's deny takes no Front, so it sends the Core nothing. What the
// RP is held to here is R3 and R4 on the denial's values (R12, the POST's own checks, and the RP's
// handling of an error callback are not played: the harness's RP has no form_post endpoint).

let w: World;
beforeAll(async () => {
	w = await world(["rp-deny"]);
}, readyWithinMs + 10_000);
afterAll(async () => {
	await w?.stop();
});

const rp = () => w.rps[0] as World["rps"][number];
const text = new TextDecoder();
const utf8 = new TextEncoder();
type Person = Awaited<ReturnType<World["person"]>>;
type Front = Awaited<ReturnType<World["front"]>>;

/** A session's start on the person's screen, by value or by the request_uri its push was given. */
const startOf = (person: Person, front: Front, session: Session, uri: string | undefined) =>
	uri === undefined
		? person.screen.start(front, rp().clientId, session.jar)
		: person.screen.startPushed(front, rp().clientId, uri);

/** A session of the RP's started on the person's screen, by value or pushed: the session, T read, and its request_uri. */
async function begun(
	person: Person,
	front: Front,
	pushed: boolean,
): Promise<[Session, Started, string | undefined]> {
	const session = rp().authorization();
	const uri = pushed
		? ((await front.post(rp().par(session.jar))).body as { request_uri: string }).request_uri
		: undefined;
	const s = await startOf(person, front, session, uri);
	if (stopped(s)) throw new Error(JSON.stringify(s));
	return [session, s, uri];
}

/** ②'s answer with T's approval changed by `change`, its signature left as the Core made it. */
const tampered =
	(change: (approval: Record<string, unknown>) => Record<string, unknown>) =>
	(reply: WireReply): WireReply => {
		if (reply.outcome !== "ok") return reply;
		const body = JSON.parse(text.decode(reply.message.body)) as { statement: string };
		const [head, payload, signature] = body.statement.split(".");
		const t = JSON.parse(Buffer.from(payload ?? "", "base64url").toString("utf8"));
		const changed = Buffer.from(JSON.stringify({ ...t, approval: change(t.approval) }));
		const statement = `${head}.${changed.toString("base64url")}.${signature}`;
		return {
			...reply,
			message: { ...reply.message, body: utf8.encode(JSON.stringify({ ...body, statement })) },
		};
	};

describe("the person's denial on the screen", () => {
	it("is T's access_denied, by value and pushed, its values passing the RP's R3 and R4, with no code", async () => {
		for (const pushed of [false, true]) {
			const person = await w.person();
			const front = await w.front();
			const [session, s] = await begun(person, front, pushed);
			const denied = person.screen.deny(s);
			if (stopped(denied)) throw new Error(JSON.stringify(denied));
			expect(denied, String(pushed)).toEqual({
				error: "access_denied",
				state: session.state,
				iss: provider.issuer,
				redirectUri: rp().redirectUri,
			});
			expect(rp().callbackFaults(denied, session), String(pushed)).toEqual([]);
		}
	});

	it("leaves the screen nothing to deny where the Front changes T in ②'s answer, by value and pushed", async () => {
		for (const pushed of [false, true]) {
			const person = await w.person();
			const front = await w.front();
			const session = rp().authorization();
			const uri = pushed
				? ((await front.post(rp().par(session.jar))).body as { request_uri: string }).request_uri
				: undefined;
			// Another redirect_uri in T: any byte changed breaks the Core's signature over it.
			front.rewrite({
				replies: {
					loginStart: tampered((a) => ({ ...a, redirect_uri: "https://evil.example/cb" })),
				},
			});
			expect(await startOf(person, front, session, uri), String(pushed)).toMatchObject({
				stopped: "sdk",
				at: pushed ? "authorization.readPushed" : "authorization.read",
				error: "signature",
			});
		}
	});

	it("ends the attempt, by value and pushed: the T denied is approved by no later step, and a new JAR logs in", async () => {
		for (const pushed of [false, true]) {
			const person = await w.person();
			const front = await w.front();
			const [session, s, uri] = await begun(person, front, pushed);
			expect(stopped(person.screen.deny(s))).toBe(false);
			const relayed = front.seen().length;
			// A page brought back after the denial cannot approve it: the SDK stops before a passkey is asked.
			expect(await person.screen.approve(front, s, [person.credential])).toMatchObject({
				stopped: "sdk",
				at: "authorization.assertionOptions",
				error: "denied",
			});
			expect(front.seen()).toHaveLength(relayed);
			// The same request again under new screen keys is refused, as any started JAR's is (A20).
			expect(await startOf(person, front, session, uri)).toMatchObject({
				stopped: "core",
				at: "/login/start",
				answered: {
					body: { error: "invalid_request", error_description: "the request was used already" },
				},
			});
			// The RP starts again with a new JAR, and the person logs in.
			const [again, t] = await begun(person, front, pushed);
			const callback = await person.screen.approve(front, t, [person.credential]);
			if (stopped(callback)) throw new Error(JSON.stringify(callback));
			expect(rp().callbackFaults(callback, again)).toEqual([]);
		}
	});
});
