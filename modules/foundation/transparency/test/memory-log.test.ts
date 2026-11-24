import { describe, expect, it } from "vitest";
import { logBook } from "./fixtures/log.ts";

const flow = { of: "client", id: "svc" } as const;
const preimage = { v: 1, evidence: [], content: {} } as const;

describe("the log in memory", () => {
	it("answers one receipt per token, in the request's order, and one for a record of none", async () => {
		const log = logBook(() => 1).as("w1");
		const start = await log.append({
			kind: "start",
			flow,
			op: "o",
			stage: 1,
			last: false,
			preimage,
		} as never);
		const bundle = await log.append({
			kind: "bundle",
			flow,
			op: "o",
			stage: 2,
			last: true,
			tokens: [
				{ frame: "accessToken", digest: "a" },
				{ frame: "idToken", digest: "i" },
				{ frame: "family", digest: "f" },
			],
			preimage,
		} as never);
		expect(start.result === "accepted" && start.receipts).toEqual(["h.p.s"]);
		expect(bundle.result === "accepted" && bundle.receipts).toEqual(["h.p.s", "h.p1.s", "h.p2.s"]);
	});
});
