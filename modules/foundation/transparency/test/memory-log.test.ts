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
				{ frame: "accessToken", digest: "a".repeat(43) },
				{ frame: "idToken", digest: "i".repeat(43) },
				{ frame: "family", digest: "f".repeat(43) },
			],
			preimage,
		} as never);
		expect(start.result === "accepted" && start.receipts).toEqual(["h.p.s"]);
		expect(bundle.result === "accepted" && bundle.receipts).toEqual(["h.p.s", "h.p1.s", "h.p2.s"]);
	});

	it("refuses, where it places it, a stage that would make a record off the wire's form", async () => {
		const log = logBook(() => 1).as("w1");
		await expect(
			log.append({
				kind: "start",
				flow,
				op: "o",
				stage: 1,
				last: true,
				tokens: [{ frame: "accessToken", digest: "a" }],
				preimage,
			} as never),
		).rejects.toThrow(/off the wire's form, at tokens/);
		// Off every form of the union: told through each, by the form's keys.
		const stage = { kind: "start", flow, op: "o", stage: "one", last: true, preimage };
		await expect(log.append(stage as never)).rejects.toThrow(/off the wire's form, at stage$/);
		// A refused stage takes no record's number.
		const placed = await log.append({
			kind: "start",
			flow,
			op: "o",
			stage: 1,
			last: true,
			preimage,
		} as never);
		expect(placed.result === "accepted" && placed.id).toBe("r1");
	});
});
