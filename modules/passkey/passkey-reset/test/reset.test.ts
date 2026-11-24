import type { PasskeyGenerations, Passkeys } from "@mod/passkeys";
import { resetRefusal } from "@mod/reset-wire";
import type { ResetAnswer, Transparency } from "@mod/transparency";
import { schemas } from "@mod/transparency-wire";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { resetOver } from "../src/reset.ts";

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
const instruction = `${b64({ alg: "ES256", typ: "reset-instruction+jwt" })}.${b64({
	v: 1,
	installation: "inst-1",
	subject: "sub-1",
	action: "reset",
	kg: 0,
	id: "A".repeat(22),
	iat: 1,
	exp: 600,
})}.c2ln`;
const accepted: ResetAnswer = {
	v: 1,
	result: "accepted",
	id: "r1",
	position: 1,
	shard: "s1",
	n: 1,
	acceptedAt: 1,
	receipts: ["h.p.s"],
};

function world(answer: { answer: ResetAnswer }) {
	const calls: string[] = [];
	const transparency = {
		reset: async () => {
			calls.push("reset");
			return answer;
		},
		tend: async (flow: { of: string; id: string }) => {
			calls.push(`tend ${flow.of}:${flow.id}`);
			return { stepped: 1 };
		},
	} as unknown as Transparency;
	const passkeys = {
		settle: async (subject: string) => {
			calls.push(`settle ${subject}`);
			return false;
		},
	} as unknown as Passkeys;
	const generations: PasskeyGenerations = {
		generation: async (subject) => (subject === "sub-1" ? 2 : 0),
	};
	return { calls, reset: resetOver({ transparency, passkeys, generations }) };
}

describe("the reset's path", () => {
	it("hands the instruction to the log and, where placed, takes the subject's boundary in and settles its passkeys before answering", async () => {
		const w = world({ answer: accepted });
		expect(await w.reset.reset(instruction)).toEqual(accepted);
		expect(w.calls).toEqual(["reset", "tend subject:sub-1", "settle sub-1"]);
	});

	it("answers a reset not placed as it came, changing nothing", async () => {
		for (const answer of [
			{ answer: { v: 1, result: "invalid", fault: "generation" } as ResetAnswer },
			{ answer: { v: 1, result: "conflict" } as ResetAnswer },
			{ answer: { v: 1, result: "refused", refusal: "temporary" } as ResetAnswer },
		]) {
			const w = world(answer);
			expect(await w.reset.reset(instruction), JSON.stringify(answer)).toEqual(answer.answer);
			expect(w.calls).toEqual(["reset"]);
		}
	});

	it("answers the wire's own form, read back by the log's append answer or reset-wire's refusal", async () => {
		const read = z.union([schemas.appendAnswer, resetRefusal.schema]);
		for (const answer of [
			accepted,
			{ v: 1, result: "invalid", fault: "generation" } as ResetAnswer,
			{ v: 1, result: "conflict" } as ResetAnswer,
			{ v: 1, result: "refused", refusal: "temporary" } as ResetAnswer,
		]) {
			const line = JSON.stringify(await world({ answer }).reset.reset(instruction));
			expect(read.parse(JSON.parse(line)), line).toEqual(answer);
		}
	});

	it("tells a subject's key generation as the Core holds it, its flow tended first and settled where it stepped", async () => {
		const w = world({ answer: accepted });
		expect(await w.reset.generation("sub-1")).toBe(2);
		expect(w.calls).toEqual(["tend subject:sub-1", "settle sub-1"]);
	});

	it("gives no answer where the take-in throws, and the same instruction sent again runs it again", async () => {
		const w = world({ answer: accepted });
		let fail = true;
		const failing = resetOver({
			transparency: {
				reset: async () => ({ answer: accepted }),
				tend: async () => {
					w.calls.push("tend");
					if (fail) throw new Error("unavailable");
					return { stepped: 1 };
				},
			} as unknown as Transparency,
			passkeys: {
				settle: async () => {
					w.calls.push("settle");
					return false;
				},
			} as unknown as Passkeys,
			generations: { generation: async () => 0 },
		});
		await expect(failing.reset(instruction)).rejects.toThrow("unavailable");
		fail = false;
		expect(await failing.reset(instruction)).toEqual(accepted);
		expect(w.calls).toEqual(["tend", "tend", "settle"]);
	});
});
