import { BootRefused } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { audienceOf, narrowing, serve } from "../../../test/served.ts";

describe("the audience a request asks for", () => {
	it("reads no resource where no rule is composed", async () => {
		const post = await serve();
		const issued = await post(
			{ grant_type: "client_credentials", resource: "https://two" },
			"narrow",
		);
		expect(audienceOf(issued.body)).toBe("https://api");
	});

	it("refuses to boot with two rules", async () => {
		await expect(serve([narrowing("one"), narrowing("two")])).rejects.toSatisfy(
			(error) =>
				error instanceof BootRefused && JSON.stringify(error.refusals).includes("target-rules"),
		);
	});
});
