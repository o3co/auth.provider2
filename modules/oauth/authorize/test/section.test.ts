import { expect, it } from "vitest";
import { section } from "../src/section.ts";

it("refuses `delegation-lifetime`, moved to `refresh.lifetime` (O27): one setting of a session's length", () => {
	const given = { "screen-url": "https://login.example/screen" };
	expect(section.safeParse(given).success).toBe(true);
	expect(section.safeParse({ ...given, "delegation-lifetime": "1d" }).success).toBe(false);
});
