import { describe, expect, it } from "vitest";
import { heldUnderAudit } from "./held.ts";

const held = '{"event":"app-permissions.held","mode":"audit"}';

describe("the permission model's audit, as a scene's servers wrote it", () => {
	it("names the servers held under audit, and every event line, anywhere in a line, of any app's output", () => {
		const read = heldUnderAudit([
			{ name: "nextgen-core", out: `boot\n${held}\nserving` },
			{ name: "nextgen-front", out: "boot, held in another mode" },
			{
				name: "src/keys-publish.ts",
				out: 'a log line\'s part{"event":"app-permissions.event","path":"/x"}',
			},
		]);
		expect(read).toEqual({
			servers: ["nextgen-core", "nextgen-front"],
			held: ["nextgen-core"],
			events: ['a log line\'s part{"event":"app-permissions.event","path":"/x"}'],
		});
		expect(heldUnderAudit([{ name: "nextgen-core", out: held }]).events).toEqual([]);
	});
});
