import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { keptPages, reviewed, reviewPagesOf } from "../review.ts";

const test =
	"fapi2-security-profile-final-ensure-unsigned-authorization-request-without-using-par-fails";
const src = "ExpectAuthorizationRequestWithoutRequestObjectErrorPage";
// A module's log as the suite writes it: a REVIEW entry in each state its code leaves one.
const base = { result: "REVIEW", testId: "rkfETVIovoGu7p2", src, msg: "must show an error page" };
const open = { ...base, blockId: "a5af82", upload: "33rsUqVoPt" };
const filled = {
	...base,
	blockId: "b1",
	page_source: '<p id="refused">This sign-in was refused.</p>',
	content_type: "text/html",
	matched_regexp: ".*refused.*",
};
const image = {
	...base,
	blockId: "b2",
	img: `data:image/png;base64,${Buffer.from("png").toString("base64")}`,
};
// The module ended by its callback: the suite cleared the placeholder (AbstractTestModule's fireTestFinished).
const released = { ...base, blockId: "b3", image_no_longer_required: true };
const others = [{ result: "SUCCESS", src: "x" }, null, "text"];

const dirs: string[] = [];
afterAll(async () => {
	for (const dir of dirs) await rm(dir, { recursive: true, force: true });
});

describe("a module's review", () => {
	it("reads the pages its log asks reviewed, each in the state the suite left it, nothing else", () => {
		const pages = reviewPagesOf(test, [...others, open, filled, image, released]);
		expect(pages.map((p) => [p.blockId, p.state])).toEqual([
			["a5af82", "open"],
			["b1", "filled"],
			["b2", "image"],
			["b3", "released"],
		]);
		expect(pages[0]).toMatchObject({ test, testId: base.testId, src, placeholder: "33rsUqVoPt" });
		expect(pages[1]).toMatchObject({
			pageSource: filled.page_source,
			contentType: "text/html",
			matched: ".*refused.*",
		});
	});

	it("refuses a log whose REVIEW names no condition, never reading it as no review", () => {
		expect(() => reviewPagesOf(test, [{ result: "REVIEW" }])).toThrow(/names no condition/);
	});

	it("keeps each filled page and image under its test instance, none open or released, never writing one over", async () => {
		const dir = await mkdtemp(join(tmpdir(), "interop-oidf-review-"));
		dirs.push(dir);
		const pages = reviewPagesOf(test, [
			open,
			filled,
			image,
			released,
			{ ...filled, content_type: "application/json" },
		]);
		const kept = await keptPages(pages, join(dir, "pages"));
		expect([kept[0], kept[3]]).toEqual([undefined, undefined]);
		expect(await readFile(kept[1] ?? "", "utf8")).toBe(filled.page_source);
		expect(await readFile(kept[2] ?? "")).toEqual(Buffer.from("png"));
		expect([kept[1], kept[2], kept[4]].map((f) => f?.split(".").at(-1))).toEqual([
			"html",
			"png",
			"json",
		]);
		const names = await readdir(join(dir, "pages"));
		expect(names.every((f) => f.startsWith(base.testId) && /^[A-Za-z0-9-]+\.[a-z]+$/.test(f))).toBe(
			true,
		);
		// The same pages kept again in the same place: refused, the first kept as they were.
		await expect(keptPages(pages, join(dir, "pages"))).rejects.toThrow();
		expect(await readFile(kept[1] ?? "", "utf8")).toBe(filled.page_source);
	});

	it("records the harness's verdict, approving or explaining only a page kept", () => {
		const [o, f, , r] = reviewPagesOf(test, [open, filled, image, released]);
		if (o === undefined || f === undefined || r === undefined) throw new Error("pages");
		expect(reviewed(f, "approved", "own-condition", "/k")).toEqual({
			test,
			src,
			blockId: "b1",
			verdict: "approved",
			why: "own-condition",
			kept: "/k",
		});
		expect(reviewed(f, "unconfirmed", "jar-required's shared words")).toMatchObject({
			verdict: "unconfirmed",
		});
		for (const page of [o, r])
			expect(reviewed(page, "approved", "own-condition")).toMatchObject({
				verdict: "unmatched",
				why: `own-condition; no page kept (${page.state})`,
			});
		expect(reviewed(f, "unmatched", "no entry")).not.toHaveProperty("kept");
		// A filled page with no file kept: nothing to stand on.
		for (const verdict of ["approved", "explained"] as const)
			expect(reviewed(f, verdict, "own-condition")).toMatchObject({
				verdict: "unmatched",
				why: "own-condition; no page kept (no file)",
			});
	});
});
