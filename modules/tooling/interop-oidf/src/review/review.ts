import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

/** A module's review: the pages its result REVIEW stands on, kept, and the verdict the harness records of each. */

/**
 * Where a page a condition asked reviewed stands: `filled` by the suite's browser (the page's source),
 * an `image` uploaded, `open` (its placeholder unfilled), or `released` (the module ended by its
 * callback, the suite clearing the placeholder: no page to review).
 */
export type PageState = "filled" | "image" | "open" | "released";

/** A page a module asks reviewed: the condition's log entry (its test instance, `src`, message, block), its state and what fills it. */
export interface ReviewPage {
	readonly test: string;
	readonly testId: string;
	readonly src: string;
	readonly msg: string;
	readonly blockId?: string;
	readonly state: PageState;
	readonly placeholder?: string;
	readonly pageSource?: string;
	readonly contentType?: string;
	readonly matched?: string;
	readonly img?: string;
}

/**
 * The harness's verdict of a page, never the suite's (its API gives a REVIEW none): `approved`, the
 * module's own condition; `explained`, a failure a ledger key names; `unconfirmed`, words the table leaves
 * apart, left unapproved, failing no run; `unmatched`, none of these, failing the run.
 */
export type Verdict = "approved" | "explained" | "unconfirmed" | "unmatched";

/** A page's verdict, why (the reading that gave it), its block, and the file it is kept in. */
export interface Reviewed {
	readonly test: string;
	readonly src: string;
	readonly blockId?: string;
	readonly verdict: Verdict;
	readonly why: string;
	readonly kept?: string;
}

const text = (v: unknown) => (typeof v === "string" ? v : undefined);

const stateOf = (e: Record<string, unknown>): PageState =>
	text(e.page_source) !== undefined
		? "filled"
		: text(e.img) !== undefined
			? "image"
			: e.image_no_longer_required === true
				? "released"
				: "open";

/** The pages a module's log asks reviewed, each entry its condition logged REVIEW; one with no condition named refuses the log. */
export function reviewPagesOf(test: string, log: readonly unknown[]): readonly ReviewPage[] {
	return log.flatMap((entry) => {
		if (typeof entry !== "object" || entry === null) return [];
		const e = entry as Record<string, unknown>;
		if (e.result !== "REVIEW") return [];
		const src = text(e.src);
		if (src === undefined) throw new Error(`${test}: a REVIEW in its log names no condition`);
		const optional = {
			blockId: text(e.blockId),
			placeholder: text(e.upload),
			pageSource: text(e.page_source),
			contentType: text(e.content_type),
			matched: text(e.matched_regexp),
			img: text(e.img),
		};
		const defined = Object.fromEntries(Object.entries(optional).filter(([, v]) => v !== undefined));
		const testId = text(e.testId) ?? "";
		return [{ test, testId, src, msg: text(e.msg) ?? "", state: stateOf(e), ...defined }];
	});
}

/** A file's extension by what it holds: an image's by its data URI, a page's by its content type. */
const extensionOf = (page: ReviewPage) => {
	if (page.state === "image")
		return /^data:image\/(png|jpeg)/.exec(page.img ?? "")?.[1] === "jpeg" ? "jpg" : "png";
	const type = page.contentType ?? "";
	return type.includes("json") ? "json" : type.includes("html") ? "html" : "txt";
};

/**
 * Keeps each filled page or image in `dir`, named by its test instance and condition, never written
 * over (a name taken refuses); an open or released one keeps none. Answers each page's file.
 */
export async function keptPages(
	pages: readonly ReviewPage[],
	dir: string,
): Promise<readonly (string | undefined)[]> {
	await mkdir(dir, { recursive: true });
	const kept: (string | undefined)[] = [];
	for (const [at, page] of pages.entries()) {
		const bytes =
			page.state === "filled"
				? Buffer.from(page.pageSource ?? "")
				: page.state === "image"
					? Buffer.from((page.img ?? "").replace(/^data:[^,]*,/, ""), "base64")
					: undefined;
		if (bytes === undefined) {
			kept.push(undefined);
			continue;
		}
		const name = `${page.testId}-${page.src}-${at + 1}`.replace(/[^A-Za-z0-9-]/g, "-");
		const file = join(dir, `${name}.${extensionOf(page)}`);
		await writeFile(file, bytes, { flag: "wx" });
		kept.push(file);
	}
	return kept;
}

/** The harness's verdict of a page; `approved` or `explained` stands only on a page kept (filled or an image, its file given), any other's is `unmatched`. */
export function reviewed(page: ReviewPage, verdict: Verdict, why: string, kept?: string): Reviewed {
	const keepable = page.state === "filled" || page.state === "image";
	const stands = keepable && kept !== undefined;
	const given =
		(verdict === "approved" || verdict === "explained") && !stands ? "unmatched" : verdict;
	return {
		test: page.test,
		src: page.src,
		...(page.blockId === undefined ? {} : { blockId: page.blockId }),
		verdict: given,
		why: given === verdict ? why : `${why}; no page kept (${keepable ? "no file" : page.state})`,
		...(kept === undefined ? {} : { kept }),
	};
}
