import { extensionPoint } from "@mod/kernel";
import type { KeyHolder } from "./contract.ts";

/** The one holder of the keys, contributed by the composition's adapter of the keys axis; with none, or two, boot is refused. */
export const keyHolders = extensionPoint<KeyHolder>("keys.holders", {
	multiplicity: "one",
	missing: "compose one adapter of the keys axis",
});
