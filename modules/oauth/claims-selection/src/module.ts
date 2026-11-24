import { redemptionHooks } from "@mod/code-grant";
import { erasers } from "@mod/erasure-extensions";
import { type BuildContext, defineModule } from "@mod/kernel";
import { claimScopes, claimsSelections, selectionRecords } from "./contract.ts";
import { selectionEraser } from "./erasure/eraser.ts";
import { portsRefused } from "./erasure/ports.ts";
import { selectionsWith } from "./selections.ts";

const takes = [selectionRecords, claimScopes];

const built = async (c: Pick<BuildContext<unknown>, "get" | "collect" | "clock">) => {
	const [scopes] = await c.collect(claimScopes);
	return selectionsWith({ records: await c.get(selectionRecords), scopes, now: c.clock.now });
};

export default defineModule({ name: "claims-selection", replicaSafe: true, takes }, (m) => [
	m.provide(claimsSelections).by(async (c) => {
		if ((await c.collect(claimScopes)).length > 1) {
			return c.refuse("claims-selection", "more than one table of claim scopes");
		}
		const refused = portsRefused(await c.get(selectionRecords));
		if (refused) return c.refuse("claims-selection", refused);
		return (await built(c)).selections;
	}),
	m.contribute(redemptionHooks).by(async (c) => (await built(c)).hook),
	// Its build takes only its store, collecting no probes: the erasure gate collects erasers.
	m.contribute(erasers).by(async (c) => selectionEraser(await c.get(selectionRecords))),
]);
