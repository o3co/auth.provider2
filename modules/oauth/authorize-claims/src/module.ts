import { requestClaims } from "@mod/authorize";
import { claimsSelections } from "@mod/claims-selection";
import { defineModule } from "@mod/kernel";
import { claimsReading } from "./reading.ts";

// Holds nothing: the selection and its records are claims-selection's.
export default defineModule(
	{ name: "authorize-claims", replicaSafe: true, takes: [claimsSelections] },
	(m) => [
		m.contribute(requestClaims).by(async (c) => claimsReading(await c.get(claimsSelections))),
	],
);
