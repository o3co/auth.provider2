import { requestClaims } from "@mod/authorize";
import { claimsSelections } from "@mod/claims-selection";
import { codes } from "@mod/code-grant";
import { metadata } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { claimsReading } from "./reading.ts";

// Holds nothing: the selection and its records are claims-selection's.
export default defineModule(
	{ name: "authorize-claims", replicaSafe: true, takes: [claimsSelections, codes] },
	(m) => [
		m.contribute(requestClaims).by(async (c) => claimsReading(await c.get(claimsSelections))),
		// Said here, where the parameter is read (authorize refuses it with no such module), and only
		// where ID tokens are made: without, authorize refuses every OpenID request before its claims.
		m.contribute(metadata).by(async (c) => ({
			name: "claims_parameter_supported",
			value: (await c.get(codes)).issuesIdTokens() ? true : undefined,
		})),
	],
);
