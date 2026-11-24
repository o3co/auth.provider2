import { defineModule } from "@mod/kernel";
import { passkeyWitnesses } from "@mod/passkey-witness";
import { passkeyWitnessing } from "@mod/passkeys";
import { witnessingOver } from "./witnessing.ts";

// Holds nothing of its own: every mark is the witness's.
export default defineModule(
	{ name: "passkey-witnessing", replicaSafe: true, takes: [passkeyWitnesses] },
	(m) => [
		m.contribute(passkeyWitnessing).by(async (c) => {
			const [witness, ...more] = await c.collect(passkeyWitnesses);
			if (!witness || more.length > 0)
				return c.refuse("passkey-witnessing", "exactly one passkey witness must be composed");
			return witnessingOver(witness);
		}),
	],
);
