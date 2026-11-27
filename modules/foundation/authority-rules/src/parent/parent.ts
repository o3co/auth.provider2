import { passkeyThumbprintInput } from "@mod/passkey-key-wire";
import type { Checks } from "../evidence/evidence.ts";

/** Why not, in the rules' words; none where it holds. */
type Refusal = string | undefined;

/**
 * Why the creation's approving key is not the record's parent (V30, FIX_ADD_PARENT): the screen's own
 * key, as it checks its assertion verifies under it, and the parent, by thumbprint. An RS256 parent
 * approves no passkey-add in 0.1.0: no binding against duplicate-signature key selection is shown for
 * it. A creation naming no key of a passkey's form (none at all, while the wire takes it) is refused.
 */
export function approverRefusal(checks: Checks, parentKey: string, named: unknown): Refusal {
	const approving = checks.keyThumbprint(parentKey);
	if (!approving) return "the approving key does not read";
	if (approving.alg === -257) return "an RSA key approves no passkey-add";
	const input = passkeyThumbprintInput(named);
	if (input === undefined) return "the creation names no approving key a passkey's";
	return checks.digest(input) === approving.jkt
		? undefined
		: "the creation names another approving key than the record's parent";
}
