import { issuer } from "@mod/issuer";
import type { BuildContext } from "@mod/kernel";
import { keys } from "@mod/keys";
import { keyList } from "@mod/passkeys";
import { approvalStore } from "../contract.ts";
import type { Settings } from "../section.ts";
import { beyondLimits } from "./padded.ts";
import { passkeyAddCompletionsOver } from "./passkey-add.ts";
import { passkeyManageCompletionsOver } from "./passkey-manage.ts";

/** What the passkey completions take, which the package names among its own takes. */
export const passkeyCompletionTakes = [keys, issuer, keyList, approvalStore] as const;

/** Refuses boot where these settings would make a passkey completion not fit the wire's limits. */
export async function completionLimitsChecked(c: BuildContext<Settings>) {
	// A completion these settings would not fit is refused at boot, never to one person alone.
	const rings = (await c.get(keys)).coreRings();
	const beyond = beyondLimits((await c.get(issuer)).url, rings);
	if (beyond) c.refuse("approvals", beyond);
}

/** A passkey-add's and a passkey-manage's completions, made in a build. */
export async function passkeyCompletionOf(c: BuildContext<Settings>) {
	const signer = await c.get(keys);
	const iss = (await c.get(issuer)).url;
	const store = await c.get(approvalStore);
	const now = c.clock.now;
	return {
		completePasskeyAdd: passkeyAddCompletionsOver({ keys: signer, store, issuer: iss, now }),
		completePasskeyManage: passkeyManageCompletionsOver({
			keys: signer,
			store,
			list: await c.get(keyList),
			issuer: iss,
			now,
		}),
	};
}
