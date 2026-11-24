import type { BuildContext } from "@mod/kernel";
import { delegation } from "@mod/refresh";

/** What the delegation's length is read from: `refresh`'s, the one setting of it (O27). */
export const delegationTakes = [delegation] as const;

/** How long a login's delegation lasts from its statement's issue, in seconds: its session's end. */
export const delegationSecondsIn = async (c: Pick<BuildContext<unknown>, "get">) =>
	(await c.get(delegation)).lifetimeMs / 1000;
