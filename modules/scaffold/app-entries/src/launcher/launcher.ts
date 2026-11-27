/** The app's start: the launcher that holds the entry under Node's permission model. */
import { configFiles, filled, type KeysWritten, kernel, refusedPart } from "../start.ts";

/** What the app's start makes Node's permission flags with. */
export const appPermissions = "@mod/app-permissions";

const noKeys: KeysWritten = { read: {}, severalLines: [], local: "config/local.conf" };

/**
 * The app's start, which `start` runs: Node's permission flags made from `permissions.json` and the
 * configuration, as `APP_PERMISSION` says, and the entry (`main.ts`) started in this process under them.
 */
export const startSource = async (importOf = (name: string) => name, keys: KeysWritten = noKeys) =>
	filled("start.ts.template", {
		refused: await refusedPart(keys),
		kernel: importOf(kernel),
		configFiles: importOf(configFiles),
		appPermissions: importOf(appPermissions),
	});

/** What the start loads before the entry where the permission model holds it: each event a line on standard error. */
export const permissionLinesSource = () => filled("permission-lines.ts.template", {});
