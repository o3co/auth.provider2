import type { z } from "zod";
import type { section } from "./section.ts";

export type PasskeyManagementSettings = z.input<typeof section>;

/** The passkey-management part of a test's configuration. */
export const passkeyManagementConfig = (settings: Partial<PasskeyManagementSettings> = {}) => ({
	"passkey-management": settings,
});
