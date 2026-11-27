/** The files a configuration's load read, and the paths it looked for and found nothing at (`config-files`' shape). */
export interface ConfigReads {
	readonly read: readonly string[];
	readonly probed: readonly string[];
}
