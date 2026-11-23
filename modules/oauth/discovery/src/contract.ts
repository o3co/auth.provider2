import { contract } from "@mod/kernel";

/** A run of `discovery-publish`: the lines it writes and its exit code. */
export interface Published {
	readonly lines: readonly string[];
	readonly code: number;
}

export interface Discovery {
	/**
	 * `discovery-publish <directory>`: writes the discovery document there, at OpenID Connect
	 * Discovery's place and at RFC 8414's, each a path under the directory.
	 */
	publish(args: readonly string[]): Promise<Published>;
}

export const discovery = contract<Discovery>("discovery");
