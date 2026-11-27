/**
 * What a scene's servers wrote of the permission model's audit, once stopped (so each drain is in it):
 * those held under audit, and every audit event line, anywhere in a line (stdout and stderr arrive as
 * one text, an event line may follow a log line's part).
 */
export function heldUnderAudit(
	outputs: readonly { readonly name: string; readonly out: string }[],
): {
	readonly servers: readonly string[];
	readonly held: readonly string[];
	readonly events: readonly string[];
} {
	const servers = outputs.filter(({ name }) => name === "nextgen-core" || name === "nextgen-front");
	return {
		servers: servers.map(({ name }) => name),
		held: servers
			.filter(({ out }) => out.includes('{"event":"app-permissions.held","mode":"audit"}'))
			.map(({ name }) => name),
		events: outputs
			.flatMap(({ out }) => out.split("\n"))
			.filter((line) => line.includes('"event":"app-permissions.event"')),
	};
}
