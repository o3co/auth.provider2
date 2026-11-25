/** The identifier as a mail and a statement show it: its first character, and an address's domain. */
export function masked(identifier: string): string {
	const at = identifier.lastIndexOf("@");
	const first = [...identifier][0] ?? "";
	return at > 0 ? `${first}***${identifier.slice(at)}` : `${first}***`;
}
