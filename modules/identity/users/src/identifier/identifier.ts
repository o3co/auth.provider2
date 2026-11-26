/** The longest identifier users takes, in UTF-8 bytes: a fixed guard on what is held and sent, past an email's 254. */
export const maxIdentifierBytes = 255;
/** Whether a text holds a C0 control, which JSON writes as `\uXXXX`, or DEL, which no one types (a lone surrogate is checked apart). */
const escaped = (text: string) => {
	for (let i = 0; i < text.length; i++) {
		const unit = text.charCodeAt(i);
		if (unit < 0x20 || unit === 0x7f) return true;
	}
	return false;
};
/**
 * Whether an identifier is within the bound, of no character JSON escapes as `\uXXXX` (a C0 control,
 * a lone surrogate) and no DEL; non-ASCII is taken, as an internationalized address is. One otherwise
 * is none, refused, or malformed, never asked for.
 */
export const identifierFits = (identifier: string) =>
	Buffer.byteLength(identifier) <= maxIdentifierBytes &&
	!escaped(identifier) &&
	identifier.isWellFormed();
