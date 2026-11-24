/** Bytes and their texts, with no Node builtins: the shipped code runs in a browser. */

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export const utf8 = (text: string): Uint8Array<ArrayBuffer> => encoder.encode(text);

/** The UTF-8 text of the bytes, or none where they are not UTF-8. */
export function textOf(bytes: Uint8Array): string | undefined {
	try {
		return decoder.decode(bytes);
	} catch {
		return undefined;
	}
}

export function concat(...parts: readonly Uint8Array[]): Uint8Array<ArrayBuffer> {
	const out = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
	let at = 0;
	for (const part of parts) {
		out.set(part, at);
		at += part.length;
	}
	return out;
}

/** base64url without padding. */
export function base64url(bytes: Uint8Array): string {
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** The bytes of a base64url text without padding in its one canonical spelling, or none where it is not one. */
export function fromBase64url(text: string): Uint8Array<ArrayBuffer> | undefined {
	if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return undefined;
	const binary = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
	const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
	return base64url(bytes) === text ? bytes : undefined;
}

/** SHA-256 of the text's UTF-8 bytes, or of the bytes. */
export async function sha256(data: string | Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
	const bytes = typeof data === "string" ? utf8(data) : new Uint8Array(data);
	return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

/** SHA-256, base64url without padding: the form a payload's hashes take. */
export const digest = async (data: string | Uint8Array) => base64url(await sha256(data));
