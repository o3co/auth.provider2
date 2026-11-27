import {
	type FieldSpec,
	headerLength,
	maxRequestBody,
	type RequestKind,
	requests,
} from "@mod/front-core-wire";
import { encodeRequest, type Message } from "./contract.ts";

/**
 * A fuzzer of the wire for tests, reproducible from its seed: well-formed frames of a kind, and
 * mutations of a frame (a bit flipped, a byte set, cut, added or removed, a length rewritten).
 */
export function fuzzer(seed: number) {
	let state = seed;
	const random = () => {
		state = (state + 0x6d2b79f5) | 0;
		let t = state;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 2 ** 32;
	};
	const int = (n: number) => Math.floor(random() * n);
	const pick = <T>(xs: readonly T[]): T => xs[int(xs.length)] as T;
	const randomBytes = (n: number) => Uint8Array.from({ length: n }, () => int(256));
	const alphabet = [..."ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"];
	const base64url = (n: number) => Array.from({ length: n }, () => pick(alphabet)).join("");

	function wellFormed(spec: FieldSpec): unknown {
		const n = spec.min + int(Math.min(spec.max, 300) - spec.min + 1);
		switch (spec.type) {
			case "bytes":
				return randomBytes(n);
			case "enum":
				return int(spec.values ?? 1);
			case "b64url":
				return base64url(Math.max(n, spec.min === 0 ? 0 : 1));
			case "visible":
				return Array.from({ length: n }, () => String.fromCharCode(0x21 + int(94))).join("");
			// A character is four bytes at most: n / 4 of them stay within the limit.
			case "utf8":
				return Array.from({ length: Math.max(1, Math.floor(n / 4)) }, () =>
					pick(["a", "é", "名", "{", '"', " ", "😀"]),
				).join("");
			case "jws": {
				if (n === 0) return "";
				const k = Math.max(3, n);
				const a = 1 + int(k - 2);
				const b = 1 + int(k - a - 1);
				return `${base64url(a)}.${base64url(b)}.${base64url(Math.max(1, k - a - b))}`.slice(
					0,
					spec.max,
				);
			}
		}
	}

	/** A frame of this kind its encoder accepts, each field drawn within its spec. */
	function validFrame(kind: RequestKind): Uint8Array {
		let last: unknown;
		for (let tries = 0; tries < 100; tries++) {
			const message = Object.fromEntries(requests[kind].fields.map((f) => [f.name, wellFormed(f)]));
			try {
				return encodeRequest(kind, int(2 ** 32), message as Message<typeof kind>);
			} catch (error) {
				// A draw at a length's edge; draw again, a hundred times at most.
				last = error;
			}
		}
		throw new Error(`no ${kind} frame drawn: ${String(last)}`);
	}

	/** One to three mutations of a frame. */
	function mutate(bytes: Uint8Array): Uint8Array {
		let x = new Uint8Array(bytes);
		for (let k = 1 + int(3); k > 0; k--) {
			const i = int(Math.max(1, x.length));
			switch (int(9)) {
				case 0:
					x[i] = (x[i] ?? 0) ^ (1 << int(8));
					break;
				case 1:
					x[i] = int(256);
					break;
				case 2:
					x[i] = pick([0x00, 0xff, 0x2e, 0x20, 0x7f, 0x80, 0xc0, 0xed]);
					break;
				case 3:
					x = x.slice(0, i);
					break;
				case 4: {
					const y = new Uint8Array(x.length + 1);
					y.set(x.subarray(0, i));
					y[i] = int(256);
					y.set(x.subarray(i), i + 1);
					x = y;
					break;
				}
				case 5:
					x = Uint8Array.from([...x.subarray(0, i), ...x.subarray(i + 1)]);
					break;
				case 6:
					if (x.length >= headerLength)
						new DataView(x.buffer).setUint32(
							6,
							pick([0, x.length - headerLength + 1, maxRequestBody + 1, 0xffffffff, int(2 ** 32)]),
						);
					break;
				case 7:
					if (x.length > headerLength + 2) {
						const at = headerLength + 2 * int(3);
						if (at + 1 < x.length)
							new DataView(x.buffer).setUint16(at, pick([0, 1, 0xffff, (x[at + 1] ?? 0) + 1]));
					}
					break;
				case 8:
					if (x.length > 1) x[1] = int(16);
					break;
			}
		}
		return x;
	}

	return { int, pick, randomBytes, validFrame, mutate };
}
