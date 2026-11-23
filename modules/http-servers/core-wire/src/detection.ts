import type { WireErrorName } from "@mod/front-core-wire";
import type { Clock, Log } from "@mod/kernel";

/** A Front instance's id, and whether it is its workload identity (a URI name), stable across its certificates. */
export interface Instance {
	readonly id: string;
	readonly named: boolean;
}

/**
 * The detection line (C9): a frame no honest Front sends, its version aside, is a violation, warned
 * of with the Front instance's id and the code alone; a version outside the one taken is refused and
 * warned of apart, never a violation. Under `cut`, an instance that sent a violation is cut: its
 * connections are closed, and refused from then on by this process; and an instance its certificate
 * does not name by a URI, whose id would change with each certificate, is refused.
 */
export interface Detection {
	noticed(code: WireErrorName, instance: Instance): void;
	/** Whether a connection of this instance is taken; one refused is warned of. */
	admits(instance: Instance): boolean;
	/** Each connection's instance, so a cut closes every one of it; the returned function forgets it. */
	connected(instance: Instance, close: () => void): () => void;
}

/** How long one instance's warnings of one event are held to one line, the others counted into the next. */
const quietMs = 60_000;
/** The most of an id a log line shows; the id itself is kept whole. */
const shownMax = 256;

export function detection(onViolation: "notify" | "cut", log: Log, clock: Clock): Detection {
	const cut = new Set<string>();
	const open = new Map<string, Set<() => void>>();
	const last = new Map<string, { at: number; held: number }>();
	/** One warning per instance and event a minute, carrying how many were held since the last. */
	const warn = (event: string, instance: Instance, fields: Record<string, string> = {}) => {
		const key = `${event} ${instance.id}`;
		const now = clock.now();
		const seen = last.get(key);
		if (seen && now >= seen.at && now - seen.at < quietMs) {
			seen.held++;
			return;
		}
		last.set(key, { at: now, held: 0 });
		const held = seen?.held ? { held: String(seen.held) } : {};
		log.warn(event, { instance: instance.id.slice(0, shownMax), ...fields, ...held });
	};
	return {
		noticed: (code, instance) => {
			if (code === "version") {
				warn("core-wire.version_refused", instance);
				return;
			}
			warn("core-wire.violation", instance, { code });
			if (onViolation !== "cut" || cut.has(instance.id)) return;
			cut.add(instance.id);
			log.warn("core-wire.cut", { instance: instance.id.slice(0, shownMax) });
			for (const close of open.get(instance.id) ?? []) close();
		},
		admits: (instance) => {
			if (cut.has(instance.id)) {
				warn("core-wire.cut_refused", instance);
				return false;
			}
			if (onViolation === "cut" && !instance.named) {
				warn("core-wire.unnamed_refused", instance);
				return false;
			}
			return true;
		},
		connected: (instance, close) => {
			const closers = open.get(instance.id) ?? new Set();
			closers.add(close);
			open.set(instance.id, closers);
			return () => {
				closers.delete(close);
				if (closers.size === 0) open.delete(instance.id);
			};
		},
	};
}

/** A Front instance's id: its certificate's first URI name (its workload identity), else its subject's CN, else its fingerprint. */
export function instanceOf(certificate: {
	readonly subjectaltname?: string;
	readonly subject?: { readonly CN?: string | string[] };
	readonly fingerprint256?: string;
}): Instance {
	const uri = certificate.subjectaltname
		?.split(", ")
		.find((name) => name.startsWith("URI:"))
		?.slice(4);
	if (uri) return { id: uri, named: true };
	const cn = [certificate.subject?.CN ?? []].flat()[0];
	return { id: cn ?? certificate.fingerprint256 ?? "unknown", named: false };
}
