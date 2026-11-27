import { type WireCertificates, wireCertificates } from "@mod/front-relay/testing";

/** The holds on the wire's certificates in this process, one set for the process, not let go. */
let live = 0;

/** A hold on the wire's certificates: the certificates, and letting go of them (once; later calls do nothing). */
export interface Held {
	readonly certificates: WireCertificates;
	letGo(): Promise<void>;
}

/** One hold let go: the last removes them (counted again after the wait, as another may hold meanwhile). */
async function release() {
	live -= 1;
	if (live !== 0) return;
	const certificates = await wireCertificates();
	if (live === 0) await certificates.remove();
}

/**
 * Holds the wire's certificates for a Core started and the Fronts that reach it, from before the
 * wait, so a last hold let go meanwhile does not remove them under this one; let go where getting
 * them fails.
 */
export async function holdCertificates(): Promise<Held> {
	live += 1;
	let held = true;
	const letGo = async () => {
		if (!held) return;
		held = false;
		await release();
	};
	try {
		return { certificates: await wireCertificates(), letGo };
	} catch (error) {
		await letGo();
		throw error;
	}
}
