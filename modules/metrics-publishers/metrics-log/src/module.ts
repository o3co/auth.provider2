import { contract, defineModule } from "@mod/kernel";
import { metrics } from "@mod/metrics";
import { fieldsOf } from "./line.ts";
import { section } from "./section.ts";

/**
 * Never read: the kernel builds every provider at boot, so providing this sets the sampling going
 * at start, with nothing else for a module to take.
 */
const sampling = contract<true>("metrics-log.sampling");

// Safe on many instances: each writes its own counts, on its own log.
export default defineModule(
	{ name: "metrics-log", section, replicaSafe: true, takes: [metrics] },
	(m) => [
		m.provide(sampling).by(async (c) => {
			const counts = await c.get(metrics);
			const write = async () => {
				c.log.info("metrics.sample", fieldsOf(await counts.sample()));
			};
			// Once at start, so each boot tells at once where the promises stand; the start hooks end
			// before the periodic tasks begin, so the two never sample at once.
			c.onStart(write);
			c.every(c.section.interval, write);
			return true as const;
		}),
	],
);
