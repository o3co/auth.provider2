import { defineConfig } from "vitest/config";

/**
 * The tests that run child processes (`*.process.test.ts`): slow and bound to the machine's load, so
 * they run apart from `pnpm check`, in CI's own job (`pnpm test:process`), never skipped there.
 */
export default defineConfig({
	test: {
		include: [
			"modules/*/*/test/**/*.process.test.ts",
			"modules/*/*/src/**/test/**/*.process.test.ts",
		],
		exclude: ["**/node_modules/**"],
	},
});
