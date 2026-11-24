import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		// The patterns follow the workspace definition; tests that need an outside system run in an
		// integration config instead, and tests that run child processes in `vitest.process.config.ts`.
		include: ["modules/*/*/test/**/*.test.ts", "modules/*/*/src/**/test/**/*.test.ts"],
		exclude: ["**/*.integration.test.ts", "**/*.process.test.ts", "**/node_modules/**"],
	},
});
