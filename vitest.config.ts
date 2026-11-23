import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		// The patterns follow the workspace definition; tests that need an outside system run in an
		// integration config instead.
		include: ["modules/*/*/test/**/*.test.ts", "modules/*/*/src/**/test/**/*.test.ts"],
		exclude: ["**/*.integration.test.ts", "**/node_modules/**"],
	},
});
