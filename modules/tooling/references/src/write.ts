/** Writes every section's `reference.conf` from its schema: `pnpm --filter @mod/references run configuration`. */
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { readWorkspace } from "@mod/guard-imports";
import { referenceConfFile, referenceConfOf, sectionsIn } from "./contract.ts";

const root = join(import.meta.dirname, "..", "..", "..", "..");
for (const section of await sectionsIn(readWorkspace(root))) {
	await writeFile(referenceConfFile(section.dir), referenceConfOf(section));
}
