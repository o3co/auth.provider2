import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { sdkViolations } from "./guard.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const findings = sdkViolations(root);
for (const finding of findings) console.error(`${finding.id} ${finding.place}: ${finding.what}`);
process.exitCode = findings.length === 0 ? 0 : 1;
