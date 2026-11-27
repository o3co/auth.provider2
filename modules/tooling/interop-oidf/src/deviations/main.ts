import { writeFileSync } from "node:fs";
import { ledger, pageOf, pagePath } from "./deviations.ts";

// Writes the public compliance page from the ledger: `pnpm --filter @mod/interop-oidf run deviations`.
writeFileSync(pagePath, pageOf(ledger()));
