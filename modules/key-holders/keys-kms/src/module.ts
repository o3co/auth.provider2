import { keysKms } from "./adapter.ts";
import { kmsIn } from "./kms.ts";

export default keysKms((s) => kmsIn(s.region));
