import { passkeyStoreContract } from "../src/testing.ts";
import { memoryCredentials } from "./fixtures/world.ts";

passkeyStoreContract("the credentials in memory", async () => memoryCredentials().store);
