import { frameStoreContract } from "../src/testing.ts";
import { memoryFrames } from "./fixtures/frames.ts";

// The tests' frame store keeps the contract the driver's tests rely on.
frameStoreContract("the tests' memory frames", {
	open: async () => ({ frames: memoryFrames(["p"]).frames, part: "p" }),
});
