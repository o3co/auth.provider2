import { capabilityBlind, kindOrder, kinds } from "@mod/kinds";
import type { Budget } from "./contract.ts";

/** The order and roles of the kinds: the direction as `kinds` states it, the roles in its words. */
export const kindRules = {
	kindOrder,
	verificationKind: kinds.verification,
	productKinds: [kinds.foundation, kinds.capability, kinds.feature, kinds.adapter, kinds.wiring],
	wiringKind: kinds.wiring,
	capabilityKind: kinds.capability,
	commonKind: kinds.common,
	protocolKind: kinds.protocol,
	capabilityBlind,
	runtimeFromKernel: [kinds.foundation, kinds.capability, kinds.feature, kinds.adapter],
	widerSurfaceKinds: [kinds.common, kinds.foundation],
	adapterKind: kinds.adapter,
	featureKind: kinds.feature,
} satisfies Partial<Budget>;

/** The kinds whose shipped code G26 holds to its network words: the product's, and a companion, a program of its own. */
export const networkKinds: readonly string[] = [...kindRules.productKinds, kinds.companion];
