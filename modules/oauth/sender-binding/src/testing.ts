import { type BindingRequirement, requirementSection } from "./requirement.ts";

/**
 * A test client's sections holding its sender-binding requirement. The card has no line left under G7
 * to name it (45 of 45): whoever next deepens sender-binding names it there.
 */
export function senderBindingFor(requirement: BindingRequirement) {
	return { [requirementSection.name]: requirement };
}
