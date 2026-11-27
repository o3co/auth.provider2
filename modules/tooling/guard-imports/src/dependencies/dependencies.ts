import { packagesUsed } from "../rules.ts";
import type { Scope } from "../scope/scope.ts";
import type { Pkg } from "../workspace.ts";

/** G2, G10, G14, G16, G36: what a package may depend on. */
export function dependencyRules(s: Scope, p: Pkg) {
	const { budget, byName, kindOf, level, report, workspaceDeps } = s;
	// The bottom level (common, protocol) is what every kind may build on: it builds on nothing.
	if (level(p) === 0) {
		for (const dep of workspaceDeps(p, true)) {
			report("G2 the bottom level depends on nothing in the workspace", p.name, dep);
		}
	}
	if (level(p) < 0) report("G10 kind direction", p.name, "no kind, or an unknown kind");
	const runtime = new Set(workspaceDeps(p, false));
	for (const dep of workspaceDeps(p, true)) {
		const target = byName.get(dep) as Pkg;
		// Tests assemble, so a test may reach up to wiring, and to no other higher kind.
		const testUp = !runtime.has(dep) && kindOf(target) === budget.wiringKind;
		if (level(p) >= 0 && level(target) > level(p) && !testUp) {
			report("G10 kind direction", p.name, `a lower kind depends on a higher one: ${dep}`);
		}
	}
	// G14: a check package other check packages build on stays free of the product's modules.
	const isCheck = (q: Pkg) => kindOf(q) === budget.verificationKind;
	const builtOn = s.packages.some(
		(q) => q !== p && isCheck(q) && workspaceDeps(q, true).includes(p.name),
	);
	if (isCheck(p) && builtOn) {
		for (const dep of workspaceDeps(p, true)) {
			if (budget.productKinds.includes(kindOf(byName.get(dep) as Pkg))) {
				report("G14 a verification base depends on no product module", p.name, dep);
			}
		}
	}
	// G36: only a verification package runs on one; another's tests may use its fakes and harnesses.
	if (!isCheck(p)) {
		for (const dep of runtime) {
			if (isCheck(byName.get(dep) as Pkg)) {
				report("G36 only verification depends on verification at run time", p.name, dep);
			}
		}
	}
	// G16: a feature never depends on a capability, nor on what declares forWiring; its tests may use the stand-in.
	const g16 = "G16 a feature depends on no capability, nor on what declares forWiring";
	if (p.manifest.forWiring !== undefined && p.manifest.forWiring !== true) {
		report(g16, p.name, "forWiring is true only");
	}
	if (budget.capabilityBlind.includes(kindOf(p))) {
		for (const dep of workspaceDeps(p, true)) {
			const target = byName.get(dep) as Pkg;
			if (kindOf(target) !== budget.capabilityKind && target.manifest.forWiring !== true) continue;
			const beyondStandIn = s
				.sources(p)
				.some((file) =>
					packagesUsed(s.factsOf(p, file)).some((u) => u.name === dep && u.subpath !== "testing"),
				);
			if (runtime.has(dep) || beyondStandIn) report(g16, p.name, dep);
		}
	}
}
