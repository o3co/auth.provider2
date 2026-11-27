import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { type Docker, dockerWithin, docker as systemDocker } from "@mod/docker-client";

/** The label each container carries: the process that started it, so a suite whose owner is gone is known. */
export const ownerLabel = "o3co.oidf.owner";

/** Whether a process of the pid runs here. */
const alive = (pid: number) => {
	try {
		process.kill(pid, 0);
		return true;
	} catch (error) {
		return (error as NodeJS.ErrnoException).code === "EPERM";
	}
};

/**
 * Takes down the suites whose owner no longer runs, as a run killed before its stop leaves them, on
 * the suite's fixed ports: each container's log, what it wrote to either stream, kept in `logs`
 * where given and where it can be made, then its containers, their volumes and their networks
 * removed. Answers the projects taken down; any step that fails is told after every one was tried.
 */
export async function reclaimOrphans(
	docker: Docker = systemDocker,
	logs?: string,
	running: (pid: number) => boolean = alive,
): Promise<string[]> {
	const listed = await docker(
		[
			"ps",
			"--all",
			"--filter",
			`label=${ownerLabel}`,
			"--format",
			`{{.ID}}\t{{.Label "${ownerLabel}"}}\t{{.Label "com.docker.compose.project"}}\t{{.Names}}`,
		],
		dockerWithin.control,
	);
	const orphans = new Map<string, { id: string; name: string }[]>();
	for (const line of listed.split("\n").filter((l) => l.trim() !== "")) {
		const [id = "", owner = "", project = "", name = ""] = line.split("\t");
		if (running(Number(owner))) continue;
		orphans.set(project, [...(orphans.get(project) ?? []), { id, name }]);
	}
	const problems: unknown[] = [];
	/** Runs `step`, telling whether it went; a failure is kept for after every step was tried. */
	const tried = (step: () => Promise<unknown>) =>
		step().then(
			() => true,
			(error: unknown) => {
				problems.push(error);
				return false;
			},
		);
	// A directory that cannot be made keeps no log, and the suites still go: they hold the fixed ports.
	const kept =
		logs !== undefined && orphans.size > 0 && (await tried(() => mkdir(logs, { recursive: true })))
			? logs
			: undefined;
	for (const [project, containers] of orphans) {
		for (const c of containers) {
			if (kept === undefined) continue;
			await tried(async () => {
				// A container without a tty writes its stderr to the client's: both are kept, in the order written.
				const wrote = await docker(["logs", c.id], dockerWithin.control, { merged: true });
				await writeFile(join(kept, `${project}-${c.name}.log`), wrote);
			});
		}
		await tried(() =>
			docker(
				["rm", "--force", "--volumes", ...containers.map((c) => c.id)],
				2 * dockerWithin.control,
			),
		);
		const networks = await docker(
			["network", "ls", "--quiet", "--filter", `label=com.docker.compose.project=${project}`],
			dockerWithin.control,
		).catch((error: unknown) => {
			problems.push(error);
			return "";
		});
		for (const network of networks.split("\n").filter((n) => n.trim() !== ""))
			await tried(() => docker(["network", "rm", network], dockerWithin.control));
	}
	if (problems.length > 0)
		throw new AggregateError(problems, "a suite left behind could not be taken down");
	return [...orphans.keys()];
}
