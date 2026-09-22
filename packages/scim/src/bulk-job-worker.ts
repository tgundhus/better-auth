import {
	getCurrentAdapter,
	runWithTransaction,
} from "@better-auth/core/context";
import type { DBAdapter } from "better-auth";
import { generateId } from "better-auth";
import type { SCIMBulkBody, SCIMBulkExecution } from "./bulk";
import { errorResult, executeOperation } from "./bulk";
import type { SCIMBulkJob } from "./bulk-job-storage";
import {
	authorizeJob,
	findJob,
	jobDescriptor,
	jobScopes,
	readJobBody,
	readOutcomes,
	writeOutcome,
} from "./bulk-job-storage";
import { bulkDependencies } from "./bulk-references";
import type { SCIMPrincipal } from "./configuration";
import { createSCIMError } from "./scim-error";

// A lease outlives a Lambda invocation. Revision fencing also protects databases
// when a paused worker resumes after another owner has claimed its lease.
const LEASE_MS = 930_000;
const ROLLBACK = Symbol("scim-bulk-operation-rollback");

interface JobWorkerInput {
	database: DBAdapter;
	principal: SCIMPrincipal;
	jobId: string;
	maxOperations: number;
	timeBudgetMs: number;
	baseURL: string;
	headers: Headers;
	dispatch: (request: Request) => Promise<Response>;
	onAfterCommitHookError: (error: unknown) => void;
}

async function claim(
	input: JobWorkerInput,
): Promise<{ job: SCIMBulkJob; owned: boolean }> {
	const job = await findJob(input.database, input.jobId);
	authorizeJob(job, input.principal);
	if (job.state !== "ready" || job.leaseUntil > Date.now())
		return { job, owned: false };
	const owned = await input.database.incrementOne<SCIMBulkJob>({
		model: "scimBulkJob",
		where: [
			{ field: "id", value: job.id },
			{ field: "revision", value: job.revision },
			{ field: "state", value: "ready" },
		],
		increment: { revision: 1 },
		set: {
			leaseId: generateId(32),
			leaseUntil: Date.now() + LEASE_MS,
			updatedAt: new Date(),
		},
	});
	if (!owned)
		throw createSCIMError("CONFLICT", {
			detail: "SCIM Bulk job was claimed concurrently; retry later",
		});
	return { job: owned, owned: true };
}

function nextOperation(
	body: SCIMBulkBody,
	pending: Set<number>,
	resolved: Map<string, string>,
) {
	for (const index of pending) {
		const operation = body.Operations[index]!;
		if (
			bulkDependencies(operation.path, operation.data).every((id) =>
				resolved.has(id),
			)
		)
			return { index, unresolved: false };
	}
	return { index: pending.values().next().value!, unresolved: true };
}

async function executeAtomically(
	input: JobWorkerInput,
	job: SCIMBulkJob,
	body: SCIMBulkBody,
	index: number,
	resolved: Map<string, string>,
	unresolved: boolean,
) {
	const operation = body.Operations[index]!;
	const execute = async (): Promise<SCIMBulkExecution> => {
		if (unresolved)
			return {
				result: errorResult(
					operation,
					409,
					"Unresolved, failed or circular bulkId dependency",
				),
			};
		const scope = operation.path.startsWith("/Groups")
			? "scim.groups.write"
			: "scim.users.write";
		if (!jobScopes(job).includes(scope))
			return {
				result: errorResult(
					operation,
					403,
					"The job's original credential did not grant the required scope",
				),
			};
		return executeOperation(operation, resolved, input);
	};
	try {
		return await runWithTransaction(
			input.database,
			async () => {
				const database = await getCurrentAdapter(input.database);
				const current = await findJob(database, job.id);
				if (
					current.revision !== job.revision ||
					current.leaseId !== job.leaseId ||
					current.state !== "ready"
				)
					throw createSCIMError("CONFLICT", {
						detail: "SCIM Bulk job ownership changed",
					});
				const execution = await execute();
				// Routers translate exceptions into HTTP responses. Throw outside the
				// router so a failed resource mutation cannot commit partial writes.
				if (Number(execution.result.status) >= 400)
					throw { [ROLLBACK]: execution };
				return {
					job: await writeOutcome(database, current, index, execution, body),
					execution,
				};
			},
			{ onAfterCommitHookError: input.onAfterCommitHookError },
		);
	} catch (error) {
		if (!error || typeof error !== "object" || !(ROLLBACK in error))
			throw error;
		const execution = (error as { [ROLLBACK]: SCIMBulkExecution })[ROLLBACK];
		const status = Number(execution.result.status);
		// Rate limiting and server failures are retryable. Leave the operation
		// pending, with no outcome marker, after rolling back its writes.
		if (status === 429 || status >= 500)
			return { job, retryableStatus: status };
		return runWithTransaction(input.database, async () => ({
			job: await writeOutcome(
				await getCurrentAdapter(input.database),
				job,
				index,
				execution,
				body,
			),
			execution,
		}));
	}
}

/** Advance a durable job only at atomic resource boundaries, then yield. */
export async function processBulkJob(input: JobWorkerInput) {
	const deadline = Date.now() + input.timeBudgetMs;
	const acquired = await claim(input);
	let job = acquired.job;
	if (!acquired.owned) return { ...jobDescriptor(job), processed: 0 };
	const leaseId = job.leaseId;
	let processed = 0;
	let retryableStatus: number | undefined;
	try {
		const body = await readJobBody(input.database, job);
		const outcomes = await readOutcomes(input.database, job.id);
		const pending = new Set(body.Operations.map((_, index) => index));
		const resolved = new Map<string, string>();
		for (const outcome of outcomes) {
			pending.delete(outcome.operationIndex);
			const operation = body.Operations[outcome.operationIndex];
			if (
				operation?.method === "POST" &&
				operation.bulkId &&
				outcome.resolvedId
			)
				resolved.set(operation.bulkId, outcome.resolvedId);
		}
		while (
			job.state === "ready" &&
			pending.size &&
			processed < input.maxOperations &&
			Date.now() < deadline
		) {
			const renewed = await input.database.incrementOne<SCIMBulkJob>({
				model: "scimBulkJob",
				where: [
					{ field: "id", value: job.id },
					{ field: "revision", value: job.revision },
					{ field: "leaseId", value: leaseId },
				],
				increment: { revision: 1 },
				set: { leaseUntil: Date.now() + LEASE_MS },
			});
			if (!renewed)
				throw createSCIMError("CONFLICT", {
					detail: "SCIM Bulk job ownership changed",
				});
			job = renewed;
			const next = nextOperation(body, pending, resolved);
			const result = await executeAtomically(
				input,
				job,
				body,
				next.index,
				resolved,
				next.unresolved,
			);
			job = result.job;
			if ("retryableStatus" in result) {
				retryableStatus = result.retryableStatus;
				break;
			}
			const operation = body.Operations[next.index]!;
			if (
				operation.method === "POST" &&
				operation.bulkId &&
				result.execution.id
			)
				resolved.set(operation.bulkId, result.execution.id);
			pending.delete(next.index);
			processed++;
		}
	} finally {
		// Match the lease, not the cached revision: a lost commit acknowledgement
		// may have advanced the row. Never release another owner's lease.
		const released = await input.database.incrementOne<SCIMBulkJob>({
			model: "scimBulkJob",
			where: [
				{ field: "id", value: job.id },
				{ field: "leaseId", value: leaseId },
			],
			increment: { revision: 1 },
			set: {
				leaseId: "",
				leaseUntil: retryableStatus ? Date.now() + 30_000 : 0,
				updatedAt: new Date(),
			},
		});
		if (released) job = released;
	}
	return {
		...jobDescriptor(job),
		processed,
		...(retryableStatus ? { retryableStatus, retryAfterSeconds: 30 } : {}),
	};
}
