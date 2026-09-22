/** Minimal public API surface needed by a scheduled provisioning worker. */
export interface SCIMBulkWorkerAPI {
	nextSCIMBulkJob(input: { body: { worker: string } }): Promise<{
		job: {
			id: string;
			connectionId: string;
			credentialId: string;
			leaseUntil: number;
		} | null;
		passComplete: boolean;
	}>;
	processSCIMBulkJob(input: {
		headers: Headers;
		body: { jobId: string; maxOperations: number; timeBudgetMs: number };
	}): Promise<{ processed: number; retryableStatus?: number }>;
}

/** Run bounded, durable queue discovery and resource processing across invocations. */
export async function runSCIMBulkWorker(input: {
	api: SCIMBulkWorkerAPI;
	/** Resolve a currently valid credential without persisting it in job state. */
	resolveBearerToken: (job: {
		connectionId: string;
		credentialId: string;
	}) => Promise<string>;
	/** A stable name selects the persisted discovery cursor. */
	worker?: string;
	maxCalls?: number;
	maxOperationsPerJob?: number;
	/** Pass the Lambda context method, bound to its context. */
	getRemainingTimeInMillis: () => number;
	/** Stop starting work with less time remaining. Defaults to 60 seconds. */
	minRemainingTimeMs?: number;
}) {
	const maxCalls = input.maxCalls ?? 100;
	const maxOperations = input.maxOperationsPerJob ?? 25;
	const minimum = input.minRemainingTimeMs ?? 60_000;
	if (
		![maxCalls, maxOperations, minimum].every(
			(value) => Number.isSafeInteger(value) && value > 0,
		) ||
		maxOperations > 10_000
	)
		throw new Error(
			"SCIM Bulk worker budgets must be positive safe integers; maxOperationsPerJob cannot exceed 10000",
		);
	const failures: { jobId: string; retryableStatus?: number }[] = [];
	let calls = 0;
	let processed = 0;
	let passComplete = false;
	while (calls < maxCalls && input.getRemainingTimeInMillis() > minimum) {
		const next = await input.api.nextSCIMBulkJob({
			body: { worker: input.worker ?? "default" },
		});
		calls++;
		passComplete = next.passComplete;
		if (passComplete) break;
		const job = next.job;
		if (!job || job.leaseUntil > Date.now()) continue;
		// A checkpoint is already durable. Failure here cannot starve later jobs;
		// this job remains queued and is revisited on the next complete pass.
		try {
			const token = await input.resolveBearerToken(job);
			const remaining = input.getRemainingTimeInMillis();
			if (remaining <= minimum) break;
			const result = await input.api.processSCIMBulkJob({
				headers: new Headers({ authorization: `Bearer ${token}` }),
				body: {
					jobId: job.id,
					maxOperations,
					timeBudgetMs: Math.min(870_000, remaining - minimum),
				},
			});
			processed += result.processed;
			if (result.retryableStatus)
				failures.push({
					jobId: job.id,
					retryableStatus: result.retryableStatus,
				});
		} catch {
			// Do not expose bearer credentials, resource data, or raw callback errors.
			failures.push({ jobId: job.id });
		}
	}
	return { calls, processed, passComplete, failures };
}
