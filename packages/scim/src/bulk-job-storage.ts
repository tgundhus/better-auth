import {
	getCurrentAdapter,
	runWithTransaction,
} from "@better-auth/core/context";
import type {
	BetterAuthPlugin,
	DBAdapter,
	DBTransactionAdapter,
} from "better-auth";
import { BetterAuthError } from "better-auth";
import type { SCIMBulkBody, SCIMBulkExecution } from "./bulk";
import { bulkBodySchema } from "./bulk";
import type { SCIMPrincipal, SCIMScope } from "./configuration";
import { areValidSCIMScopes } from "./connection-authentication";
import { findAllSCIMRows } from "./read-all";
import { createScopedKey } from "./resource-key";
import { createSCIMError } from "./scim-error";

export interface SCIMBulkJob {
	id: string;
	jobKey: string;
	bodyHash: string;
	connectionId: string;
	provisioningDomainId: string;
	credentialId: string;
	grantedScopes: string;
	inputParts: number;
	operationCount: number;
	completedCount: number;
	errorCount: number;
	state: string;
	queueKey: string;
	revision: number;
	leaseId: string;
	leaseUntil: number;
	createdAt: Date;
	updatedAt: Date;
}

export interface SCIMBulkOutcome {
	id: string;
	jobId: string;
	operationIndex: number;
	completionIndex: number;
	status: number;
	resolvedId: string;
	parts: number;
}

interface BlobRow {
	id: string;
	jobId: string;
	kind: string;
	part: number;
	payload: string;
}

const text = { type: "string", required: true } as const;
const number = { type: "number", required: true } as const;
const date = { type: "date", required: true } as const;

/** Durable job metadata, bounded payload chunks, and atomic per-operation outcomes. */
export const scimBulkJobSchema = {
	scimBulkJob: {
		fields: {
			jobKey: { ...text, unique: true, returned: false },
			bodyHash: text,
			connectionId: { ...text, index: true },
			provisioningDomainId: text,
			credentialId: text,
			grantedScopes: text,
			inputParts: number,
			operationCount: number,
			completedCount: number,
			errorCount: number,
			state: text,
			queueKey: { ...text, index: true },
			revision: number,
			leaseId: text,
			leaseUntil: number,
			createdAt: date,
			updatedAt: date,
		},
	},
	scimBulkBlob: {
		fields: {
			jobId: { ...text, index: true },
			kind: { ...text, index: true },
			part: number,
			payload: { ...text, returned: false },
		},
	},
	scimBulkOutcome: {
		fields: {
			jobId: { ...text, index: true },
			operationIndex: number,
			completionIndex: number,
			status: number,
			resolvedId: text,
			parts: number,
		},
	},
	scimBulkWorker: {
		fields: {
			name: { ...text, unique: true },
			shard: number,
			afterId: text,
			revision: number,
		},
	},
} satisfies NonNullable<BetterAuthPlugin["schema"]>;

export function jobQueueKey(id: string, state = "ready"): string {
	return `${state}:${(id.charCodeAt(0) % 16).toString(16)}`;
}

function canonicalBody(body: SCIMBulkBody): string {
	return JSON.stringify(body, (_key, value: unknown) =>
		value && typeof value === "object" && !Array.isArray(value)
			? Object.fromEntries(
					Object.entries(value).sort(([left], [right]) =>
						left < right ? -1 : left > right ? 1 : 0,
					),
				)
			: value,
	);
}

function splitPayload(value: string): string[] {
	const parts: string[] = [];
	for (let start = 0; start < value.length; ) {
		let end = Math.min(start + 32_000, value.length);
		// Never split a UTF-16 surrogate pair across DynamoDB strings.
		if (end < value.length && /[\uD800-\uDBFF]/.test(value[end - 1]!)) end--;
		parts.push(value.slice(start, end));
		start = end;
	}
	return parts;
}

export async function writeJobPayload(
	database: DBTransactionAdapter,
	jobId: string,
	kind: string,
	value: string,
): Promise<number> {
	const parts = splitPayload(value);
	for (let part = 0; part < parts.length; part++) {
		await database.create({
			model: "scimBulkBlob",
			data: {
				id: `${jobId}:${kind}:${String(part).padStart(8, "0")}`,
				jobId,
				kind,
				part,
				payload: parts[part]!,
			},
			forceAllowId: true,
		});
	}
	return parts.length;
}

export async function readJobPayload(
	database: DBTransactionAdapter,
	jobId: string,
	kind: string,
	count: number,
): Promise<string> {
	const rows: BlobRow[] = [];
	for (let start = 0; start < count; start += 500) {
		const ids = Array.from(
			{ length: Math.min(500, count - start) },
			(_, index) =>
				`${jobId}:${kind}:${String(start + index).padStart(8, "0")}`,
		);
		rows.push(
			...(await database.findMany<BlobRow>({
				model: "scimBulkBlob",
				where: [{ field: "id", operator: "in", value: ids }],
				limit: ids.length,
			})),
		);
	}
	rows.sort((left, right) => left.part - right.part);
	if (rows.length !== count || rows.some((row, index) => row.part !== index))
		throw new BetterAuthError(
			"SCIM Bulk job payload is incomplete; restore its persisted data before retrying.",
		);
	return rows.map((row) => row.payload).join("");
}

export function jobScopes(job: SCIMBulkJob): readonly SCIMScope[] {
	const scopes: unknown = JSON.parse(job.grantedScopes);
	if (!areValidSCIMScopes(scopes))
		throw new BetterAuthError("Invalid persisted SCIM Bulk job scopes");
	return scopes;
}

export function authorizeJob(job: SCIMBulkJob, principal: SCIMPrincipal): void {
	if (
		job.connectionId !== principal.connectionId ||
		job.provisioningDomainId !== principal.provisioningDomainId
	)
		throw createSCIMError("NOT_FOUND", { detail: "SCIM Bulk job not found" });
	if (!jobScopes(job).every((scope) => principal.scopes.includes(scope)))
		throw createSCIMError("FORBIDDEN", {
			detail:
				"The credential no longer has the job's originally granted scopes",
		});
}

export async function findJob(
	database: DBTransactionAdapter,
	id: string,
): Promise<SCIMBulkJob> {
	const job = await database.findOne<SCIMBulkJob>({
		model: "scimBulkJob",
		where: [{ field: "id", value: id }],
	});
	if (!job)
		throw createSCIMError("NOT_FOUND", { detail: "SCIM Bulk job not found" });
	return job;
}

/** Persist the complete request before acknowledging acceptance. The key is scoped to its connection. */
export async function enqueueBulkJob(
	database: DBAdapter,
	principal: SCIMPrincipal,
	body: SCIMBulkBody,
	requestKey: string | null,
): Promise<SCIMBulkJob> {
	if (!requestKey || new TextEncoder().encode(requestKey).byteLength > 1024)
		throw createSCIMError("BAD_REQUEST", {
			detail:
				"Asynchronous Bulk requires an Idempotency-Key header of 1 to 1024 bytes",
		});
	const ids = body.Operations.flatMap((operation) =>
		operation.bulkId ? [operation.bulkId] : [],
	);
	if (new Set(ids).size !== ids.length)
		throw createSCIMError("BAD_REQUEST", {
			detail: "bulkId values must be unique within the request",
		});
	const payload = canonicalBody(body);
	const bodyHash = createScopedKey([payload]);
	const jobKey = createScopedKey([
		"scim-bulk-job",
		principal.connectionId,
		requestKey,
	]);
	const lookup = () =>
		database.findOne<SCIMBulkJob>({
			model: "scimBulkJob",
			where: [{ field: "jobKey", value: jobKey }],
		});
	const validate = (job: SCIMBulkJob) => {
		authorizeJob(job, principal);
		if (job.bodyHash !== bodyHash)
			throw createSCIMError("CONFLICT", {
				detail:
					"Idempotency-Key was already used with a different Bulk request",
			});
		return job;
	};
	const existing = await lookup();
	if (existing) return validate(existing);
	try {
		return await runWithTransaction(database, async () => {
			const transaction = await getCurrentAdapter(database);
			const now = new Date();
			const job = await transaction.create<
				Omit<SCIMBulkJob, "id">,
				SCIMBulkJob
			>({
				model: "scimBulkJob",
				data: {
					jobKey,
					bodyHash,
					connectionId: principal.connectionId,
					provisioningDomainId: principal.provisioningDomainId,
					credentialId: principal.credentialId,
					grantedScopes: JSON.stringify(principal.scopes),
					inputParts: splitPayload(payload).length,
					operationCount: body.Operations.length,
					completedCount: 0,
					errorCount: 0,
					state: "ready",
					queueKey: jobQueueKey(jobKey),
					revision: 0,
					leaseId: "",
					leaseUntil: 0,
					createdAt: now,
					updatedAt: now,
				},
			});
			await writeJobPayload(transaction, job.id, "input", payload);
			return job;
		});
	} catch (error) {
		const winner = await lookup();
		if (winner) return validate(winner);
		throw error;
	}
}

export async function readJobBody(
	database: DBTransactionAdapter,
	job: SCIMBulkJob,
): Promise<SCIMBulkBody> {
	const payload = await readJobPayload(
		database,
		job.id,
		"input",
		job.inputParts,
	);
	if (createScopedKey([payload]) !== job.bodyHash)
		throw new BetterAuthError("SCIM Bulk job payload checksum does not match");
	return bulkBodySchema.parse(JSON.parse(payload));
}

export async function readOutcomes(
	database: DBTransactionAdapter,
	jobId: string,
): Promise<SCIMBulkOutcome[]> {
	return findAllSCIMRows<SCIMBulkOutcome>(database, {
		model: "scimBulkOutcome",
		where: [{ field: "jobId", value: jobId }],
	});
}

export async function writeOutcome(
	database: DBTransactionAdapter,
	job: SCIMBulkJob,
	index: number,
	execution: SCIMBulkExecution,
	body: SCIMBulkBody,
): Promise<SCIMBulkJob> {
	const parts = await writeJobPayload(
		database,
		job.id,
		`result-${index}`,
		JSON.stringify(execution.result),
	);
	await database.create({
		model: "scimBulkOutcome",
		data: {
			id: `${job.id}:${String(index).padStart(8, "0")}`,
			jobId: job.id,
			operationIndex: index,
			completionIndex: job.completedCount,
			status: Number(execution.result.status),
			resolvedId: execution.id ?? "",
			parts,
		},
		forceAllowId: true,
	});
	const completedCount = job.completedCount + 1;
	const errorCount =
		job.errorCount + (Number(execution.result.status) >= 400 ? 1 : 0);
	const complete =
		completedCount === job.operationCount ||
		Boolean(body.failOnErrors && errorCount >= body.failOnErrors);
	const updated = await database.incrementOne<SCIMBulkJob>({
		model: "scimBulkJob",
		where: [
			{ field: "id", value: job.id },
			{ field: "revision", value: job.revision },
			{ field: "leaseId", value: job.leaseId },
			{ field: "state", value: "ready" },
		],
		increment: { revision: 1 },
		set: {
			completedCount,
			errorCount,
			state: complete ? "complete" : "ready",
			queueKey: jobQueueKey(job.jobKey, complete ? "complete" : "ready"),
			updatedAt: new Date(),
		},
	});
	if (!updated)
		throw createSCIMError("CONFLICT", {
			detail: "SCIM Bulk job ownership changed; retry its worker",
		});
	return updated;
}

export function jobDescriptor(job: SCIMBulkJob) {
	return {
		schemas: ["urn:better-auth:params:scim:api:messages:2.0:BulkJob"],
		id: job.id,
		status:
			job.state === "ready"
				? job.leaseId && job.leaseUntil > Date.now()
					? "running"
					: "queued"
				: job.state,
		totalOperations: job.operationCount,
		completedOperations: job.completedCount,
		failedOperations: job.errorCount,
		createdAt: job.createdAt,
		updatedAt: job.updatedAt,
	};
}
