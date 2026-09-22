import {
	getCurrentAdapter,
	runWithTransaction,
} from "@better-auth/core/context";
import { HIDE_METADATA } from "better-auth";
import { createAuthEndpoint, router } from "better-auth/api";
import * as z from "zod";
import type { SCIMBulkOperationResult } from "./bulk";
import type { SCIMBulkJob, SCIMBulkOutcome } from "./bulk-job-storage";
import {
	authorizeJob,
	findJob,
	jobDescriptor,
	jobQueueKey,
	readJobPayload,
} from "./bulk-job-storage";
import { processBulkJob } from "./bulk-job-worker";
import type { SCIMConnectionMiddleware } from "./connection-authentication";
import { createSCIMError } from "./scim-error";
import { defineSCIMEndpointMetadata } from "./scim-metadata";

const jobId = z.string().min(1).max(255);
interface WorkerCursor {
	id: string;
	name: string;
	shard: number;
	afterId: string;
	revision: number;
}

/** Polling is authenticated; dispatch and queue discovery exist only in auth.api. */
export function createSCIMBulkJobEndpoints(
	authMiddleware: SCIMConnectionMiddleware,
	enabled: boolean,
) {
	function assertEnabled() {
		if (!enabled)
			throw createSCIMError("NOT_IMPLEMENTED", {
				detail: "Asynchronous SCIM Bulk is not enabled",
			});
	}
	return {
		nextSCIMBulkJob: createAuthEndpoint.serverOnly(
			{
				method: "POST",
				body: z.object({
					worker: z.string().min(1).max(128).default("default"),
				}),
			},
			async (ctx) => {
				assertEnabled();
				// Checkpoint discovery before dispatch. A killed invocation may skip its
				// candidate until the next full pass, but cannot lose the queued job.
				return ctx.json(
					await runWithTransaction(ctx.context.adapter, async () => {
						const database = await getCurrentAdapter(ctx.context.adapter);
						const current =
							(await database.findOne<WorkerCursor>({
								model: "scimBulkWorker",
								where: [{ field: "name", value: ctx.body.worker }],
							})) ??
							(await database.create<Omit<WorkerCursor, "id">, WorkerCursor>({
								model: "scimBulkWorker",
								data: {
									name: ctx.body.worker,
									shard: 0,
									afterId: "",
									revision: 0,
								},
							}));
						const jobs = await database.findMany<SCIMBulkJob>({
							model: "scimBulkJob",
							where: [
								{
									field: "queueKey",
									value: `ready:${current.shard.toString(16)}`,
								},
								...(current.afterId
									? [
											{
												field: "id",
												operator: "gt" as const,
												value: current.afterId,
											},
										]
									: []),
							],
							sortBy: { field: "id", direction: "asc" },
							limit: 1,
						});
						const job = jobs[0];
						const passComplete = !job && current.shard === 15;
						const updated = await database.incrementOne<WorkerCursor>({
							model: "scimBulkWorker",
							where: [
								{ field: "id", value: current.id },
								{ field: "revision", value: current.revision },
							],
							increment: { revision: 1 },
							set: {
								shard: job ? current.shard : (current.shard + 1) % 16,
								afterId: job?.id ?? "",
							},
						});
						if (!updated)
							throw createSCIMError("CONFLICT", {
								detail: "SCIM Bulk queue checkpoint changed concurrently",
							});
						return {
							job: job
								? {
										...jobDescriptor(job),
										connectionId: job.connectionId,
										credentialId: job.credentialId,
										leaseUntil: job.leaseUntil,
									}
								: null,
							passComplete,
						};
					}),
				);
			},
		),
		getSCIMBulkJob: createAuthEndpoint(
			"/scim/v2/BulkJobs/:jobId",
			{
				method: "GET",
				use: [authMiddleware],
				query: z.object({
					startIndex: z.coerce.number().int().min(0).default(0),
					count: z.coerce.number().int().min(1).max(100).default(25),
				}),
				metadata: defineSCIMEndpointMetadata(HIDE_METADATA),
			},
			async (ctx) => {
				assertEnabled();
				const job = await findJob(ctx.context.adapter, ctx.params.jobId);
				authorizeJob(job, ctx.context.scimPrincipal);
				if (job.state === "purging" || job.state === "expired")
					throw createSCIMError(410, {
						detail: "SCIM Bulk job results have expired",
					});
				const outcomes = await ctx.context.adapter.findMany<SCIMBulkOutcome>({
					model: "scimBulkOutcome",
					where: [
						{ field: "jobId", value: job.id },
						{
							field: "completionIndex",
							operator: "gte",
							value: ctx.query.startIndex,
						},
					],
					sortBy: { field: "completionIndex", direction: "asc" },
					limit: ctx.query.count,
				});
				const Operations = [];
				for (const outcome of outcomes)
					Operations.push({
						operationIndex: outcome.operationIndex,
						...(JSON.parse(
							await readJobPayload(
								ctx.context.adapter,
								job.id,
								`result-${outcome.operationIndex}`,
								outcome.parts,
							),
						) as SCIMBulkOperationResult),
					});
				ctx.setHeader("cache-control", "no-store");
				return ctx.json({
					...jobDescriptor(job),
					Operations,
					startIndex: ctx.query.startIndex,
					nextStartIndex: outcomes.length
						? outcomes[outcomes.length - 1]!.completionIndex + 1
						: ctx.query.startIndex,
				});
			},
		),
		processSCIMBulkJob: createAuthEndpoint.serverOnly(
			{
				method: "POST",
				requireHeaders: true,
				use: [authMiddleware],
				body: z.object({
					jobId,
					maxOperations: z.number().int().min(1).max(10_000).default(25),
					timeBudgetMs: z.number().int().min(1).max(870_000).default(30_000),
				}),
			},
			async (ctx) => {
				assertEnabled();
				return ctx.json(
					await processBulkJob({
						database: ctx.context.adapter,
						principal: ctx.context.scimPrincipal,
						...ctx.body,
						baseURL: ctx.context.baseURL,
						headers: new Headers(ctx.headers),
						dispatch: async (request) => {
							const adapter = await getCurrentAdapter(ctx.context.adapter);
							return router(
								{
									...ctx.context,
									adapter: { ...ctx.context.adapter, ...adapter },
								},
								ctx.context.options,
							).handler(request);
						},
						onAfterCommitHookError: () =>
							ctx.context.logger.error(
								"SCIM Bulk job committed, but an after-commit hook failed",
								{ jobId: ctx.body.jobId },
							),
					}),
				);
			},
		),
		listSCIMBulkJobs: createAuthEndpoint.serverOnly(
			{
				method: "POST",
				body: z.object({
					state: z.enum(["ready", "complete", "purging"]).default("ready"),
					shard: z.number().int().min(0).max(15).default(0),
					afterId: z.string().optional(),
					count: z.number().int().min(1).max(100).default(25),
				}),
			},
			async (ctx) => {
				assertEnabled();
				const { state, shard, count, afterId } = ctx.body;
				const jobs = await ctx.context.adapter.findMany<SCIMBulkJob>({
					model: "scimBulkJob",
					where: [
						{ field: "queueKey", value: `${state}:${shard.toString(16)}` },
						...(afterId
							? [{ field: "id", operator: "gt" as const, value: afterId }]
							: []),
					],
					sortBy: { field: "id", direction: "asc" },
					limit: count,
				});
				const cursor =
					jobs.length === count
						? { shard, afterId: jobs[jobs.length - 1]!.id }
						: shard < 15
							? { shard: shard + 1 }
							: null;
				return ctx.json({
					jobs: jobs.map((job) => ({
						...jobDescriptor(job),
						connectionId: job.connectionId,
						credentialId: job.credentialId,
						leaseUntil: job.leaseUntil,
					})),
					cursor,
				});
			},
		),
		purgeSCIMBulkJob: createAuthEndpoint.serverOnly(
			{
				method: "POST",
				body: z.object({
					jobId,
					maxRows: z.number().int().min(1).max(100).default(25),
				}),
			},
			async (ctx) => {
				assertEnabled();
				return ctx.json(
					await runWithTransaction(ctx.context.adapter, async () => {
						const database = await getCurrentAdapter(ctx.context.adapter);
						const job = await findJob(database, ctx.body.jobId);
						if (job.state === "expired") return jobDescriptor(job);
						if (job.state !== "complete" && job.state !== "purging")
							throw createSCIMError("CONFLICT", {
								detail: "Only completed SCIM Bulk jobs can be purged",
							});
						const rows = await database.findMany<{ id: string }>({
							model: "scimBulkBlob",
							where: [{ field: "jobId", value: job.id }],
							limit: ctx.body.maxRows,
						});
						for (const row of rows)
							await database.delete({
								model: "scimBulkBlob",
								where: [{ field: "id", value: row.id }],
							});
						const outcomes = rows.length
							? []
							: await database.findMany<{ id: string }>({
									model: "scimBulkOutcome",
									where: [{ field: "jobId", value: job.id }],
									limit: ctx.body.maxRows,
								});
						for (const row of outcomes)
							await database.delete({
								model: "scimBulkOutcome",
								where: [{ field: "id", value: row.id }],
							});
						const state =
							rows.length || outcomes.length ? "purging" : "expired";
						const updated = await database.incrementOne<SCIMBulkJob>({
							model: "scimBulkJob",
							where: [
								{ field: "id", value: job.id },
								{ field: "revision", value: job.revision },
							],
							increment: { revision: 1 },
							set: {
								state,
								queueKey: jobQueueKey(job.jobKey, state),
								updatedAt: new Date(),
							},
						});
						if (!updated)
							throw createSCIMError("CONFLICT", {
								detail: "SCIM Bulk job changed during cleanup",
							});
						return jobDescriptor(updated);
					}),
				);
			},
		),
	};
}
