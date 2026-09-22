import { DatabaseSync } from "node:sqlite";
import {
	getCurrentAdapter,
	queueAfterTransactionHook,
	runWithTransaction,
} from "@better-auth/core/context";
import { NodeSqliteDialect } from "@better-auth/kysely-adapter/node-sqlite-dialect";
import type { AuthContext, BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { getTestInstance } from "better-auth/test";
import { describe, expect, it, vi } from "vitest";
import { runSCIMBulkWorker, scim } from ".";
import type { SCIMBulkJob } from "./bulk-job-storage";
import { processBulkJob } from "./bulk-job-worker";
import type { SCIMPrincipal } from "./configuration";
import {
	runGroupMutationTransaction,
	throwConcurrentSCIMGroupMutation,
} from "./group-state";

const base = "http://localhost:3000/api/auth/scim/v2";
const schema = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
const headers = { authorization: "Bearer all-scopes" };
const principal: SCIMPrincipal = {
	type: "static-bearer",
	connectionId: "workforce",
	provisioningDomainId: "workforce",
	credentialId: "all",
	scopes: [
		"scim.users.read",
		"scim.users.write",
		"scim.groups.read",
		"scim.groups.write",
	],
};
const user = (id: string) => ({
	method: "POST",
	path: "/Users",
	bulkId: id,
	data: {
		schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
		userName: `${id}@example.com`,
	},
});

async function fixture(
	onTestFinished: (fn: () => void) => void,
	databaseHooks?: BetterAuthOptions["databaseHooks"],
) {
	const sqlite = new DatabaseSync(":memory:");
	onTestFinished(() => sqlite.close());
	const { auth } = await getTestInstance(
		{
			baseURL: "http://localhost:3000",
			databaseHooks,
			advanced: { database: { defaultFindManyLimit: 1 } },
			database: {
				dialect: new NodeSqliteDialect({ database: sqlite }),
				type: "sqlite",
				transaction: true,
			},
			plugins: [
				scim({
					bulk: { jobs: true },
					groups: { maxMembers: null },
					connections: [
						{
							id: "workforce",
							credentials: [
								{ type: "bearer", id: "all", token: "all-scopes" },
								{
									type: "bearer",
									id: "users",
									token: "users-only",
									scopes: ["scim.users.write"],
								},
							],
						},
						{
							id: "other",
							credentials: [{ type: "bearer", id: "other", token: "other" }],
						},
					],
				}),
			],
		},
		{ disableTestUser: true, testWith: "sqlite" },
	);
	await (await getMigrations(auth.options)).runMigrations();
	const context = (await auth.$context) as unknown as AuthContext;
	const submit = (
		Operations: unknown[],
		key = "request-1",
		token = "all-scopes",
		failOnErrors?: number,
	) =>
		auth.handler(
			new Request(`${base}/Bulk`, {
				method: "POST",
				headers: {
					authorization: `Bearer ${token}`,
					"content-type": "application/scim+json",
					prefer: "respond-async",
					"idempotency-key": key,
				},
				body: JSON.stringify({ schemas: [schema], Operations, failOnErrors }),
			}),
		);
	const enqueue = async (
		Operations: unknown[],
		key?: string,
		token?: string,
		failOnErrors?: number,
	) => {
		const response = await submit(Operations, key, token, failOnErrors);
		expect(response.status).toBe(202);
		expect(response.headers.get("preference-applied")).toBe("respond-async");
		return (await response.json()) as { id: string; status: string };
	};
	const poll = (id: string, token = "all-scopes", query = "") =>
		auth.handler(
			new Request(`${base}/BulkJobs/${id}${query}`, {
				headers: { authorization: `Bearer ${token}` },
			}),
		);
	const process = (id: string, maxOperations = 25) =>
		auth.api.processSCIMBulkJob({
			headers,
			body: { jobId: id, maxOperations },
		});
	return { auth, context, submit, enqueue, poll, process };
}

describe("durable SCIM Bulk jobs", () => {
	it("resumes the persisted queue cursor after a failed credential lookup without starving later jobs", async ({
		onTestFinished,
	}) => {
		const f = await fixture(onTestFinished);
		const failed = await f.enqueue(
			[user("missing-credential")],
			"missing-credential",
		);
		const good = await f.enqueue([user("good-credential")], "good-credential");
		const resolveBearerToken = vi.fn(async () => "invalid");
		const first = await runSCIMBulkWorker({
			api: f.auth.api,
			resolveBearerToken,
			getRemainingTimeInMillis: () => 120_000,
		});
		expect(first.failures).toHaveLength(2);
		expect(first.passComplete).toBe(true);
		await runSCIMBulkWorker({
			api: f.auth.api,
			resolveBearerToken: async () => "all-scopes",
			maxCalls: 2,
			getRemainingTimeInMillis: () => 120_000,
		});
		const result = await runSCIMBulkWorker({
			api: f.auth.api,
			resolveBearerToken: async () => "all-scopes",
			getRemainingTimeInMillis: () => 120_000,
		});
		expect(result.passComplete).toBe(true);
		// A job discovered by the interrupted/failed pass may be retried next pass.
		await runSCIMBulkWorker({
			api: f.auth.api,
			resolveBearerToken: async () => "all-scopes",
			getRemainingTimeInMillis: () => 120_000,
		});
		expect(await (await f.poll(good.id)).json()).toMatchObject({
			status: "complete",
		});
		expect(await (await f.poll(failed.id)).json()).toMatchObject({
			status: "complete",
		});
		expect(await f.context.adapter.count({ model: "scimUser" })).toBe(2);
		const exhausted = await runSCIMBulkWorker({
			api: f.auth.api,
			resolveBearerToken,
			getRemainingTimeInMillis: () => 1,
		});
		expect(exhausted.calls).toBe(0);
	});
	it("does not repeat a database effect after a lost commit acknowledgement", async ({
		onTestFinished,
	}) => {
		const f = await fixture(onTestFinished);
		const job = await f.enqueue([user("uncertain")]);
		const dispatch = vi.fn(async () => {
			await (await getCurrentAdapter(f.context.adapter)).create({
				model: "verification",
				data: {
					identifier: "once",
					value: "committed",
					expiresAt: new Date(Date.now() + 10_000),
				},
			});
			return new Response(JSON.stringify({ id: "created-id" }), {
				status: 201,
			});
		});
		const database = {
			...f.context.adapter,
			transaction: async <T>(
				callback: Parameters<typeof f.context.adapter.transaction<T>>[0],
			) => {
				await f.context.adapter.transaction(callback);
				throw new Error("commit acknowledgement lost");
			},
		};
		await expect(
			processBulkJob({
				database,
				principal,
				jobId: job.id,
				maxOperations: 25,
				timeBudgetMs: 10_000,
				baseURL: f.context.baseURL,
				headers: new Headers(headers),
				onAfterCommitHookError: vi.fn(),
				dispatch,
			}),
		).rejects.toThrow("acknowledgement lost");
		expect(await f.process(job.id)).toMatchObject({
			status: "complete",
			processed: 0,
		});
		expect(dispatch).toHaveBeenCalledTimes(1);
		expect(await f.context.adapter.count({ model: "verification" })).toBe(1);
		expect(await f.context.adapter.count({ model: "scimBulkOutcome" })).toBe(1);
	});

	it("reports an after-commit hook failure without replaying the committed resource", async ({
		onTestFinished,
	}) => {
		const f = await fixture(onTestFinished);
		const job = await f.enqueue([user("hook")]);
		const report = vi.fn();
		const result = await processBulkJob({
			database: f.context.adapter,
			principal,
			jobId: job.id,
			maxOperations: 25,
			timeBudgetMs: 10_000,
			baseURL: f.context.baseURL,
			headers: new Headers(headers),
			onAfterCommitHookError: report,
			dispatch: async () => {
				await queueAfterTransactionHook(async () => {
					throw new Error("external hook failed");
				});
				return new Response(JSON.stringify({ id: "hook-user" }), {
					status: 201,
				});
			},
		});
		expect(result).toMatchObject({
			status: "complete",
			completedOperations: 1,
		});
		expect(report).toHaveBeenCalledTimes(1);
		expect(await f.process(job.id)).toMatchObject({ processed: 0 });
	});

	it("only grants one concurrent worker ownership of a queued job", async ({
		onTestFinished,
	}) => {
		const f = await fixture(onTestFinished);
		const job = await f.enqueue([user("concurrent")]);
		const results = await Promise.allSettled([
			f.process(job.id),
			f.process(job.id),
		]);
		expect(
			results.some(
				(result) =>
					result.status === "fulfilled" &&
					result.value.completedOperations === 1,
			),
		).toBe(true);
		expect(await f.context.adapter.count({ model: "scimUser" })).toBe(1);
		expect(await f.context.adapter.count({ model: "scimBulkOutcome" })).toBe(1);
	});

	it("rejects corrupted payloads before dispatch and releases the worker lease", async ({
		onTestFinished,
	}) => {
		const f = await fixture(onTestFinished);
		const job = await f.enqueue([user("corrupt")]);
		await f.context.adapter.update({
			model: "scimBulkBlob",
			where: [{ field: "id", value: `${job.id}:input:00000000` }],
			update: { payload: "{}" },
		});
		await expect(f.process(job.id)).rejects.toThrow("checksum");
		expect(await f.context.adapter.count({ model: "scimUser" })).toBe(0);
		expect(
			await f.context.adapter.findOne<SCIMBulkJob>({
				model: "scimBulkJob",
				where: [{ field: "id", value: job.id }],
			}),
		).toMatchObject({ leaseId: "", completedCount: 0 });
	});

	it("resumes forward references over invocations and replays one idempotent submission", async ({
		onTestFinished,
	}) => {
		const f = await fixture(onTestFinished);
		const operations = [
			{
				method: "POST",
				path: "/Groups",
				bulkId: "group",
				data: {
					schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
					displayName: "Engineering",
					members: [{ value: "bulkId:alice" }],
				},
			},
			user("alice"),
			user("bob"),
		];
		const job = await f.enqueue(operations);
		expect((await f.enqueue(operations)).id).toBe(job.id);
		expect((await f.submit([user("changed")])).status).toBe(409);
		expect((await f.process(job.id, 1)).completedOperations).toBe(1);
		expect((await f.process(job.id, 1)).completedOperations).toBe(2);
		expect(await f.process(job.id)).toMatchObject({
			status: "complete",
			completedOperations: 3,
		});
		expect(await f.process(job.id)).toMatchObject({
			status: "complete",
			processed: 0,
		});
		const response = await f.poll(job.id, "all-scopes", "?count=1");
		expect(response.headers.get("cache-control")).toBe("no-store");
		expect(await response.json()).toMatchObject({
			Operations: [{ operationIndex: 1, status: "201" }],
			nextStartIndex: 1,
		});
		expect(
			await (
				await f.poll(job.id, "all-scopes", "?startIndex=1&count=1")
			).json(),
		).toMatchObject({
			Operations: [{ operationIndex: 0, status: "201" }],
			nextStartIndex: 2,
		});
		expect(await f.context.adapter.count({ model: "scimUser" })).toBe(2);
		expect(await f.context.adapter.count({ model: "scimGroupMember" })).toBe(1);
	});

	it("isolates jobs by connection and preserves the original authorization after credential rotation", async ({
		onTestFinished,
	}) => {
		const f = await fixture(onTestFinished);
		const job = await f.enqueue(
			[
				user("allowed"),
				{
					method: "POST",
					path: "/Groups",
					bulkId: "forbidden",
					data: {
						schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
						displayName: "Forbidden",
					},
				},
			],
			"scoped",
			"users-only",
		);
		expect((await f.poll(job.id, "other")).status).toBe(404);
		await expect(
			f.auth.api.processSCIMBulkJob({
				headers: { authorization: "Bearer other" },
				body: { jobId: job.id },
			}),
		).rejects.toMatchObject({ statusCode: 404 });
		expect(await f.process(job.id)).toMatchObject({
			completedOperations: 2,
			failedOperations: 1,
		});
		expect(await f.context.adapter.count({ model: "scimGroup" })).toBe(0);
		const broader = await f.enqueue([user("broader")], "broader");
		expect((await f.poll(broader.id, "users-only")).status).toBe(403);
	});

	it("does not expose trusted worker, queue, or purge APIs as HTTP routes", async ({
		onTestFinished,
	}) => {
		const f = await fixture(onTestFinished);
		for (const path of [
			"process-scim-bulk-job",
			"list-scim-bulk-jobs",
			"purge-scim-bulk-job",
		]) {
			const response = await f.auth.handler(
				new Request(`http://localhost:3000/api/auth/${path}`, {
					method: "POST",
					headers,
					body: "{}",
				}),
			);
			expect(response.status).toBe(404);
		}
	});

	it("rolls back partial router writes before recording a permanent failure", async ({
		onTestFinished,
	}) => {
		const f = await fixture(onTestFinished);
		const job = await f.enqueue(
			[user("rollback"), user("not-run")],
			"rollback",
			undefined,
			1,
		);
		await processBulkJob({
			database: f.context.adapter,
			principal,
			jobId: job.id,
			maxOperations: 25,
			timeBudgetMs: 10_000,
			baseURL: f.context.baseURL,
			headers: new Headers(headers),
			onAfterCommitHookError: vi.fn(),
			dispatch: async () => {
				const database = await getCurrentAdapter(f.context.adapter);
				await database.create({
					model: "verification",
					data: {
						identifier: "partial",
						value: "must-rollback",
						expiresAt: new Date(Date.now() + 10_000),
					},
				});
				return new Response(JSON.stringify({ detail: "invalid" }), {
					status: 400,
				});
			},
		});
		expect(await f.context.adapter.count({ model: "verification" })).toBe(0);
		expect(await (await f.poll(job.id)).json()).toMatchObject({
			status: "complete",
			completedOperations: 1,
			failedOperations: 1,
		});
	});

	it("rolls back retryable failures and retries only after persisted backoff", async ({
		onTestFinished,
	}) => {
		const f = await fixture(onTestFinished);
		const job = await f.enqueue([user("retry")]);
		const result = await processBulkJob({
			database: f.context.adapter,
			principal,
			jobId: job.id,
			maxOperations: 25,
			timeBudgetMs: 10_000,
			baseURL: f.context.baseURL,
			headers: new Headers(headers),
			onAfterCommitHookError: vi.fn(),
			dispatch: async () => new Response("{}", { status: 429 }),
		});
		expect(result).toMatchObject({
			retryableStatus: 429,
			completedOperations: 0,
		});
		expect(await f.process(job.id)).toMatchObject({ processed: 0 });
		await f.context.adapter.update({
			model: "scimBulkJob",
			where: [{ field: "id", value: job.id }],
			update: { leaseUntil: 0 },
		});
		expect(await f.process(job.id)).toMatchObject({
			status: "complete",
			completedOperations: 1,
		});
	});

	it("reclaims expired leases and never re-executes committed outcomes", async ({
		onTestFinished,
	}) => {
		const f = await fixture(onTestFinished);
		const job = await f.enqueue([user("first"), user("second")]);
		await f.process(job.id, 1);
		await f.context.adapter.update({
			model: "scimBulkJob",
			where: [{ field: "id", value: job.id }],
			update: { leaseId: "killed-worker", leaseUntil: Date.now() - 1 },
		});
		expect(await f.process(job.id)).toMatchObject({
			status: "complete",
			processed: 1,
		});
		expect(await f.context.adapter.count({ model: "scimUser" })).toBe(2);
	});

	it("stores large Unicode payloads in bounded chunks and cleans them without losing idempotency", async ({
		onTestFinished,
	}) => {
		const f = await fixture(onTestFinished);
		const operation = {
			...user("unicode"),
			data: { ...user("unicode").data, ignored: "😀".repeat(120_000) },
		};
		const job = await f.enqueue([operation]);
		const blobs = await f.context.adapter.findMany<{ payload: string }>({
			model: "scimBulkBlob",
			limit: 100,
		});
		expect(blobs.length).toBeGreaterThan(5);
		expect(
			blobs.every(
				(blob) => new TextEncoder().encode(blob.payload).byteLength <= 128_000,
			),
		).toBe(true);
		expect(await f.process(job.id)).toMatchObject({
			status: "complete",
			failedOperations: 0,
		});
		let result: Awaited<ReturnType<typeof f.auth.api.purgeSCIMBulkJob>>;
		do {
			result = await f.auth.api.purgeSCIMBulkJob({
				body: { jobId: job.id, maxRows: 2 },
			});
		} while (result.status !== "expired");
		expect(await f.context.adapter.count({ model: "scimBulkBlob" })).toBe(0);
		expect(await f.context.adapter.count({ model: "scimBulkOutcome" })).toBe(0);
		expect((await f.poll(job.id)).status).toBe(410);
		expect((await f.enqueue([operation])).id).toBe(job.id);
		expect(await f.process(job.id)).toMatchObject({
			status: "expired",
			processed: 0,
		});
	});

	it("discovers queued jobs across shards with bounded pages", async ({
		onTestFinished,
	}) => {
		const f = await fixture(onTestFinished);
		const ids = new Set<string>();
		for (let index = 0; index < 18; index++)
			ids.add((await f.enqueue([user(`queue-${index}`)], `queue-${index}`)).id);
		let cursor: { shard: number; afterId?: string } | null = { shard: 0 };
		const found = new Set<string>();
		while (cursor) {
			const page: Awaited<ReturnType<typeof f.auth.api.listSCIMBulkJobs>> =
				await f.auth.api.listSCIMBulkJobs({ body: { ...cursor, count: 1 } });
			for (const job of page.jobs) found.add(job.id);
			cursor = page.cursor;
		}
		expect(found).toEqual(ids);
	});

	/** @see https://www.better-auth.com/docs/concepts/database#transactions */
	it("does not retry a failed nested mutation without a rollback savepoint", async ({
		onTestFinished,
	}) => {
		const f = await fixture(onTestFinished);
		let attempts = 0;
		await expect(
			runWithTransaction(f.context.adapter, () =>
				runGroupMutationTransaction(f.context.adapter, async (database) => {
					attempts++;
					await database.create({
						model: "verification",
						data: {
							identifier: "nested",
							value: "rollback",
							expiresAt: new Date(Date.now() + 10_000),
						},
					});
					throwConcurrentSCIMGroupMutation();
				}),
			),
		).rejects.toThrow("changed concurrently");
		expect(attempts).toBe(1);
		expect(await f.context.adapter.count({ model: "verification" })).toBe(0);
	});

	it("rejects a live lease and missing or mismatched idempotency keys", async ({
		onTestFinished,
	}) => {
		const f = await fixture(onTestFinished);
		expect((await f.submit([user("missing")], "")).status).toBe(400);
		const job = await f.enqueue([user("lease")]);
		await f.context.adapter.update({
			model: "scimBulkJob",
			where: [{ field: "id", value: job.id }],
			update: { leaseId: "live-worker", leaseUntil: Date.now() + 60_000 },
		});
		expect(await f.process(job.id)).toMatchObject({ processed: 0 });
		const root = await f.context.adapter.findOne<SCIMBulkJob>({
			model: "scimBulkJob",
			where: [{ field: "id", value: job.id }],
		});
		expect(root?.leaseId).toBe("live-worker");
		await expect(
			f.auth.api.purgeSCIMBulkJob({ body: { jobId: job.id } }),
		).rejects.toMatchObject({ statusCode: 409 });
	});
});
