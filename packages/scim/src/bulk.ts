import { BetterAuthError, HIDE_METADATA } from "better-auth";
import { createAuthEndpoint, router } from "better-auth/api";
import * as z from "zod";
import { enqueueBulkJob, jobDescriptor } from "./bulk-job-storage";
import {
	bulkDependencies,
	replaceBulkData,
	replaceBulkPath,
} from "./bulk-references";
import type { SCIMOptions } from "./configuration";
import type { SCIMConnectionMiddleware } from "./connection-authentication";
import { createSCIMError } from "./scim-error";
import {
	defineSCIMEndpointMetadata,
	getResourceURL,
	SCIM_REQUEST_MEDIA_TYPES,
} from "./scim-metadata";

const REQUEST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
const RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:BulkResponse";
const ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";
export const bulkBodySchema = z.object({
	schemas: z.array(z.literal(REQUEST_SCHEMA)).length(1),
	failOnErrors: z.number().int().nonnegative().optional(),
	Operations: z
		.array(
			z.object({
				method: z.enum(["POST", "PUT", "PATCH", "DELETE"]),
				path: z.string().min(1),
				bulkId: z.string().min(1).optional(),
				version: z.string().optional(),
				data: z.unknown().optional(),
			}),
		)
		.min(1),
});

export type SCIMBulkBody = z.infer<typeof bulkBodySchema>;
export type Operation = SCIMBulkBody["Operations"][number];
export interface SCIMBulkExecution {
	result: SCIMBulkOperationResult;
	id?: string;
}
export interface SCIMBulkOperationResult {
	method: Operation["method"];
	bulkId?: string;
	location?: string;
	status: string;
	response?: unknown;
}

/** Resolve the advertised RFC 7644 request limits once, at plugin construction. */
export function resolveSCIMBulkOptions(options: SCIMOptions["bulk"]) {
	const limits = {
		maxOperations: options?.maxOperations ?? 10_000,
		maxPayloadSize: options?.maxPayloadSize ?? 16 * 1024 * 1024,
	};
	for (const value of Object.values(limits)) {
		if (!Number.isSafeInteger(value) || value < 1)
			throw new BetterAuthError(
				"SCIM bulk limits must be positive safe integers",
			);
	}
	return limits;
}

export function errorResult(
	operation: Operation,
	status: number,
	detail: string,
): SCIMBulkOperationResult {
	return {
		method: operation.method,
		...(operation.bulkId ? { bulkId: operation.bulkId } : {}),
		status: String(status),
		response: { schemas: [ERROR_SCHEMA], status: String(status), detail },
	};
}

function validateOperation(operation: Operation): string | undefined {
	const collection = /^\/(Users|Groups)$/.test(operation.path);
	const resource = /^\/(Users|Groups)\/[^/?#\\]+$/.test(operation.path);
	if (operation.method === "POST" ? !collection : !resource)
		return "Bulk paths must target /Users or /Groups resources";
	if (operation.method === "POST" && !operation.bulkId)
		return "POST operations require a unique bulkId";
	if (
		operation.method !== "DELETE" &&
		(operation.data === undefined || operation.data === null)
	)
		return "The operation requires data";
	if (operation.version)
		return "This service provider does not support resource version preconditions";
	return undefined;
}

export async function executeOperation(
	operation: Operation,
	resolved: ReadonlyMap<string, string>,
	input: {
		baseURL: string;
		headers: Headers;
		dispatch: (request: Request) => Promise<Response>;
	},
): Promise<{ result: SCIMBulkOperationResult; id?: string }> {
	const invalid = validateOperation(operation);
	if (invalid)
		return {
			result: errorResult(operation, operation.version ? 412 : 400, invalid),
		};
	const path = replaceBulkPath(operation.path, resolved);
	// Reject encoded path separators and dot segments before URL normalization.
	let identifier: string | undefined;
	try {
		identifier = path.split("/")[2] && decodeURIComponent(path.split("/")[2]!);
	} catch {
		return {
			result: errorResult(operation, 400, "Invalid resource identifier"),
		};
	}
	if (
		identifier &&
		(/[/\\?#]/.test(identifier) || identifier === "." || identifier === "..")
	)
		return {
			result: errorResult(operation, 400, "Invalid resource identifier"),
		};
	const location = getResourceURL(`/scim/v2${path}`, input.baseURL);
	const headers = new Headers(input.headers);
	headers.delete("content-length");
	headers.delete("idempotency-key");
	headers.delete("prefer");
	headers.set("content-type", "application/scim+json");
	const request = new Request(location, {
		method: operation.method,
		headers,
		...(operation.method === "DELETE"
			? {}
			: { body: JSON.stringify(replaceBulkData(operation.data, resolved)) }),
	});
	const response = await input.dispatch(request);
	const body: unknown =
		response.status === 204
			? undefined
			: await response.json().catch(() => undefined);
	const result: SCIMBulkOperationResult = {
		method: operation.method,
		...(operation.bulkId ? { bulkId: operation.bulkId } : {}),
		status: String(response.status),
	};
	if (response.ok) {
		result.location = response.headers.get("location") ?? location;
		const id =
			body &&
			typeof body === "object" &&
			"id" in body &&
			typeof body.id === "string"
				? body.id
				: undefined;
		return { result, id };
	}
	result.response =
		body ??
		errorResult(operation, response.status, "SCIM operation failed").response;
	return { result };
}

/** Process dependencies without a transaction across the Bulk envelope. */
export async function processSCIMBulk(
	body: z.infer<typeof bulkBodySchema>,
	input: {
		baseURL: string;
		headers: Headers;
		dispatch: (request: Request) => Promise<Response>;
	},
) {
	const ids = body.Operations.flatMap((operation) =>
		operation.bulkId ? [operation.bulkId] : [],
	);
	if (new Set(ids).size !== ids.length)
		throw createSCIMError("BAD_REQUEST", {
			detail: "bulkId values must be unique within the request",
			scimType: "invalidValue",
		});
	const resolved = new Map<string, string>();
	const pending = new Set(body.Operations.map((_, index) => index));
	const results: SCIMBulkOperationResult[] = [];
	let errors = 0;
	while (pending.size > 0) {
		let progressed = false;
		for (const index of pending) {
			const operation = body.Operations[index]!;
			if (
				bulkDependencies(operation.path, operation.data).some(
					(id) => !resolved.has(id),
				)
			)
				continue;
			const { result, id } = await executeOperation(operation, resolved, input);
			if (id && operation.bulkId && operation.method === "POST")
				resolved.set(operation.bulkId, id);
			results.push(result);
			pending.delete(index);
			progressed = true;
			if (Number(result.status) >= 400) errors++;
			if (body.failOnErrors && errors >= body.failOnErrors)
				return { schemas: [RESPONSE_SCHEMA], Operations: results };
		}
		if (progressed) continue;
		// No resolvable dependency remains. Fail each affected resource without
		// writing a partially populated resource or retrying a completed mutation.
		for (const index of pending) {
			results.push(
				errorResult(
					body.Operations[index]!,
					409,
					"Unresolved, failed or circular bulkId dependency",
				),
			);
			errors++;
			if (body.failOnErrors && errors >= body.failOnErrors) break;
		}
		break;
	}
	return { schemas: [RESPONSE_SCHEMA], Operations: results };
}

/** Install Bulk with the same authentication and per-resource request pipeline. */
export function createSCIMBulkEndpoint(
	authMiddleware: SCIMConnectionMiddleware,
	options: SCIMOptions["bulk"],
) {
	const limits = resolveSCIMBulkOptions(options);
	return createAuthEndpoint(
		"/scim/v2/Bulk",
		{
			method: "POST",
			body: bulkBodySchema,
			use: [authMiddleware],
			metadata: defineSCIMEndpointMetadata({
				...HIDE_METADATA,
				allowedMediaTypes: SCIM_REQUEST_MEDIA_TYPES,
			}),
		},
		async (ctx) => {
			if (!options)
				throw createSCIMError("NOT_IMPLEMENTED", {
					detail: "SCIM Bulk is not enabled",
				});
			if (
				ctx.body.Operations.length > limits.maxOperations ||
				new TextEncoder().encode(JSON.stringify(ctx.body)).byteLength >
					limits.maxPayloadSize
			)
				throw createSCIMError(413, {
					detail: "Bulk request exceeds the advertised limits",
				});
			if (
				ctx.headers
					?.get("prefer")
					?.split(",")
					.some((value) => value.trim().toLowerCase() === "respond-async")
			) {
				if (!options.jobs)
					throw createSCIMError("NOT_IMPLEMENTED", {
						detail: "Asynchronous SCIM Bulk is not enabled",
					});
				const job = await enqueueBulkJob(
					ctx.context.adapter,
					ctx.context.scimPrincipal,
					ctx.body,
					ctx.headers.get("idempotency-key"),
				);
				ctx.setHeader(
					"location",
					getResourceURL(
						`/scim/v2/BulkJobs/${encodeURIComponent(job.id)}`,
						ctx.context.baseURL,
					),
				);
				ctx.setHeader("preference-applied", "respond-async");
				ctx.setHeader("cache-control", "no-store");
				ctx.setStatus(202);
				return ctx.json(jobDescriptor(job), { status: 202 });
			}
			const dispatch = router({ ...ctx.context }, ctx.context.options).handler;
			return ctx.json(
				await processSCIMBulk(ctx.body, {
					baseURL: ctx.context.baseURL,
					headers: new Headers(ctx.headers),
					dispatch,
				}),
			);
		},
	);
}
