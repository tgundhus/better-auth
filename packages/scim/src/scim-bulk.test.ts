import { DatabaseSync } from "node:sqlite";
import { NodeSqliteDialect } from "@better-auth/kysely-adapter/node-sqlite-dialect";
import { getMigrations } from "better-auth/db/migration";
import { getTestInstance } from "better-auth/test";
import { describe, expect, it } from "vitest";
import { scim } from ".";
import type { SCIMBulkOperationResult } from "./bulk";
import type { SCIMOptions } from "./configuration";

const base = "http://localhost:3000/api/auth/scim/v2";
const userSchema = "urn:ietf:params:scim:schemas:core:2.0:User";
const groupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group";
const bulkSchema = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
const patchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

async function fixture(
	onTestFinished: (fn: () => void) => void,
	bulk: SCIMOptions["bulk"] = {},
	projection?: SCIMOptions["projection"],
) {
	const sqlite = new DatabaseSync(":memory:");
	onTestFinished(() => sqlite.close());
	const { auth } = await getTestInstance(
		{
			baseURL: "http://localhost:3000",
			advanced: { database: { defaultFindManyLimit: 1 } },
			database: {
				dialect: new NodeSqliteDialect({ database: sqlite }),
				type: "sqlite",
				transaction: true,
			},
			plugins: [
				scim({
					groups: { maxMembers: null },
					bulk,
					projection,
					connections: [
						{
							id: "workforce",
							credentials: [
								{ type: "bearer", id: "all", token: "all-scopes" },
								{
									type: "bearer",
									id: "groups",
									token: "groups-only",
									scopes: ["scim.groups.write"],
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
	const request = (
		path: string,
		method: string,
		data?: unknown,
		token = "all-scopes",
	) =>
		auth.handler(
			new Request(`${base}${path}`, {
				method,
				headers: {
					authorization: `Bearer ${token}`,
					"content-type": "application/scim+json",
				},
				...(data === undefined ? {} : { body: JSON.stringify(data) }),
			}),
		);
	const send = async (
		Operations: unknown[],
		failOnErrors?: number,
		token?: string,
	) => {
		const response = await request(
			"/Bulk",
			"POST",
			{ schemas: [bulkSchema], Operations, failOnErrors },
			token,
		);
		const body = (await response.json()) as {
			schemas: string[];
			Operations: SCIMBulkOperationResult[];
			status?: string;
		};
		return { response, body };
	};
	return { auth, request, send };
}

describe("SCIM Bulk over transactional storage", () => {
	it("retains projected roles from every group beyond the adapter default page", async ({
		onTestFinished,
	}) => {
		const grantCounts = new Map<string, number>();
		const { send } = await fixture(
			onTestFinished,
			{},
			{
				roles: {
					map: ({ source }) => [source.displayName],
					exists: () => true,
				},
				reconcileUser: (input) => {
					grantCounts.set(input.userId, input.grants.length);
				},
			},
		);
		const result = await send([
			{
				method: "POST",
				path: "/Users",
				bulkId: "employee",
				data: { schemas: [userSchema], userName: "many-roles@example.com" },
			},
			{
				method: "POST",
				path: "/Users",
				bulkId: "second",
				data: { schemas: [userSchema], userName: "second-roles@example.com" },
			},
			...Array.from({ length: 125 }, (_, index) => ({
				method: "POST",
				path: "/Groups",
				bulkId: `role-${index}`,
				data: {
					schemas: [groupSchema],
					displayName: `Role ${index}`,
					members: [{ value: "bulkId:employee" }, { value: "bulkId:second" }],
				},
			})),
		]);
		expect(result.body.Operations).toHaveLength(127);
		expect(
			new Set(result.body.Operations.map((operation) => operation.status)),
			JSON.stringify(
				result.body.Operations.filter(
					(operation) => operation.status !== "201",
				).slice(0, 2),
			),
		).toEqual(new Set(["201"]));
		expect([...grantCounts.values()]).toEqual([125, 125]);
	});
	it("preserves opaque bulkIds in values, encoded paths and PATCH filters", async ({
		onTestFinished,
	}) => {
		const { send, request } = await fixture(onTestFinished);
		const userId = 'employé +/"one"';
		const groupId = "équipe +/two";
		const created = await send([
			{
				method: "POST",
				path: "/Groups",
				bulkId: groupId,
				data: {
					schemas: [groupSchema],
					displayName: "Opaque references",
					members: [{ value: `bulkId:${userId}` }],
				},
			},
			{
				method: "POST",
				path: "/Users",
				bulkId: userId,
				data: { schemas: [userSchema], userName: "opaque@example.com" },
			},
			{
				method: "PATCH",
				path: `/Groups/bulkId:${encodeURIComponent(groupId)}`,
				data: {
					schemas: [patchSchema],
					Operations: [
						{
							op: "remove",
							path: `members[value eq ${JSON.stringify(`bulkId:${userId}`)}]`,
						},
					],
				},
			},
		]);
		expect(
			created.body.Operations.map((operation) => operation.status),
		).toEqual(["201", "201", "200"]);
		const group = created.body.Operations.find(
			(operation) => operation.bulkId === groupId,
		)!;
		const id = group.location!.split("/").at(-1);
		expect(
			(await (await request(`/Groups/${id}`, "GET")).json()).members,
		).toEqual([]);
	});
	it("preserves ordinary bulkId-looking text while resolving PATCH membership references", async ({
		onTestFinished,
	}) => {
		const { send, request } = await fixture(onTestFinished);
		const result = await send([
			{
				method: "POST",
				path: "/Users",
				bulkId: "u",
				data: {
					schemas: [userSchema],
					userName: "literal@example.com",
					displayName: "bulkId:literal",
				},
			},
			{
				method: "POST",
				path: "/Groups",
				bulkId: "g",
				data: { schemas: [groupSchema], displayName: "bulkId:literal" },
			},
			{
				method: "PATCH",
				path: "/Groups/bulkId:g",
				data: {
					schemas: [patchSchema],
					Operations: [
						{ op: "add", path: "members", value: [{ value: "bulkId:u" }] },
					],
				},
			},
		]);
		expect(result.body.Operations.map((operation) => operation.status)).toEqual(
			["201", "201", "200"],
		);
		const id = result.body.Operations[1]!.location!.split("/").at(-1);
		const group = await (await request(`/Groups/${id}`, "GET")).json();
		expect(group.displayName).toBe("bulkId:literal");
		expect(group.members).toHaveLength(1);
	});

	it("enforces payload bytes including whitespace before parsing and accepts more than 100 operations", async ({
		onTestFinished,
	}) => {
		const { auth, send } = await fixture(onTestFinished, {
			maxPayloadSize: 20_000,
		});
		const response = await auth.handler(
			new Request(`${base}/Bulk`, {
				method: "POST",
				headers: {
					authorization: "Bearer all-scopes",
					"content-type": "application/scim+json",
				},
				body:
					" ".repeat(20_001) +
					JSON.stringify({ schemas: [bulkSchema], Operations: [] }),
			}),
		);
		expect(response.status).toBe(413);
		const result = await send(
			Array.from({ length: 125 }, (_, index) => ({
				method: "POST",
				path: "/Groups",
				bulkId: `group-${index}`,
				data: { schemas: [groupSchema], displayName: `Group ${index}` },
			})),
		);
		expect(result.response.status).toBe(200);
		expect(result.body.Operations).toHaveLength(125);
		expect(
			new Set(result.body.Operations.map((operation) => operation.status)),
		).toEqual(new Set(["201"]));
	});

	it("resolves forward references and supports POST, PUT, PATCH and DELETE", async ({
		onTestFinished,
	}) => {
		const { send, request } = await fixture(onTestFinished);
		const { response, body } = await send([
			{
				method: "POST",
				path: "/Groups",
				bulkId: "group",
				data: {
					schemas: [groupSchema],
					displayName: "Bulk group",
					members: [{ value: "bulkId:user" }],
				},
			},
			{
				method: "POST",
				path: "/Users",
				bulkId: "user",
				data: { schemas: [userSchema], userName: "bulk@example.com" },
			},
		]);
		expect(response.status).toBe(200);
		expect(body.Operations.map((result) => result.status)).toEqual([
			"201",
			"201",
		]);
		const user = body.Operations.find((result) => result.bulkId === "user")!;
		const group = body.Operations.find((result) => result.bulkId === "group")!;
		const groupId = group.location!.split("/").at(-1)!;
		const resource = await (await request(`/Groups/${groupId}`, "GET")).json();
		expect(resource.members[0].$ref).toBe(user.location);
		const edited = await send([
			{
				method: "PUT",
				path: `/Groups/${groupId}`,
				data: { schemas: [groupSchema], displayName: "Replaced", members: [] },
			},
			{
				method: "PATCH",
				path: `/Groups/${groupId}`,
				data: {
					schemas: [patchSchema],
					Operations: [
						{ op: "replace", path: "displayName", value: "Patched" },
					],
				},
			},
			{ method: "DELETE", path: `/Groups/${groupId}` },
		]);
		expect(edited.body.Operations.map((result) => result.status)).toEqual([
			"200",
			"200",
			"204",
		]);
		expect((await request(`/Groups/${groupId}`, "GET")).status).toBe(404);
	});

	it("keeps successful resources when another operation fails and honors failOnErrors", async ({
		onTestFinished,
	}) => {
		const { send, request } = await fixture(onTestFinished);
		const create = (bulkId: string, userName: string) => ({
			method: "POST",
			path: "/Users",
			bulkId,
			data: { schemas: [userSchema], userName },
		});
		const first = await send([
			create("a", "a@example.com"),
			create("duplicate", "a@example.com"),
			create("b", "b@example.com"),
		]);
		expect(first.body.Operations.map((result) => result.status)).toEqual([
			"201",
			"409",
			"201",
		]);
		const stopped = await send(
			[
				create("duplicate", "a@example.com"),
				create("never", "never@example.com"),
			],
			1,
		);
		expect(stopped.body.Operations).toHaveLength(1);
		const users = await (await request("/Users", "GET")).json();
		expect(users.totalResults).toBe(2);
	});

	it("authorizes each operation and prevents cross-connection membership", async ({
		onTestFinished,
	}) => {
		const { send, request } = await fixture(onTestFinished);
		const scoped = await send(
			[
				{
					method: "POST",
					path: "/Users",
					bulkId: "no",
					data: { schemas: [userSchema], userName: "no@example.com" },
				},
				{
					method: "POST",
					path: "/Groups",
					bulkId: "yes",
					data: { schemas: [groupSchema], displayName: "Allowed" },
				},
			],
			undefined,
			"groups-only",
		);
		expect(scoped.body.Operations.map((result) => result.status)).toEqual([
			"403",
			"201",
		]);
		const otherUser = await (
			await request(
				"/Users",
				"POST",
				{ schemas: [userSchema], userName: "other@example.com" },
				"other",
			)
		).json();
		const cross = await send([
			{
				method: "POST",
				path: "/Groups",
				bulkId: "cross",
				data: {
					schemas: [groupSchema],
					displayName: "Rejected",
					members: [{ value: otherUser.id }],
				},
			},
		]);
		expect(cross.body.Operations[0]?.status).toBe("400");
		expect(
			(
				await send(
					[{ method: "DELETE", path: "/Users/nonexistent" }],
					undefined,
					"wrong",
				)
			).response.status,
		).toBe(401);
	});

	it("advertises limits, validates the envelope and rejects unsafe paths without dispatching them", async ({
		onTestFinished,
	}) => {
		const { send, request } = await fixture(onTestFinished, {
			maxOperations: 3,
			maxPayloadSize: 4_096,
		});
		const config = await (
			await request("/ServiceProviderConfig", "GET")
		).json();
		expect(config.bulk).toEqual({
			supported: true,
			maxOperations: 3,
			maxPayloadSize: 4_096,
		});
		expect(
			(
				await send(
					Array.from({ length: 4 }, () => ({
						method: "DELETE",
						path: "/Users/missing",
					})),
				)
			).response.status,
		).toBe(413);
		expect(
			(
				await send([
					{ method: "POST", path: "/Users", bulkId: "same" },
					{ method: "POST", path: "/Groups", bulkId: "same" },
				])
			).response.status,
		).toBe(400);
		const unsafe = await send([
			{ method: "DELETE", path: "https://example.com/Users/x" },
			{ method: "DELETE", path: "/Users/%2e%2e" },
			{ method: "DELETE", path: "/Bulk" },
		]);
		expect(unsafe.body.Operations.map((result) => result.status)).toEqual([
			"400",
			"400",
			"400",
		]);
		const dependent = await send([
			{
				method: "POST",
				path: "/Groups",
				bulkId: "g",
				data: {
					schemas: [groupSchema],
					displayName: "Missing",
					members: [{ value: "bulkId:absent" }],
				},
			},
		]);
		expect(dependent.body.Operations[0]?.status).toBe("409");
	});
});
