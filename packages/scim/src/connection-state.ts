import type { DBAdapter, DBTransactionAdapter } from "better-auth";
import { BetterAuthError } from "better-auth";
import type { SCIMConnectionBinding } from "./persistence";
import { findAllSCIMRows } from "./read-all";
import { createScopedKey } from "./resource-key";
import { createSCIMError } from "./scim-error";

/** Creates the stable lookup key for a code-defined connection id. */
export function createSCIMConnectionKey(connectionId: string): string {
	return createScopedKey(["scim-connection", connectionId]);
}

/**
 * Finds a connection's persisted binding, or creates it with the caller's
 * initial lifecycle fields. Concurrent creators race on the unique
 * connectionKey; the loser re-reads and validates the winner's row instead
 * of failing.
 */
export async function findOrCreateSCIMConnectionBinding(
	database: Pick<DBAdapter, "create" | "findOne">,
	connectionId: string,
	provisioningDomainId: string | undefined,
	now: Date,
	initialFields: Pick<SCIMConnectionBinding, "decommissionStatus"> &
		Partial<
			Pick<
				SCIMConnectionBinding,
				"decommissionedAt" | "decommissionCompletedAt"
			>
		>,
	assertBinding: (binding: SCIMConnectionBinding) => void,
): Promise<SCIMConnectionBinding> {
	const connectionKey = createSCIMConnectionKey(connectionId);
	const findBinding = () =>
		database.findOne<SCIMConnectionBinding>({
			model: "scimConnectionBinding",
			where: [{ field: "connectionKey", value: connectionKey }],
		});
	const existing = await findBinding();
	if (existing) {
		assertBinding(existing);
		return existing;
	}
	if (!provisioningDomainId) {
		throw new BetterAuthError(
			`SCIM connection "${connectionId}" has no persisted binding.`,
		);
	}

	try {
		return await database.create<
			Omit<SCIMConnectionBinding, "id">,
			SCIMConnectionBinding
		>({
			model: "scimConnectionBinding",
			data: {
				connectionId,
				connectionKey,
				provisioningDomainId,
				createdAt: now,
				decommissionReconciledUserCount: 0,
				decommissionBatchCount: 0,
				decommissionRevision: 0,
				...initialFields,
			},
		});
	} catch (error) {
		const concurrentlyCreated = await findBinding();
		if (!concurrentlyCreated) throw error;
		assertBinding(concurrentlyCreated);
		return concurrentlyCreated;
	}
}

/** Finds connections that no longer participate in lifecycle or access state. */
export async function findDecommissionedSCIMConnectionIds(
	database: Pick<DBAdapter, "findMany">,
	connectionIds: readonly string[],
): Promise<Set<string>> {
	const ids = [...new Set(connectionIds)];
	const retired = new Set<string>();
	for (let offset = 0; offset < ids.length; offset += 500) {
		const bindings = await findAllSCIMRows<SCIMConnectionBinding>(database, {
			model: "scimConnectionBinding",
			where: [
				{
					field: "connectionId",
					value: ids.slice(offset, offset + 500),
					operator: "in",
				},
			],
		});
		for (const binding of bindings) {
			if (binding.decommissionStatus !== "active")
				retired.add(binding.connectionId);
		}
	}
	return retired;
}

/**
 * Fence a completed resource mutation against concurrent connection
 * retirement. The atomic update orders decommission after this transaction,
 * or fails the transaction when retirement won the race.
 */
export async function fenceActiveSCIMConnection(
	database: Pick<DBTransactionAdapter, "incrementOne">,
	connectionId: string,
): Promise<SCIMConnectionBinding> {
	const binding = await tryFenceActiveSCIMConnection(database, connectionId);
	if (binding) return binding;
	throw createSCIMError("UNAUTHORIZED", {
		detail: "SCIM connection is decommissioned",
	});
}

/** Attempts to fence a connection without assigning an HTTP failure policy. */
export async function tryFenceActiveSCIMConnection(
	database: Pick<DBTransactionAdapter, "incrementOne">,
	connectionId: string,
): Promise<SCIMConnectionBinding | null> {
	return database.incrementOne<SCIMConnectionBinding>({
		model: "scimConnectionBinding",
		where: [
			{
				field: "connectionKey",
				value: createSCIMConnectionKey(connectionId),
			},
			{ field: "connectionId", value: connectionId },
			{ field: "decommissionStatus", value: "active" },
		],
		increment: { decommissionRevision: 1 },
	});
}
