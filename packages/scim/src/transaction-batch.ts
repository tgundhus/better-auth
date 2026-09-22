import type { DBAdapter, DBTransactionAdapter } from "better-auth";

const MAX_TRANSACTION_BATCH_CONCURRENCY = 64;

type TransactionBatchCapability = {
	maxConcurrency: number;
	createMany(input: {
		model: string;
		data: Record<string, unknown>[];
	}): Promise<Record<string, unknown>[]>;
};

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null;
}

function transactionBatch(
	database: Pick<DBAdapter, "options">,
): TransactionBatchCapability | null {
	const candidate = isRecord(database.options)
		? database.options.transactionBatch
		: undefined;
	if (
		!isRecord(candidate) ||
		typeof candidate.createMany !== "function" ||
		!Number.isSafeInteger(candidate.maxConcurrency) ||
		Number(candidate.maxConcurrency) < 1
	)
		return null;
	return candidate as TransactionBatchCapability;
}

/** Batch a set of independent creates when the transaction adapter advertises support. */
export async function createManyInTransaction<Result>(
	database: Pick<DBTransactionAdapter, "create" | "options">,
	input: { model: string; data: Record<string, unknown>[] },
): Promise<Result[]> {
	if (input.data.length === 0) return [];
	const capability = transactionBatch(database);
	if (capability) return (await capability.createMany(input)) as Result[];
	const created: Result[] = [];
	for (const data of input.data) {
		created.push(
			await database.create<Record<string, unknown>, Result>({
				model: input.model,
				data,
			}),
		);
	}
	return created;
}

/** Run independent transaction work with adapter-selected bounded concurrency. */
export async function mapTransactionWork<Item, Result>(
	database: Pick<DBTransactionAdapter, "options">,
	items: readonly Item[],
	operation: (item: Item) => Promise<Result>,
): Promise<Result[]> {
	const concurrency = Math.min(
		transactionBatch(database)?.maxConcurrency ?? 1,
		MAX_TRANSACTION_BATCH_CONCURRENCY,
		items.length,
	);
	if (concurrency === 0) return [];
	const state = { cursor: 0, failure: undefined as unknown, stopped: false };
	const results = new Array<Result>(items.length);
	await Promise.all(
		Array.from({ length: concurrency }, () =>
			runWorker(items, results, state, operation),
		),
	);
	if (state.stopped) throw state.failure;
	return results;
}

async function runWorker<Item, Result>(
	items: readonly Item[],
	results: Result[],
	state: { cursor: number; failure: unknown; stopped: boolean },
	operation: (item: Item) => Promise<Result>,
): Promise<void> {
	while (!state.stopped && state.cursor < items.length) {
		const index = state.cursor++;
		try {
			results[index] = await operation(items[index]!);
		} catch (error) {
			if (!state.stopped) state.failure = error;
			state.stopped = true;
		}
	}
}
