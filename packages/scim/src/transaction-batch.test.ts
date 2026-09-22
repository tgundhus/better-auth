import type { DBTransactionAdapter } from "better-auth";
import { describe, expect, it, vi } from "vitest";
import {
	createManyInTransaction,
	mapTransactionWork,
} from "./transaction-batch";

function database(input: {
	options?: Record<string, unknown>;
	create?: (input: {
		model: string;
		data: Record<string, unknown>;
	}) => Promise<Record<string, unknown>>;
}) {
	return {
		options: input.options ?? {},
		create:
			input.create ??
			(async ({ data }) => ({ ...data, id: String(data.value) })),
	} as unknown as Pick<DBTransactionAdapter, "create" | "options">;
}

function deferred() {
	let resolve!: () => void;
	const promise = new Promise<void>((resolvePromise) => {
		resolve = resolvePromise;
	});
	return { promise, resolve };
}

describe("transaction batch capabilities", () => {
	it("uses the advertised transaction-scoped batch create", async () => {
		const create = vi.fn();
		const createMany = vi.fn(
			async (input: { model: string; data: Record<string, unknown>[] }) =>
				input.data.map((row, index) => ({ ...row, id: `batch-${index}` })),
		);
		const adapter = database({
			create,
			options: { transactionBatch: { maxConcurrency: 4, createMany } },
		});

		const rows = await createManyInTransaction<Record<string, unknown>>(
			adapter,
			{
				model: "membership",
				data: [{ value: 1 }, { value: 2 }],
			},
		);

		expect(createMany).toHaveBeenCalledOnce();
		expect(create).not.toHaveBeenCalled();
		expect(rows.map((row) => row.id)).toEqual(["batch-0", "batch-1"]);
	});

	it("keeps sequential create compatibility when no capability is present", async () => {
		const calls: number[] = [];
		const adapter = database({
			create: async ({ data }) => {
				calls.push(Number(data.value));
				return { ...data, id: `row-${String(data.value)}` };
			},
		});

		const rows = await createManyInTransaction<Record<string, unknown>>(
			adapter,
			{
				model: "membership",
				data: [{ value: 1 }, { value: 2 }],
			},
		);

		expect(calls).toEqual([1, 2]);
		expect(rows.map((row) => row.id)).toEqual(["row-1", "row-2"]);
	});

	it("preserves order while respecting advertised concurrency", async () => {
		let active = 0;
		let maximumActive = 0;
		const adapter = database({
			options: {
				transactionBatch: { maxConcurrency: 3, createMany: vi.fn() },
			},
		});

		const results = await mapTransactionWork(
			adapter,
			[5, 4, 3, 2, 1],
			async (value) => {
				active++;
				maximumActive = Math.max(maximumActive, active);
				await Promise.resolve();
				active--;
				return value * 2;
			},
		);

		expect(maximumActive).toBe(3);
		expect(results).toEqual([10, 8, 6, 4, 2]);
	});

	it("stops claiming work after a failure and waits for started work", async () => {
		const gate = deferred();
		const started: number[] = [];
		const adapter = database({
			options: {
				transactionBatch: { maxConcurrency: 2, createMany: vi.fn() },
			},
		});
		const failure = new Error("failed");
		const work = mapTransactionWork(adapter, [0, 1, 2, 3], async (value) => {
			started.push(value);
			if (value === 0) await gate.promise;
			if (value === 1) throw failure;
			return value;
		});
		await Promise.resolve();
		await Promise.resolve();
		expect(started).toEqual([0, 1]);
		gate.resolve();

		await expect(work).rejects.toBe(failure);
		expect(started).toEqual([0, 1]);
	});

	it("defensively caps third-party capability concurrency", async () => {
		let active = 0;
		let maximumActive = 0;
		const adapter = database({
			options: {
				transactionBatch: {
					maxConcurrency: Number.MAX_SAFE_INTEGER,
					createMany: vi.fn(),
				},
			},
		});

		await mapTransactionWork(
			adapter,
			Array.from({ length: 100 }, (_, index) => index),
			async (value) => {
				active++;
				maximumActive = Math.max(maximumActive, active);
				await Promise.resolve();
				active--;
				return value;
			},
		);

		expect(maximumActive).toBe(64);
	});

	it("does not call either create path for empty input", async () => {
		const create = vi.fn();
		const createMany = vi.fn();
		const adapter = database({
			create,
			options: { transactionBatch: { maxConcurrency: 4, createMany } },
		});

		expect(
			await createManyInTransaction(adapter, {
				model: "membership",
				data: [],
			}),
		).toEqual([]);
		expect(create).not.toHaveBeenCalled();
		expect(createMany).not.toHaveBeenCalled();
	});
});
