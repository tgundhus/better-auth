import type { DBAdapter, Where } from "better-auth";

/** Read an internal relation completely without relying on adapter default limits. */
export async function findAllSCIMRows<Row>(
	adapter: Pick<DBAdapter, "findMany">,
	input: { model: string; where: Where[] },
): Promise<Row[]> {
	const rows: Row[] = [];
	const limit = 500;
	for (;;) {
		const page = await adapter.findMany<Row>({
			...input,
			limit,
			offset: rows.length,
			sortBy: { field: "id", direction: "asc" },
		});
		rows.push(...page);
		if (page.length < limit) return rows;
	}
}
