/** bulkId is an opaque string, not a restricted identifier alphabet. */
function mapReference(value: string, replace: (id: string) => string): string {
	if (value.startsWith("bulkId:")) return replace(value.slice(7));
	// URI references encode an opaque bulkId as their final path segment.
	const uri = /^(.*\/)bulkId:([^/?#]+)$/.exec(value);
	if (uri) {
		try {
			return uri[1]! + encodeURIComponent(replace(decodeURIComponent(uri[2]!)));
		} catch {
			return value;
		}
	}
	// PATCH value filters contain JSON string literals. Preserve escaping and
	// avoid replacing ordinary text outside the selected reference attributes.
	return value.replace(/"(?:[^"\\]|\\.)*"/g, (literal) => {
		try {
			const parsed: string = JSON.parse(literal);
			return parsed.startsWith("bulkId:")
				? JSON.stringify(replace(parsed.slice(7)))
				: literal;
		} catch {
			return literal;
		}
	});
}

function referencePath(path: string): boolean {
	return /(^|[:.])(members|manager)(\.|\[|$)/i.test(path);
}

/** Rewrite schema reference attributes and PATCH paths, preserving ordinary text. */
function mapReferences(
	value: unknown,
	replace: (value: string) => string,
	reference = false,
): unknown {
	if (typeof value === "string") return reference ? replace(value) : value;
	if (Array.isArray(value))
		return value.map((item) => mapReferences(item, replace, reference));
	if (!value || typeof value !== "object") return value;
	const entries = Object.entries(value);
	const patchPath =
		"op" in value && "path" in value && typeof value.path === "string"
			? value.path
			: undefined;
	return Object.fromEntries(
		entries.map(([key, item]) => {
			if (key === "path" && patchPath && referencePath(patchPath))
				return [key, replace(patchPath)];
			const name = key.slice(key.lastIndexOf(":") + 1).toLowerCase();
			const isReference =
				name === "members" ||
				name === "manager" ||
				(reference && (name === "value" || name === "$ref")) ||
				(name === "value" &&
					patchPath !== undefined &&
					referencePath(patchPath));
			return [key, mapReferences(item, replace, isReference)];
		}),
	);
}

export function bulkDependencies(path: string, data: unknown): string[] {
	const ids = new Set<string>();
	const collect = (value: string) => {
		return mapReference(value, (id) => {
			ids.add(id);
			return `bulkId:${id}`;
		});
	};
	collect(path);
	mapReferences(data, collect);
	return [...ids];
}

export function replaceBulkPath(
	path: string,
	resolved: ReadonlyMap<string, string>,
): string {
	return mapReference(path, (id) => resolved.get(id) ?? `bulkId:${id}`);
}

export function replaceBulkData(
	data: unknown,
	resolved: ReadonlyMap<string, string>,
): unknown {
	return mapReferences(data, (value) =>
		mapReference(value, (id) => resolved.get(id) ?? `bulkId:${id}`),
	);
}
