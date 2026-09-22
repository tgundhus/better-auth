/** Read a request clone with an optional byte budget before parsing JSON. */
export async function readSCIMRequestBody(
	request: Request,
	maximum?: number,
): Promise<{ text: string } | { tooLarge: true }> {
	if (maximum === undefined) return { text: await request.clone().text() };
	const reader = request.clone().body?.getReader();
	if (!reader) return { text: "" };
	const decoder = new TextDecoder();
	const parts: string[] = [];
	let bytes = 0;
	for (;;) {
		const chunk = await reader.read();
		if (chunk.done) break;
		bytes += chunk.value.byteLength;
		if (bytes > maximum) {
			// Cancelling a cloned stream can wait for its unused sibling.
			void reader.cancel().catch(() => {});
			return { tooLarge: true };
		}
		parts.push(decoder.decode(chunk.value, { stream: true }));
	}
	parts.push(decoder.decode());
	return { text: parts.join("") };
}
