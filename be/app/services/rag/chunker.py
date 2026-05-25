def chunk_document(
    text: str, chunk_size: int = 800, overlap: int = 120
) -> list[dict]:
    if not text:
        return []

    chunks = []
    start = 0
    index = 0
    while start < len(text):
        end = min(start + chunk_size, len(text))
        content = text[start:end].strip()

        if content:
            chunks.append(
                {
                    "content": content,
                    "meta": {
                        "chunk_index": index,
                        "start_offset": start,
                        "end_offset": end,
                    },
                }
            )
            index += 1

        next_start = end - overlap
        start = next_start if next_start > start else end

    return chunks


def chunk_text(text: str, chunk_size: int = 800, overlap: int = 120) -> list[str]:
    return [chunk["content"] for chunk in chunk_document(text, chunk_size, overlap)]
