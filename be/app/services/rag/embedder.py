from typing import Sequence

from langchain_community.embeddings import OllamaEmbeddings

from app.core.config import settings


class LocalEmbedder:
    def __init__(self, model: str | None = None) -> None:
        self.model = model or settings.embeddings_model
        self.client = OllamaEmbeddings(
            model=self.model,
            base_url=settings.ollama_base_url,
        )

    def embed_texts(self, texts: Sequence[str]) -> list[list[float]]:
        return self.client.embed_documents(list(texts))

    def embed_query(self, text: str) -> list[float]:
        return self.client.embed_query(text)
