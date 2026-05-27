"""add HNSW vector index and GIN tsvector index on embeddings

Revision ID: 004
Revises: 003
Create Date: 2026-05-26

Notes:
  - HNSW (m=16, ef_construction=64): ~2× faster build than IVFFlat,
    better recall at high ef_search, no training step needed.
  - GIN tsvector: enables fast BM25-style full-text search (ts_rank_cd).
  - Both CREATE INDEX use IF NOT EXISTS so reruns are safe.
  - CONCURRENTLY not used here because Alembic wraps in a transaction;
    run `CREATE INDEX CONCURRENTLY` manually on large datasets.
"""
from typing import Sequence, Union

from alembic import op

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Ensure pgvector extension is present (idempotent)
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    # HNSW cosine-distance index — replaces sequential O(n) scan
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_embeddings_hnsw
        ON embeddings
        USING hnsw (embedding vector_cosine_ops)
        WITH (m = 16, ef_construction = 64)
    """)

    # GIN full-text search index for BM25 hybrid retrieval
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_embeddings_content_fts
        ON embeddings
        USING GIN (to_tsvector('english', content))
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_embeddings_content_fts")
    op.execute("DROP INDEX IF EXISTS idx_embeddings_hnsw")
