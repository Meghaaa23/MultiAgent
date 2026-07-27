# agents/vector_search.py

from typing import List, Dict, Optional
from sentence_transformers import SentenceTransformer


class VectorSearch:
    """
    Vector search for knowledge base using LOCAL embeddings
    No OpenAI API key required!
    """

    def __init__(self, mongodb_client, collection_name: str = "security_knowledge_base"):
        self.mongo_client = mongodb_client
        self.db_name = "multiagentllm"
        self.collection_name = collection_name
        self._disabled = mongodb_client is None

        if self._disabled:
            self.db = None
            self.collection = None
            self.embedding_model = None
            print("⚠ VectorSearch disabled — MongoDB client unavailable")
            return

        self.db = self.mongo_client[self.db_name]
        self.collection = self.db[self.collection_name]

        # Use same local model as RAG collection
        self.embedding_model = SentenceTransformer("all-MiniLM-L6-v2")

        print(f"✓ VectorSearch initialized: {self.db_name}.{self.collection_name}")
        print("  Using local embeddings: all-MiniLM-L6-v2")

    def get_embedding(self, text: str) -> List[float]:
        """Generate embedding using local model"""
        embedding = self.embedding_model.encode(text, convert_to_numpy=True)
        return embedding.tolist()

    async def search(
        self,
        query: str,
        filters: Optional[Dict] = None,
        top_k: int = 10,
    ) -> List[Dict]:
        """
        Vector search in knowledge base using local embeddings

        Args:
            query: Search query
            filters: MongoDB filters (e.g., {"source": {"$in": ["CISA", "IEEE"]}})
            top_k: Number of results

        Returns:
            List of relevant chunks with scores
        """
        if self._disabled:
            return []

        query_embedding = self.get_embedding(query)

        pipeline = [
            {
                "$vectorSearch": {
                    "queryVector": query_embedding,
                    "path": "embedding",
                    "numCandidates": top_k * 10,
                    "limit": top_k,
                    "index": "vector_index",
                }
            }
        ]

        if filters:
            pipeline.append({"$match": filters})

        pipeline.append(
            {
                "$project": {
                    "content": 1,
                    "source": 1,
                    "doc_type": 1,
                    "title": 1,
                    "filename": 1,
                    "chunk_index": 1,
                    "score": {"$meta": "vectorSearchScore"},
                }
            }
        )

        try:
            results = list(self.collection.aggregate(pipeline))
            print(f"  Vector search '{query[:50]}...' → {len(results)} results")
            return results

        except Exception as e:
            error_msg = str(e)
            low = error_msg.lower()

            if "vector_index" in error_msg or "$vectorSearch" in error_msg:
                print("⚠️  Vector index not found - using text search fallback")
                return await self._text_search_fallback(query, filters, top_k)

            # TLS / Atlas connectivity — fail fast, do not cascade into regex fallbacks
            if any(
                tok in low
                for tok in ("ssl", "tls", "handshake", "server selection", "timeout")
            ):
                print(
                    "✗ Vector search skipped — MongoDB Atlas unreachable "
                    f"({error_msg.split('(configured timeouts')[0].strip()[:120]})"
                )
                self._disabled = True
                return []

            print(f"✗ Vector search error: {e}")
            return []

    async def _text_search_fallback(
        self,
        query: str,
        filters: Optional[Dict] = None,
        top_k: int = 10,
    ) -> List[Dict]:
        """Fallback to text search if vector index doesn't exist."""
        if self._disabled:
            return []

        print("  Using text search fallback (create vector index for better results)")

        search_filter = {"$text": {"$search": query}}
        if filters:
            search_filter.update(filters)

        try:
            results = list(
                self.collection.find(search_filter, {"score": {"$meta": "textScore"}})
                .sort([("score", {"$meta": "textScore"})])
                .limit(top_k)
            )
            print(f"  Text search '{query[:50]}...' → {len(results)} results")
            return results
        except Exception as e:
            print(f"  Text search also failed: {e}")
            print("  Falling back to regex search")
            return await self._regex_search_fallback(query, filters, top_k)

    async def _regex_search_fallback(
        self,
        query: str,
        filters: Optional[Dict] = None,
        top_k: int = 10,
    ) -> List[Dict]:
        """Last resort: simple regex search."""
        if self._disabled:
            return []

        keywords = query.lower().split()
        pattern = "|".join(keywords[:3])
        search_filter = {"content": {"$regex": pattern, "$options": "i"}}
        if filters:
            search_filter.update(filters)

        try:
            results = list(self.collection.find(search_filter).limit(top_k))
        except Exception as e:
            print(f"  Regex search failed: {e}")
            return []

        print(f"  Regex search '{query[:50]}...' → {len(results)} results")
        return results
