# agents/vector_search.py

import os
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
        
        self.db = self.mongo_client[self.db_name]
        self.collection = self.db[self.collection_name]
        
        # Use same local model as RAG collection
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        
        print(f"✓ VectorSearch initialized: {self.db_name}.{self.collection_name}")
        print(f"  Using local embeddings: all-MiniLM-L6-v2")
    
    def get_embedding(self, text: str) -> List[float]:
        """Generate embedding using local model"""
        embedding = self.embedding_model.encode(text, convert_to_numpy=True)
        return embedding.tolist()
    
    async def search(
        self,
        query: str,
        filters: Optional[Dict] = None,
        top_k: int = 10
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
        
        # Generate query embedding
        query_embedding = self.get_embedding(query)
        
        # Build aggregation pipeline for vector search
        pipeline = [
            {
                "$vectorSearch": {
                    "queryVector": query_embedding,
                    "path": "embedding",
                    "numCandidates": top_k * 10,
                    "limit": top_k,
                    "index": "vector_index"  
                }
            }
        ]
        
        # Add filters if provided
        if filters:
            pipeline.append({"$match": filters})
        
        # Project fields we need
        pipeline.append({
            "$project": {
                "content": 1,
                "source": 1,
                "doc_type": 1,
                "title": 1,
                "filename": 1,
                "chunk_index": 1,
                "score": {"$meta": "vectorSearchScore"}
            }
        })
        
        # Execute search
        try:
            results = list(self.collection.aggregate(pipeline))
            print(f"  Vector search '{query[:50]}...' → {len(results)} results")
            return results
            
        except Exception as e:
            error_msg = str(e)
            
            # Check if vector index doesn't exist
            if "vector_index" in error_msg or "$vectorSearch" in error_msg:
                print(f"⚠️  Vector index not found - using text search fallback")
                return await self._text_search_fallback(query, filters, top_k)
            else:
                print(f"✗ Vector search error: {e}")
                return []
    
    async def _text_search_fallback(
        self,
        query: str,
        filters: Optional[Dict] = None,
        top_k: int = 10
    ) -> List[Dict]:
        """
        Fallback to text search if vector index doesn't exist
        This is temporary until you create the vector index
        """
        print(f"  Using text search fallback (create vector index for better results)")
        
        # Build text search filter
        search_filter = {
            "$text": {"$search": query}
        }
        
        # Add additional filters
        if filters:
            search_filter.update(filters)
        
        # Search with text score
        try:
            results = list(
                self.collection.find(
                    search_filter,
                    {"score": {"$meta": "textScore"}}
                )
                .sort([("score", {"$meta": "textScore"})])
                .limit(top_k)
            )
            
            print(f"  Text search '{query[:50]}...' → {len(results)} results")
            return results
            
        except Exception as e:
            print(f"  Text search also failed: {e}")
            print(f"  Falling back to regex search")
            return await self._regex_search_fallback(query, filters, top_k)
    
    async def _regex_search_fallback(
        self,
        query: str,
        filters: Optional[Dict] = None,
        top_k: int = 10
    ) -> List[Dict]:
        """
        Last resort: simple regex search
        """
        # Extract keywords from query
        keywords = query.lower().split()
        
        # Build regex pattern
        pattern = "|".join(keywords[:3])  # Use first 3 words
        
        search_filter = {
            "content": {"$regex": pattern, "$options": "i"}
        }
        
        if filters:
            search_filter.update(filters)
        
        results = list(self.collection.find(search_filter).limit(top_k))
        
        print(f"  Regex search '{query[:50]}...' → {len(results)} results")
        
        return results