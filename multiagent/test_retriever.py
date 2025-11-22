# test_retriever.py
import os
from pprint import pprint
from pymongo import MongoClient
from langchain_mongodb.vectorstores import MongoDBAtlasVectorSearch
from langchain_community.embeddings import SentenceTransformerEmbeddings

# ==== CONFIG ====
MONGO_URI = "mongodb+srv://meghanakonka2_db_user:EFniS5uYCifkoU0G@multiagent.r97ace3.mongodb.net/?appName=multiagent"
DB_NAME = "multiagentllm"
COLLECTION_NAME = "RAG"
INDEX_NAME = "vector_index"

EMBED_MODEL = "all-MiniLM-L6-v2"

# ==== CONNECT ====
client = MongoClient(MONGO_URI)
collection = client[DB_NAME][COLLECTION_NAME]

embeddings = SentenceTransformerEmbeddings(
    model_name=EMBED_MODEL
)

# Build vectorstore
vectorstore = MongoDBAtlasVectorSearch(
    collection=collection,
    embedding=embeddings,
    index_name=INDEX_NAME,
    text_key="page_content"
)

retriever = vectorstore.as_retriever(search_kwargs={"k": 10})

# ==== QUERIES TO TEST ====
queries = [
    "What is angular distance?",
]

# ==== RUN ====
for q in queries:
    print("\n" + "="*100)
    print(f"QUERY: {q}")
    print("="*100)

    try:
        docs = retriever.invoke(q)
    except:
        docs = retriever.get_relevant_documents(q)

    for i, d in enumerate(docs):
        print(f"\n--- Chunk {i+1} ---")
        print("METADATA:", d.metadata)
        print("\nTEXT:\n", d.page_content[:800], "...")
