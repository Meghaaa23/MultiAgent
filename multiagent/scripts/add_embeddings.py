import os
from pymongo import MongoClient
from sentence_transformers import SentenceTransformer
from dotenv import load_dotenv
from tqdm import tqdm

load_dotenv()

print("="*70)
print("ADDING EMBEDDINGS TO SECURITY KNOWLEDGE BASE")
print("="*70)

# Connect
client = MongoClient(os.getenv("MONGODB_ATLAS_URI"))
db = client["multiagentllm"]
collection = db["security_knowledge_base"]

# Load model
print("\n Loading embedding model...")
model = SentenceTransformer('all-MiniLM-L6-v2')
print(" Model loaded: all-MiniLM-L6-v2 (384 dimensions)")

# Get all documents
print("\n Finding documents without embeddings...")
docs = list(collection.find({"embedding": {"$exists": False}}))
total = len(docs)

print(f"Found {total} documents without embeddings")

if total == 0:
    print("\n All documents already have embeddings!")
    exit(0)

# Add embeddings
print(f"\n Generating and adding embeddings...")
updated = 0
errors = 0

for doc in tqdm(docs, desc="Processing"):
    content = doc.get('content', '')
    
    if not content:
        errors += 1
        continue
    
    try:
        # Generate embedding
        embedding = model.encode(content, convert_to_numpy=True).tolist()
        
        # Update document
        collection.update_one(
            {"_id": doc["_id"]},
            {"$set": {"embedding": embedding}}
        )
        
        updated += 1
        
    except Exception as e:
        print(f"\n Error processing document {doc['_id']}: {e}")
        errors += 1

print(f"\n Successfully added embeddings to {updated} documents")
if errors > 0:
    print(f" Failed: {errors} documents")

# Verify
final_count = collection.count_documents({"embedding": {"$exists": True}})
print(f" Total documents with embeddings: {final_count}")

# Check sample
if final_count > 0:
    sample = collection.find_one({"embedding": {"$exists": True}})
    print(f" Sample embedding dimensions: {len(sample['embedding'])}")