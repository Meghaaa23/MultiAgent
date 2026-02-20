# scripts/ingest_knowledge_base.py

import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pymongo
from openai import OpenAI
from dotenv import load_dotenv
import PyPDF2
from datetime import datetime

load_dotenv()

class KnowledgeBaseIngestion:
    """
    Ingest security documents with LOCAL embeddings
    No OpenAI API key required!
    """
    
    def __init__(self, chunk_size=1000, overlap=200):
        # MongoDB setup
        mongodb_uri = os.getenv("MONGODB_ATLAS_URI")
        self.mongo_client = pymongo.MongoClient(mongodb_uri)
        self.db = self.mongo_client["multiagentllm"]
        self.collection = self.db["security_knowledge_base"]
        
        # Local embedding model
        print("Loading embedding model...")
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        print(" Embedding model loaded")
        
        self.chunk_size = chunk_size
        self.overlap = overlap
        
        print(" Connected to MongoDB")
        print(f"  Database: {self.db.name}")
        print(f"  Collection: {self.collection.name}")
    
    def get_embedding(self, text: str) -> list:
        """Generate embedding for text using local model"""
        try:
            embedding = self.embedding_model.encode(text, convert_to_numpy=True)
            return embedding.tolist()
        except Exception as e:
            print(f" Embedding failed: {e}")
            return None
    
    def chunk_text(self, text: str, metadata: dict = None) -> list:
        """Split text into overlapping chunks"""
        chunks = []
        start = 0
        chunk_index = 0
        
        while start < len(text):
            end = start + self.chunk_size
            chunk_text = text[start:end].strip()
            
            if not chunk_text:
                break
            
            chunk = {
                "chunk_index": chunk_index,
                "content": chunk_text,
                "char_count": len(chunk_text)
            }
            
            if metadata:
                chunk.update(metadata)
            
            chunks.append(chunk)
            start = end - self.overlap
            chunk_index += 1
            
            if start >= len(text):
                break
        
        return chunks
    
    def extract_text_from_pdf(self, filepath: str) -> str:
        """Extract text from PDF"""
        text = ""
        try:
            reader = PyPDF2.PdfReader(filepath)
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n\n"
        except Exception as e:
            print(f" Error extracting {filepath}: {e}")
        return text
    
    def ingest_document(self, filepath: str, source: str, doc_type: str, metadata: dict = None) -> int:
        """Ingest a single document with embeddings"""
        print(f"\n{'='*70}")
        print(f"Processing: {os.path.basename(filepath)}")
        print(f"Source: {source} | Type: {doc_type}")
        print(f"{'='*70}")
        
        # Extract text
        print("Extracting text...")
        if filepath.endswith('.pdf'):
            content = self.extract_text_from_pdf(filepath)
        else:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
        
        print(f" Extracted {len(content)} characters")
        
        # Prepare metadata
        doc_metadata = {
            "source": source,
            "doc_type": doc_type,
            "filepath": filepath,
            "filename": os.path.basename(filepath),
            "ingestion_date": datetime.now().isoformat(),
            "title": metadata.get('title', os.path.basename(filepath)) if metadata else os.path.basename(filepath),
        }
        
        if metadata:
            doc_metadata.update(metadata)
        
        # Chunk the document
        print("Chunking document...")
        chunks = self.chunk_text(content, doc_metadata)
        print(f" Created {len(chunks)} chunks")
        
        # Add total chunks count
        for chunk in chunks:
            chunk["total_chunks"] = len(chunks)
        
        # Generate embeddings
        print(f"Generating embeddings...")
        chunks_with_embeddings = []
        
        for idx, chunk in enumerate(chunks):
            if (idx + 1) % 10 == 0:
                print(f"  Progress: {idx + 1}/{len(chunks)} chunks")
            
            embedding = self.get_embedding(chunk["content"])
            
            if embedding:
                chunk["embedding"] = embedding
                chunks_with_embeddings.append(chunk)
            else:
                print(f"  Skipping chunk {idx} (embedding failed)")
        
        print(f" Generated {len(chunks_with_embeddings)} embeddings")
        
        # Insert into MongoDB
        if chunks_with_embeddings:
            print(f"Inserting {len(chunks_with_embeddings)} chunks into MongoDB...")
            result = self.collection.insert_many(chunks_with_embeddings)
            print(f" Successfully inserted {len(result.inserted_ids)} chunks")
            return len(result.inserted_ids)
        
        return 0
    
    def ingest_folder(self, folder_path: str, source: str, doc_type: str):
        """Ingest all documents in a folder"""
        folder = Path(folder_path)
        if not folder.exists():
            print(f" Folder not found: {folder_path}")
            return
        
        files = list(folder.glob("*.pdf")) + list(folder.glob("*.txt"))
        
        if not files:
            print(f" No documents found in {folder_path}")
            return
        
        print(f"\nFound {len(files)} file(s) in {folder_path}")
        
        total_chunks = 0
        for file_path in files:
            try:
                chunks = self.ingest_document(str(file_path), source=source, doc_type=doc_type)
                total_chunks += chunks
            except Exception as e:
                print(f" Error processing {file_path}: {e}")
        
        print(f"\n Total chunks ingested from {folder_path}: {total_chunks}")
    
    def get_stats(self):
        """Get statistics"""
        total_chunks = self.collection.count_documents({})
        
        pipeline = [
            {"$group": {
                "_id": "$source",
                "count": {"$sum": 1},
                "documents": {"$addToSet": "$filename"}
            }}
        ]
        
        results = list(self.collection.aggregate(pipeline))
        
        print("\n" + "="*70)
        print("KNOWLEDGE BASE STATISTICS")
        print("="*70)
        print(f"Total chunks: {total_chunks}\n")
        
        for item in results:
            print(f"{item['_id']}:")
            print(f"  Documents: {len(item['documents'])}")
            print(f"  Chunks: {item['count']}\n")
        
        print("="*70 + "\n")

def main():
    """Main ingestion function"""
    print("\n" + "="*70)
    print("KNOWLEDGE BASE INGESTION WITH EMBEDDINGS")
    print("="*70 + "\n")
    
    ingestion = KnowledgeBaseIngestion(chunk_size=1000, overlap=200)
    
    # Clear existing data first
    print("Clearing existing data...")
    ingestion.collection.delete_many({})
    print(" Cleared\n")
    
    folders = [
        ("knowledge_base/cisa", "CISA", "guideline"),
        ("knowledge_base/ieee", "IEEE", "paper"),
        ("knowledge_base/intel_tdx", "Intel_TDX", "specification"),
        ("knowledge_base/owasp", "OWASP", "cheatsheet"),
    ]
    
    for folder_path, source, doc_type in folders:
        if os.path.exists(folder_path):
            ingestion.ingest_folder(folder_path, source, doc_type)
    
    ingestion.get_stats()
    
    print("\n Ingestion complete!")

if __name__ == "__main__":
    main()