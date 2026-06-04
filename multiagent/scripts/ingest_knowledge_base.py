import os
import re
import time
from pathlib import Path
from datetime import datetime

import pymongo
import requests
import PyPDF2
from dotenv import load_dotenv
from sentence_transformers import SentenceTransformer

BASE_DIR = Path(__file__).resolve().parent.parent

# =========================
# LOAD ENV
# =========================
load_dotenv()
MONGO_URI = os.getenv("MONGODB_ATLAS_URI")

# =========================
# FOLDER CONFIG
# =========================
FOLDER_CONFIG = {
    "ATLAS": ("MITRE_ATLAS", "ai_attack_framework"),
    "cisa": ("CISA", "guideline"),
    "ieee": ("IEEE", "paper"),
    "intel_tdx": ("Intel_TDX", "specification"),
    "owasp": ("OWASP", "cheatsheet"),
}

# =========================
# MAIN CLASS
# =========================
class KnowledgeBaseIngestion:

    def __init__(self, chunk_size=1200):
        print("🔌 Connecting to MongoDB...")
        self.client = pymongo.MongoClient(MONGO_URI)
        self.db = self.client["multiagentllm"]
        self.collection = self.db["security_knowledge_base"]

        print("🧠 Loading embedding model...")
        self.model = SentenceTransformer("all-MiniLM-L6-v2")

        self.chunk_size = chunk_size

        # Indexes
        self.collection.create_index("folder")
        self.collection.create_index("source")

        print("✅ Ready\n")

    # =========================
    # TEXT EXTRACTION
    # =========================
    def extract_pdf(self, filepath):
        text = ""
        try:
            reader = PyPDF2.PdfReader(filepath)
            for i, page in enumerate(reader.pages):
                page_text = page.extract_text()
                if page_text:
                    text += f"\n--- Page {i+1} ---\n{page_text}"
        except Exception as e:
            print(f"⚠ PDF error: {e}")
        return text

    def extract_text_file(self, filepath):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except:
            return ""

    # =========================
    # CHUNKING (SEMANTIC)
    # =========================
    def chunk_text(self, text):
        sentences = re.split(r'(?<=[.!?]) +', text)

        chunks = []
        current = ""

        for sentence in sentences:
            if len(current) + len(sentence) < self.chunk_size:
                current += " " + sentence
            else:
                chunks.append(current.strip())
                current = sentence

        if current:
            chunks.append(current.strip())

        return chunks

    # =========================
    # EMBEDDING
    # =========================
    def embed(self, text):
        try:
            return self.model.encode(text).tolist()
        except:
            return None

    # =========================
    # CHECK DUPLICATE
    # =========================
    def already_exists(self, filename):
        return self.collection.count_documents({"filename": filename}) > 0

    # =========================
    # PROCESS FILE
    # =========================
    def process_file(self, filepath, folder_name):
        filename = os.path.basename(filepath)

        if self.already_exists(filename):
            print(f"⏭ Skipping {filename}")
            return 0

        print(f"\n📄 {filename} ({folder_name})")

        # Extract content
        if filepath.endswith(".pdf"):
            content = self.extract_pdf(filepath)
        else:
            content = self.extract_text_file(filepath)

        if not content or len(content) < 50:
            print("⚠ Empty content")
            return 0

        chunks = self.chunk_text(content)
        print(f"   → {len(chunks)} chunks")

        source, doc_type = FOLDER_CONFIG[folder_name]

        docs = []
        for i, chunk in enumerate(chunks):
            emb = self.embed(chunk)
            if not emb:
                continue

            docs.append({
                "folder": folder_name,
                "source": source,
                "doc_type": doc_type,
                "filename": filename,
                "file_type": filepath.split('.')[-1],
                "chunk_index": i,
                "total_chunks": len(chunks),
                "content": chunk,
                "embedding": emb,
                "created_at": datetime.utcnow()
            })

        if docs:
            self.collection.insert_many(docs)
            print(f"✅ Inserted {len(docs)} chunks")
            return len(docs)

        return 0

    # =========================
    # PROCESS FOLDER
    # =========================
    def process_folder(self, folder_name):
        folder_path = BASE_DIR / "knowledge_base" / folder_name

        print(f"Looking in: {folder_path}")  # 🔍 debug

        if not folder_path.exists():
            print(f"⚠ Missing folder: {folder_name}")
            return 0

        files = list(folder_path.glob("*"))
        print(f"\n📂 {folder_name} → {len(files)} files")

        total = 0
        for file in files:
            if file.suffix.lower() in [".pdf", ".txt", ".md", ".json", ".yaml"]:
                try:
                    total += self.process_file(str(file), folder_name)
                except Exception as e:
                    print(f"⚠ Error {file.name}: {e}")

        return total

    # =========================
    # RUN ALL
    # =========================
    def run(self):
        total = 0

        for folder in FOLDER_CONFIG.keys():
            total += self.process_folder(folder)

        print("\n" + "="*60)
        print(f"🎉 DONE — Total chunks added: {total}")
        print("="*60)


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    ingestion = KnowledgeBaseIngestion()
    ingestion.run()