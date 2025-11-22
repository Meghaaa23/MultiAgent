from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv(dotenv_path=".env")  # explicitly point to file
uri = os.getenv("MONGODB_ATLAS_URI")

print("Connecting to:", uri)
client = MongoClient(uri)
print("Ping:", client.admin.command("ping"))
print("Databases:", client.list_database_names())
