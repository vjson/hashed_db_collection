import hashlib
from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient("mongodb+srv://main_user:Mymongouser12@rbsandbox.64mo7.mongodb.net/")
db = client['apple_diag']
collection = db['diag_0802_2023']

# Function to hash a field value
def hash_field(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

# Function to recursively access nested fields using a dictionary and return the value
# Function to recursively access nested fields, handling lists
def get_nested_value(document, field_path):
    keys = field_path.split(".")
    value = document
    for key in keys:
        if isinstance(value, list):
            # If the current level is a list, stop processing
            # or apply logic for lists (e.g., processing each element)
            return None  # Adjust logic as needed for lists
        value = value.get(key, None)
        if value is None:
            break
    return value
    
# Function to recursively set nested fields in a document
def set_nested_value(document, field_path, value):
    keys = field_path.split(".")
    current = document
    for key in keys[:-1]:
        if key not in current or not isinstance(current[key], dict):
            current[key] = {}
        current = current[key]
    current[keys[-1]] = value

# Fields to hash (supports dot notation for nested fields)
#fields_to_hash = ['hp', 'rsid', 'ht.ipAddress']
fields_to_hash = ['hp', 'rsid', 'ht.ipAddress', 'cmdLineOpts.parsed.replication.replSetName', 'cmdLineOpts.parsed.security.keyFile',  'cmdLineOpts.parsed.auditLog.path', 'cmdLineOpts.parsed.systemLog.path', 'cmdLineOpts.parsed.storage.dbPath', 'cmdLineOpts.parsed.net.bindIp','cmdLineOpts.parsed.net.tls.certificateKeyFile', 'cmdLineOpts.parsed.config', 'hostInfo.system.hostname', 'n']

# Update the collection by hashing specified fields and adding them as separate fields
def hash_and_update_collection():
    for document in collection.find():
        updated_fields = {}
        
        for field in fields_to_hash:
            value = get_nested_value(document, field)  # Get the value of the nested field
            if value:
                hashed_field_name = f"hashed_{field.replace('.', '_')}"  # Create a new field name for the hash
                hashed_value = hash_field(value)
                set_nested_value(updated_fields, hashed_field_name, hashed_value)  # Prepare the hashed field
        
        if updated_fields:
            collection.update_one({"_id": document["_id"]}, {"$set": updated_fields})  # Update the document with hashed fields

# Run the function
hash_and_update_collection()

print("Fields hashed and updated in the collection.")