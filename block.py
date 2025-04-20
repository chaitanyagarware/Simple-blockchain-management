import json
import hashlib
import time
import os

# Creates class to represent the blockchain

class Block:
    def __init__(self, height, previous_block_hash, transactions):
        self.height = height
        self.timestamp = int(time.time())
        self.previous_block_hash = previous_block_hash
        self.body = transactions
        self.hash = self.calculate_hash()

    def add_transaction(self, transaction, public_key):
        """
        Adds a transaction to the block after validation.
        """
        if transaction.has_required_fields() and transaction.is_valid(public_key):
            self.body.append(transaction)
        else:
            raise Exception("Invalid transaction")

    # Calculates hash using SHA256 based on the header (new file name)
    def calculate_hash(self):
        header = {
            "height": self.height,
            "timestamp": self.timestamp,
            "previous_block_hash": self.previous_block_hash,
            "body_hash": self.calculate_body_hash()
        }
        header_json = json.dumps(header, separators=(',', ':'))
        hash_object = hashlib.sha256(header_json.encode())
        return hash_object.hexdigest()

    # Calculates hash using SHA256 based on body
    def calculate_body_hash(self):
        body_json = json.dumps(self.body, separators=(',', ':'))
        hash_object = hashlib.sha256(body_json.encode())
        return hash_object.hexdigest()

    # Saves the block as a json in the blocks folder
    def save_to_file(self, block_folder):
        if not os.path.exists(block_folder):
            os.makedirs(block_folder)
        
        file_name = self.hash + ".json"
        file_path = os.path.join(block_folder, file_name)
        with open(file_path, "w") as f:
            json.dump(self.to_json(), f)
        return file_name

    # Returns the file as a .json file
    def to_json(self):
        return {
            "header": {
                "height": self.height,
                "timestamp": self.timestamp,
                "previous_block_hash": self.previous_block_hash,
                "hash": self.hash
            },
            "body": self.body
        }

# Retrieves the current block height
def get_block_height(block_folder):
    if not os.path.exists(block_folder):
        os.makedirs(block_folder)
        return 0
    
    block_files = [f for f in os.listdir(block_folder) if f.endswith(".json")]
    if not block_files:
        return 0
    
    # Sort by the block height in descending order and get the highest
    block_files.sort(reverse=True)
    latest_block_file = block_files[0]
    
    with open(os.path.join(block_folder, latest_block_file), "r") as f:
        block_data = json.load(f)
        return block_data["header"]["height"] + 1

# Creates a block and moves transactions
def create_block(pending_folder, block_folder):
    if not os.path.exists(pending_folder):
        os.makedirs(pending_folder)
    
    pending_transactions = [f for f in os.listdir(pending_folder) if f.endswith(".json")]
    if not pending_transactions:
        print("No pending transactions.")
        return
    
    transactions = []
    for file in pending_transactions:
        with open(os.path.join(pending_folder, file), "r") as f:
            transaction = json.load(f)
            transactions.append(transaction)
    
    current_block_height = get_block_height(block_folder)
    previous_block_hash = "NA" if current_block_height == 0 else Block(current_block_height - 1, "", []).hash
    
    new_block = Block(current_block_height, previous_block_hash, transactions)
    new_block.save_to_file(block_folder)
    
    # Move processed transactions
    processed_folder = os.path.join(pending_folder, "processed")
    if not os.path.exists(processed_folder):
        os.makedirs(processed_folder)
    
    for file in pending_transactions:
        os.rename(os.path.join(pending_folder, file), os.path.join(processed_folder, file))

if __name__ == "__main__":
    pending_folder = "pending_transactions"
    block_folder = "blocks"

    create_block(pending_folder, block_folder)

    # Verifies a transaction's signature using the public key of the sender
    def verify_transaction(self, transaction):
        transaction_json = json.dumps(transaction.to_json()).encode('utf-8')
        h = hashlib.sha256(transaction_json).digest()
        public_key = RSA.import_key(transaction.from_addr.public_key)
        try:
            pkcs1_15.new(public_key).verify(h, transaction.signature)
            return True
        except (ValueError, TypeError):
            return False
    
    # Validate all transactions before adding to the chain
    def validate_transactions(self, transactions):
        for transaction in transactions:
            if not self.verify_transaction(transaction):
                return False
        return True
