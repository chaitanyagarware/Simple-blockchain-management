import json
import hashlib
import time
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

class Transaction:
    def __init__(self, from_address, to_address, amount, signature=None):
        self.timestamp = int(time.time())  # Add the timestamp attribute here
        self.from_address = from_address  # Correct attribute name
        self.to_address = to_address  # Correct attribute name
        self.amount = amount
        self.signature = signature

    def calculate_hash(self):
        """
        Calculates the hash of the transaction, excluding the signature.
        """
        transaction_data = f"{self.from_address}{self.to_address}{self.amount}{self.timestamp}"
        return hashlib.sha256(transaction_data.encode()).hexdigest()

    def sign_transaction(self, private_key):
        """
        Signs the transaction using the sender's private key.
        """
        transaction_hash = self.calculate_hash()
        self.signature = private_key.sign(
            transaction_hash.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

    def is_valid(self, public_key):
        """
        Verifies if the transaction is valid by checking its signature.
        """
        if not self.signature:
            return False

        try:
            public_key.verify(
                self.signature,
                self.calculate_hash().encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Invalid transaction signature: {e}")
            return False

    def has_required_fields(self):
        """
        Ensures the transaction contains all the required fields.
        """
        return all([self.from_address, self.to_address, self.amount, self.signature])

    # Returns the transaction as a json object
    def to_json(self):
        return {
            "timestamp": self.timestamp,  # Now this is properly initialized
            "from": self.from_address,  # Correct attribute name
            "to": self.to_address,  # Correct attribute name
            "amount": self.amount,
            "signature": self.signature
        }

    # Saves the transaction as .json in the pending_transactions folder
    def save_to_file(self, pending_folder):
        if not os.path.exists(pending_folder):
            os.makedirs(pending_folder)

        json_data = json.dumps(self.to_json(), separators=(',', ':'))
        hash_object = hashlib.sha256(json_data.encode())
        file_name = hash_object.hexdigest() + ".json"
        file_path = os.path.join(pending_folder, file_name)
        with open(file_path, "w") as f:
            f.write(json_data)
        return file_name


# Gets input from user and saves to folder
def get_transaction_from_user(pending_folder):
    from_addr = input("Enter from address: ")
    to_addr = input("Enter to address: ")
    amount = int(input("Enter amount: "))
    transaction = Transaction(from_addr, to_addr, amount)
    file_name = transaction.save_to_file(pending_folder)
    print(f"Transaction saved to {file_name} in pending_transactions folder")


if __name__ == "__main__":
    pending_folder = "pending_transactions"
    
    get_transaction_from_user(pending_folder)
