import os
import json
import time
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

WALLET_KEY_FILE = 'wallet.pem'

class Wallet:
    def __init__(self):
        self.private_key = self.load_private_key()
        self.public_key = self.private_key.public_key()
        self.address = self.create_address()

    def load_private_key(self):
        """
        Loads the private key from the PEM file or generates a new key if none exists.
        """
        if not os.path.exists(WALLET_KEY_FILE):
            return self.generate_wallet_key()
        with open(WALLET_KEY_FILE, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    def generate_wallet_key(self):
        """
        Generates a new private key and saves it in the wallet.pem file.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(WALLET_KEY_FILE, 'wb') as f:
            f.write(pem)
        print("Wallet created and saved in wallet.pem")
        return private_key

    def create_address(self):
        """
        Creates a unique address using the public key and SHA256 hashing.
        """
        pub_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return hashlib.sha256(pub_key_bytes).hexdigest()

    def sign_transaction(self, transaction):
        """
        Signs a transaction using the wallet's private key.
        """
        transaction.sign_transaction(self.private_key)

    def validate_balance(self, transaction, block_folder="processed_blocks"):
        """
        Validates the wallet's balance before sending a transaction.
        """
        balance = self.get_balance(block_folder)
        if balance < transaction['amount']:
            raise Exception('Insufficient funds')
        return True

    def get_balance(self, blockchain_path="processed_blocks"):
        """
        Calculate and return the balance of the wallet by scanning the blockchain.
        """
        if not os.path.exists(blockchain_path):
            print(f"Blockchain path '{blockchain_path}' does not exist. Please ensure the blockchain has been processed.")
            return 0

        balance = 0
        for block_file in os.listdir(blockchain_path):
            with open(os.path.join(blockchain_path, block_file), 'r') as f:
                block_data = json.load(f)
                for tx in block_data['body']:
                    if tx['from'] == self.address:
                        balance -= tx['amount']
                    if tx['to'] == self.address:
                        balance += tx['amount']
        return balance


def create_transaction(private_key, from_address, to_address, amount, pending_folder="pending_transactions"):
    transaction = {
        'timestamp': time.time(),
        'from': from_address,
        'to': to_address,
        'amount': amount
    }

    # Sign the transaction using the private key
    signature = private_key.sign(
        json.dumps(transaction, sort_keys=True).encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    transaction['signature'] = signature.hex()

    # Save transaction to the pending folder
    tx_hash_hex = hashlib.sha256(json.dumps(transaction, sort_keys=True).encode()).hexdigest()
    with open(f'{pending_folder}/{tx_hash_hex}.json', 'w') as f:
        json.dump(transaction, f)

    print(f"Transaction created and saved as {tx_hash_hex}.json")


def verify_transaction_signature(transaction, public_key):
    """
    Verifies the signature of a transaction using the public key.
    """
    try:
        tx_content = {
            'timestamp': transaction['timestamp'],
            'from': transaction['from'],
            'to': transaction['to'],
            'amount': transaction['amount']
        }
        signature = bytes.fromhex(transaction['signature'])
        public_key.verify(
            signature,
            json.dumps(tx_content, sort_keys=True).encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False


# Wallet functionality
if __name__ == "__main__":
    wallet = Wallet()
    wallet_address = wallet.address
    print(f"Your wallet address: {wallet_address}")

    while True:
        print("\nOptions:\n1. Check balance\n2. Send transaction\n3. Check another wallet balance\n4. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            balance = wallet.get_balance()
            print(f"Your balance: {balance}")

        elif choice == '2':
            to_address = input("Enter the recipient's wallet address: ")
            amount = float(input("Enter amount to send: "))
            wallet.validate_balance({'amount': amount})
            create_transaction(wallet.private_key, wallet.address, to_address, amount)

        elif choice == '3':
            other_wallet = input("Enter another wallet address: ")
            balance = wallet.get_balance()
            print(f"Balance of wallet {other_wallet}: {balance}")

        elif choice == '4':
            break

        else:
            print("Invalid choice.")
