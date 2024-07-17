import hashlib
import json
from time import time
from uuid import uuid4
from urllib.parse import urlparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature, decode_dss_signature
)

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.nodes = set()

        # Create the genesis block
        self.new_block(previous_hash='1', proof=100)

    def register_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof']):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    def new_block(self, proof, previous_hash=None):
    
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount, signature):
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
            'signature': signature.hex(),  # Convert bytes to hex string
        })

        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
    
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_proof):
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof):

        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"


class Transaction:
    def __init__(self, sender_private_key, recipient, amount):
        self.sender_private_key = sender_private_key
        self.sender_public_key = sender_private_key.public_key()
        self.recipient = recipient
        self.amount = amount

    def sign_transaction(self):
    
        transaction_data = f'{self.sender_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).hex()}{self.recipient.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).hex()}{self.amount}'.encode()
        signature = self.sender_private_key.sign(
            transaction_data,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    @staticmethod
    def verify_transaction(sender_public_key, recipient, amount, signature):
  
        transaction_data = f'{sender_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).hex()}{recipient.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).hex()}{amount}'.encode()
        try:
            sender_public_key.verify(
                signature,
                transaction_data,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except:
            return False


# Helper function to create new ECDSA keys
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


# Helper function to display the blockchain data
def print_blockchain(blockchain):
    print("Blockchain:")
    for block in blockchain.chain:
        print(json.dumps(block, indent=4))

# Example usage of the Blockchain and Transaction classes
if __name__ == '__main__':
    # Generate keys for two users
    private_key1, public_key1 = generate_keys()
    private_key2, public_key2 = generate_keys()

    # Instantiate the Blockchain
    blockchain = Blockchain()

    # Create a transaction
    transaction1 = Transaction(private_key1, public_key2, 50)
    signature1 = transaction1.sign_transaction()
    blockchain.new_transaction(
        public_key1.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).hex(),
        public_key2.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).hex(),
        50, signature1
    )

    # Mine a new block
    last_proof = blockchain.last_block['proof']
    proof = blockchain.proof_of_work(last_proof)
    blockchain.new_block(proof)

    # Create another transaction
    transaction2 = Transaction(private_key2, public_key1, 30)
    signature2 = transaction2.sign_transaction()
    blockchain.new_transaction(
        public_key2.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).hex(),
        public_key1.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).hex(),
        30, signature2
    )

    # Mine another block
    last_proof = blockchain.last_block['proof']
    proof = blockchain.proof_of_work(last_proof)
    blockchain.new_block(proof)

    # Print the blockchain
    print_blockchain(blockchain)
