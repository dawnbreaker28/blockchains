import threading
import hashlib
import json
import time
import random
import queue

# Transaction structure as JSON
def create_transaction(tx_number, inputs, outputs, sig):
    transaction = {
        "number": tx_number,
        "input": inputs,
        "output": outputs,
        "sig": sig
    }
    return transaction

# Block structure as JSON
def create_block(transaction, nonce, prev, pow_hash):
    block = {
        "tx": transaction,
        "nonce": nonce,
        "prev": prev,
        "pow": pow_hash
    }
    return block

# Compute SHA256 hash
def compute_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Proof-of-work simulation
def proof_of_work(block_data, difficulty="07FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"):
    nonce = 0
    while True:
        pow_data = f"{block_data}{nonce}"
        pow_hash = compute_hash(pow_data)
        if pow_hash <= difficulty:
            return nonce, pow_hash
        nonce += 1

# Node simulation
class Node(threading.Thread):
    def __init__(self, node_id, transaction_pool, blockchain, lock):
        super().__init__()
        self.node_id = node_id
        self.transaction_pool = transaction_pool
        self.blockchain = blockchain
        self.lock = lock

    def run(self):
        while not self.transaction_pool.empty():
            tx = self.transaction_pool.get()
            block_data = json.dumps(tx)
            nonce, pow_hash = proof_of_work(block_data)
            with self.lock:
                prev_block_hash = self.blockchain[-1]['pow'] if self.blockchain else '0'*64
                block = create_block(tx, hex(nonce), prev_block_hash, pow_hash)
                self.blockchain.append(block)
            print(f"Node {self.node_id} mined block with nonce {nonce}")

# Driver program
def main():
    # Sample transaction pool (use more realistic data for full implementation)
    transactions = queue.Queue()
    transactions.put(create_transaction("1", [], [{"value": 50, "pubkey": "Alice"}], ""))
    transactions.put(create_transaction("2", [{"number": "1", "output": {"value": 50, "pubkey": "Alice"}}], [{"value": 50, "pubkey": "Bob"}], "Alice's Signature"))
    
    blockchain = []
    lock = threading.Lock()

    # Start 8 nodes
    nodes = [Node(i, transactions, blockchain, lock) for i in range(8)]
    for node in nodes:
        node.start()
    
    for node in nodes:
        node.join()

    # Write blockchain to file
    with open('blockchain.json', 'w') as f:
        json.dump(blockchain, f, indent=2)

if __name__ == "__main__":
    main()
