# blockchain/block.py

from blockchain.transaction import Transaction
from utils.crypto import sha256
import config.constants

class Block:
    def __init__(self, prev_hash: str, transaction: Transaction, nonce: int = 0):
        self.prev_hash = prev_hash
        self.transaction = transaction
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        data = bytes.fromhex(self.prev_hash) + self.transaction.to_bytes() + self.nonce.to_bytes(8, 'big')
        return sha256(data)

    def mine(self):
        self.nonce = 0
        while int(self.calculate_hash(), 16) > constants.DIFFICULTY:
            self.nonce += 1
            if self.nonce >= constants.MAX_NONCE:
                raise Exception("Failed to find a valid nonce")
        self.hash = self.calculate_hash()
