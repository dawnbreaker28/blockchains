# blockchain/blockchain.py

from blockchain.block import Block
from typing import List

class Blockchain:
    def __init__(self):
        self.chain: List[Block] = []

    def add_block(self, block: Block) -> bool:
        if self.validate_block(block):
            self.chain.append(block)
            return True
        return False

    def validate_block(self, block: Block) -> bool:
        # Implement block validation logic, including proof-of-work and transaction verification
        pass

    def get_last_block(self) -> Block:
        return self.chain[-1] if self.chain else None
