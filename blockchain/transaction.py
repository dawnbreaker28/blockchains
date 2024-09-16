# blockchain/transaction.py

from typing import List
from dataclasses import dataclass
from utils.crypto import sha256

@dataclass
class Output:
    value: int
    pubkey: str  # Receiver's public key in hex

    def to_bytes(self) -> bytes:
        return self.value.to_bytes(8, 'big') + bytes.fromhex(self.pubkey)

@dataclass
class Input:
    tx_number: str  # Transaction number (hash) being referenced
    output_index: int  # Index of the output in the referenced transaction

    def to_bytes(self) -> bytes:
        return bytes.fromhex(self.tx_number) + self.output_index.to_bytes(4, 'big')

class Transaction:
    def __init__(self, inputs: List[Input], outputs: List[Output], sigs: List[str]):
        self.inputs = inputs
        self.outputs = outputs
        self.sigs = sigs  # Signatures corresponding to inputs
        self.number = self.calculate_tx_number()

    def to_bytes(self, include_sigs: bool = True) -> bytes:
        data = b''
        for input in self.inputs:
            data += input.to_bytes()
        for output in self.outputs:
            data += output.to_bytes()
        if include_sigs:
            for sig in self.sigs:
                data += bytes.fromhex(sig)
        return data

    def calculate_tx_number(self) -> str:
        tx_hash = sha256(self.to_bytes(include_sigs=False))
        return tx_hash

    def verify(self) -> bool:
        # Implement transaction verification logic here
        pass
