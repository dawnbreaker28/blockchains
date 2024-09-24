import hashlib
from typing import List, Optional, Dict
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
import threading
import queue
import time
import random

DIFFICULTY = 0x07FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

"""
Please do not modify any of the signatures on the classes below so the
autograder can properly run your submission. You are free (and encouraged!) to
add additional data members as you implement these functions.
"""

class Output:
    """
    A transaction output.
    """

    def __init__(self, value: int, pub_key: str):
        self.value = value
        self.pub_key = pub_key

    # Serialize the output to bytes
    def to_bytes(self) -> bytes:
        return self.value.to_bytes(4, 'big', signed=False) + bytes.fromhex(self.pub_key)
    
    def __eq__(self, other):
        if isinstance(other, Output):
            return self.value == other.value and self.pub_key == other.pub_key
        return False

    def __hash__(self):
        return hash((self.value, self.pub_key))

class Input:
    """
    A transaction input. The number refers to the transaction number where the
    input was generated (see `Transaction.update_number()`).
    """

    def __init__(self, output: Output, number: str):
        self.output = output
        self.number = number

    # Serialize the output to bytes
    def to_bytes(self) -> bytes:
        return self.output.to_bytes() + bytes.fromhex(self.number)


class Transaction:
    """
    A transaction in a block. A signature is the hex-encoded string that
    represents the bytes of the signature.
    """

    def __init__(self, inputs: List[Input], outputs: List[Output], sig_hex: str):
        self.inputs = inputs
        self.outputs = outputs
        self.sig_hex = sig_hex
        self.number = None

        self.update_number()

    # Set the transaction number to be SHA256 of self.to_bytes().
    def update_number(self):
        # TODO
        transaction_bytes = bytes.fromhex(self.to_bytes()) 
        transaction_hash = hashlib.sha256(transaction_bytes).hexdigest()
        self.number = transaction_hash

    # Get the bytes of the transaction before signatures; signers need to sign
    # this value!
    def bytes_to_sign(self) -> str:
        m = b''

        for i in self.inputs:
            m += i.to_bytes()
        
        for o in self.outputs:
            m += o.to_bytes()

        return m.hex()
    
    def to_bytes(self) -> str:
        m = b''

        for i in self.inputs:
            m += i.to_bytes()
        
        for o in self.outputs:
            m += o.to_bytes()

        m += bytes.fromhex(self.sig_hex)

        return m.hex()
    
    def to_bytes_bytes(self) -> bytes:
        # Serialize the transaction including the signature
        m = b''

        for i in self.inputs:
            m += i.to_bytes()

        for o in self.outputs:
            m += o.to_bytes()

        if self.sig_hex:
            m += bytes.fromhex(self.sig_hex)

        return m
    
class Block:
    """
    A block on a blockchain. Prev is a string that contains the hex-encoded hash
    of the previous block.
    """

    def __init__(self, prev: str, tx: Transaction, nonce: Optional[str]):
        self.tx = tx
        self.nonce = nonce
        self.prev = prev
        self.pow = None

    # Find a valid nonce such that the hash below is less than the DIFFICULTY
    # constant. Record the nonce as a hex-encoded string (bytearray.hex(), see
    # Transaction.to_bytes() for an example).
    def mine(self):
        # TODO
        nonce = 0
        while True:
            nonce_bytes = nonce.to_bytes(8, byteorder='big', signed=False)
            self.nonce = nonce_bytes.hex()
            
            # compute block hash
            block_hash = self.hash()
            
            block_hash_int = int(block_hash, 16)
            
            if block_hash_int <= DIFFICULTY:
                print(f"Valid nonce found: {self.nonce}")
                print(f"Block hash: {block_hash}")
                self.pow = block_hash
                break  
            nonce += 1  
    
    # Hash the block.
    def hash(self) -> str:
        m = hashlib.sha256()

        m.update(bytes.fromhex(self.prev))
        m.update(bytes.fromhex(self.tx.to_bytes()))
        m.update(bytes.fromhex(self.nonce))

        return m.hexdigest()
    
class Blockchain:
    """
    A blockchain. This class is provided for convenience only; the autograder
    will not call this class.
    """
    
    def __init__(self, chain: List[Block], utxos: List[str]):
        self.chain = chain
        self.utxos = utxos
    
    def append(self, block: Block) -> bool:
        # TODO
        # Step 1: Verify the Previous Hash
        if self.chain:
            last_block_hash = self.chain[-1].hash()
            if block.prev != last_block_hash:
                print("Invalid previous hash.")
                return False
        else:
            # If the chain is empty, we're adding the genesis block
            pass

        # Step 2: Validate the Block's Hash and Nonce
        calculated_hash = block.hash()
        block_hash_int = int(calculated_hash, 16)
        if block_hash_int > DIFFICULTY:
            print("Block hash does not meet difficulty requirement.")
            return False

        # Step 3: Validate the Transaction
        tx = block.tx

        # 3a: Verify the transaction signature
        if not self.verify_transaction_signature(tx):
            print("Invalid transaction signature.")
            return False

        # 3b: Verify that all inputs are unspent and exist in the UTXO set
        for tx_input in tx.inputs:
            input_identifier = tx_input.number
            if input_identifier not in self.utxos:
                print(f"Input UTXO {input_identifier} is not available.")
                return False

        # 3c: Verify that the sum of inputs equals the sum of outputs
        input_value = sum([inp.output.value for inp in tx.inputs])
        output_value = sum([out.value for out in tx.outputs])

        if input_value != output_value:
            print("Input and output values do not match.")
            return False

        # Step 4: Update the UTXO Set
        # Remove spent UTXOs
        for tx_input in tx.inputs:
            self.utxos.remove(tx_input.number)

        # Add new UTXOs
        for index, tx_output in enumerate(tx.outputs):
            # UTXO identifier can be transaction number combined with output index
            utxo_identifier = f"{tx.number}:{index}"
            self.utxos.append(utxo_identifier)
            # Update the output's number for future referencing
            tx_output.number = utxo_identifier

        # Step 5: Append the Block
        self.chain.append(block)
        return True

    def verify_transaction_signature(self, tx: Transaction) -> bool:
        # Get the message to verify (transaction data to sign)
        message = tx.bytes_to_sign()

        # Get the signature in bytes
        signature = bytes.fromhex(tx.sig_hex)

        # For simplicity, assume all inputs are from the same public key
        if not tx.inputs:
            print("Transaction has no inputs.")
            return False

        # Retrieve the public key from the first input's output
        pub_key_hex = tx.inputs[0].output.pub_key
        pub_key_bytes = bytes.fromhex(pub_key_hex)

        try:
            # Create a VerifyKey object
            verify_key = VerifyKey(pub_key_bytes)

            # Verify the signature
            verify_key.verify(message, signature)

            # If no exception is raised, the signature is valid
            return True
        except BadSignatureError:
            # The signature is invalid
            return False

class Node:
    """
    All chains that the node is currently aware of.
    """
    def __init__(self):
        # We will not access this field, you are free change it if needed.
        # self.node_id = node_id
        # self.genesis_block = genesis_block
        # self.tx_pool = tx_pool
        # self.block_broadcast_queue = block_broadcast_queue
        self.chains = []

    # Create a new chain with the given genesis block. The autograder will give
    # you the genesis block.
    def new_chain(self, genesis: Block):
        # TODO
        new_chain = [genesis]
        self.chains.append(new_chain)

    # Attempt to append a block broadcast on the network; return true if it is
    # possible to add (e.g. could be a fork). Return false otherwise.
    def append(self, block: Block) -> bool:
        # TODO
        appended = False
        new_fork_chains = []

        for chain in self.chains:
            last_block = chain[-1]

            # Step 2: Verify the prev hash
            if block.prev == last_block.hash():
                # Step 1: Verify the proof-of-work
                if not self.verify_proof_of_work(block):
                    print("Invalid proof-of-work.")
                    return False

                # Step 3: Validate the transaction in the block
                if not self.validate_transaction(block.tx, chain):
                    print("Invalid transaction in the block.")
                    return False

                # Step 4: Append the block
                chain.append(block)
                appended = True
                break  # Block appended, no need to check other chains
            else:
                # Potential fork
                for index, existing_block in enumerate(chain):
                    if block.prev == existing_block.hash():
                        # Verify the block before creating a fork
                        if not self.verify_proof_of_work(block):
                            print("Invalid proof-of-work in forked block.")
                            return False
                        if not self.validate_transaction(block.tx, chain[:index+1]):
                            print("Invalid transaction in forked block.")
                            return False

                        # Step 5: Handle the fork
                        new_chain = chain[:index+1] + [block]
                        new_fork_chains.append(new_chain)
                        appended = True
                        break

        if new_fork_chains:
            self.chains.extend(new_fork_chains)

        return appended

    # Build a block on the longest chain you are currently tracking. If the
    # transaction is invalid (e.g. double spend), return None.
    def build_block(self, tx: Transaction) -> Optional[Block]:
        # TODO
        if not self.chains:
            print("No chains available.")
            return None

        # Find the longest chain
        longest_chain = max(self.chains, key=len)
        last_block = longest_chain[-1]

        # Validate the transaction according to the specified steps
        if not self.validate_transaction(tx, longest_chain):
            print("Invalid transaction.")
            return None

        # Construct the block
        new_block = Block(prev=last_block.hash(), tx=tx, nonce=None)

        # Mine the block (find a valid nonce)
        new_block.mine()

        # Append the block to the longest chain
        longest_chain.append(new_block)

        return new_block
    
    def validate_transaction(self, tx: Transaction, chain: List[Block]) -> bool:
        # Step 1(a): Verify that the transaction's number hash is correct
        expected_number = hashlib.sha256(tx.to_bytes_bytes()).hexdigest()
        if tx.number != expected_number:
            print("Transaction number hash is incorrect.")
            return False

        # Build UTXO set from the chain
        utxos = self.build_utxo_set(chain)

        # Step 1(b): Validate each input
        if not tx.inputs:
            print("Transaction has no inputs.")
            return False

        # Collect public keys from inputs to verify they are the same
        input_pub_keys = set()

        for tx_input in tx.inputs:
            input_id = tx_input.output.to_bytes().hex()

            # (i) Check if the input exists on the blockchain
            if input_id not in utxos:
                print(f"Input {input_id} does not exist or has been spent.")
                return False

            # (ii) Check if the output actually exists in the named transaction
            # This is ensured by the UTXO set construction

            # (iii) Check if all inputs have the same public key
            output = utxos[input_id]
            input_pub_keys.add(output.pub_key)

        if len(input_pub_keys) != 1:
            print("All inputs must have the same public key.")
            return False

        # (iv) Verify the public key can verify the signature
        if not self.verify_transaction_signature(tx, input_pub_keys.pop()):
            print("Invalid transaction signature.")
            return False

        # Step 1(c): Check that the sum of input and output values are equal
        input_value = sum([utxos[tx_input.output.to_bytes().hex()].value for tx_input in tx.inputs])
        output_value = sum([output.value for output in tx.outputs])

        if input_value != output_value:
            print("Input and output values do not match.")
            return False

        return True
    
    def build_utxo_set(self, chain: List[Block]) -> Dict[str, Output]:
        utxos = {}
        spent_outputs = set()

        for block in chain:
            tx = block.tx

            # Remove spent outputs
            for tx_input in tx.inputs:
                spent_outputs.add(tx_input.output)
                utxos.pop(tx_input.output.to_bytes().hex(), None)

            # Add new outputs
            for output in tx.outputs:
                utxo_id = output.to_bytes().hex()
                if output not in spent_outputs:
                    utxos[utxo_id] = output

        return utxos

    def verify_transaction_signature(self, tx: Transaction, pub_key_hex: str) -> bool:
        # Get the message to verify (transaction data)
        message_hex = tx.bytes_to_sign()
        # Convert the hex string message back to bytes
        message_bytes = bytes.fromhex(message_hex)

        signature = bytes.fromhex(tx.sig_hex)

        pub_key_bytes = bytes.fromhex(pub_key_hex)

        try:
            verify_key = VerifyKey(pub_key_bytes)
            verify_key.verify(message_bytes, signature)
            return True
        except BadSignatureError:
            return False
    
    def verify_proof_of_work(self, block: Block) -> bool:
        calculated_hash = block.hash()
        block_hash_int = int(calculated_hash, 16)
        return block_hash_int <= DIFFICULTY


# Build and sign a transaction with the given inputs and outputs. If it is
# impossible to build a valid transaction given the inputs and outputs, you
# should return None. Do not verify that the inputs are unspent.
def build_transaction(inputs: List[Input], outputs: List[Output], signing_key: SigningKey) -> Optional[Transaction]:

    # get signing pub key
    signing_pub_key = signing_key.verify_key.encode().hex()

    # verify signing_key align with output.pub_key 
    for tx_input in inputs:
        if signing_pub_key != tx_input.output.pub_key:
            print("Signing key didn't match。")
            return None
        
    # Used for checking duplication
    seen_utxos = {tx_input.number for tx_input in inputs} 
    if len(seen_utxos) != len(inputs):
        print(f"Duplication in inputs")
        return None
    
    # Create a transaction without a signature
    temp_tx = Transaction(inputs=inputs, outputs=outputs, sig_hex='')

    # Ensure that input and output values are equal
    input_value = sum([tx_input.output.value for tx_input in inputs])
    output_value = sum([output.value for output in outputs])

    if input_value != output_value:
        print("Input and output values do not match.")
        return None

    # Get the message to sign (transaction data)
    message = temp_tx.bytes_to_sign()

    # Sign the transaction
    signature = signing_key.sign(bytes.fromhex(message)).signature
    temp_tx.sig_hex = signature.hex()

    # Now update the transaction number with the signature included
    temp_tx.update_number()

    return temp_tx
