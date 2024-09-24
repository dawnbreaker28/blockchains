import hashlib
from typing import List, Optional, Dict
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
from submission import Input, Output, Node, Block, Blockchain, Transaction, build_transaction

# Assume the classes Output, Input, Transaction, Block, Blockchain, and Node are defined as in your provided code.

def main():
    # Step 1: Create the Genesis Block
    print("Creating the Genesis Block...")

    genesis_signing_key = SigningKey.generate()
    genesis_pub_key_hex = genesis_signing_key.verify_key.encode().hex()

    genesis_output = Output(value=100, pub_key=genesis_pub_key_hex)
    genesis_tx = Transaction(inputs=[], outputs=[genesis_output], sig_hex='')
    genesis_tx.update_number()

    genesis_block = Block(prev='0' * 64, tx=genesis_tx, nonce='0' * 16)
    def genesis_block_hash(self):
        return '0' * 64
    genesis_block.hash = genesis_block_hash.__get__(genesis_block, Block)

    print("Genesis Block created.")

    # Initialize blockchain and UTXO set
    blockchain = [genesis_block]
    utxos = {}
    # Add genesis UTXO
    output_index_bytes = (0).to_bytes(4, byteorder='big')
    output_index_hex = output_index_bytes.hex()
    utxo_id = genesis_tx.number + output_index_hex
    utxos[utxo_id] = genesis_output

    # Create users
    user_keys = [SigningKey.generate() for _ in range(2)]
    user_pub_keys = [key.verify_key.encode().hex() for key in user_keys]

    # Transaction 1: Genesis user sends 100 coins to User 1
    print("\nBuilding Transaction 1...")
    input_utxo_id = utxo_id
    tx_input1 = Input(output=utxos[input_utxo_id], number=input_utxo_id)
    output1 = Output(value=100, pub_key=user_pub_keys[0])
    tx1 = build_transaction(inputs=[tx_input1], outputs=[output1], signing_key=genesis_signing_key)
    tx1.update_number()

    # Update UTXOs
    utxos.pop(input_utxo_id)
    output_index_bytes = (0).to_bytes(4, byteorder='big')
    output_index_hex = output_index_bytes.hex()
    utxo_id1 = tx1.number + output_index_hex
    utxos[utxo_id1] = output1

    # Build Block 1
    block1 = Block(prev=genesis_block.hash(), tx=tx1, nonce=None)
    block1.mine()
    blockchain.append(block1)

    # Transaction 2: User 1 sends 50 coins to User 2
    print("\nBuilding Transaction 2...")
    input_utxo_id2 = utxo_id1
    tx_input2 = Input(output=utxos[input_utxo_id2], number=input_utxo_id2)
    output2 = Output(value=50, pub_key=user_pub_keys[1])
    change_output = Output(value=50, pub_key=user_pub_keys[0])
    tx2 = build_transaction(inputs=[tx_input2], outputs=[output2, change_output], signing_key=user_keys[0])
    tx2.update_number()

    # Update UTXOs
    utxos.pop(input_utxo_id2)
    # Add new UTXOs
    for idx, output in enumerate(tx2.outputs):
        output_index_bytes = idx.to_bytes(4, byteorder='big')
        output_index_hex = output_index_bytes.hex()
        utxo_id = tx2.number + output_index_hex
        utxos[utxo_id] = output

    # Build Block 2
    block2 = Block(prev=block1.hash(), tx=tx2, nonce=None)
    block2.mine()
    blockchain.append(block2)

    # Continue with additional transactions as needed...

    # Print Blockchain
    print("\nBlockchain:")
    for idx, block in enumerate(blockchain):
        print(f"\nBlock {idx}:")
        print(f"Previous Hash: {block.prev}")
        print(f"Nonce: {block.nonce}")
        print(f"Block Hash: {block.hash()}")
        print("Transaction:")
        print(f"  Transaction Number: {block.tx.number}")
        print(f"  Inputs:")
        for tx_input in block.tx.inputs:
            print(f"    {tx_input.number}")
        print(f"  Outputs:")
        for i, tx_output in enumerate(block.tx.outputs):
            output_index_bytes = i.to_bytes(4, byteorder='big')
            output_index_hex = output_index_bytes.hex()
            utxo_id = block.tx.number + output_index_hex
            print(f"    {utxo_id} - Value: {tx_output.value}, PubKey: {tx_output.pub_key}")

    print("\nDriver program execution completed.")

if __name__ == "__main__":
    main()

