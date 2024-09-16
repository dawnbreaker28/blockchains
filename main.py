# main.py

from nodes.node import Node
from network.network import Network
import threading
import time
import random

def read_transactions(file_path: str):
    # Implement logic to read transactions from the file
    pass

def main():
    num_nodes = 8
    network = Network()
    nodes = []

    # Create and start nodes
    for i in range(num_nodes):
        node = Node(node_id=i, network=network)
        network.register_node(node)
        nodes.append(node)
        node.start()

    # Read transactions and add them to the global unverified pool
    transactions = read_transactions('transactions.txt')
    for tx in transactions:
        # Add transaction to the unverified pool with random delay
        # Implement logic to distribute transactions to nodes
        time.sleep(random.uniform(0, 1))

    # Wait for nodes to finish processing
    # Implement logic to determine when to stop the simulation

    # Terminate node threads gracefully
    for node in nodes:
        node.join()

    # After termination, write each node's blockchain to a file
    for node in nodes:
        blockchain_file = f'node_{node.node_id}_blockchain.json'
        # Implement logic to write blockchain to file

if __name__ == '__main__':
    main()
