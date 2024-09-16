# network/network.py

import threading
from blockchain.block import Block
from typing import Dict, List

class Network:
    def __init__(self):
        self.nodes = {}
        self.lock = threading.Lock()

    def register_node(self, node):
        with self.lock:
            self.nodes[node.node_id] = node

    def broadcast_block(self, block: Block, sender_id: int):
        with self.lock:
            for node_id, node in self.nodes.items():
                if node_id != sender_id:
                    node.handle_incoming_block(block)
