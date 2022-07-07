import time
from typing import List

from pykka import ThreadingActor

from block import mine_block
from constants import (
    BLOCK_ID_SIZE_IN_BYTES,
    MAX_BLOCK_TRANSACTIONS,
    MINE_BLOCK_DELAY_IN_SECONDS,
    MINE_BLOCK_TIMEOUT_IN_SECONDS
)
from node import NodeStateSummary
from transaction import Transaction


class Miner(ThreadingActor):
    def __init__(self, node, address):
        super().__init__()
        self.node = node
        self.address = address

    def mine_block(self):
        print("\nAbout to mine block")
        while True:
            summary: NodeStateSummary = self.node.state_summary().get()
            difficulty = self.node.current_difficulty().get()
            transactions: List[Transaction] = self.node.get_transactions().get()
            transactions.sort(key=lambda t: t.fee, reverse=True)
            transactions = transactions[:MAX_BLOCK_TRANSACTIONS]

            time.sleep(MINE_BLOCK_DELAY_IN_SECONDS)

            print(f"Attempting mining with difficulty: '{difficulty}'")
            block = mine_block(
                summary.block_id or bytes(BLOCK_ID_SIZE_IN_BYTES),
                summary.height,
                self.address,
                transactions,
                int(time.time()),
                difficulty,
                time.time() + MINE_BLOCK_TIMEOUT_IN_SECONDS
            )
            if block is not None:
                break
        print(f"Mined block: '{block.block_id.hex()}'")
        self.node.received_blocks([block])

    def start_mining(self):
        while True:
            self.mine_block()
