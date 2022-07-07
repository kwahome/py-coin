import sys

import tornado

from connections import run_server, remote_connection
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from dotenv import load_dotenv
from hashing import get_hash, HashAlgorithm
from helpers import getenv
from miner import Miner
from node import Node
from transaction import create_signed_transaction

# load env vars
load_dotenv()

MINER_KEY = ec.generate_private_key(ec.SECP256K1)

MINER_ADDRESS = get_hash(
    (MINER_KEY.public_key().public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo),),
    algorithm=HashAlgorithm.SHA1
)

print(f"Miner private key: {MINER_KEY}\nMiner address: {bytes.hex(MINER_ADDRESS)}")

NODE_PORT = 46030
REMOTE_NODE_HOST = getenv("REMOTE_NODE_HOST", key_error=True)
REMOTE_NODE_PORT = int(getenv("REMOTE_NODE_PORT", default=NODE_PORT))

# MINER_ADDRESS = bytes.fromhex(getenv("MINER_ADDRESS_HASH", key_error=True))  # <--- put your address here

if __name__ == "__main__":
    if len(sys.argv) == 1:
        REMOTE_NODES = [f"{REMOTE_NODE_HOST}:{REMOTE_NODE_PORT}/"]
        node = Node.start("./blocks.sqlite").proxy()
        miner = Miner.start(node, MINER_ADDRESS).proxy()

        for remote in REMOTE_NODES:
            remote_connection(node, remote)
        miner.start_mining()

        # transactions in the mempool
        transaction = create_signed_transaction(
            sender_private_key=MINER_KEY,
            recipient_hash=bytes.fromhex("0202020202020202020202020202020202020202"),
            amount=1000,
            fee=0,
            nonce=1
        )

        node.received_transactions([transaction])

        tornado.ioloop.IOLoop.current().start()
    elif sys.argv[1] == 'server':
        REMOTE_NODES = []
        node = Node.start("./blocks.sqlite").proxy()
        miner = Miner.start(node, MINER_ADDRESS).proxy()
        miner.start_mining()
        run_server(node, NODE_PORT)
    else:
        print("Unknown command")
