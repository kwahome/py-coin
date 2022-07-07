# PyCoin 1: Transactions and verification

## Introduction

`PyCoin ` is a simplified cryptocurrency designed to teach the principles behind blockchains, proof of work and
consensus. It may, as a side benefit, make us crypto billionaires.

Some compromises have been made for the sake of simplicity:

1. Address format - Bitcoin addresses have a checksum at the end, so that a bitcoin wallet can  tell if you mistype 
   the recipients addresses when you are sending money. In PyCoin, your address is simply the hexadecimal 
   representation of the SHA-1 hash of your public key, so no such error detection is possible.
   
2. Smart Contracts - PyCoin has no support for either output scripts or smart contracts. 

3. Fractional Quantities - In Bitcoin, amounts are measured in Satoshi, where 1 Bitcoin is 100,000,000 Satoshi. 
   This means that you can send small fractions of a Bitcoin. In the PyCoin cryptocurrency however, 1 PyCoin is 
   the smallest unit of currency. It is impossible to send someone half a PyCoin .

4. PyCoin prioritizes simplicity and ease of implementation over flexibility or performance. For example, data is 
   transferred in `json`, rather than the efficient binary formats used by other cryptocurrencies.

PyCoin , like Ethereum, is based on addresses, not on outputs. This means there is no notion of
an unspent transaction output. Instead, transactions move funds directly from one address to
another or to itself. (Side Question: Why might you send money to yourself?)

## Code
The following Python scripts, that are enclosed in this `py-coin` directory:

- `blocks.py` - this is the Python file containing classes and functions that are concerned with a block.

- `connections.py` - Creates connections to other nodes, handles incoming connections.
  Serializes and deserializes messages from other nodes, passes them on to the Node
  
- `chain.py` - this is the Python file containing classes and functions that are concerned with the blockchain and
  its state.
  
- `hashing.py` - this is the Python file containing classes and functions that are concerned with hashing.

- `helpers.py` - this is the Python file containing various general helper classes and functions.

- `main.py` - This is the main file, by default it will create a connection to a node that we are running in a 
  data centre somewhere. It will create a key pair and try to mine a block using the public key.
  
- `mempool.py` - Maintains a list of unconfirmed transactions. Discards the lowest fee transactions if there are too 
  many unconfirmed transactions at once. Only allows one unconfirmed transaction from each sender (this is unusually 
  conservative).

- `miner.py` - Keeps trying to mine blocks using the current difficulty and the highest fee transactions in the mempool.

- `node.py` - Keeps track of the state of the node. Contains a BlockchainState and a Mempool , and also knows what other
  nodes are connected at what block they are up to. This decides what to do when incoming transactions and blocks are 
  received. This is the most interesting file if you want to see how the network works.

- `persistence.py` - Stores the blocks in a file, so the node can restart without losing everything. Does not store 
  unconfirmed transactions, since these are considered 'ephemeral' and can be recovered quickly from other nodes on 
  start up.

- `transaction.py` - this is the Python file containing the `Transaction` class as well as functions concerned with the
  creation and verification of transactions.

- `test_transaction.py` - this is a test file that contains unit tests for the transaction class.
  Use the command `python test_transaction.py` to run these unit tests.
  
## Running the code and connecting a node
1. Set up a Python environment that has a version of Python 3 installed - preferably the latest Python 3 release.
   
2. Install the package dependencies defined in `requirements.txt`. You can use the command:
> pip install -r requirements.txt

3. Ensure that env variables `MINER_ADDRESS_HASH`, `REMOTE_NODE_HOST` and `REMOTE_NODE_PORT` are configured into the
application environment. You can use a `.env` file to do this. This file will be loaded in the main function using 
functions from the `dotenv` package.

4. Once the dependencies are installed, start the `main.py` script either from the IDE or from a command line terminal
using the command `python main.py`
