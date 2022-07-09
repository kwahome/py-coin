import copy
import random
import sys

from constants import (
    ADDRESS_HASH_SIZE,
    DIFFICULTY_SIZE_IN_BYTES,
    NONCE_INCREMENT,
    NONCE_LOWER_BOUND,
    NONCE_UPPER_BOUND,
    NONCE_SIZE_IN_BYTES,
    MINE_BLOCK_TIMEOUT_IN_SECONDS,
    TIMESTAMP_SIZE_IN_BYTES
)
from hashing import HashAlgorithm, get_hash, get_intermediate_hash
from helpers import ByteOrder, int_from_bytes, int_to_bytes
from state import UserState
from time import time
from transaction import Transaction
from typing import List, Mapping


class BlockConstants:
    """
    Block constants
    """
    BLOCK_HASH_SIZE: int = 256
    # block reward equals to 10000 Pycoins
    BLOCK_REWARD: int = 10_000
    MAX_TRANSACTIONS: int = 25


class Block:
    """
    Block class
    """

    def __init__(
        self,
        previous: bytes,
        height: int,
        miner: bytes,
        transactions: List[Transaction],
        timestamp: int,
        difficulty: int,
        block_id: bytes,
        nonce: int
    ):
        """
        Class constructor.

        :param previous: The block id of the block before this one in the block chain.
        This is zero for the first block.
        :param height: The number of blocks before this one in the block chain.
        The first block will have a height of 0.
        :param miner: The public key hash of the user responsible for mining this block.
        :param transactions: A list containing the transactions contained within this block.
        :param timestamp: An integer between 0 and 2^64 - 1, the number of seconds since
        1st January 1970. This is often called Unix Time.
        :param difficulty: An integer between 1 and 2^128 - 1 indicating difficulty of the
        proof of work needed to mine this block.
        :param block_id:  A 32 byte hash of the block.
        :param nonce: An integer between 0 and 2^64 - 1.
        """
        self.previous = previous
        self.height = height
        self.miner = miner
        self.transactions = transactions
        self.timestamp = timestamp
        self.difficulty = difficulty
        self.block_id = block_id
        self.nonce = nonce

    def verify_and_get_changes(
        self,
        difficulty: int,
        previous_user_states: Mapping[bytes, UserState]
    ) -> Mapping[bytes, UserState]:
        """
        A method that verifies a block.

        :param difficulty: The expected difficulty for this block.
        :param previous_user_states: A map from bytes to UserState .
        The state of all the users before this block.
        :return: Mapping[bytes, UserState]
        """
        # Step 1: verify
        self._verify_difficulty(difficulty)
        self._verify_block_id(difficulty)
        self._verify_proof_of_work(difficulty)
        self._verify_miner_hash()
        self._verify_transactions_count()

        # Step 2: update

        # we don't want mutation of the passed down state object
        # so we deep copy to create a new one
        # this is expected to have performance implications for
        # large objects
        user_states = copy.deepcopy(previous_user_states)
        self._update_states(user_states)
        return user_states

    def get_changes_for_undo(
        self,
        user_states_after: Mapping[bytes, UserState]
    ) -> Mapping[bytes, UserState]:
        """
        A method that can be thought of as the reverse of the verify_and_get_changes
        method. In this method, we iterate through the list of transactions in a
        similar manner to the verify_and_get_changes method except that the balances
        of the senders should be increased and the balances of the recipients should
        be decreased. The mining reward (and the transaction fees) are to be
        subtracted from this block.

        There is no need to perform any verification.

        :param user_states_after: A map from bytes to UserStates
        :return: A map from bytes to UserStates
        """
        # we don't want mutation of the passed down state object
        # so we deep copy to create a new one
        # this is expected to have performance implications for
        # large objects
        user_states = copy.deepcopy(user_states_after)
        self._reverse_states(user_states)
        return user_states

    def _update_states(self, user_states: Mapping[bytes, UserState]):
        mining_proceeds = BlockConstants.BLOCK_REWARD

        for transaction in self.transactions:
            # sender state has to exist
            sender_state = user_states[transaction.sender_hash]

            # verify transaction
            transaction.verify(sender_state.balance, sender_state.nonce)

            # debit the sender's state
            sender_state.balance -= transaction.amount
            sender_state.nonce = transaction.nonce

            # receiver state
            # credit the recipient's state
            receiver_state = self._get_or_default_state(user_states, transaction.recipient_hash)
            receiver_state.balance += (transaction.amount - transaction.fee)

            # miner gets the fee
            mining_proceeds += transaction.fee

        # update the miner's total proceeds from this block
        miner_state = self._get_or_default_state(user_states, self.miner)
        miner_state.balance += mining_proceeds

    def _reverse_states(self, user_states: Mapping[bytes, UserState]):
        mining_proceeds = BlockConstants.BLOCK_REWARD

        for transaction in self.transactions:
            sender_state = user_states[transaction.sender_hash]

            # credit the sender's state
            sender_state.balance += transaction.amount
            sender_state.nonce -= NONCE_INCREMENT

            # receiver state
            # debit the recipient's state
            receiver_state = user_states[transaction.recipient_hash]
            receiver_state.balance -= (transaction.amount - transaction.fee)

            mining_proceeds += transaction.fee

        # subtract the total proceeds from this block from the the miner's state
        miner_state = user_states[self.miner]
        miner_state.balance -= mining_proceeds

    @staticmethod
    def _get_or_default_state(states: Mapping[bytes, UserState], user_id: bytes):
        user_state = states[user_id] = states.get(user_id, UserState(0, -1))
        return user_state

    def _verify_difficulty(self, difficulty: int):
        assert difficulty == self.difficulty, \
            f"The difficulty of the block does not match with the one supplied"

    def _verify_block_id(self, difficulty: int):
        calculated_block_id = get_hash(
            data=(
                self.previous,
                self.miner,
                b''.join([transaction.txid for transaction in self.transactions]),
                int_to_bytes(self.timestamp, length=TIMESTAMP_SIZE_IN_BYTES),
                int_to_bytes(difficulty, length=DIFFICULTY_SIZE_IN_BYTES),
                int_to_bytes(self.nonce, length=NONCE_SIZE_IN_BYTES),
            ),
            algorithm=HashAlgorithm.SHA256
        )

        assert calculated_block_id == self.block_id, \
            f"Invalid block id. The block id '{self.block_id.hex()}' should be a SHA256 hash of " \
            f"previous, miner hash, transaction_ids, timestamp, difficulty and nonce"

    def _verify_proof_of_work(self, difficulty: int):
        assert proof_of_work(self.block_id, difficulty, BlockConstants.BLOCK_HASH_SIZE), \
            f"Invalid proof of work."

    def _verify_transactions_count(self):
        assert len(self.transactions) <= BlockConstants.MAX_TRANSACTIONS, \
            f"The number of transactions should be at most {BlockConstants.MAX_TRANSACTIONS}."

    def _verify_miner_hash(self):
        assert sys.getsizeof(self.miner) != ADDRESS_HASH_SIZE, \
            f"Miner hash '{self.miner.hex()}' should be {ADDRESS_HASH_SIZE} bytes long"


def proof_of_work(block_id: bytes, difficulty: int, block_hash_size: int = 256) -> bool:
    # This can be considered to be a generalization of the
    # method used in the lectures (and in the competition!),
    # where we were looking for a hash with a
    # sufficient number of leading zeros.

    return int_from_bytes(block_id, byteorder=ByteOrder.BIG_ENDIAN) <= ((2 ** block_hash_size) // difficulty)


def mine_block(
    previous: bytes,
    height: int,
    miner: bytes,
    transactions: List[Transaction],
    timestamp: int,
    difficulty: int,
    cutoff_time: int = time() + MINE_BLOCK_TIMEOUT_IN_SECONDS
) -> Block:
    """
    A function that produces a block that has a block_id and verifies proof of work.

    :param previous: The block id of the block before this one in the block chain.
    This is zero for the first block.
    :param height: The number of blocks before this one in the block chain.
    The first block will have a height of 0.
    :param miner: The public key hash of the user responsible for mining this block.
    :param transactions: A list containing the transactions contained within this block.
    :param timestamp: An integer between 0 and 2^64 - 1, the number of seconds since
    1st January 1970. This is often called Unix Time.
    :param difficulty: An integer between 1 and 2^128 - 1 indicating difficulty of the
    proof of work needed to mine this block.
    :param cutoff_time: A cut off time to make the function give up mining after a
    certain timeout. This will prevent your implementation from mining a 'stale block'
    :return: Block
    """
    valid: bool = False
    nonce: int = NONCE_LOWER_BOUND
    block_id: bytes = b''

    intermediate_hash = get_intermediate_hash(
        data=(
            previous,
            miner,
            b''.join([transaction.txid for transaction in transactions]),
            int_to_bytes(timestamp, length=TIMESTAMP_SIZE_IN_BYTES),
            int_to_bytes(difficulty, length=DIFFICULTY_SIZE_IN_BYTES)
        ),
        algorithm=HashAlgorithm.SHA256
    )

    while not valid and time() < cutoff_time:
        nonce = random.randint(NONCE_LOWER_BOUND, NONCE_UPPER_BOUND)

        intermediate_hash_copy = intermediate_hash.copy()

        intermediate_hash_copy.update(int_to_bytes(nonce, length=NONCE_SIZE_IN_BYTES))

        block_id = intermediate_hash_copy.finalize()

        valid = proof_of_work(block_id, difficulty, BlockConstants.BLOCK_HASH_SIZE)

    return Block(
        previous=previous,
        height=height,
        miner=miner,
        transactions=transactions,
        timestamp=timestamp,
        difficulty=difficulty,
        block_id=block_id,
        nonce=nonce
    )
