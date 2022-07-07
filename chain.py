from block import Block
from copy import deepcopy
from constants import (
    BLOCK_ID_SIZE_IN_BYTES,
    BLOCK_MINING_TIME_IN_SECONDS,
    BLOCK_MINING_WINDOW_SIZE,
    DEFAULT_DIFFICULTY
)
from helpers import int_to_bytes
from state import UserState
from typing import List, Mapping


class BlockchainState:
    """
    BlockChainState class to keep track of the longest chain.
    """

    def __init__(
        self,
        longest_chain: List[Block],
        user_states: Mapping[bytes, UserState],
        total_difficulty: int
    ):
        """
        Class constructor.

        :param longest_chain: A list of Blocks
        :param user_states: A map bytes to UserState
        :param total_difficulty: An integer representing the sum of
        the difficulties of all the blocks in the longest chain
        """
        self.longest_chain = longest_chain
        self.user_states = user_states
        self.total_difficulty = total_difficulty

    def calculate_difficulty(self) -> int:
        """
        Like app proof-of-work based cryptocurrencies, we want to
        adjust the difficulty based on the rate at which blocks are
        produced. The difficulty is adjusted in order to make the
        average time between blocks as close as possible to 2 mins.

        We do this by looking at the time to mine the last 10 blocks.
        If the length of the longest chain is 10 or fewer blocks,
        then the default difficulty of 1000 should be returned.
        Otherwise, we first calculate the sum of the difficulties in
        the previous 10 blocks (total_difficulty_for_period) then
        calculate the total time needed to mine the previous 10 blocks
        (total_time_for_period). We then return a value calculated as:

            total_difficulty_for_period * 120 // total_time_for_period

        This calculation means that assuming the hash rate stays about
        the same, then each block should take about 2 minutes to mine.

        :return: integer representing the difficulty of mining a block
        """
        difficulty = DEFAULT_DIFFICULTY

        if len(self.longest_chain) > BLOCK_MINING_WINDOW_SIZE:
            total_difficulty_for_period = self._calculate_total_difficulty_for_period()

            total_time_for_period = self._calculate_total_time_for_period() or 1  # to avoid ZeroDivisionError

            difficulty = (total_difficulty_for_period // total_time_for_period) * BLOCK_MINING_TIME_IN_SECONDS

        return difficulty

    def verify_and_apply_block(self, block: Block):
        """
        This method takes a single argument, a Block. If this block is
        not a valid addition to the longest chain, it should raise an
        exception.

        The following checks must be done to determine this:
        - The height of the block is the length of the longest chain
        - If the longest chain is empty then the previous fields of
        the block should be 0x00...00, otherwise it should be the
        block_id of the last block in the chain
        - if the longest chain is not empty then the timestamp of the
        new block should be at least the timestamp of the most recent
        block
        - The verify_and_get_changes method succeeds (i.e does not
        raise an exception) when provided the difficulty calculated
        by the calculate_difficulty method and the current user_states
        dictionary.

        :param block: A block
        :return:
        """
        # 1: running checks
        self._verify_new_block_height(new_block=block)
        self._verify_new_block_valid_for_longest_chain(new_block=block)

        updated_user_states = block.verify_and_get_changes(
            difficulty=self.calculate_difficulty(),
            previous_user_states=self.user_states
        )

        # 2: applying the new block
        self.longest_chain.append(block)
        self.total_difficulty += block.difficulty
        self.user_states = updated_user_states

    def undo_last_block(self):
        """
        This method takes no argument and return no value. It should
        revert the last block from the end of the chain.

        To do this, we must do the following:
        - the final block should be removed from the end of the
        longest_chain
        - total_difficulty should be decreased by the difficulty of
        the block that was removed
        - the user_states dictionary should be updated with the
        results of the get_changes_for_undo method
        :return:
        """
        latest_block_in_chain = self.longest_chain.pop()
        self.total_difficulty -= latest_block_in_chain.difficulty
        self.user_states = latest_block_in_chain.get_changes_for_undo(self.user_states)

    def _calculate_total_difficulty_for_period(self) -> int:
        # sum of the difficulties of the last 10 blocks
        return sum(block.difficulty for block in self.longest_chain[-BLOCK_MINING_WINDOW_SIZE:])

    def _calculate_total_time_for_period(self) -> int:
        # the difference between the timestamp of the previous block in the chain
        # and the block which is 11 blocks away from it to give us a window
        # size of 10
        return self.longest_chain[-1].timestamp - self.longest_chain[-(BLOCK_MINING_WINDOW_SIZE + 1)].timestamp

    def _verify_new_block_height(self, new_block: Block):
        assert new_block.height == len(self.longest_chain), f"Invalid block height."

    def _verify_new_block_valid_for_longest_chain(self, new_block: Block):
        if len(self.longest_chain) == 0:
            # previous field in the block represents the block id of the block before
            # this one in the block chain. It is zero for the first block.
            assert new_block.previous == int_to_bytes(0, length=BLOCK_ID_SIZE_IN_BYTES), \
                f"Invalid value for block previous field."
        else:
            last_block_in_chain = self.longest_chain[-1]
            assert new_block.previous == last_block_in_chain.block_id, f"Invalid value for block previous field."
            assert new_block.timestamp >= last_block_in_chain.timestamp, f"Invalid value for block timestamp."


def verify_reorg(
    old_state: BlockchainState,
    new_branch: List[Block]
) -> BlockchainState:
    """
    This function attempts to calculate a new blockchain state that
    corresponds to the new longest chain. It raises an exception if
    the new chain is invalid.

    To do this, we should first make a copy of the old_state, that is
    henceforth referred to as the new_state. This is important because
    we do not want to change the old_state at all in case it turns out
    that the proposed chain is invalid. We then keep calling
    undo_last_block until we reach the block height of the first block
    in the new_branch. Then we call verify_and_apply_block with each of
    the blocks in the new branch.

    Finally, we check that the new_state has a higher total difficulty
    than the old state. If it does, then the new chain is accepted and
    we return new_state. An exception is raised if it is the same or
    lower.

    :param old_state:
    :param new_branch:
    :return:
    """
    new_state = BlockchainState(
        longest_chain=deepcopy(old_state.longest_chain),
        user_states=deepcopy(old_state.user_states),
        total_difficulty=deepcopy(old_state.total_difficulty)
    )

    exit_condition = False

    while not exit_condition:
        new_state.undo_last_block()

        # we want to undo until we reach the height of the new branch
        # we then undo one more block which is the block in both branches
        # that has the same height
        if new_state.longest_chain[-1].height == new_branch[0].height - 1:
            exit_condition = True

    for block in new_branch:
        new_state.verify_and_apply_block(block=block)

    if new_state.total_difficulty <= old_state.total_difficulty:
        raise Exception("The total difficulty of the new state is less than or equal to the old state")

    return new_state
