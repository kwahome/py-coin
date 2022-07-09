
class UserState:
    """
    UserState class
    """

    def __init__(self, balance: int, nonce: int):
        """
        Class constructor.

        :param balance: The (on-chain) balance of the user.
        :param nonce: The most recently used nonce of the user.
        """
        self.balance = balance
        self.nonce = nonce
