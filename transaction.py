import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, ECDSA
from cryptography.hazmat.primitives.serialization import load_der_public_key

from constants import ADDRESS_HASH_SIZE, NONCE_INCREMENT
from hashing import HashAlgorithm, get_hash
from helpers import is_whole_number, int_to_bytes


class TransactionConstants:
    """
    Transaction constants
    """
    MIN_AMOUNT: int = 1
    MAX_AMOUNT: int = 2 ** 64


class Transaction:
    """
    Transaction class
    """

    def __init__(
        self,
        sender_hash: bytes,
        recipient_hash: bytes,
        sender_public_key: bytes,
        amount: int,
        fee: int,
        nonce: int,
        signature: bytes,
        txid: bytes
    ):
        """
        Class constructor.

        :param sender_hash: The public key hash of the user sending the funds.
        :param recipient_hash: The public key hash of the user receiving the funds.
        :param sender_public_key: A byte array representing the public key of the
        user sending the funds.
        :param amount: The amount of funds being sent from the sender's address.
        :param fee: The amount of funds paid as a mining fee in this transaction.
        :param nonce: A 64 bit number, this should increase by 1 for each transfer
        made by the sender.
        :param signature: A signature, created by the sender, confirming that they
        consent to this transaction.
        :param txid: The transaction id, this is a hash of the other fields of the
        transaction.
        """
        self.sender_hash = sender_hash
        self.recipient_hash = recipient_hash
        self.sender_public_key = load_der_public_key(sender_public_key, default_backend())
        self.amount = amount
        self.fee = fee
        self.nonce = nonce
        self.signature = signature
        self.txid = txid

    def verify(self, sender_balance: int, sender_previous_nonce: int = -1):
        """
        A method to verify that a transaction is valid

        :param sender_balance: The (on-chain) balance of the sender of the transaction
        :param sender_previous_nonce: The nonce of the previous on-chain transaction from the sender
        of the transaction, or -1 if no such transaction exists.
        :return: None
        """
        self._verify_amount(sender_balance)
        self._verify_fee()
        self._verify_sender_hash()
        self._verify_recipient_hash()
        self._verify_nonce(sender_previous_nonce)
        self._verify_txid()
        self._verify_signature()

    def _verify_amount(self, sender_balance: int):
        assert is_whole_number(self.amount), f"Transaction amount of {self.amount} is not a whole number"

        assert self.amount > TransactionConstants.MIN_AMOUNT, \
            f"Transaction amount of {self.amount} is less than the minimum " \
            f"allowed of {TransactionConstants.MIN_AMOUNT}"

        assert self.amount <= sender_balance, \
            f"Transaction amount of {self.amount} is more than the available balance of {sender_balance}"

    def _verify_fee(self):
        assert is_whole_number(self.fee), f"Transaction fee of {self.fee} is not a whole number"

        assert self.fee >= 0, f"Transaction fee should be greater than or equal to zero"

        assert self.fee <= self.amount, \
            f"Transaction fee of {self.fee} is greater than the transaction amount of {self.amount}"

    def _verify_sender_hash(self):
        assert sys.getsizeof(self.sender_hash) != ADDRESS_HASH_SIZE, \
            f"Sender hash {self.sender_hash.hex()} should be {ADDRESS_HASH_SIZE} bytes long"

        sender_public_key_bytes = self.sender_public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        calculated_sender_hash = get_hash(
            (sender_public_key_bytes,),
            algorithm=HashAlgorithm.SHA1
        )

        assert calculated_sender_hash == self.sender_hash, \
            f"Sender hash '{self.sender_hash.hex()}' should be the SHA1 hash of sender's public key"

    def _verify_recipient_hash(self):
        assert sys.getsizeof(self.recipient_hash) != ADDRESS_HASH_SIZE, \
            f"Recipient hash '{self.recipient_hash.hex()}' should be {ADDRESS_HASH_SIZE} bytes long"

    def _verify_nonce(self, sender_previous_nonce: int):
        assert self.nonce == sender_previous_nonce + NONCE_INCREMENT, f"Invalid nonce"

    def _verify_txid(self):
        calculated_txid = get_txid_hash(
            sender_hash=self.sender_hash,
            recipient_hash=self.recipient_hash,
            sender_public_key=self.sender_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            amount=self.amount,
            fee=self.fee,
            nonce=self.nonce,
            signature=self.signature
        )

        assert calculated_txid == self.txid, \
            f"Invalid txid. txid should be a SHA256 hash of recipient_hash, amount, fee and nonce"

    def _verify_signature(self):
        try:
            self.sender_public_key.verify(
                signature=self.signature,
                data=get_signature_hash(
                    recipient_hash=self.recipient_hash,
                    amount=self.amount,
                    fee=self.fee,
                    nonce=self.nonce
                ),
                signature_algorithm=ECDSA(utils.Prehashed(algorithm=HashAlgorithm.SHA256.value))
            )
        except InvalidSignature:
            raise AssertionError(f"Signature '{self.signature.hex()}' could not be verified with the sender public key")


def get_signature_hash(recipient_hash: bytes, amount: int, fee: int, nonce: int):
    """
    A function that generates a SHA-256 hash signature

    :param recipient_hash: SHA-1 hash of the recipient's public key
    :param amount: The amount of funds transferred by this transaction
    :param fee: The amount of funds that will be paid as a mining fee by this transaction
    :param nonce: A 64 bit number, this will increase by 1 for each transfer made by the sender
    :return: a SHA-256 hash signature
    """
    return get_hash(
        data=(recipient_hash, int_to_bytes(amount), int_to_bytes(fee), int_to_bytes(nonce)),
        algorithm=HashAlgorithm.SHA256
    )


def get_txid_hash(
    sender_hash: bytes,
    recipient_hash: bytes,
    sender_public_key: bytes,
    amount: int,
    fee: int,
    nonce: int,
    signature: bytes
) -> bytes:
    """
    A function that generates a SHA-256 hash transaction id

    :param sender_hash: SHA-1 hash of the sender's public key
    :param recipient_hash: SHA-1 hash of the recipient's public key
    :param sender_public_key: The public key of the sender
    :param amount: The amount of funds transferred by this transaction
    :param fee: The amount of funds that will be paid as a mining fee by this transaction
    :param nonce: A 64 bit number, this will increase by 1 for each transfer made by the sender
    :param signature: A signature generated using the sender's private key
    :return: a SHA-256 hash transaction id
    """
    return get_hash(
        data=(
            sender_hash,
            recipient_hash,
            sender_public_key,
            int_to_bytes(amount),
            int_to_bytes(fee),
            int_to_bytes(nonce),
            signature
        ),
        algorithm=HashAlgorithm.SHA256
    )


def create_signed_transaction(
    sender_private_key: EllipticCurvePrivateKey,
    recipient_hash: bytes,
    amount: int,
    fee: int,
    nonce: int
) -> Transaction:
    """
    A function that returns a new Transaction with a valid txid and signature
    :param sender_private_key: - The EllipticCurvePrivateKey object representing the private key
    of the sender of the transaction
    :param recipient_hash: The public key hash of the recipient of the transaction
    :param amount: The amount of funds transferred by this transaction
    :param fee: The amount of funds that will be paid as a mining fee by this transaction
    :param nonce: A 64 bit number, this will increase by 1 for each transfer made by the sender
    :return: a Transaction
    """

    # obtained from the supplied private key
    sender_public_key = sender_private_key.public_key()

    sender_public_key_bytes = sender_public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # the SHA-1 hash of sender_public_key
    sender_hash = get_hash(
        data=(sender_public_key_bytes,),
        algorithm=HashAlgorithm.SHA1
    )

    # a valid ECDSA signature that can be checked using the sender's public key
    # by default the sign function in cryptography library will compute a hash
    # of the data that is passed in
    signature = sender_private_key.sign(
        data=get_signature_hash(
            recipient_hash=recipient_hash,
            amount=amount,
            fee=fee,
            nonce=nonce
        ),
        signature_algorithm=ECDSA(utils.Prehashed(algorithm=HashAlgorithm.SHA256.value))
    )

    # a SHA-256 hash of the sender_hash, recipient_hash, sender_public_key, amount, fee, nonce and signature
    txid = get_txid_hash(
        sender_hash=sender_hash,
        recipient_hash=recipient_hash,
        sender_public_key=sender_public_key_bytes,
        amount=amount,
        fee=fee,
        nonce=nonce,
        signature=signature
    )

    transaction = Transaction(
        sender_hash=sender_hash,
        recipient_hash=recipient_hash,
        sender_public_key=sender_public_key_bytes,
        amount=amount,
        fee=fee,
        nonce=nonce,
        signature=signature,
        txid=txid
    )

    return transaction
