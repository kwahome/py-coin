#!/usr/bin/env python3

import unittest

from struct import unpack
from os import urandom

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

from transaction import create_signed_transaction, get_signature_hash, get_txid_hash, Transaction
from hashing import get_hash, HashAlgorithm


class TestTransaction(unittest.TestCase):

    def test_valid_sender_balance(self):
        sender_balance = 20
        tx_amount = 10
        tx_fee = 1
        tx_nonce = unpack("!Q", urandom(8))[0]

        recipient_public_key = ec.generate_private_key(
            curve=ec.SECP256K1(), backend=default_backend()
        ).public_key()

        recipient_public_key_bytes = recipient_public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        recipient_hash = get_hash(
            data=(recipient_public_key_bytes,),
            algorithm=HashAlgorithm.SHA1
        )

        transaction = create_signed_transaction(
            sender_private_key=ec.generate_private_key(curve=ec.SECP256K1(), backend=default_backend()),
            recipient_hash=recipient_hash,
            amount=tx_amount,
            fee=tx_fee,
            nonce=tx_nonce
        )

        transaction.verify(sender_balance=sender_balance, sender_previous_nonce=transaction.nonce - 1)

    def test_modifying_transaction_raised_invalid_txid(self):
        sender_balance = 20
        tx_amount = 10
        tx_fee = 1
        tx_nonce = unpack("!Q", urandom(8))[0]

        recipient_public_key = ec.generate_private_key(
            curve=ec.SECP256K1(), backend=default_backend()
        ).public_key()

        recipient_public_key_bytes = recipient_public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        recipient_hash = get_hash(
            data=(recipient_public_key_bytes,),
            algorithm=HashAlgorithm.SHA1
        )

        transaction = create_signed_transaction(
            sender_private_key=ec.generate_private_key(curve=ec.SECP256K1(), backend=default_backend()),
            recipient_hash=recipient_hash,
            amount=tx_amount,
            fee=tx_fee,
            nonce=tx_nonce
        )

        # modification to change the recipient address
        malicious_recipient_public_key = ec.generate_private_key(
            curve=ec.SECP256K1(), backend=default_backend()
        ).public_key()

        malicious_recipient_public_key_bytes = malicious_recipient_public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        transaction.recipient_hash = get_hash(
            data=(malicious_recipient_public_key_bytes,),
            algorithm=HashAlgorithm.SHA1
        )

        with self.assertRaises(AssertionError) as context:
            transaction.verify(sender_balance=sender_balance, sender_previous_nonce=transaction.nonce - 1)

        self.assertTrue(
            "Invalid txid. txid should be a SHA256 hash of recipient_hash, amount, fee and nonce"
            in str(context.exception)
        )

    def test_invalid_signature_modified_amount_and_txid(self):
        sender_balance = 20
        tx_amount = 10
        tx_fee = 1
        tx_nonce = unpack("!Q", urandom(8))[0]

        recipient_public_key = ec.generate_private_key(
            curve=ec.SECP256K1(), backend=default_backend()
        ).public_key()

        recipient_public_key_bytes = recipient_public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        recipient_hash = get_hash(
            data=(recipient_public_key_bytes,),
            algorithm=HashAlgorithm.SHA1
        )

        sender_private_key = ec.generate_private_key(curve=ec.SECP256K1(), backend=default_backend())
        sender_public_key = sender_private_key.public_key()
        sender_public_key_bytes = sender_public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        transaction = create_signed_transaction(
            sender_private_key=sender_private_key,
            recipient_hash=recipient_hash,
            amount=tx_amount,
            fee=tx_fee,
            nonce=tx_nonce
        )

        # modification to change the amount
        tx_new_amount = 15

        transaction.amount = tx_new_amount

        # regenerate txid so that it's valid again
        transaction.txid = get_txid_hash(
            sender_hash=get_hash(
                data=(sender_public_key_bytes,),
                algorithm=HashAlgorithm.SHA1
            ),
            recipient_hash=recipient_hash,
            sender_public_key=sender_public_key_bytes,
            amount=tx_new_amount,
            fee=tx_fee,
            nonce=tx_nonce,
            signature=transaction.signature
        )

        with self.assertRaises(AssertionError) as context:
            transaction.verify(sender_balance=sender_balance, sender_previous_nonce=transaction.nonce - 1)

        self.assertTrue(
            f"Signature '{transaction.signature.hex()}' could not be verified with the sender public key"
            in str(context.exception)
        )

    def test_sender_balance_too_low(self):
        sender_balance = 5
        tx_amount = 10
        tx_fee = 1
        tx_nonce = unpack("!Q", urandom(8))[0]

        recipient_public_key = ec.generate_private_key(
            curve=ec.SECP256K1(), backend=default_backend()
        ).public_key()

        recipient_public_key_bytes = recipient_public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        recipient_hash = get_hash(
            data=(recipient_public_key_bytes,),
            algorithm=HashAlgorithm.SHA1
        )

        transaction = create_signed_transaction(
            sender_private_key=ec.generate_private_key(curve=ec.SECP256K1(), backend=default_backend()),
            recipient_hash=recipient_hash,
            amount=tx_amount,
            fee=tx_fee,
            nonce=tx_nonce
        )

        with self.assertRaises(AssertionError) as context:
            transaction.verify(sender_balance=sender_balance, sender_previous_nonce=transaction.nonce - 1)

        self.assertTrue(
            f"Transaction amount of {tx_amount} is more than the available balance of {sender_balance}"
            in str(context.exception)
        )

    def test_sender_previous_nonce_incorrect(self):
        sender_balance = 20
        tx_amount = 10
        tx_fee = 1
        tx_nonce = unpack("!Q", urandom(8))[0]

        recipient_public_key = ec.generate_private_key(
            curve=ec.SECP256K1(), backend=default_backend()
        ).public_key()

        recipient_public_key_bytes = recipient_public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        recipient_hash = get_hash(
            data=(recipient_public_key_bytes,),
            algorithm=HashAlgorithm.SHA1
        )

        transaction = create_signed_transaction(
            sender_private_key=ec.generate_private_key(curve=ec.SECP256K1(), backend=default_backend()),
            recipient_hash=recipient_hash,
            amount=tx_amount,
            fee=tx_fee,
            nonce=tx_nonce
        )

        previous_nonce = unpack("!Q", urandom(8))[0]
        with self.assertRaises(AssertionError) as context:
            transaction.verify(sender_balance=sender_balance, sender_previous_nonce=previous_nonce)

        self.assertTrue(
            f"Invalid nonce"
            in str(context.exception)
        )

    def test_invalid_signature_different_private_keys(self):
        sender_balance = 20
        tx_amount = 10
        tx_fee = 1
        tx_nonce = unpack("!Q", urandom(8))[0]

        recipient_public_key = ec.generate_private_key(
            curve=ec.SECP256K1(), backend=default_backend()
        ).public_key()

        recipient_public_key_bytes = recipient_public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        recipient_hash = get_hash(
            data=(recipient_public_key_bytes,),
            algorithm=HashAlgorithm.SHA1
        )

        # private key A
        sender_private_key_a = ec.generate_private_key(curve=ec.SECP256K1(), backend=default_backend())
        sender_public_key_a = sender_private_key_a.public_key()
        sender_public_key_a_bytes = sender_public_key_a.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        sender_public_key_a_hash = get_hash(
            data=(sender_public_key_a_bytes,),
            algorithm=HashAlgorithm.SHA1
        )

        # private key B
        sender_private_key_b = ec.generate_private_key(curve=ec.SECP256K1(), backend=default_backend())
        sender_public_key_b = sender_private_key_b.public_key()
        sender_public_key_b_bytes = sender_public_key_b.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        sender_public_key_b_hash = get_hash(
            data=(sender_public_key_b_bytes,),
            algorithm=HashAlgorithm.SHA1
        )

        # create a valid transaction with private key A
        transaction = create_signed_transaction(
            sender_private_key=sender_private_key_a,
            recipient_hash=recipient_hash,
            amount=tx_amount,
            fee=tx_fee,
            nonce=tx_nonce
        )

        # replace signature with one created with private key B
        signature = sender_private_key_b.sign(
            data=get_signature_hash(
                recipient_hash=recipient_hash,
                amount=tx_amount,
                fee=tx_fee,
                nonce=tx_nonce
            ),
            signature_algorithm=ECDSA(utils.Prehashed(algorithm=HashAlgorithm.SHA256.value))
        )

        transaction.signature = signature

        # regenerate the txid

        transaction.txid = get_txid_hash(
            sender_hash=sender_public_key_a_hash,
            recipient_hash=recipient_hash,
            sender_public_key=sender_public_key_a_bytes,
            amount=tx_amount,
            fee=tx_fee,
            nonce=tx_nonce,
            signature=signature
        )

        with self.assertRaises(AssertionError) as context:
            transaction.verify(sender_balance=sender_balance, sender_previous_nonce=transaction.nonce - 1)

        self.assertTrue(
            f"Signature '{signature.hex()}' could not be verified with the sender public key"
            in str(context.exception)
        )

    def test_valid_transaction(self):

        valid_transaction = Transaction(
            sender_hash=bytes.fromhex("3df8f04b3c159fdc6631c4b8b0874940344d173d"),
            recipient_hash=bytes.fromhex("5c1499a0484ace2f731b0afb83241e15f0e168ca"),
            sender_public_key=bytes.fromhex(
                "3056301006072a8648ce3d020106052b8104000a03420004886ed03cb7ffd4cbd95579ea2e202f1d" +
                "b29afc3bf5d7c2c34a34701bbb0685a7b535f1e631373afe8d1c860a9ac47d8e2659b74d437435b0" +
                "5f2c55bf3f033ac1"
            ),
            amount=10,
            fee=2,
            nonce=5,
            signature=bytes.fromhex(
                "3046022100f9c076a72a2341a1b8cb68520713e12f173378cf78cf79c7978a2337fbad141d022100" +
                "ec27704d4d604f839f99e62c02e65bf60cc93ae1735c1ccf29fd31bd3c5a40ed"
            ),
            txid=bytes.fromhex("ca388e0890b71bd1775460d478f26af3776c9b4f6c2b936e1e788c5c87657bc3")
        )

        valid_transaction.verify(sender_balance=20, sender_previous_nonce=4)


if __name__ == '__main__':
    unittest.main()
