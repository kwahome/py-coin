from cryptography.hazmat.primitives import hashes
from enum import Enum


class HashAlgorithm(Enum):
    """
    An enumerations of hash algorithms available for use
    """
    SHA1: hashes.HashAlgorithm = hashes.SHA1()
    SHA256: hashes.HashAlgorithm = hashes.SHA256()
    SHA512: hashes.HashAlgorithm = hashes.SHA512()


def get_intermediate_hash(
    data: tuple,
    algorithm: HashAlgorithm = HashAlgorithm.SHA256
) -> hashes.Hash:
    """
    A helper function to calculate an intermediate and
    un-finalized hash object.

    :param data: a dictionary containing input data
    :param algorithm: the hashing algorithm to use
    :return: hashes.Hash instance
    """
    intermediate_hash = hashes.Hash(algorithm.value)

    for value in data:
        intermediate_hash.update(value)

    return intermediate_hash


def get_hash(data: tuple, algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> bytes:
    """
    A helper function to calculate a hash of the supplied input

    :param data: a dictionary containing input data
    :param algorithm: the hashing algorithm to use
    :return: bytes
    """
    return get_intermediate_hash(data, algorithm).finalize()
