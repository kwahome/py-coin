"""
A module containing general helper functions
"""
import os

from enum import Enum


class ByteOrder(Enum):
    """
    An enumerations of byte order
    """
    BIG_ENDIAN: str = "big"
    LITTLE_ENDIAN: str = "little"


def is_whole_number(number: int) -> bool:
    """
    A helper function to check that a number is a whole number
    :param number: a number under check
    :return: boolean
    """
    return number - int(number) == 0


def int_to_bytes(
    integer: int,
    length: int = 8,
    byteorder: ByteOrder = ByteOrder.LITTLE_ENDIAN,
    signed: bool = False
) -> bytes:
    """
    A helper function to convert an integer into its byte representation
    :param integer: input int
    :param length: the size in bytes
    :param byteorder: significant bit order or endianness i.e, little or big
    :param signed: boolean to indicate whether the int is signed or not
    :return: bytes
    """
    return integer.to_bytes(length=length, byteorder=byteorder.value, signed=signed)


def int_from_bytes(
    input_bytes: bytes,
    byteorder: ByteOrder = ByteOrder.BIG_ENDIAN,
    signed: bool = False
) -> int:
    """
    A helper function to convert bytes into its integer equivalent.
    :param input_bytes: input bytes
    :param byteorder: significant bit order or endianness i.e, little or big
    :param signed: boolean to indicate whether the int is signed or not
    :return: int
    """
    return int.from_bytes(bytes=input_bytes, byteorder=byteorder.value, signed=signed)


def getenv(key: str, default: object = None, key_error: bool = False) -> object:
    """
    A helper function to retrieve an environment variable by key.

    :param key: variable key
    :param default: default value
    :param key_error: whether a key error should be raised if not found
    :return: value fetches from environment variables
    """
    value = os.getenv(key, default)

    if key_error and not value:
        raise KeyError(f"Environment variable '{key}' could not be found")

    return value
