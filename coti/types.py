from typing import List, TypeAlias, TypedDict

CtBool: TypeAlias = int

CtUint: TypeAlias = int

class CtString(TypedDict):
    value: List[int]

class ItBool(TypedDict):
    ciphertext: int
    signature: bytes

class ItUint(TypedDict):
    ciphertext: int
    signature: bytes

class ItString(TypedDict):
    ciphertext: CtString
    signature: List[bytes]