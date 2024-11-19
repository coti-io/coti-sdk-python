from typing import Dict, List, TypeAlias, Union

ItBool: TypeAlias = Dict[str, Union[int, bytes]] # { 'ciphertext': int, 'signature': bytes }

ItUint: TypeAlias = Dict[str, Union[int, bytes]] # { 'ciphertext': int, 'signature': bytes }

ItString: TypeAlias = Dict[str, Union[Dict[str, List[int]], List[bytes]]] # { 'ciphertext': { 'value': List[int] }, 'signature': List[bytes] }

CtBool: TypeAlias = int

CtUint: TypeAlias = int

CtString: TypeAlias = Dict[str, List[int]] # { 'value': List[int] }