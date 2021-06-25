#!/usr/bin/python3

import base64
import json

from typing import Any, Dict, Union

def encode_dict(dict_to_dump: Dict[Any, Any]) -> bytes:
    dump = bytes(json.dumps(dict_to_dump), 'utf-8')
    return base64.urlsafe_b64encode(dump)

def decode_dict(json_dict: bytes) -> str:
    text = base64.urlsafe_b64decode(json_dict)
    return json.loads(text)

def b64encode(data: Union[bytes, str]) -> bytes:
    if not isinstance(data, bytes):
        data = bytes(data, 'utf-8')

    return base64.urlsafe_b64encode(data)

def b64encode_str(data: bytes) -> str:
    return b64encode(data).decode('utf-8')

def b64decode(data: Union[bytes, str]) -> bytes:
    if not isinstance(data, bytes):
        data = bytes(data, 'utf-8')

    return base64.urlsafe_b64decode(data)

def b64decode_str(data: Union[bytes, str]) -> str:
    if not isinstance(data, bytes):
        data = bytes(data, 'utf-8')

    return base64.urlsafe_b64encode(data).decode('utf-8')
