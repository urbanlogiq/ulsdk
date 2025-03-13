# Copyright (c), CommunityLogiq Software

import os
from configparser import ConfigParser
from pathlib import Path
from typing import NamedTuple
from uuid import UUID
from enum import Enum


class Environment(Enum):
    Prod = 1
    Stage = 2

    @classmethod
    def parse(cls, s: str):
        match s.lower():
            case "prod":
                return cls.Prod
            case "stage":
                return cls.Stage
            case _:
                raise ValueError(f"Unknown environment: {s}")

    def str(self):
        return self.name.lower()


class Region(Enum):
    CA = 1
    US = 2

    @classmethod
    def parse(cls, s: str):
        match s.lower():
            case "ca":
                return cls.CA
            case "us":
                return cls.US
            case _:
                raise ValueError(f"Unknown region: {s}")

    def str(self):
        return self.name.lower()


class Key(NamedTuple):
    user_id: UUID
    region: Region
    access_key: str
    secret_key: str


def _load_keys() -> ConfigParser:
    """use Configparser to read your secret keys from your local ~/.ul/keys file"""
    ul = os.path.join(Path.home(), ".ul")
    if not os.path.exists(ul):
        os.makedirs(ul)

    keys_file = os.path.join(ul, "keys")
    keys = ConfigParser()

    if not os.path.exists(keys_file):
        return keys

    keys.read(keys_file)

    for section in keys.sections():
        if "connection_string" in keys[section]:
            raise Exception("Please remove connection_string from your keys file")

    return keys


def load_key(profile: str) -> Key:
    keys = _load_keys()
    if profile not in keys:
        raise ValueError(f"Profile '{profile}' does not exist")

    config_profile = keys[profile]
    user_id = UUID(config_profile["user_id"])
    region = Region.parse(config_profile["region"])
    access_key = config_profile["access_key"]
    secret_key = config_profile["secret_key"]

    return Key(user_id, region, access_key, secret_key)
