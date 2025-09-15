from dataclasses import dataclass, asdict, field
from typing import List, Optional, Dict
import os
import base64
import hashlib
import yaml


GLOBAL_CONFIG: Optional["DefaultConfig"] = None


@dataclass
class DefaultConfig:
    extensions: Optional[List[str]] = None
    principals: Optional[List[str]] = None
    valid_for: Optional[str] = None

    def __post_init__(self):
        if self.extensions is None:
            self.extensions = []


@dataclass
class UserConfig:
    username: str
    password: Optional[str] = None
    publickey: Optional[str] = None
    principals: Optional[List[str]] = field(
        default_factory=lambda: GLOBAL_CONFIG.principals
    )
    extensions: Optional[List[str]] = field(
        default_factory=lambda: GLOBAL_CONFIG.extensions
    )
    valid_for: Optional[str] = field(
        default_factory=lambda: GLOBAL_CONFIG.valid_for)

    def __post_init__(self):
        if self.principals is None:
            self.principals = []
        if self.extensions is None:
            self.extensions = []

    def password_hash(password: str) -> str:
        salt = os.urandom(16)
        hashed_password = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=2**14, r=2, p=1
        )
        return base64.b64encode(salt + hashed_password).decode("utf-8")

    def password_verify(self, password: str) -> bool:
        decoded_hash = base64.b64decode(self.password)
        recovered_salt = decoded_hash[:16]
        stored_hashed_password = decoded_hash[16:]

        computed_hashed_password = hashlib.scrypt(
            password.encode("utf-8"), salt=recovered_salt, n=2**14, r=8, p=1
        )

        return computed_hashed_password == stored_hashed_password


@dataclass
class AppConfig:
    default: Optional[DefaultConfig] = None
    users: Optional[Dict[str, UserConfig]] = None

    def __post_init__(self):
        if self.default is None:
            self.default = DefaultConfig()
            if self.users is None:
                self.users = {}

    def get_user_config(self, username: str) -> Optional[UserConfig]:
        if self.users and username in self.users:
            return self.users[username]
        return None

    @classmethod
    def from_yaml(cls, yaml_path: str) -> "AppConfig":
        """Load configuration from YAML file and create AppConfig object."""
        with open(yaml_path, "r") as file:
            config_data = yaml.safe_load(file)

        global GLOBAL_CONFIG

        # Handle default section
        default_data = config_data.get("default", {})

        default_config = DefaultConfig(**default_data)

        GLOBAL_CONFIG = default_config

        # Handle users section - now a dictionary with username as key
        users_data = config_data.get("users", {})
        users_config = {}
        for username, user_data in users_data.items():
            user_config = UserConfig(username, **user_data)
            users_config[username] = user_config

        return cls(default=default_config, users=users_config)

    def to_dict(self) -> dict:
        """Convert AppConfig object to dictionary."""
        result = asdict(self)
        # Convert users dict to list for proper serialization
        if "users" in result and isinstance(result["users"], dict):
            result["users"] = [
                {
                    "username": username,
                    **{k: v for k, v in user_config.__dict__.items() if v is not None},
                }
                for username, user_config in result["users"].items()
            ]
        return result

    @classmethod
    def load_config(cls, config_filename: str) -> "AppConfig":
        return AppConfig.from_yaml(config_filename)
