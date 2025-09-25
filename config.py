from pydantic import BaseModel, Field
from typing import List, Optional, Dict
import os
import base64
import hashlib
from pathlib import Path
import yaml


class DefaultConfig(BaseModel):
    extensions: List[str] = Field(default_factory=list)
    principals: List[str] = Field(default_factory=list)
    valid_for: str = "1d"


class UserConfig(BaseModel):
    username: str
    password: Optional[str] = None
    publickey: Optional[str] = None
    principals: List[str] = Field(default_factory=list)
    extensions: List[str] = Field(default_factory=list)
    valid_for: str = "1d"

    def password_hash(self, password: str) -> str:
        salt = os.urandom(16)
        hashed_password = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=2**14, r=2, p=1
        )
        return base64.b64encode(salt + hashed_password).decode("utf-8")

    def password_verify(self, password: str) -> bool:
        if self.password is None:
            return False
        decoded_hash = base64.b64decode(self.password)
        recovered_salt = decoded_hash[:16]
        stored_hashed_password = decoded_hash[16:]

        computed_hashed_password = hashlib.scrypt(
            password.encode("utf-8"), salt=recovered_salt, n=2**14, r=8, p=1
        )

        return computed_hashed_password == stored_hashed_password


class AppConfig(BaseModel):
    default: DefaultConfig = Field(default_factory=DefaultConfig)
    users: Dict[str, UserConfig] = Field(default_factory=dict)

    def get_user_config(self, username: str) -> Optional[UserConfig]:
        if self.users and username in self.users:
            return self.users[username]
        return None

    @classmethod
    def from_yaml(cls, yaml_path: str | Path) -> "AppConfig":
        """Load configuration from YAML file and create AppConfig object."""
        with open(yaml_path, "r") as file:
            config_data = yaml.safe_load(file)

        # Handle default section
        default_data = config_data.get("default", {})
        default_config = DefaultConfig(**default_data)

        # Handle users section - now a dictionary with username as key
        users_data = config_data.get("users", {})
        users_config = {}
        for username, user_data in users_data.items():
            # Inherit from default config
            user_config_data = default_config.model_dump()
            user_config_data.update(user_data)
            user_config_data['username'] = username
            user_config = UserConfig(**user_config_data)
            users_config[username] = user_config

        return cls(default=default_config, users=users_config)

    def to_dict(self) -> dict:
        """Convert AppConfig object to dictionary."""
        return self.model_dump(exclude_none=True)

    @classmethod
    def load_config(cls, config_filename: str | Path) -> "AppConfig":
        return AppConfig.from_yaml(config_filename)