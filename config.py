from dataclasses import dataclass, asdict, field
from typing import List, Optional, Dict, Any
import yaml


GLOBAL_CONFIG: "DefaultConfig" = None

@dataclass
class DefaultConfig:
    extensions: List[str] = None
    principals: List[str] = None
    valid_for: Optional[str] = None

    def __post_init__(self):
        if self.extensions is None:
            self.extensions = []

@dataclass
class UserConfig:
    username: str
    password: Optional[str] = None
    publickey: Optional[str] = None
    principals: List[str] = field(default_factory=lambda: GLOBAL_CONFIG.principals)
    extensions: List[str] = field(default_factory=lambda: GLOBAL_CONFIG.extensions)
    valid_for: Optional[str] = field(default_factory=lambda: GLOBAL_CONFIG.valid_for)
    
    def __post_init__(self):
        if self.principals is None:
            self.principals = []
        if self.extensions is None:
            self.extensions = []


@dataclass
class AppConfig:
    default: DefaultConfig = None
    users: Dict[str, UserConfig] = None

    def __post_init__(self):
        if self.default is None:
            self.default = DefaultConfig()
        if self.users is None:
            self.users = {}

    def get_user_config(self, username: str) -> UserConfig:
        return self.users[username]

    @classmethod
    def from_yaml(cls, yaml_path: str) -> 'AppConfig':
        """Load configuration from YAML file and create AppConfig object."""
        with open(yaml_path, 'r') as file:
            config_data = yaml.safe_load(file)

        global GLOBAL_CONFIG

        # Handle default section
        default_data = config_data.get('default', {})


        default_config = DefaultConfig(**default_data)

        GLOBAL_CONFIG = default_config

        # Handle users section - now a dictionary with username as key
        users_data = config_data.get('users', {})
        users_config = {}
        for username, user_data in users_data.items():
            user_config = UserConfig(username, **user_data)
            users_config[username] = user_config

        return cls(default=default_config, users=users_config)

   
    def to_dict(self) -> dict:
        """Convert AppConfig object to dictionary."""
        result = asdict(self)
        # Convert users dict to list for proper serialization
        if 'users' in result and isinstance(result['users'], dict):
            result['users'] = [
                {
                    'username': username,
                    **{k: v for k, v in user_config.__dict__.items() if v is not None}
                }
                for username, user_config in result['users'].items()
            ]
        return result

def load_config(config_filename: str) -> AppConfig:
    return AppConfig.from_yaml(config_filename)
