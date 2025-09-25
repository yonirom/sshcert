from ipaddress import IPv4Address
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import FilePath, computed_field, field_validator
from pydantic.networks import IPvAnyAddress
from pathlib import Path

__VERSION__ = 0.1

# The pre-authentication banner text
PRE_AUTH_BANNER = """
   __________ __  __________________  ______
  / ___/ ___// / / / ____/ ____/ __ \\/_  __/
  \\__ \\\\__ \\/ /_/ / /   / __/ / /_/ / / /   
 ___/ /__/ / __  / /___/ /___/ _, _/ / /    
/____/____/_/ /_/\\____/_____/_/ |_| /_/     
                                            
==================================================
SSH Certificate Signing Server
==================================================
This server signs SSH certificates for authorized users.
Please contact system administrator for access.
==================================================
"""


DEFAULT_CONFIG = """
default:
  extensions:
  - permit-pty
  - permit-X11-forwarding
  - permit-agent-forwarding
  - permit-port-forwarding
  - permit-user-rc
  valid_for: 1d
"""

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')

    installation_id: str = 'homenet'
    config_file: FilePath = Path('config.yaml')
    ca_private_key_file: FilePath = Path('./keys/ca')
    host_private_key_file: FilePath = Path('./keys/hostfile')
    listen_address: IPvAnyAddress = IPv4Address('0.0.0.0') 
    listen_port: int = 2222
    pre_auth_banner: str = PRE_AUTH_BANNER
    server_version: str = f"SSHCert-v{__VERSION__}"



    @computed_field
    @property
    def config_directory(self) -> Path:
        return self.config_file.parent

    @field_validator('config_file', mode='before')
    def create_default_config(cls, config_path: str | Path):
        if not Path(config_path).exists():
            with open(config_path, "w") as c:
                c.write(DEFAULT_CONFIG)
        return Path(config_path)
    
