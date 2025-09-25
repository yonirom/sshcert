import asyncio
from pathlib import Path
import asyncssh
import logging
from datetime import datetime
from typing import Optional, Tuple
from asyncssh.connection import SSHServerConnectionOptions
from asyncssh.public_key import SSHKey, SSHOpenSSHCertificate
import config as config_module
from watchfiles import awatch, Change, DefaultFilter
from settings import Settings

# Configure logging
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Disable noisy watchfiles
logging.getLogger("watchfiles.main").setLevel(logging.INFO)

SETTINGS = Settings()


class SSHCertSignerServer(asyncssh.SSHServer):
    def __init__(self, app_config: config_module.AppConfig):
        self.app_config: config_module.AppConfig = app_config
        self.user_config: config_module.UserConfig
        self.user_found: bool = False

    def connection_made(self, conn: asyncssh.SSHServerConnection):
        self._conn = conn
        logger.info(f"Connection from {conn.get_extra_info('peername')[0]}")
        conn.send_auth_banner(SETTINGS.pre_auth_banner)

    async def begin_auth(self, username: str) -> bool:
        user_config: Optional[config_module.UserConfig] = (
            self.app_config.get_user_config(username)
        )
        if user_config is None:
            return True
        self.user_config = user_config
        self.user_found = True
        await self._conn.create_agent_listener()
        return True

    def password_auth_supported(self):
        return True

    def public_key_auth_supported(self):
        return True

    def kbdint_auth_supported(self):
        return False

    async def session_requested(self) -> asyncssh.SSHServerSession:
        self.agent_connection = await asyncssh.connect_agent(self._conn)
        keys = await self.agent_connection.get_keys()
        for key in keys:
            if key.get_comment() == SETTINGS.installation_id:
                await self.agent_connection.remove_keys([key])

        await self.agent_connection.add_keys(sign_certificate(self.user_config))
        return asyncssh.SSHServerSession()

    async def validate_password(self, username, password):
        if self.user_found:
            if self.user_config.password_verify(password):
                logger.info(f"Successful password authentication for user: {username}")
                self._conn.set_extra_info(username=username)
                return True
            else:
                logger.warning(
                    f"Failed password authentication attempt for user: {username}"
                )
        return False

    async def validate_public_key(self, username, key):

        self._conn.set_extra_info(public_key=key)
        self._conn.set_extra_info(username=username)

        logger.info(
            f"Auth attempt for user: {
                username} with public key type: {key.algorithm}"
        )

        if self.user_found:
            try:
                user_key = asyncssh.import_public_key(self.user_config.publickey or "")
            except asyncssh.public_key.KeyImportError:
                logger.warning(f"Invalid key in config for user {username}")
                return False
            if key == user_key:
                logger.info(
                    f"publickey authentication succeeded for {
                        username}"
                )
                return True
        return False

    def connection_lost(self, exc):
        if exc:
            logger.error(f"Connection lost: {exc}")
        else:
            logger.info("Connection closed.")


def sign_certificate(user_config: config_module.UserConfig) -> Tuple[SSHKey, SSHOpenSSHCertificate]:
    new_user_key: SSHKey = asyncssh.generate_private_key("ssh-ed25519")
    ca: SSHKey = asyncssh.read_private_key(SETTINGS.ca_private_key_file)
    principals = user_config.principals or user_config.username
    user_certificate: SSHOpenSSHCertificate= ca.generate_user_certificate(new_user_key, key_id="meepmeep", principals=principals, valid_after=datetime.now(), valid_before=user_config.valid_for)
    new_user_key.set_comment(SETTINGS.installation_id)

    return new_user_key, user_certificate


class EntryPoint():

    def __init__(self) -> None:
        self.load_config()

    def load_config(self):
        self.app_config: config_module.AppConfig = config_module.AppConfig.load_config(
            SETTINGS.config_file
        )
        logger.info("Configuration loaded successfully")


    async def reload_config(self):
        self.app_config: config_module.AppConfig = config_module.AppConfig.load_config(
            SETTINGS.config_file
        )
        logger.info("Configuration reloaded successfully")
        

    async def monitor_conf_dir(self, directory: Path):
        async for _ in awatch(directory, watch_filter=ConfigFilter(), recursive=False, force_polling=False):
            await self.reload_config()

    async def start_server(self):
        """Start the SSH server."""
        options: asyncssh.SSHServerConnectionOptions = SSHServerConnectionOptions(
            server_factory=lambda: SSHCertSignerServer(app_config=self.app_config), 
            server_version=SETTINGS.server_version,
            server_host_keys=SETTINGS.host_private_key_file,
            agent_forwarding=True,
            connect_timeout="5s",
            login_timeout="10s")
        await asyncssh.listen(str(SETTINGS.listen_address), SETTINGS.listen_port, reuse_address=True, options=options)


class ConfigFilter(DefaultFilter):
    def __call__(self, change: Change, path: str) -> bool:
        return ( super().__call__(change, path) and path.endswith("config.yaml") and change in (Change.added, Change.modified))


async def main():
    """Main function to start the SSH certificate signing server."""

    entry_point: EntryPoint = EntryPoint()

    async with asyncio.TaskGroup() as tg:
        tg.create_task(entry_point.monitor_conf_dir(SETTINGS.config_directory))
        tg.create_task(entry_point.start_server())


if __name__ == "__main__":


    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
    except Exception as e:
        logger.error(f"Server error: {e}")
