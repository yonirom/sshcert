import asyncio
import asyncssh
import logging
from datetime import datetime, timedelta
from typing import Optional
from sshkey_tools.keys import PrivateKey, PublicKey
from sshkey_tools.cert import CertificateFields, SSHCertificate
import config as config_module
from pytimeparse2 import parse

# Configure logging
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# The pre-authentication banner text
PRE_AUTH_BANNER = """
==================================================
SSH Certificate Signing Server
==================================================
This server signs SSH certificates for authorized users.
Please contact system administrator for access.
==================================================
"""

# Configuration
HOSTFILE = "hostfile"

USER_SSH_CERTIFICATE_TYPE = 1
HOST_SSH_CERTIFICATE_TYPE = 2

CA_PRIVATE_KEY_FILE = "ca"

CA_CERTIFICATE_PRIVATE_KEY = PrivateKey.from_file(CA_PRIVATE_KEY_FILE)


class SSHCertSignerServer(asyncssh.SSHServer):
    def __init__(self, app_config: config_module.AppConfig):
        self.app_config: config_module.AppConfig = app_config
        self.user_config: config_module.UserConfig | None

    def connection_made(self, conn: asyncssh.SSHServerConnection):
        self._conn = conn
        logger.info(f"Connection from {conn.get_extra_info('peername')[0]}")
        conn.send_auth_banner(PRE_AUTH_BANNER)

    def begin_auth(self, username: str) -> bool:
        user_config: Optional[config_module.UserConfig] = (
            self.app_config.get_user_config(username)
        )
        self.user_config = user_config
        return True

    def password_auth_supported(self):
        return True

    def public_key_auth_supported(self):
        return True

    def kbdint_auth_supported(self):
        return False

    async def validate_password(self, username, password):
        if not self.user_config:
            return False
        if not self.user_config.password:
            return True
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

        if not self.user_config:
            return False
        logger.info(
            f"Auth attempt for user: {
                username} with public key type: {key.algorithm}"
        )
        if not self.user_config.publickey:
            logger.info(
                f"publickey authentication succeeded for {
                    username} because no key defined for user"
            )
            return True
        try:
            user_key = asyncssh.import_public_key(self.user_config.publickey)
        except asyncssh.public_key.KeyImportError:
            logger.warning(f"Invalid key in config for user {username}")
            return False
        if key == user_key:
            logger.info(
                f"publickey authentication succeeded for {
                    username} because no key defined for user"
            )
            return True
        return False

    def connection_lost(self, exc):
        if exc:
            logger.error(f"Connection lost: {exc}")
        else:
            logger.info("Connection closed.")


class SSHCertSignerServerProcess:

    def __init__(
        self, process: asyncssh.SSHServerProcess, app_config: config_module.AppConfig
    ):
        self.process: asyncssh.SSHServerProcess = process
        self.app_config = app_config

    @classmethod
    async def handle_client(
        cls, process: asyncssh.SSHServerProcess, app_config: config_module.AppConfig
    ):
        await cls(process, app_config).run()

    async def run(self):
        try:
            username = self.process.get_extra_info("username")
            if not (user_config := self.app_config.get_user_config(username)):
                raise asyncssh.Error(-1, "Internal Error")
            if not (public_key := self.process.get_extra_info("public_key")):
               raise asyncssh.Error(-1, "no public key sent by user") 

            result = sign_certificate(
                public_key,
                user_config,
            )
            self.process.stdout.write(result)
            self.process.exit(0)
        except Exception as e:
            logger.error(f"Error signing certificate: {e}")
            self.process.stderr.write(f"Error signing certificate: {e}\n")
            self.process.exit(1)


def sign_certificate(
    public_key: asyncssh.SSHKey,
    user_config: config_module.UserConfig,
) -> str:
    
    """Sign an SSH certificate with the given parameters."""
    logger.info(f"Signing certificate for user: {user_config.username}")

    # Create certificate fields
    cert_fields = CertificateFields(
        serial=0,
        cert_type=USER_SSH_CERTIFICATE_TYPE,
        principals=user_config.principals,
        valid_after=datetime.now(),
        valid_before=datetime.now() + timedelta(seconds=parse(user_config.valid_for)),
        extensions=user_config.extensions,
    )

    # Sign the certificate
    sshtools_pubkey = PublicKey.from_string(
        public_key.export_public_key().decode("utf-8")
    )
    certificate: SSHCertificate = SSHCertificate.create(
        subject_pubkey=sshtools_pubkey,
        ca_privkey=CA_CERTIFICATE_PRIVATE_KEY,
        fields=cert_fields,
    )

    certificate.sign()
    logger.info(
        f"Certificate signed successfully for user: {
            user_config.username} for {user_config.valid_for}"
    )
    return certificate.to_string()


async def start_server(app_config: config_module.AppConfig):
    """Start the SSH server."""
    await asyncssh.create_server(
        lambda: SSHCertSignerServer(app_config),
        "0.0.0.0",
        2222,
        server_host_keys=[HOSTFILE],
        process_factory=lambda p: SSHCertSignerServerProcess.handle_client(
            p, app_config
        ),
    )
    logger.info("SSH Certificate Signing Server started on port 2222")
    await asyncio.get_running_loop().create_future()


async def main():
    """Main function to start the SSH certificate signing server."""
    # Load configuration if available

    await asyncio.gather(start_server(app_config))


if __name__ == "__main__":

    app_config: config_module.AppConfig = config_module.AppConfig.load_config(
        "config.yaml"
    )
    logger.info("Configuration loaded successfully")

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
    except Exception as e:
        logger.error(f"Server error: {e}")
