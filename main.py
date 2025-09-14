import asyncio
import asyncssh
import logging
from datetime import datetime, timedelta
from typing import Optional
from sshkey_tools.cert import SSHCertificate, CertificateFields
from sshkey_tools.keys import PublicKey, PrivateKey
import config as config_module

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
SIGN_PASSWORD = "wiki"
SIGN_KEY_PATH = "ca"
CERT_VALIDITY = timedelta(days=365)
HOSTFILE = "hostfile"

USER_SSH_CERTIFICATE_TYPE = 1
HOST_SSH_CERTIFICATE_TYPE = 2

CA_PRIVATE_KEY_FILE = "ca"

CA_CERTIFICATE_PRIVATE_KEY = PrivateKey.from_file(CA_PRIVATE_KEY_FILE)


class SSHCertSignerServer(asyncssh.SSHServer):
    def __init__(self, app_config: config_module.AppConfig):
        self.app_config: config_module.AppConfig = app_config
        self.user_config: Optional[config_module.UserConfig] = None
        self._conn: asyncssh.SSHServerConnection = None

    def connection_made(self, conn: asyncssh.SSHServerConnection):
        self._conn = conn
        logger.info(f"Connection from {conn.get_extra_info('peername')[0]}")
        conn.send_auth_banner(PRE_AUTH_BANNER)

    def password_auth_supported(self):
        return True

    def public_key_auth_supported(self):
        return True

    async def validate_password(self, username, password):
        self.user_config = self.app_config.get_user_config(username)
        if not self.user_config:
            raise asyncssh.PermissionDenied("User not found")
        if self.user_config.password_verify(password):
            logger.info(f"Successful password authentication for user: {username}")
            self._conn.set_extra_info(username=username)
            return True
        else:
            logger.warning(
                f"Failed password authentication attempt for user: {username}"
            )
            raise asyncssh.PermissionDenied("Invalid password")

    async def validate_public_key(self, username, key):
        self.user_config = self.app_config.get_user_config(username)
        logger.info(
            f"Auth attempt for user: {username} with public key type: {key.algorithm}"
        )
        self._conn.set_extra_info(public_key=key)
        self._conn.set_extra_info(username=username)
        return False

    def connection_lost(self, exc):
        if exc:
            logger.error(f"Connection lost: {exc}")
        else:
            logger.info("Connection closed.")



class SSHCertSignerServerProcess():

    def __init__(self, process: asyncssh.SSHServerProcess, app_config: config_module.AppConfig):
        self.process: asyncssh.SSHServerProcess = process
        self.app_config = app_config

    @classmethod
    async def handle_client(cls, process: asyncssh.SSHServerProcess, app_config: config_module.AppConfig):
        await cls(process, app_config).run()

    async def run(self):
        try:
            username = self.process.get_extra_info('username')
            user_config = self.app_config.get_user_config(username)
            public_key = self.process.get_extra_info('public_key')

            result = sign_certificate(
                load_signing_key(),
                public_key,
                user_config,
            )
            self.process.stdout.write(result)
            self.process.exit(0)
        except Exception as e:
            logger.error(f"Error signing certificate: {e}")
            self.process.stderr.write(f"Error signing certificate: {e}\n")
            self.exit(1)



def load_signing_key() -> PrivateKey:
    """Load the signing private key."""
    return PrivateKey.from_file(SIGN_KEY_PATH)


def sign_certificate(
    signing_key: PrivateKey,
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
        valid_before=datetime.now() + timedelta(days=user_config.valid_for),
        extensions=user_config.extensions,
    )

    # Sign the certificate
    sshtools_pubkey = PublicKey.from_string(public_key.export_public_key().decode("utf-8"))
    certificate: SSHCertificate = SSHCertificate.create(
        subject_pubkey=sshtools_pubkey, ca_privkey=CA_CERTIFICATE_PRIVATE_KEY
    )

    certificate.sign()
    logger.info(
        f"Certificate signed successfully for user: {user_config.username}"
    )
    return certificate.to_string()


async def start_server(app_config: config_module.AppConfig):
    """Start the SSH server."""
    await asyncssh.create_server(
        lambda: SSHCertSignerServer(app_config),
        "0.0.0.0",
        2222,
        server_host_keys=[HOSTFILE],
        process_factory=lambda p: SSHCertSignerServerProcess.handle_client(p, app_config)
    )
    logger.info("SSH Certificate Signing Server started on port 2222")
    await asyncio.get_running_loop().create_future()


def main():
    """Main function to start the SSH certificate signing server."""
    # Load configuration if available
    app_config: config_module.AppConfig = config_module.AppConfig.load_config(
        "config.yaml"
    )
    logger.info("Configuration loaded successfully")

    try:
        asyncio.run(start_server(app_config))
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
    except Exception as e:
        logger.error(f"Server error: {e}")


if __name__ == "__main__":
    main()
