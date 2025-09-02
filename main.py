import paramiko
import socket
import base64
import threading
import logging
from datetime import datetime, timedelta
from typing import Optional
from sshkey_tools.cert import SSHCertificate, CertificateFields
from sshkey_tools.keys import PublicKey, PrivateKey
import config as config_module

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import the config module

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
HOSTFILE = open("hostfile", "r")

USER_SSH_CERTIFICATE_TYPE = 1
HOST_SSH_CERTIFICATE_TYPE = 2

CA_PRIVATE_KEY_FILE = "ca"

CA_CERTIFICATE_PRIVATE_KEY = PrivateKey.from_file(CA_PRIVATE_KEY_FILE)


class SSHCertSignerServerInterface(paramiko.ServerInterface):

    def __init__(self, app_config: config_module.AppConfig):
        self.app_config: Optional[config_module.AppConfig] = app_config
        self.user_config: Optional[config_module.UserConfig] = None
        self.publickey: Optional[paramiko.PKey] = None
        self.username: Optional[str] = None

    def check_auth_publickey(self, username, key):
        self.user_config = self.app_config.get_user_config(username)
        logger.info(f"Auth attempt for user: {username} with public key type: {
                    key.get_name()} {type(key)}")
        # In a real server, you would check 'username' and 'key' against
        # your authorized_keys or a database of trusted public keys.
        # To accept ANY public key (DANGEROUS):
        self.publickey = key
        self.username = username
        return paramiko.AUTH_PARTIALLY_SUCCESSFUL
        # For a secure server, you'd do something like:
        # if username == "myuser" and self.allowed_keys.has_key(key):
        #     return paramiko.AUTH_SUCCESSFUL
        # return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        """Check password authentication."""
        if self.user_config.password_verify(password):
            logger.info(
                f"Successful password authentication for user: {username}")
            return paramiko.AUTH_SUCCESSFUL
        else:
            logger.warning(
                f"Failed password authentication attempt for user: {username}")
            return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            logger.info("allowing session")
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        return True

    def get_allowed_auths(self, username):
        return "password" if self.publickey else "publickey"

    def get_banner(self):
        return (PRE_AUTH_BANNER, "en-US")


def load_signing_key() -> PrivateKey:
    """Load the signing private key."""
    return PrivateKey.from_file(SIGN_KEY_PATH)


def sign_certificate(
    signing_key: PrivateKey,
    public_key: paramiko.PKey,
    user_config: config_module.UserConfig
) -> SSHCertificate:
    """Sign an SSH certificate with the given parameters."""
    logger.info(f"Signing certificate for user: {user_config.username}")

    # Create certificate fields
    cert_fields = CertificateFields(
        serial=0,
        cert_type=USER_SSH_CERTIFICATE_TYPE,
        principals=user_config.principals,
        valid_after=datetime.now(),
        valid_before=datetime.now() + timedelta(days=user_config.valid_for),
        extensions=user_config.extensions
    )

    # Sign the certificate

    sshtools_pubkey = PublicKey.from_string(public_key.get_name(
    ) + " " + base64.b64encode(public_key.asbytes()).decode("ascii"))
    certificate: SSHCertificate = SSHCertificate.create(
        subject_pubkey=sshtools_pubkey,
        ca_privkey=CA_CERTIFICATE_PRIVATE_KEY)

    certificate.sign()
    logger.info(f"Certificate signed successfully for user: {
                user_config.username}")
    return certificate.to_string()


def handle_client(client_socket, addr, app_config: config_module.AppConfig):
    """Handle a client connection."""
    logger.info(f"Connection from {addr}")

    # Create SSH server transport
    transport = paramiko.Transport(client_socket)
    transport.add_server_key(paramiko.RSAKey.from_private_key_file('hostfile'))

    # Set up the server
    server = SSHCertSignerServerInterface(app_config)

    try:
        transport.start_server(server=server)
        logger.info("SSH server started successfully")

        # Handle the session
        channel = transport.accept(20)
        if channel is None:
            logger.warning("No channel accepted")
            return

        # Process certificate signing requests
        result = sign_certificate(load_signing_key(
        ), server.publickey, app_config.get_user_config(transport.get_username()))
        channel.send(result)
        channel.send_exit_status(0)
        channel.close()
        transport.close()

    except Exception as e:
        logger.error(f"Error handling client: {e}")
    finally:
        transport.close()


def main():
    """Main function to start the SSH certificate signing server."""
    # Load configuration if available
    app_config: config_module.AppConfig = config_module.load_config(
        "config.yaml")
    logger.info("Configuration loaded successfully")

    # Create and start the SSH server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.setblocking(True)

    try:
        server_socket.bind(('0.0.0.0', 2222))
        server_socket.listen(5)
        logger.info("SSH Certificate Signing Server started on port 2222")

        # Accept connections
        while True:
            client_socket, addr = server_socket.accept()
            client_thread = threading.Thread(
                target=handle_client, args=(client_socket, addr, app_config))
            client_thread.daemon = True
            client_thread.start()

    except KeyboardInterrupt:
        logger.info("Server shutting down...")
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()
