import paramiko
import socket
import sys
import base64
import threading
from datetime import datetime, timedelta
from typing import Optional
from sshkey_tools.cert import SSHCertificate, CertificateFields
from sshkey_tools.keys import PublicKey, PrivateKey



# The pre-authentication banner text
PRE_AUTH_BANNER = """
**********************
* CARTIFICATE SIGNER *
**********************
"""

# THIS IS FOR DEMONSTRATION ONLY AND IS HIGHLY INSECURE FOR PRODUCTION USE.
# DO NOT USE THIS IN A REAL-WORLD SERVER.
SIGN_PASSWORD = "wiki"

HOSTFILE = "hostfile"


CA_PRIVATE_KEY_FILE = "ca"

CA_CERTIFICATE_PRIVATE_KEY = PrivateKey.from_file(CA_PRIVATE_KEY_FILE)

USER_SSH_CERTIFICATE_TYPE = 1
HOST_SSH_CERTIFICATE_TYPE = 2



def sign_key(ssh_pubkey: paramiko.PKey, username: str):
    print(username)
    sshtools_pubkey = PublicKey.from_string(ssh_pubkey.get_name() + " " + base64.b64encode(ssh_pubkey.asbytes()).decode("ascii"))
    certificate: SSHCertificate = SSHCertificate.create(
            subject_pubkey=sshtools_pubkey,
            ca_privkey=CA_CERTIFICATE_PRIVATE_KEY)
    certificate.fields.extensions = [
                                    "permit-pty",
                                    "permit-X11-forwarding",
                                    "permit-agent-forwarding",
                                    "permit-port-forwarding",
                                    "permit-user-rc"
                                    ]
    certificate.fields.cert_type = USER_SSH_CERTIFICATE_TYPE
    certificate.fields.principals = ["meep", username]
    certificate.fields.valid_after = datetime.now()
    certificate.fields.valid_before = datetime.now() + timedelta(hours=24)
    certificate.sign()
    return certificate.to_string()

class AllowAllKeyServer(paramiko.ServerInterface):
    def __init__(self):
        self.publickey:Optional[paramiko.PKey] = None
        self.event = threading.Event()

    def check_auth_publickey(self, username, key):
        print(f"Auth attempt for user: {username} with public key type: {key.get_name()} {type(key)}")
        print(f"{key.can_sign()}")
        # In a real server, you would check 'username' and 'key' against
        # your authorized_keys or a database of trusted public keys.
        # To accept ANY public key (DANGEROUS):
        self.publickey = key
        return paramiko.AUTH_PARTIALLY_SUCCESSFUL
        # For a secure server, you'd do something like:
        # if username == "myuser" and self.allowed_keys.has_key(key):
        #     return paramiko.AUTH_SUCCESSFUL
        # return paramiko.AUTH_FAILED
    def check_auth_password(self, username, password):
         return paramiko.AUTH_SUCCESSFUL if password == SIGN_PASSWORD else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password" if self.publickey else "publickey"

    def get_banner(self):
        return (PRE_AUTH_BANNER, "en-US")

# ... (rest of the server setup, similar to paramiko's demo_server.py)

host_key = paramiko.Ed25519Key.from_private_key_file(HOSTFILE)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(True)
    sock.bind(('', 2222)) # Bind to an unused port for testing
    sock.listen(1)
    print("Listening on port 2222...")
    conn, addr = sock.accept()
    print(f"Got a connection from {addr}")

    t = paramiko.Transport(conn)
    t.add_server_key(host_key)
    server:AllowAllKeyServer = AllowAllKeyServer()
    t.start_server(server=server)

    channel = t.accept(20) # Wait for a channel to be opened
    if channel is None:
        print("No channel.")
        sys.exit(1)

    print("Client authenticated and channel opened.")
    # Here you would handle commands or shell access
    if server.publickey is not None:
        result = sign_key(server.publickey, t.get_username())
        channel.send(result)
    channel.send_exit_status(0)
    channel.close()
    t.close()

except Exception as e:
    print(f"Error: {e}")
finally:
    if 't' in locals() and t:
        t.close()
    if 'sock' in locals() and sock:
        sock.close()


