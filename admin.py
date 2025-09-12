import click
import base64
import hashlib
import os
import config as app_config
import yaml
import tempfile
import shutil

CONFIG_FILE = "config.yaml"


def load_config():
    return app_config.load_config(CONFIG_FILE)


def password_hash(password: str) -> str:
    salt = os.urandom(16)
    hashed_password = hashlib.scrypt(password.encode(
        'utf-8'), salt=salt, n=2**14, r=8, p=1, maxmem=2**25)
    return base64.b64encode(salt + hashed_password).decode('utf-8')


def password_verify(password: str, hash: str) -> bool:
    decoded_hash = base64.b64decode(hash)
    recovered_salt = decoded_hash[:16]
    stored_hashed_password = decoded_hash[16:]

    computed_hashed_password = hashlib.scrypt(password.encode(
        'utf-8'), salt=recovered_salt, n=2**14, r=8, p=1)

    return computed_hashed_password == stored_hashed_password


@click.command()
@click.option('--username', required=True, help='Username of the user')
@click.option('--password', required=True, help='Password for the user')
def main(username: str, password: str):
    # Load configuration
    config = load_config()

    # Hash the password
    hashed_password = password_hash(password)

    # Update user's password in the configuration
    if username in config.users:
        config.users[username].password = hashed_password
    else:
        click.echo(f"User {username} not found.")
        return

    # Save the updated configuration back to the YAML file atomically
    temp_path = None
    try:
        # Create a temporary file in the same directory to ensure atomic move
        with tempfile.NamedTemporaryFile('w', dir=os.path.dirname(CONFIG_FILE) or '.', delete=False, suffix='.tmp') as temp_file:
            yaml.dump(config.to_dict(), temp_file)
            temp_path = temp_file.name

        # Atomically move the temporary file to the final destination
        shutil.move(temp_path, CONFIG_FILE)
    except Exception as e:
        # If the move fails, remove the temporary file if it exists
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        click.echo(f"Error saving configuration: {e}", err=True)
        return

    click.echo(f"Password for user {username} has been updated.")


if __name__ == "__main__":
    main()
