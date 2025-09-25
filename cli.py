import click
import yaml
import base64
import hashlib
import os
import tempfile
import shutil
from settings import Settings

SETTINGS = Settings()


def password_hash(password: str) -> str:
    salt = os.urandom(16)
    hashed_password = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1
    )
    return base64.b64encode(salt + hashed_password).decode("utf-8")


def load_config(config_file):
    """Loads the YAML configuration file."""
    print(f"Loading config from: {config_file}")
    try:
        with open(config_file, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print("Config file not found.")
        return {"users": {}}


def save_config(config, config_file):
    """Saves the configuration to the YAML file atomically."""
    print(f"Saving config to: {config_file}")
    temp_path = None
    try:
        # Create a temporary file in the same directory to ensure atomic move
        with tempfile.NamedTemporaryFile(
            "w", dir=os.path.dirname(config_file) or ".", delete=False, suffix=".tmp"
        ) as temp_file:
            yaml.dump(config, temp_file, default_flow_style=False)
            temp_path = temp_file.name

        # Atomically move the temporary file to the final destination
        shutil.move(temp_path, config_file)
    except Exception as e:
        # If the move fails, remove the temporary file if it exists
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        click.echo(f"Error saving configuration: {e}", err=True)
        return


@click.group()
@click.option(
    "--config-file", default=SETTINGS.config_file, help="Path to the configuration file."
)
@click.pass_context
def cli(ctx, config_file):
    """A CLI to manage the sshcertsigner configuration."""
    print(f"CLI context created with config file: {config_file}")
    ctx.obj = {"CONFIG_FILE": config_file}


@cli.command()
@click.argument("username")
@click.option("--password", help="User password.")
@click.option("--password-stdin", is_flag=True, help="Read password from stdin.")
@click.option("--publickey", help="User public key.")
@click.option("--publickey-file", help="File to read user public key from.")
@click.option("--principals", help="Comma-separated list of principals.")
@click.option("--extensions", help="Comma-separated list of extensions.")
@click.option("--valid-for", type=str, help="Validity period in days.")
@click.pass_context
def create(
    ctx,
    username,
    password,
    password_stdin,
    publickey,
    publickey_file,
    principals,
    extensions,
    valid_for,
):
    """Create a new user entry."""
    config_file = ctx.obj["CONFIG_FILE"]
    config = load_config(config_file)
    if username in config.get("users", {}):
        click.echo(f"Error: User '{username}' already exists.")
        return

    if password and password_stdin:
        click.echo(
            "Error: --password and --password-stdin are mutually exclusive.", err=True
        )
        return

    if publickey and publickey_file:
        click.echo(
            "Error: --publickey and --publickey-file are mutually exclusive.", err=True
        )
        return

    if password_stdin:
        password = click.prompt("Password", hide_input=True, confirmation_prompt=True)

    if publickey_file:
        try:
            with open(publickey_file, "r") as f:
                publickey = f.read().strip()
        except FileNotFoundError:
            click.echo(
                f"Error: Public key file not found at '{publickey_file}'.", err=True
            )
            return

    user_data = {}
    if password:
        user_data["password"] = password_hash(password)
    if publickey:
        user_data["publickey"] = publickey
    if principals:
        user_data["principals"] = principals.split(",")
    if extensions:
        user_data["extensions"] = extensions.split(",")
    if valid_for:
        user_data["valid_for"] = valid_for

    if "users" not in config:
        config["users"] = {}
    config["users"][username] = user_data
    save_config(config, config_file)
    click.echo(f"User '{username}' created successfully.")


@cli.command()
@click.argument("username")
@click.option("--password", help="New user password.")
@click.option("--password-stdin", is_flag=True, help="Read password from stdin.")
@click.option("--publickey", help="New user public key.")
@click.option("--publickey-file", help="File to read new user public key from.")
@click.option("--principals", help="New comma-separated list of principals.")
@click.option("--extensions", help="New comma-separated list of extensions.")
@click.option("--valid-for", type=str, help="New validity period in days.")
@click.pass_context
def update(
    ctx,
    username,
    password,
    password_stdin,
    publickey,
    publickey_file,
    principals,
    extensions,
    valid_for,
):
    """Update an existing user entry."""
    config_file = ctx.obj["CONFIG_FILE"]
    config = load_config(config_file)
    if username not in config.get("users", {}):
        click.echo(f"Error: User '{username}' not found.")
        return

    if password and password_stdin:
        click.echo(
            "Error: --password and --password-stdin are mutually exclusive.", err=True
        )
        return

    if publickey and publickey_file:
        click.echo(
            "Error: --publickey and --publickey-file are mutually exclusive.", err=True
        )
        return

    if password_stdin:
        password = click.prompt("Password", hide_input=True, confirmation_prompt=True)

    if publickey_file:
        try:
            with open(publickey_file, "r") as f:
                publickey = f.read().strip()
        except FileNotFoundError:
            click.echo(
                f"Error: Public key file not found at '{publickey_file}'.", err=True
            )
            return

    user_data = config["users"][username]
    if password:
        user_data["password"] = password_hash(password)
    if publickey:
        user_data["publickey"] = publickey
    if principals:
        user_data["principals"] = principals.split(",")
    if extensions:
        user_data["extensions"] = extensions.split(",")
    if valid_for:
        user_data["valid_for"] = valid_for

    save_config(config, config_file)
    click.echo(f"User '{username}' updated successfully.")


@cli.command()
@click.argument("username")
@click.pass_context
def delete(ctx, username):
    """Delete a user entry."""
    config_file = ctx.obj["CONFIG_FILE"]
    config = load_config(config_file)
    if username not in config.get("users", {}):
        click.echo(f"Error: User '{username}' not found.")
        return

    del config["users"][username]
    save_config(config, config_file)
    click.echo(f"User '{username}' deleted successfully.")


if __name__ == "__main__":
    cli()
