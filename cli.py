import click
import yaml
from settings import Settings
from config import AppConfig, UserConfig

SETTINGS = Settings()


@click.group()
@click.option(
    "--config-file", default=SETTINGS.config_file, help="Path to the configuration file."
)
@click.pass_context
def cli(ctx, config_file):
    """A CLI to manage the sshcertsigner configuration."""
    try:
        config = AppConfig.load_config(config_file)
    except FileNotFoundError:
        config = AppConfig()  # Create a new config if the file doesn't exist
    ctx.obj = {"CONFIG_FILE": config_file, "CONFIG": config}


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
    config: AppConfig = ctx.obj["CONFIG"]
    config_file = ctx.obj["CONFIG_FILE"]

    if config.get_user_config(username):
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

    user_data = {"username": username}
    if publickey:
        user_data["publickey"] = publickey
    if principals:
        user_data["principals"] = principals.split(",")
    if extensions:
        user_data["extensions"] = extensions.split(",")
    if valid_for:
        user_data["valid_for"] = valid_for

    new_user = UserConfig(**user_data)
    if password:
        new_user.password = new_user.password_hash(password)

    config.users[username] = new_user
    try:
        config.save_to_yaml(config_file)
        click.echo(f"User '{username}' created successfully.")
    except Exception as e:
        click.echo(f"Error saving configuration: {e}", err=True)


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
    config: AppConfig = ctx.obj["CONFIG"]
    config_file = ctx.obj["CONFIG_FILE"]

    user = config.get_user_config(username)
    if not user:
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

    if password:
        user.password = user.password_hash(password)
    if publickey:
        user.publickey = publickey
    if principals:
        user.principals = principals.split(",")
    if extensions:
        user.extensions = extensions.split(",")
    if valid_for:
        user.valid_for = valid_for

    try:
        config.save_to_yaml(config_file)
        click.echo(f"User '{username}' updated successfully.")
    except Exception as e:
        click.echo(f"Error saving configuration: {e}", err=True)


@cli.command()
@click.argument("username")
@click.option(
    "--password", "delete_password", is_flag=True, help="Delete password for the user."
)
@click.option(
    "--publickey",
    "delete_publickey",
    is_flag=True,
    help="Delete public key for the user.",
)
@click.option(
    "--principals",
    "delete_principals",
    is_flag=True,
    help="Delete principals for the user.",
)
@click.option(
    "--valid-for",
    "delete_valid_for",
    is_flag=True,
    help="Delete validity period for the user.",
)
@click.pass_context
def delete(
    ctx, username, delete_password, delete_publickey, delete_principals, delete_valid_for
):
    """Delete a user entry or specific user keys."""
    config: AppConfig = ctx.obj["CONFIG"]
    config_file = ctx.obj["CONFIG_FILE"]

    user = config.get_user_config(username)
    if not user:
        click.echo(f"Error: User '{username}' not found.")
        return

    keys_to_delete = any(
        [delete_password, delete_publickey, delete_principals, delete_valid_for]
    )

    if not keys_to_delete:
        del config.users[username]
        try:
            config.save_to_yaml(config_file)
            click.echo(f"User '{username}' deleted successfully.")
        except Exception as e:
            click.echo(f"Error saving configuration: {e}", err=True)
        return

    if delete_password:
        user.password = None
        click.echo(f"Password for user '{username}' deleted.")
    if delete_publickey:
        user.publickey = None
        click.echo(f"Public key for user '{username}' deleted.")
    if delete_principals:
        user.principals = config.default.principals
        click.echo(f"Principals for user '{username}' reset to default.")
    if delete_valid_for:
        user.valid_for = config.default.valid_for
        click.echo(f"Validity period for user '{username}' reset to default.")

    try:
        config.save_to_yaml(config_file)
        click.echo(f"User '{username}' updated successfully.")
    except Exception as e:
        click.echo(f"Error saving configuration: {e}", err=True)


@cli.group()
def show():
    """Show configuration."""
    pass


@show.command(name="all")
@click.pass_context
def show_all(ctx):
    """Show the entire configuration."""
    config: AppConfig = ctx.obj["CONFIG"]
    click.echo(yaml.dump(config.to_dict(), default_flow_style=False))


@show.command(name="defaults")
@click.pass_context
def show_defaults(ctx):
    """Show the default configuration."""
    config: AppConfig = ctx.obj["CONFIG"]
    defaults = config.default.model_dump(exclude_none=True)
    if defaults:
        click.echo(yaml.dump({"default": defaults}, default_flow_style=False))
    else:
        click.echo("No default configuration found.")


@show.command(name="user")
@click.argument("username")
@click.pass_context
def show_user(ctx, username):
    """Show configuration for a specific user."""
    config: AppConfig = ctx.obj["CONFIG"]
    user_config = config.get_user_full_config(username)
    if user_config:
        user_dict = user_config.model_dump(exclude={"username"}, exclude_none=True)
        click.echo(yaml.dump({username: user_dict}, default_flow_style=False))
    else:
        click.echo(f"User '{username}' not found.")


if __name__ == "__main__":
    cli()
