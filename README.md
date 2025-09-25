# SSH Certificate Signer

This project provides an SSH server that signs SSH certificates for authorized users. It is designed to issue temporary, signed certificates to users after they authenticate, which can then be used to access other SSH servers that trust the Certificate Authority (CA).

## Overview

The server, implemented using `asyncssh` in Python, listens for SSH connections. When a user connects, the server authenticates them based on credentials stored in a `config.yaml` file. Authentication can be done via public key or password.

Upon successful authentication, the server generates a new SSH key pair, signs the public key with a central Certificate Authority (CA) private key, and adds the signed certificate to the user's `ssh-agent`. This allows the user to seamlessly access other resources without managing multiple static keys.

The server also monitors the `config.yaml` file for changes and automatically reloads it, allowing for dynamic user management without restarting the service.

## Configuration (`config.yaml`)

The server's behavior is controlled by a central `config.yaml` file. This file defines default settings and a list of users with their specific permissions.

### Structure

The configuration is split into two main sections: `default` and `users`.

#### `default` Section

This section defines global default values that are applied to all users unless overridden in their individual configuration.

- `extensions`: A list of standard SSH certificate extensions to grant by default (e.g., `permit-pty`, `permit-port-forwarding`).
- `principals`: A list of default principals. Principals are names that the certificate is valid for, often corresponding to system usernames.
- `valid_for`: The default validity period for the certificate (e.g., `1d` for one day, `8h` for eight hours).

#### `users` Section

This section is a dictionary where each key is a username. Each user entry can have the following properties:

- `password`: The hashed password for the user. Use the `cli.py` tool to generate this hash.
- `publickey`: The user's public SSH key for authentication.
- `principals`: A list of principals specific to this user, overriding the default.
- `extensions`: A list of extensions specific to this user, overriding the default.
- `valid_for`: A specific validity period for this user's certificates, overriding the default.

### Example `config.yaml`

```yaml
default:
  extensions:
  - permit-pty
  - permit-X11-forwarding
  - permit-agent-forwarding
  - permit-port-forwarding
  - permit-user-rc
  valid_for: 1d
users:
  john_doe:
    password: "gIuazvsABAj4u8bllnzq2o5FiwGJlpUDQbIqXbJmYxATQMMs0BeQZfMOzvLItB7rMbmQuIngOIfJA4Yx++lHO/BIaQ0yi41Ohi42h2B6ksk="
    principals:
    - john_doe
    - developer
    publickey: "ssh-rsa AAAAB3NzaC1yc2E..."
  jane_smith:
    principals:
    - jane_smith
    - admin
    publickey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5..."
    valid_for: 7d
```

## CLI Management (`cli.py`)

A command-line interface, `cli.py`, is provided to easily manage the users in the `config.yaml` file.

### General Usage

The script takes a command (`create`, `update`, `delete`) followed by the username and relevant options.

```bash
python cli.py [OPTIONS] COMMAND [ARGS]...
```

You can specify a different configuration file using the `--config-file` option:

```bash
python cli.py --config-file /path/to/your/config.yaml create ...
```

### Commands

#### Create a User

To add a new user to the configuration:

```bash
python cli.py create <username> [OPTIONS]
```

**Options:**
- `--password`: Set the user's password.
- `--password-stdin`: Read the password from stdin.
- `--publickey`: Provide the public key as a string.
- `--publickey-file`: Path to the file containing the public key.
- `--principals`: Comma-separated list of principals.
- `--extensions`: Comma-separated list of extensions.
- `--valid-for`: Set the validity period (e.g., `30d`).

**Example:**
```bash
# Create a user with a password prompt and a public key from a file
python cli.py create new_user --password-stdin --publickey-file ~/.ssh/id_ed25519.pub --principals new_user,dev

# Create a user with a password provided directly
python cli.py create another_user --password "securepassword123"
```

#### Update a User

To modify an existing user's details:

```bash
python cli.py update <username> [OPTIONS]
```

The options are the same as the `create` command. Any option provided will overwrite the existing value for that user.

**Example:**
```bash
# Update the principals for user 'new_user'
python cli.py update new_user --principals new_user,dev,sudo
```

#### Delete a User

To remove a user from the configuration:

```bash
python cli.py delete <username>
```

**Example:**
```bash
python cli.py delete another_user
```
