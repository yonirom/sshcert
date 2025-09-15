import unittest
import os
import yaml
from click.testing import CliRunner
from cli import cli

CONFIG_FILE = "test_config.yaml"


class TestCli(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()
        self.config_file = CONFIG_FILE

    def tearDown(self):
        if os.path.exists(self.config_file):
            os.remove(self.config_file)

    def test_create_user(self):
        """Test creating a new user."""
        result = self.runner.invoke(
            cli,
            [
                "--config-file",
                self.config_file,
                "create",
                "testuser",
                "--password",
                "testpass",
                "--principals",
                "p1,p2",
                "--extensions",
                "e1,e2",
                "--valid-for",
                "30",
            ],
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("User 'testuser' created successfully.", result.output)

        with open(self.config_file, "r") as f:
            config = yaml.safe_load(f)
        self.assertIn("testuser", config["users"])
        self.assertIn("password", config["users"]["testuser"])
        self.assertNotEqual(config["users"]["testuser"]["password"], "testpass")

    def test_update_user(self):
        """Test updating an existing user."""
        # First, create a user
        self.runner.invoke(
            cli,
            [
                "--config-file",
                self.config_file,
                "create",
                "testuser",
                "--password",
                "oldpass",
            ],
        )

        # Now, update the user
        result = self.runner.invoke(
            cli,
            [
                "--config-file",
                self.config_file,
                "update",
                "testuser",
                "--password",
                "newpass",
            ],
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("User 'testuser' updated successfully.", result.output)

        with open(self.config_file, "r") as f:
            config = yaml.safe_load(f)
        self.assertNotEqual(config["users"]["testuser"]["password"], "oldpass")

    def test_delete_user(self):
        """Test deleting a user."""
        # First, create a user
        self.runner.invoke(
            cli,
            [
                "--config-file",
                self.config_file,
                "create",
                "testuser",
                "--password",
                "somepass",
            ],
        )

        # Now, delete the user
        result = self.runner.invoke(
            cli, ["--config-file", self.config_file, "delete", "testuser"]
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("User 'testuser' deleted successfully.", result.output)

        with open(self.config_file, "r") as f:
            config = yaml.safe_load(f)
        self.assertNotIn("testuser", config["users"])


if __name__ == "__main__":
    unittest.main()
