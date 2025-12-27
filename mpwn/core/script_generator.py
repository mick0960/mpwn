"""
Script generator for MPwn.

Generates exploit scripts from templates.
"""

import datetime
import json
from pathlib import Path

from jinja2 import Template

from mpwn.models import ChallengeFileInfo
from mpwn.config import TEMPLATE_PATH, USER_CONFIG_PATH
from mpwn.utils.console import error, success


class ScriptGenerator:
    """Generates exploit scripts from templates.

    Uses Jinja2 templates and user configuration to generate
    ready-to-use pwntools exploit scripts.
    """

    def __init__(self, challenge_info: ChallengeFileInfo):
        """Initialize the script generator.

        Args:
            challenge_info: Challenge file information to include in script
        """
        self.challenge_info = challenge_info
        self.template_path = TEMPLATE_PATH
        self.config_path = USER_CONFIG_PATH

    def generate(self) -> str:
        """Generate the exploit script.

        Returns:
            Path to the generated script

        Raises:
            SystemExit: If template file is missing or rendering fails
        """
        if not self.template_path.is_file():
            error("Missing template file")

        template_content = self._load_template()
        config = self._load_config()

        # Update config with challenge info
        config.update({
            "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "filename": str(self.challenge_info.executable or ""),
            "libcname": str(self.challenge_info.libc or ""),
        })

        try:
            rendered = Template(template_content).render(config)
            output_path = config.get("script_name", "exploit.py")

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(rendered)

            success(f"Script generated: {output_path}")
            return output_path

        except Exception as e:
            error(f"Render failed: {str(e)}")

    def _load_template(self) -> str:
        """Load the template file content.

        Returns:
            Template content as string
        """
        with open(self.template_path, "r", encoding="utf-8") as f:
            return f.read()

    def _load_config(self) -> dict:
        """Load user configuration.

        Returns:
            Configuration dictionary
        """
        config = {}

        if self.config_path.exists():
            with open(self.config_path, "r", encoding="utf-8") as f:
                config = json.load(f)

        return config


def generate_scripts(challenge_info: ChallengeFileInfo) -> str:
    """Generate exploit script from challenge info.

    This is a convenience function wrapping the ScriptGenerator class.
    Maintains backwards compatibility with the original function.

    Args:
        challenge_info: Challenge file information

    Returns:
        Path to the generated script
    """
    generator = ScriptGenerator(challenge_info)
    return generator.generate()
