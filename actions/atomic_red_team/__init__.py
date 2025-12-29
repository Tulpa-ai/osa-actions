from .ExploitAction import ExploitAction
from pathlib import Path
import yaml


def get_actions() -> list:

    directory = Path("path/to/your/directory")
    yaml_files = list(directory.glob("*.yml")) + list(directory.glob("*.yaml"))

    actions = []

    for file in yaml_files:

        with file.open("r") as f:
            action_info = yaml.safe_load(f)

        actions.append(
            ExploitAction(action_info)
        )

    return actions
