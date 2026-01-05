from .ExploitAction import ExploitAction
from pathlib import Path
import yaml


def get_actions() -> list:

    directory = Path("actions/atomic_red_team/atomics")
    yaml_files = list(directory.glob("*.yml")) + list(directory.glob("*.yaml"))

    actions = []

    for file in yaml_files:

        with file.open("r") as f:
            action_info = yaml.safe_load(f)

        for test in action_info['atomic_tests']:
            actions.append(
                ExploitAction(
                    test,
                    action_info.get('display_name', ''),
                    action_info.get('attack_technique', '')
                )
            )

    return actions
