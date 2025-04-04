import os, sys, importlib.util
from generate_metasploit_exploit_actions import ExploitAction

# Determine the root path of this package
path = os.path.dirname(os.path.abspath(__file__))

action_classes = []

# Walk through all subdirectories starting from 'path'
for root, dirs, files in os.walk(path):
    for file in files:
        # Process only .py files except for __init__.py
        if file.endswith('.py') and file != '__init__.py' and not file.endswith('Base.py'):
            file_path = os.path.join(root, file)
            # Load the module from the file path
            spec = importlib.util.spec_from_file_location('temp_module', file_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Retrieve only classes that inherit from ExploitAction
            exploit_classes = [
                getattr(module, attr) for attr in dir(module) 
                if isinstance(getattr(module, attr), type) 
                and issubclass(getattr(module, attr), ExploitAction)
                and getattr(module, attr) != ExploitAction  # Exclude the base class itself
            ]

            # If more than one class is found, prefer the one that doesn't end with 'Base'
            if len(exploit_classes) > 1:
                exploit_classes = [cls for cls in exploit_classes if not cls.__name__.endswith("Base")]
    
            # Ensure exactly one exploit class per file as expected
            if len(exploit_classes) != 1:
                raise Exception(
                    f"Expected exactly one ExploitAction class in file {file_path}, "
                    f"found {len(exploit_classes)}."
                )
            
            cls = exploit_classes[0]
            # Add the class to the current module's namespace
            setattr(sys.modules[__name__], cls.__name__, cls)
            action_classes.append(cls)


def get_actions() -> list:
    """Return a list of instantiated objects from each action class."""
    return [cls() for cls in action_classes]