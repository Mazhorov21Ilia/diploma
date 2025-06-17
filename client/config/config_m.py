import os
import yaml


def load_config(config_path=r"/home/sarah/Desktop/diploma/client/config/config.yaml"):
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Not found {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    return config
