"""Loads secure-scan.yml"""

from dataclasses import dataclass, field
import os
import yaml

VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_OUTPUT_FORMATS = {"sarif", "console", "json"}


@dataclass
class Config:
    fail_on_severity: str = "high"
    ignore_paths: list[str] = field(default_factory=list)
    enabled_rules: list[str] = field(default_factory=lambda: ["auto"])
    baseline_path: str | None = None
    output_format: str = "sarif"


def load_config(path: str = "secure-scan.yml") -> Config:
    if not os.path.exists(path):
        config = Config()
    else:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            data = {}

        kwargs = {}
        for key in ("fail_on_severity", "ignore_paths", "enabled_rules", "baseline_path", "output_format"):
            if key in data:
                kwargs[key] = data[key]

        config = Config(**kwargs)

    if config.fail_on_severity not in VALID_SEVERITIES:
        raise ValueError(
            f"Invalid fail_on_severity: {config.fail_on_severity}. Must be one of {VALID_SEVERITIES}"
        )

    if config.output_format not in VALID_OUTPUT_FORMATS:
        raise ValueError(
            f"Invalid output_format: {config.output_format}. Must be one of {VALID_OUTPUT_FORMATS}"
        )

    return config
