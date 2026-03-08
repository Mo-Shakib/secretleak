"""Configuration loading and validation."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field, field_validator


class RegexRule(BaseModel):
    id: str
    name: str
    pattern: str
    severity: str = "high"
    description: str = ""

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"critical", "high", "medium", "low"}
        if v.lower() not in allowed:
            raise ValueError(f"severity must be one of {allowed}")
        return v.lower()

    @field_validator("pattern")
    @classmethod
    def validate_pattern(cls, v: str) -> str:
        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"invalid regex pattern: {e}") from e
        return v


class EntropyConfig(BaseModel):
    enabled: bool = True
    # Minimum string length to consider for entropy analysis
    min_length: int = Field(default=20, ge=8)
    # Shannon entropy threshold (bits/char). ~4.5 catches base64-encoded secrets
    threshold: float = Field(default=4.5, ge=1.0, le=8.0)
    # Max length to avoid flagging long prose
    max_length: int = Field(default=256, ge=20)


class AllowlistConfig(BaseModel):
    # Regex patterns matched against the raw secret value – matching means skip
    patterns: list[str] = Field(default_factory=list)
    # Glob patterns matched against file paths – matching means skip entire file
    paths: list[str] = Field(default_factory=list)

    @field_validator("patterns", mode="before")
    @classmethod
    def validate_patterns(cls, v: list[str]) -> list[str]:
        for p in v:
            try:
                re.compile(p)
            except re.error as e:
                raise ValueError(f"invalid allowlist regex '{p}': {e}") from e
        return v


class ScanConfig(BaseModel):
    rules: list[RegexRule] = Field(default_factory=list)
    entropy: EntropyConfig = Field(default_factory=EntropyConfig)
    allowlist: AllowlistConfig = Field(default_factory=AllowlistConfig)
    # Additional paths/globs to ignore (on top of allowlist.paths)
    ignore_paths: list[str] = Field(default_factory=list)
    # Path to a JSON baseline file for suppressing known findings
    baseline_file: Optional[str] = None


_DEFAULT_RULES_PATH = Path(__file__).parent.parent / "rules" / "default_rules.yaml"


def load_config(config_path: Optional[Path] = None) -> ScanConfig:
    """Load scan config, merging user config over built-in defaults."""
    default_cfg = _load_yaml_config(_DEFAULT_RULES_PATH)

    if config_path is None:
        return default_cfg

    user_cfg = _load_yaml_config(config_path)

    # Merge: user rules augment (or override by id) the default rules
    default_by_id = {r.id: r for r in default_cfg.rules}
    for r in user_cfg.rules:
        default_by_id[r.id] = r  # override or add

    merged_rules = list(default_by_id.values())

    return ScanConfig(
        rules=merged_rules,
        entropy=user_cfg.entropy,
        allowlist=AllowlistConfig(
            patterns=default_cfg.allowlist.patterns + user_cfg.allowlist.patterns,
            paths=default_cfg.allowlist.paths + user_cfg.allowlist.paths,
        ),
        ignore_paths=default_cfg.ignore_paths + user_cfg.ignore_paths,
        baseline_file=user_cfg.baseline_file or default_cfg.baseline_file,
    )


def _load_yaml_config(path: Path) -> ScanConfig:
    if not path.exists():
        return ScanConfig()
    with path.open() as fh:
        data = yaml.safe_load(fh) or {}
    return ScanConfig.model_validate(data)
