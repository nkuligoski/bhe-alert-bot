"""Local JSON state management."""

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from .models import AttackPathGroup


class StateError(ValueError):
    """Raised when AlertBot state cannot be loaded or saved."""


@dataclass
class AlertState:
    version: int = 1
    last_successful_run_at: Optional[str] = None
    baseline_completed: bool = False
    alerted_attack_paths: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def has_attack_path(self, state_key: str) -> bool:
        """Return whether an Attack Path group has already been recorded."""
        return state_key in self.alerted_attack_paths

    def mark_attack_path(
        self,
        group: AttackPathGroup,
        recorded_at: str,
        baseline: bool = False,
        delivery_status_code: Optional[int] = None,
    ) -> None:
        """Record an Attack Path group after baseline or successful delivery."""
        self.alerted_attack_paths[group.state_key] = {
            "attack_path_id": group.attack_path_id,
            "domain_id": group.domain.id,
            "domain_name": group.domain.name,
            "asset_group_tag_id": group.asset_group_tag_id,
            "asset_group_tag_name": group.asset_group_tag_name,
            "attack_path_type": group.attack_path_type,
            "first_recorded_at": recorded_at,
            "baseline": baseline,
            "delivery_status_code": delivery_status_code,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize state for writing to disk."""
        return {
            "version": self.version,
            "last_successful_run_at": self.last_successful_run_at,
            "baseline_completed": self.baseline_completed,
            "alerted_attack_paths": self.alerted_attack_paths,
        }


def state_from_dict(data: Dict[str, Any]) -> AlertState:
    """Parse raw JSON state data into an AlertState instance."""
    if not isinstance(data, dict):
        raise StateError("State file must contain a JSON object")
    alerted = data.get("alerted_attack_paths", {})
    if not isinstance(alerted, dict):
        raise StateError("state.alerted_attack_paths must be an object")
    return AlertState(
        version=int(data.get("version", 1)),
        last_successful_run_at=data.get("last_successful_run_at"),
        baseline_completed=bool(data.get("baseline_completed", False)),
        alerted_attack_paths=alerted,
    )


def load_state(path: Path) -> AlertState:
    """Load state from disk, returning empty state when the file does not exist."""
    if not path.exists():
        return AlertState()
    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except json.JSONDecodeError as exc:
        raise StateError(f"State file is not valid JSON: {path}") from exc
    return state_from_dict(data)


def save_state(state: AlertState, path: Path) -> None:
    """Write state atomically to avoid partial state files."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as file:
        json.dump(state.to_dict(), file, indent=2)
        file.write("\n")
        temp_path = Path(file.name)
    temp_path.replace(path)
