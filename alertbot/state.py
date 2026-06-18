"""Local JSON state management."""

import hashlib
import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

from .models import AttackPathGroup


class StateError(ValueError):
    """Raised when AlertBot state cannot be loaded or saved."""


FINDING_ID_FIELDS = ("id", "ID", "finding_id", "Finding ID")


def _populated(value: Any) -> bool:
    """Return whether a row value is usable for identity."""
    return value is not None and value != ""


def finding_state_key(row: Dict[str, Any]) -> str:
    """Build a stable per-finding key from an ID field or row fingerprint."""
    for field_name in FINDING_ID_FIELDS:
        value = row.get(field_name)
        if _populated(value):
            return f"id:{value}"

    encoded_row = json.dumps(row, sort_keys=True, default=str, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(encoded_row.encode('utf-8')).hexdigest()}"


def finding_keys_for_group(group: AttackPathGroup) -> List[str]:
    """Return all per-finding state keys for an Attack Path group."""
    return [finding_state_key(row) for row in group.findings]


def _recorded_finding_keys(entry: Dict[str, Any]) -> Set[str]:
    """Normalize finding keys stored in one attack-path state entry."""
    finding_keys = entry.get("finding_keys", [])
    if not isinstance(finding_keys, list):
        return set()
    return {str(key) for key in finding_keys}


@dataclass
class AlertState:
    version: int = 1
    last_successful_run_at: Optional[str] = None
    baseline_completed: bool = False
    alerted_attack_paths: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def has_attack_path(self, state_key: str) -> bool:
        """Return whether an Attack Path group has already been recorded."""
        return state_key in self.alerted_attack_paths

    def has_group_dedupe_record(self, state_key: str) -> bool:
        """Return whether a state entry should suppress the whole group."""
        entry = self.alerted_attack_paths.get(state_key)
        return isinstance(entry, dict) and entry.get("dedupe_mode", "group") == "group"

    def recorded_finding_keys(self, state_key: str) -> Set[str]:
        """Return finding keys already recorded for a grouped Attack Path."""
        entry = self.alerted_attack_paths.get(state_key)
        if not isinstance(entry, dict):
            return set()
        return _recorded_finding_keys(entry)

    def unrecorded_findings(self, group: AttackPathGroup) -> List[Dict[str, Any]]:
        """Return findings in a group that have not been recorded yet."""
        seen = self.recorded_finding_keys(group.state_key)
        unrecorded = []
        for row in group.findings:
            key = finding_state_key(row)
            if key in seen:
                continue
            seen.add(key)
            unrecorded.append(row)
        return unrecorded

    def mark_attack_path(
        self,
        group: AttackPathGroup,
        recorded_at: str,
        baseline: bool = False,
        delivery_status_code: Optional[int] = None,
        dedupe_mode: str = "group",
        finding_keys: Optional[Iterable[str]] = None,
    ) -> None:
        """Record an Attack Path group after baseline or successful delivery."""
        existing = self.alerted_attack_paths.get(group.state_key)
        existing_record = existing if isinstance(existing, dict) else {}
        first_recorded_at = existing_record.get("first_recorded_at", recorded_at)
        recorded_status_code = (
            delivery_status_code
            if delivery_status_code is not None
            else existing_record.get("delivery_status_code")
        )

        record = {
            "attack_path_id": group.attack_path_id,
            "domain_id": group.domain.id,
            "domain_name": group.domain.name,
            "asset_group_tag_id": group.asset_group_tag_id,
            "asset_group_tag_name": group.asset_group_tag_name,
            "attack_path_type": group.attack_path_type,
            "first_recorded_at": first_recorded_at,
            "last_recorded_at": recorded_at,
            "baseline": baseline,
            "delivery_status_code": recorded_status_code,
            "dedupe_mode": dedupe_mode,
        }

        if dedupe_mode == "finding":
            new_keys = finding_keys if finding_keys is not None else finding_keys_for_group(group)
            merged_keys = (
                _recorded_finding_keys(existing_record)
                | {str(key) for key in new_keys}
            )
            record["finding_keys"] = sorted(merged_keys)

        self.alerted_attack_paths[group.state_key] = record

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
