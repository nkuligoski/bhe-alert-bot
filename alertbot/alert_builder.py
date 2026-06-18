"""Build webhook payloads from grouped Attack Path data."""

import urllib.parse
from typing import Any, Dict, Optional

from .models import AlertBotConfig, AttackPathGroup


FINDING_ID_FIELDS = ("id", "ID", "finding_id", "Finding ID")
OBSERVED_AT_FIELDS = ("created_at", "updated_at", "observed_at", "first_observed", "first_seen", "Updated At")
SEVERITY_FIELDS = ("severity", "Severity", "risk", "Risk")
TITLE_FIELDS = ("title", "Title", "name", "Name", "finding", "Finding")
SUMMARY_FIELDS = ("summary", "Summary", "description", "Description")
URL_FIELDS = ("url", "URL", "link", "Link")
OBJECT_FIELDS = (
    "ObjectName",
    "Object",
    "Principal",
    "PrincipalName",
    "PrincipalHash",
    "Name",
    "DisplayName",
    "Asset",
    "AssetName",
)
MAX_EXAMPLES = 3


def _field(row: Dict[str, Any], name: Optional[str]) -> Optional[Any]:
    """Return a row value, treating missing keys and empty strings as absent."""
    if not name:
        return None
    value = row.get(name)
    if value == "":
        return None
    return value


def _first_field(row: Dict[str, Any], names: tuple[str, ...]) -> Optional[Any]:
    """Return the first populated value from a list of possible BHE field names."""
    for name in names:
        value = _field(row, name)
        if value is not None:
            return value
    return None


def _derived_summary(row: Dict[str, Any]) -> Optional[str]:
    """Build a human-readable summary from relationship or object-only detail rows."""
    from_principal = _field(row, "FromPrincipal")
    finding = _field(row, "Finding")
    to_principal = _field(row, "ToPrincipal")
    affected_object = _first_field(row, OBJECT_FIELDS)

    if from_principal and finding and to_principal:
        return f"{from_principal} -> {finding} -> {to_principal}"
    if from_principal and to_principal:
        return f"{from_principal} -> {to_principal}"
    if affected_object and finding:
        return f"{affected_object} has finding {finding}"
    if affected_object:
        return f"Affected object: {affected_object}"
    return None


def _pluralize(count: int, singular: str, plural: Optional[str] = None) -> str:
    """Format a count and noun with simple singular/plural handling."""
    label = singular if count == 1 else (plural or f"{singular}s")
    return f"{count} {label}"


def _distinct_count(rows: list[Dict[str, Any]], field_name: str) -> int:
    """Count distinct non-empty values for a single field across rows."""
    return len({
        str(value)
        for row in rows
        for value in [_field(row, field_name)]
        if value is not None
    })


def _distinct_any_field_count(rows: list[Dict[str, Any]], field_names: tuple[str, ...]) -> int:
    """Count distinct entities using the first populated field from several candidates."""
    return len({
        str(value)
        for row in rows
        for value in [_first_field(row, field_names)]
        if value is not None
    })


def _compact_finding(row: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a raw BHE detail row into a small webhook-safe example object."""
    return {
        "id": _first_field(row, FINDING_ID_FIELDS),
        "from": _field(row, "FromPrincipal"),
        "to": _field(row, "ToPrincipal"),
        "object": _first_field(row, OBJECT_FIELDS),
        "title": _first_field(row, TITLE_FIELDS),
        "severity": _first_field(row, SEVERITY_FIELDS),
        "summary": _first_field(row, SUMMARY_FIELDS) or _derived_summary(row),
    }


def _group_summary(group: AttackPathGroup) -> Optional[str]:
    """Summarize multi-row alerts using counts instead of listing every finding."""
    if len(group.findings) <= 1:
        return None

    source_count = _distinct_count(group.findings, "FromPrincipal")
    target_count = _distinct_count(group.findings, "ToPrincipal")
    object_count = _distinct_any_field_count(group.findings, OBJECT_FIELDS)
    parts = [
        f"{_pluralize(len(group.findings), 'finding')} for {group.attack_path_type}",
        f"in {group.domain.name}",
    ]
    if group.asset_group_tag_name:
        parts.append(f"for {group.asset_group_tag_name}")
    if source_count:
        parts.append(f"from {_pluralize(source_count, 'source principal')}")
    if target_count:
        parts.append(f"to {_pluralize(target_count, 'target principal')}")
    if not source_count and not target_count and object_count:
        parts.append(f"affecting {_pluralize(object_count, 'object')}")

    return " ".join(parts) + "."


def _bhe_base_url(config: AlertBotConfig) -> str:
    """Build the BHE base URL without the default HTTPS port."""
    host = config.bhe.tenant
    if config.bhe.port == 443 and config.bhe.scheme == "https":
        return f"{config.bhe.scheme}://{host}"
    return f"{config.bhe.scheme}://{host}:{config.bhe.port}"


def _graph_url(group: AttackPathGroup, config: AlertBotConfig) -> str:
    """Build a BloodHound graphview URL for the grouped Attack Path."""
    query = urllib.parse.urlencode(
        {
            "environmentId": group.domain.id,
            "assetGroupTagId": group.asset_group_tag_id,
            "findingName": group.attack_path_type,
        }
    )
    return f"{_bhe_base_url(config)}/ui/graphview?{query}"


def build_alert_payload(
    group: AttackPathGroup,
    config: AlertBotConfig,
    alerted_at: str,
) -> Dict[str, Any]:
    """Build the compact JSON payload sent to a webhook for one Attack Path group."""
    first_row = group.findings[0] if group.findings else {}
    observed_at = _first_field(first_row, OBSERVED_AT_FIELDS)
    severity = _first_field(first_row, SEVERITY_FIELDS)
    title = _first_field(first_row, TITLE_FIELDS) or f"{group.attack_path_type} Attack Path"
    summary = _group_summary(group) or _first_field(first_row, SUMMARY_FIELDS) or _derived_summary(first_row)
    url = _first_field(first_row, URL_FIELDS) or _graph_url(group, config)

    source_count = _distinct_count(group.findings, "FromPrincipal")
    target_count = _distinct_count(group.findings, "ToPrincipal")
    object_count = _distinct_any_field_count(group.findings, OBJECT_FIELDS)
    examples = [_compact_finding(row) for row in group.findings[:MAX_EXAMPLES]]

    return {
        "source": "bloodhound-enterprise-alertbot",
        "event_type": "new_attack_path",
        "domain": {
            "id": group.domain.id,
            "name": group.domain.name,
            "type": group.domain.type,
        },
        "asset_group_tag": {
            "id": group.asset_group_tag_id,
            "name": group.asset_group_tag_name,
        },
        "attack_path": {
            "id": group.attack_path_id,
            "type": group.attack_path_type,
            "name": title,
            "severity": severity,
            "summary": summary,
            "url": url,
        },
        "counts": {
            "findings": len(group.findings),
            "source_principals": source_count,
            "target_principals": target_count,
            "objects": object_count,
        },
        "examples": examples,
        "additional_findings": len(group.findings) > len(examples),
        "observed_at": observed_at,
        "alerted_at": alerted_at,
    }
