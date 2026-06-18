"""Attack Path grouping logic."""

import logging
from typing import Any, Dict, Iterable, List

from .bhe_client import normalize_attack_path_type
from .models import AlertBotConfig, AssetGroupTagConfig, AttackPathGroup, DomainInfo

LOGGER = logging.getLogger(__name__)


class MappingError(ValueError):
    """Raised when BHE rows cannot be mapped into AlertBot groups."""


def _domain_id(domain: Dict[str, Any]) -> str:
    """Extract a stable domain identifier from known BHE domain fields."""
    value = domain.get("id") or domain.get("objectid") or domain.get("objectId") or domain.get("sid")
    if not value:
        raise MappingError(f"Domain row is missing an id/objectid/objectId/sid field: {domain}")
    return str(value)


def _domain_name(domain: Dict[str, Any]) -> str:
    """Extract a display name for a BHE domain row."""
    return str(domain.get("name") or domain.get("domain") or _domain_id(domain))


def domain_info_from_row(domain: Dict[str, Any]) -> DomainInfo:
    """Convert a raw BHE domain row to the internal domain model."""
    return DomainInfo(
        id=_domain_id(domain),
        name=_domain_name(domain),
        type=domain.get("type"),
    )


def select_domains(domains: Iterable[Dict[str, Any]], config: AlertBotConfig) -> List[Dict[str, Any]]:
    """Filter available domains according to config domain selection."""
    domain_rows = list(domains)
    if config.domains.mode == "all":
        return domain_rows

    selected = set(config.domains.selected_domains)
    return [
        domain
        for domain in domain_rows
        if _domain_id(domain) in selected or _domain_name(domain) in selected
    ]


def _asset_group_tag_params(tag: AssetGroupTagConfig) -> Dict[str, int]:
    """Return the query params needed to scope BHE calls to one asset group tag."""
    return {"asset_group_tag_id": tag.id}


def _tag_from_row(row: Dict[str, Any]) -> AssetGroupTagConfig:
    """Convert an asset-group-tags API row to the internal tag model."""
    return AssetGroupTagConfig(
        id=int(row["id"]),
        name=row.get("name") or None,
    )


def select_asset_group_tags(client: Any, config: AlertBotConfig) -> List[AssetGroupTagConfig]:
    """Resolve selected or all asset group tags for a run, excluding implicit tag 0."""
    if config.asset_group_tags.mode == "selected":
        return config.asset_group_tags.selected_tags

    tags: List[AssetGroupTagConfig] = []
    for tag in client.fetch_asset_group_tags():
        if tag.get("id") is None:
            continue
        tag_config = _tag_from_row(tag)
        if tag_config.id == 0:
            continue
        tags.append(tag_config)
    return tags


def collect_attack_path_groups(client: Any, config: AlertBotConfig) -> List[AttackPathGroup]:
    """Fetch domains, tags, Attack Path types, and details into alert groups."""
    groups: List[AttackPathGroup] = []
    domains = select_domains(client.fetch_all_available_domains(), config)
    asset_group_tags = select_asset_group_tags(client, config)

    for tag in asset_group_tags:
        for domain_row in domains:
            domain = domain_info_from_row(domain_row)
            raw_types = client.fetch_available_types_for_each_domain(
                domain.id,
                params=_asset_group_tag_params(tag),
            )
            attack_path_types = [normalize_attack_path_type(value) for value in raw_types]
            LOGGER.info(
                "Fetching %s attack path type(s) for domain %s (%s) and asset group tag %s.",
                len(attack_path_types),
                domain.name,
                domain.id,
                tag.id,
            )

            for attack_path_type in attack_path_types:
                rows = client.fetch_attack_path_finding_details(
                    domain_sid=domain.id,
                    finding=attack_path_type,
                    page_size=config.page_size,
                    params=_asset_group_tag_params(tag),
                )
                groups.append(
                    AttackPathGroup(
                        state_key=f"{domain.id}:{tag.id}:{attack_path_type}",
                        attack_path_id=attack_path_type,
                        domain=domain,
                        attack_path_type=attack_path_type,
                        asset_group_tag_id=tag.id,
                        asset_group_tag_name=tag.name,
                        findings=rows,
                    )
                )

    return groups
