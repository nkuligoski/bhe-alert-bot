"""Shared data models for AlertBot."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class Credentials:
    token_id: str
    token_key: str
    tenant: str


@dataclass
class BHEConfig:
    tenant: str
    scheme: str = "https"
    port: int = 443
    token_id_env: str = "BHE_ID"
    token_key_env: str = "BHE_KEY"
    token_id: Optional[str] = None
    token_key: Optional[str] = None


@dataclass
class DomainSelection:
    mode: str = "all"
    selected_domains: List[str] = field(default_factory=list)


@dataclass
class WebhookConfig:
    url: str
    timeout_seconds: float = 10.0


@dataclass
class AssetGroupTagConfig:
    id: int = 0
    name: Optional[str] = None


@dataclass
class AssetGroupTagSelection:
    mode: str = "selected"
    selected_tags: List[AssetGroupTagConfig] = field(
        default_factory=lambda: [AssetGroupTagConfig(id=0, name="Default / Hygiene")]
    )


@dataclass
class AlertBotConfig:
    bhe: BHEConfig
    domains: DomainSelection
    webhook: WebhookConfig
    asset_group_tags: AssetGroupTagSelection = field(default_factory=AssetGroupTagSelection)
    state_path: str = "alertbot.state.json"
    first_run_behavior: str = "baseline"
    dedupe_mode: str = "group"
    page_size: int = 500
    log_level: str = "INFO"


@dataclass(frozen=True)
class DomainInfo:
    id: str
    name: str
    type: Optional[str] = None


@dataclass
class AttackPathGroup:
    state_key: str
    attack_path_id: str
    domain: DomainInfo
    attack_path_type: str
    asset_group_tag_id: int = 0
    asset_group_tag_name: Optional[str] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class DeliveryResult:
    success: bool
    status_code: Optional[int] = None
    error: Optional[str] = None


@dataclass
class RunResult:
    total_attack_paths: int
    candidate_attack_paths: int
    delivered_count: int = 0
    failed_count: int = 0
    baseline_count: int = 0
    dry_run: bool = False
    payloads: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_attack_paths": self.total_attack_paths,
            "candidate_attack_paths": self.candidate_attack_paths,
            "delivered_count": self.delivered_count,
            "failed_count": self.failed_count,
            "baseline_count": self.baseline_count,
            "dry_run": self.dry_run,
            "payloads": self.payloads,
        }
