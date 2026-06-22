"""AlertBot scheduled run orchestration."""

import datetime
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, List, Optional

from .alert_builder import build_alert_payload
from .bhe_client import BHEClient
from .config import resolve_credentials, resolve_state_path, validate_config
from .grouping import collect_attack_path_groups
from .models import AlertBotConfig, AttackPathGroup, RunResult
from .state import AlertState, finding_keys_for_group, load_state, save_state
from .webhook import post_webhook


def utc_now() -> str:
    """Return the current UTC time in an API-friendly ISO format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def build_client(config: AlertBotConfig) -> BHEClient:
    """Resolve credentials and create the BHE API client for a run."""
    credentials = resolve_credentials(config)
    return BHEClient.from_config(config, credentials)


def _mark_attack_path(
    state: AlertState,
    group: AttackPathGroup,
    config: AlertBotConfig,
    recorded_at: str,
    baseline: bool = False,
    delivery_status_code: Optional[int] = None,
) -> None:
    """Record delivered or baselined data using the configured dedupe mode."""
    if config.dedupe_mode == "finding":
        state.mark_attack_path(
            group,
            recorded_at=recorded_at,
            baseline=baseline,
            delivery_status_code=delivery_status_code,
            dedupe_mode="finding",
            finding_keys=finding_keys_for_group(group),
        )
        return

    state.mark_attack_path(
        group,
        recorded_at=recorded_at,
        baseline=baseline,
        delivery_status_code=delivery_status_code,
        dedupe_mode="group",
    )


def _baseline_group_records_for_finding_mode(
    state: AlertState,
    groups: List[AttackPathGroup],
    recorded_at: str,
) -> None:
    """Convert existing group-level records into finding-level baselines."""
    for group in groups:
        if not state.has_group_dedupe_record(group.state_key):
            continue
        state.mark_attack_path(
            group,
            recorded_at=recorded_at,
            baseline=True,
            dedupe_mode="finding",
            finding_keys=finding_keys_for_group(group),
        )


def _candidate_groups(
    state: AlertState,
    groups: List[AttackPathGroup],
    dedupe_mode: str,
) -> List[AttackPathGroup]:
    """Return groups or findings that have not already been recorded."""
    if dedupe_mode == "group":
        return [group for group in groups if not state.has_attack_path(group.state_key)]

    candidates: List[AttackPathGroup] = []
    for group in groups:
        if state.has_group_dedupe_record(group.state_key):
            continue
        unrecorded_findings = state.unrecorded_findings(group)
        is_unseen_empty_group = (
            not group.findings
            and not state.has_attack_path(group.state_key)
        )
        if unrecorded_findings or is_unseen_empty_group:
            candidates.append(replace(group, findings=unrecorded_findings))
    return candidates


def run_alertbot(
    config: AlertBotConfig,
    config_path: Path,
    dry_run: bool = False,
    client: Optional[Any] = None,
    now_fn: Callable[[], str] = utc_now,
) -> RunResult:
    """Execute one AlertBot run, optionally as a non-mutating dry run."""
    validate_config(config)
    state_path = resolve_state_path(config_path, config.state_path)
    state = load_state(state_path)
    client = client or build_client(config)
    client.ensure_enterprise_edition()
    run_at = now_fn()

    groups = collect_attack_path_groups(client, config)
    first_run = not state.baseline_completed and not state.alerted_attack_paths
    if config.dedupe_mode == "finding" and not dry_run:
        _baseline_group_records_for_finding_mode(state, groups, run_at)
    candidates = _candidate_groups(state, groups, config.dedupe_mode)

    result = RunResult(
        total_attack_paths=len(groups),
        candidate_attack_paths=len(candidates),
        dry_run=dry_run,
    )

    if first_run and config.first_run_behavior == "baseline":
        result.baseline_count = len(candidates)
        if dry_run:
            result.payloads = [
                build_alert_payload(group, config, alerted_at=run_at)
                for group in candidates
            ]
            return result
        if not dry_run:
            for group in candidates:
                _mark_attack_path(state, group, config, recorded_at=run_at, baseline=True)
            state.baseline_completed = True
            state.last_successful_run_at = run_at
            save_state(state, state_path)
        return result

    for group in candidates:
        payload = build_alert_payload(group, config, alerted_at=run_at)
        if dry_run:
            result.payloads.append(payload)
            continue

        delivery = post_webhook(config.webhook.url, payload, config.webhook.timeout_seconds)
        if delivery.success:
            _mark_attack_path(
                state,
                group,
                config,
                recorded_at=run_at,
                baseline=False,
                delivery_status_code=delivery.status_code,
            )
            result.delivered_count += 1
        else:
            result.failed_count += 1

    if not dry_run:
        if result.failed_count == 0:
            state.baseline_completed = True
            state.last_successful_run_at = run_at
        save_state(state, state_path)

    return result
