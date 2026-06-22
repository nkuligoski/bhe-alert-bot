# BloodHound Enterprise AlertBot

AlertBot is a Python CLI for turning BloodHound Enterprise Attack Path data into grouped webhook alerts.

The MVP runs as a one-shot command that can be scheduled by cron, a container scheduler, CI, or any other automation runner. It keeps local JSON state so previously delivered Attack Paths are not alerted again.

## Current Commands

Install the package in editable mode while developing:

```sh
python3 -m pip install -e .
```

Run the CLI:

```sh
alertbot --help
```

Available commands:

- `alertbot setup`: interactively create `alertbot.config.json` and initialize `alertbot.state.json`.
- `alertbot run`: query BHE, group new Attack Paths, POST alerts, and update local state.
- `alertbot run --dry-run`: build alert payloads without posting webhooks or mutating state.
- `alertbot run --dry-run --output-json alerts.json`: write a local JSON preview for validation before sending to a webhook.

The existing `attack_paths.py` script remains available as the original export/reference utility.

## Configuration

By default, AlertBot reads `alertbot.config.json`.

Secrets should come from environment variables when possible:

```sh
export BHE_ID="..."
export BHE_KEY="..."
```

If you paste a token ID and token key directly during `alertbot setup`, AlertBot writes them into `alertbot.config.json` so `alertbot run --dry-run` can run without exported environment variables. Protect that file if you choose this setup path.

Minimal config shape:

```json
{
  "bhe": {
    "tenant": "example.bloodhoundenterprise.io",
    "scheme": "https",
    "port": 443,
    "token_id_env": "BHE_ID",
    "token_key_env": "BHE_KEY"
  },
  "domains": {
    "mode": "all",
    "selected_domains": []
  },
  "webhook": {
    "url": "https://webhook.example/alertbot",
    "timeout_seconds": 10.0
  },
  "asset_group_tags": {
    "mode": "selected",
    "selected_tags": [
      {
        "id": 1,
        "name": "Tier Zero"
      }
    ]
  },
  "state_path": "alertbot.state.json",
  "first_run_behavior": "baseline",
  "dedupe_mode": "group",
  "page_size": 500,
  "log_level": "INFO"
}
```

AlertBot always groups webhook payloads by the Attack Path types returned by BloodHound Enterprise. State deduplication is controlled by `dedupe_mode`:

- `group`: track each domain, asset group tag, and Attack Path type as alerted after the first successful delivery or baseline. This is the default.
- `finding`: track individual finding rows within each grouped Attack Path. The first payload for a group includes all unrecorded findings, and later payloads include only newly observed finding rows.

## Setup Flow

Run:

```sh
alertbot setup
```

Setup retrieves available domains and asset group tags from BHE. For domains and asset group tags, enter `all` to monitor everything listed or enter comma-separated numbers such as `1,5,8` to choose specific entries. It also asks whether the first real run should:

- `baseline`: record all current Attack Paths without alerting.
- `alert`: send alerts for all current Attack Paths.

Setup also asks for the deduplication mode. Use `group` to alert once per grouped Attack Path, or `finding` to keep alerting when new finding rows appear inside an already-seen group.

Setup and scheduled runs first check `/api/version` and stop unless `product_edition` is `enterprise`.

Scheduled runs are non-interactive.

To monitor every asset group tag returned by `/api/v2/asset-group-tags`, use:

```json
{
  "asset_group_tags": {
    "mode": "all"
  }
}
```

`assetGroupTagId=0` is not included in `all` mode because it is not returned by `/api/v2/asset-group-tags`. Select it explicitly if you want the default/hygiene behavior.

## Running

Dry-run first:

```sh
alertbot run --dry-run
```

Write the generated alert payloads to a local JSON file for validation:

```sh
alertbot run --dry-run --output-json alerts.json
```

The output file contains the run summary and the exact alert payloads AlertBot generated. In dry-run mode, AlertBot does not POST to the webhook and does not update local state.

Run for real:

```sh
alertbot run
```

AlertBot groups findings by the available Attack Path type returned by BloodHound Enterprise for each monitored domain and monitored asset group tag. Each webhook POST contains one compact domain-specific, tag-specific Attack Path alert with counts and a small set of findings.

State is updated only after successful webhook delivery. Failed deliveries are not marked as alerted, so they remain eligible for retry on the next run.

In `finding` deduplication mode, AlertBot prefers finding ID fields such as `id`, `ID`, `finding_id`, or `Finding ID` for state keys. If a row has no recognized ID field, AlertBot falls back to a stable hash of the row content.

If an existing `group` state file is switched to `finding`, AlertBot treats current findings under already-recorded groups as a finding-level baseline to avoid duplicate alert bursts. Newly observed finding rows after that baseline remain eligible for alerts.

## Webhook Payload

AlertBot sends JSON using `POST` and treats only `2xx` responses as success.

Example payload:

```json
{
  "source": "bloodhound-enterprise-alertbot",
  "event_type": "new_attack_path",
  "domain": {
    "id": "S-1-5-21-example",
    "name": "example.local",
    "type": "active-directory"
  },
  "asset_group_tag": {
    "id": 1,
    "name": "Tier Zero"
  },
  "attack_path": {
    "id": "Attack Path Type",
    "type": "Attack Path Type",
    "name": "Attack Path Type",
    "severity": "high",
    "summary": "3 findings for Attack Path Type in example.local for Tier Zero from 2 source principals to 2 target principals.",
    "url": "https://example.bloodhoundenterprise.io/ui/graphview?environmentId=S-1-5-21-example&assetGroupTagId=1&findingName=Attack+Path+Type"
  },
  "counts": {
    "findings": 3,
    "source_principals": 2,
    "target_principals": 2,
    "objects": 0
  },
  "findings": [
    {
      "id": 1,
      "from": "alice@example.local",
      "to": "server01.example.local",
      "object": null,
      "title": "Attack Path Type",
      "severity": "high",
      "summary": "alice@example.local -> Attack Path Type -> server01.example.local"
    }
  ],
  "additional_findings": true,
  "observed_at": "2024-08-28T21:21:40.845Z",
  "alerted_at": "2026-06-17T12:05:00Z"
}
```

AlertBot builds `attack_path.url` from the configured BHE tenant, monitored domain ID, configured asset group tag ID, and Attack Path type.

## Development Checks

Run tests:

```sh
python3 -m pytest
```

Run a syntax check without writing bytecode into user-level cache directories:

```sh
python3 -c "import py_compile; py_compile.compile('attack_paths.py', cfile='/tmp/attack_paths.pyc', doraise=True)"
```
