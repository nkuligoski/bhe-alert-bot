from alertbot.config import config_from_dict
from alertbot.grouping import collect_attack_path_groups


class FakeClient:
    def __init__(self, rows):
        self.rows = rows

    def fetch_all_available_domains(self):
        return [{"id": "S-1", "name": "example.local", "type": "active-directory"}]

    def fetch_available_types_for_each_domain(self, domain_id, params=None):
        assert domain_id == "S-1"
        assert params == {"asset_group_tag_id": 3}
        return ["Type A"]

    def fetch_attack_path_finding_details(self, domain_sid, finding, page_size, params=None):
        assert params == {"asset_group_tag_id": 3}
        return self.rows


def _config():
    return config_from_dict(
        {
            "bhe": {"tenant": "tenant.example"},
            "webhook": {"url": "https://webhook.example"},
            "asset_group_tag": {"id": 3, "name": "Server Tier"},
        }
    )


def test_collect_attack_path_groups_by_available_type():
    rows = [
        {"finding_id": "f-1"},
        {"finding_id": "f-2"},
        {"finding_id": "f-3"},
    ]

    groups = collect_attack_path_groups(FakeClient(rows), _config())

    assert len(groups) == 1
    assert groups[0].attack_path_id == "Type A"
    assert groups[0].attack_path_type == "Type A"
    assert len(groups[0].findings) == 3
    assert groups[0].asset_group_tag_id == 3
    assert groups[0].asset_group_tag_name == "Server Tier"
    assert groups[0].state_key == "S-1:3:Type A"


def test_detail_rows_only_need_to_be_fetchable():
    groups = collect_attack_path_groups(FakeClient([{"finding_id": "f-1"}]), _config())

    assert len(groups) == 1
    assert groups[0].attack_path_id == "Type A"


class FakeAllTagsClient:
    def fetch_all_available_domains(self):
        return [{"id": "S-1", "name": "example.local", "type": "active-directory"}]

    def fetch_asset_group_tags(self):
        return [
            {"id": 0, "name": "Default / Hygiene"},
            {"id": 1, "name": "Tier Zero"},
            {"id": 3, "name": "Server Tier"},
        ]

    def fetch_available_types_for_each_domain(self, domain_id, params=None):
        return [f"Type {params['asset_group_tag_id']}"]

    def fetch_attack_path_finding_details(self, domain_sid, finding, page_size, params=None):
        return [{"finding_id": f"f-{params['asset_group_tag_id']}"}]


def test_collect_attack_path_groups_for_all_asset_group_tags_excludes_default_zero():
    config = config_from_dict(
        {
            "bhe": {"tenant": "tenant.example"},
            "webhook": {"url": "https://webhook.example"},
            "asset_group_tags": {"mode": "all"},
        }
    )

    groups = collect_attack_path_groups(FakeAllTagsClient(), config)

    assert [group.asset_group_tag_id for group in groups] == [1, 3]
    assert [group.state_key for group in groups] == ["S-1:1:Type 1", "S-1:3:Type 3"]
