"""The Aegis research playbooks and their open·kritt publish."""

from __future__ import annotations

from aegis.hunt.workflows import WORKFLOWS, build_workflow, publish_workflows


def test_every_workflow_builds_a_valid_single_depth_payload():
    for spec in WORKFLOWS:
        wf = build_workflow(spec)
        assert wf["name"] and wf["description"]
        assert len(wf["levels"]) == 1
        level = wf["levels"][0]
        assert level["depth"] == 0 and level["multiOutput"] is True
        # terminal level emits all eight required vulnerability keys
        assert set(level["outputFormat"]) == {
            "vulnerability_type", "file_path", "line", "summary", "explanation",
            "trigger_flow", "malicious_input_example", "malicious_actor"}
        assert level["outputFormat"]["line"] == "number"
        assert level["steps"][0]["content"].strip()


def test_prompts_reference_the_repo_and_demand_falsification():
    for spec in WORKFLOWS:
        content = build_workflow(spec)["levels"][0]["steps"][0]["content"]
        assert "{{repo_full}}" in content          # scoped to the scanned repo
        assert "falsif" in content.lower()          # candidate != verification


def test_covers_the_core_corpus_classes():
    names = " ".join(s["name"].lower() for s in WORKFLOWS)
    # every detector family we built is represented as a playbook
    for cls in ("access control", "injection", "secrets", "contract",
                "systems", "memory safety", "misconfiguration",
                "authentication", "business logic", "dependencies"):
        assert cls in names


class FakeClient:
    def __init__(self, existing=()):
        self._existing = list(existing)
        self.created = []

    def list_workflows(self):
        return [{"name": n} for n in self._existing]

    def create_workflow(self, payload):
        self.created.append(payload)
        return {"id": str(100 + len(self.created)), "name": payload["name"]}


def test_publish_creates_all_when_none_exist():
    c = FakeClient()
    result = publish_workflows(c)
    assert len(result["created"]) == len(WORKFLOWS) and result["skipped"] == []
    assert len(c.created) == len(WORKFLOWS)


def test_publish_is_idempotent_by_name():
    first = WORKFLOWS[0]["name"]
    c = FakeClient(existing=[first])
    result = publish_workflows(c)
    assert first in result["skipped"]
    assert first not in [w["name"] for w in result["created"]]
    assert len(c.created) == len(WORKFLOWS) - 1
