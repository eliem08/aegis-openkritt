"""The repository scanner container profile cannot be widened by an adapter."""

from __future__ import annotations

import pytest

from aegis.process.container import (
    ContainerLimits,
    ContainerPolicyError,
    HardenedDockerCommandBuilder,
    ReadOnlyMount,
    directory_sha256,
)

DIGEST = "a" * 64
IMAGE = f"registry.example/scanner@sha256:{DIGEST}"


def _tree(tmp_path):
    repos = tmp_path / "repos"
    repo = repos / "owner" / "project"
    repo.mkdir(parents=True)
    approved = tmp_path / "approved"
    rules = approved / "semgrep-rules"
    rules.mkdir(parents=True)
    return repos, repo, approved, rules


def test_builder_forces_digest_no_egress_read_only_non_root_and_limits(tmp_path):
    repos, repo, approved, rules = _tree(tmp_path)
    builder = HardenedDockerCommandBuilder(
        str(repos), approved_mount_roots=(str(approved),),
    )

    argv = builder.build(
        image=IMAGE,
        repository=str(repo),
        command=("scanner", "--json", "/src"),
        mounts=(ReadOnlyMount(str(rules), "/rules", directory_sha256(rules)),),
    )
    joined = " ".join(argv)

    assert argv[:3] == ["docker", "run", "--rm"]
    assert "--pull never" in joined
    assert "--network none" in joined
    assert "--read-only" in argv
    assert "--cap-drop ALL" in joined
    assert "--security-opt no-new-privileges" in joined
    assert "--user 65532:65532" in joined
    assert "--pids-limit 128" in joined
    assert "--memory 1073741824" in joined
    assert "--cpus 1.0" in joined
    assert "noexec,nosuid,nodev" in joined
    assert f"src={repo.resolve()},dst=/src,readonly" in joined
    assert f"src={rules.resolve()},dst=/rules,readonly" in joined
    assert argv[-4:] == [IMAGE, "scanner", "--json", "/src"]
    assert "--env HOME=/tmp" in joined
    assert "--env XDG_CACHE_HOME=/tmp/.cache" in joined
    assert "--env TMPDIR=/tmp" in joined
    assert "SECRET" not in joined and "/var/run/docker.sock" not in joined


@pytest.mark.parametrize("image", ["scanner:latest", "scanner", "scanner@sha256:bad"])
def test_builder_rejects_mutable_or_invalid_images(tmp_path, image):
    repos, repo, _, _ = _tree(tmp_path)
    builder = HardenedDockerCommandBuilder(str(repos))
    with pytest.raises(ValueError, match="pinned|invalid"):
        builder.build(image=image, repository=str(repo), command=("scan",))


def test_repository_must_be_below_approved_clone_root(tmp_path):
    repos, repo, _, _ = _tree(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    builder = HardenedDockerCommandBuilder(str(repos))
    with pytest.raises(ContainerPolicyError, match="outside"):
        builder.build(image=IMAGE, repository=str(outside), command=("scan",))
    with pytest.raises(ContainerPolicyError, match="child"):
        builder.build(image=IMAGE, repository=str(repos), command=("scan",))


def test_extra_mounts_need_approved_root_and_safe_unique_destination(tmp_path):
    repos, repo, approved, rules = _tree(tmp_path)
    outside = tmp_path / "outside-rules"
    outside.mkdir()
    builder = HardenedDockerCommandBuilder(
        str(repos), approved_mount_roots=(str(approved),),
    )
    with pytest.raises(ContainerPolicyError, match="outside approved"):
        builder.build(
            image=IMAGE, repository=str(repo), command=("scan",),
            mounts=(ReadOnlyMount(str(outside), "/rules", "0" * 64),),
        )
    with pytest.raises(ContainerPolicyError, match="forbidden"):
        builder.build(
            image=IMAGE, repository=str(repo), command=("scan",),
            mounts=(ReadOnlyMount(str(rules), "/var/run/docker.sock", directory_sha256(rules)),),
        )
    with pytest.raises(ContainerPolicyError, match="duplicate"):
        builder.build(
            image=IMAGE, repository=str(repo), command=("scan",),
            mounts=(ReadOnlyMount(str(rules), "/rules", directory_sha256(rules)), ReadOnlyMount(str(rules), "/rules", directory_sha256(rules))),
        )


def test_read_only_mount_content_must_match_approved_digest(tmp_path):
    repos, repo, approved, rules = _tree(tmp_path)
    (rules / "rule.yml").write_text("rules: []")
    builder = HardenedDockerCommandBuilder(
        str(repos), approved_mount_roots=(str(approved),),
    )
    good = directory_sha256(rules)
    builder.build(
        image=IMAGE, repository=str(repo), command=("scan",),
        mounts=(ReadOnlyMount(str(rules), "/rules", good),),
    )
    (rules / "rule.yml").write_text("rules: [changed]")
    with pytest.raises(ContainerPolicyError, match="checksum mismatch"):
        builder.build(
            image=IMAGE, repository=str(repo), command=("scan",),
            mounts=(ReadOnlyMount(str(rules), "/rules", good),),
        )


def test_limits_and_identity_fail_closed(tmp_path):
    repos, _, _, _ = _tree(tmp_path)
    with pytest.raises(ContainerPolicyError, match="non-root"):
        HardenedDockerCommandBuilder(str(repos), uid=0)
    with pytest.raises(ContainerPolicyError, match="memory"):
        HardenedDockerCommandBuilder(str(repos), limits=ContainerLimits(memory_bytes=1))
