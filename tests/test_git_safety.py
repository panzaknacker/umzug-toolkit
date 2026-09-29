from __future__ import annotations

import configparser

import pytest

from umzug.git_safety import dangerous_git_config


@pytest.mark.parametrize(
    ("section", "key", "value", "reason"),
    (
        ('merge "custom"', "driver", "sh -c payload", "merge-driver"),
        ("interactive", "diffFilter", "payload", "interactive-diff-filter"),
        ("sendemail", "sendmailCmd", "payload", "sendmail-command"),
        ('tar "custom"', "command", "payload", "archive-command"),
        ("sequence", "editor", "payload", "sequence-editor"),
        ("core", "askPass", "payload", "command-or-hook"),
        ('remote "origin"', "vcs", "custom", "remote-helper-or-command"),
        ('remote "origin"', "uploadPack", "payload", "remote-helper-or-command"),
        ('remote "origin"', "url", "ext::sh -c payload", "external-remote-helper"),
        ('remote "origin"', "url", "custom::payload", "external-remote-helper"),
        ('remote "origin"', "url", "custom://payload", "external-remote-helper"),
        ('submodule "dep"', "url", "ext::payload", "external-remote-helper"),
    ),
)
def test_git_execution_and_remote_helper_primitives_are_blocked(
    section: str,
    key: str,
    value: str,
    reason: str,
) -> None:
    rows = dangerous_git_config(f"[{section}]\n\t{key} = {value}\n")

    assert len(rows) == 1
    assert rows[0]["reason"] == reason
    assert rows[0]["value_sha256"] != value
    assert value not in rows[0].values()


def test_repository_local_config_uses_a_strict_key_allowlist() -> None:
    safe = """
[core]
    repositoryFormatVersion = 0
    fileMode = true
[remote "origin"]
    url = https://example.invalid/repository.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
    remote = origin
    merge = refs/heads/main
"""
    assert dangerous_git_config(safe, repository_local=True) == []

    rows = dangerous_git_config(
        "[gui]\n\twmState = normal\n",
        repository_local=True,
    )
    assert len(rows) == 1
    assert rows[0]["reason"] == "repository-key-not-allowlisted"


def test_duplicate_git_keys_fail_closed_instead_of_hiding_an_earlier_value() -> None:
    text = """
[remote "origin"]
    url = ext::sh -c payload
    url = https://example.invalid/repository.git
"""
    with pytest.raises(configparser.DuplicateOptionError):
        dangerous_git_config(text, repository_local=True)


def test_default_named_and_legacy_dotted_sections_cannot_bypass_checks() -> None:
    default_rows = dangerous_git_config(
        "[DEFAULT]\n\tcommand = payload\n",
        repository_local=True,
    )
    dotted_rows = dangerous_git_config(
        "[merge.custom]\n\tdriver = payload\n",
        repository_local=True,
    )

    assert default_rows[0]["reason"] == "repository-key-not-allowlisted"
    assert dotted_rows[0]["reason"] == "merge-driver"
