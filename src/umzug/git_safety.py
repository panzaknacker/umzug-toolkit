from __future__ import annotations

import configparser
import hashlib
import re


_SAFE_REPOSITORY_KEYS: dict[str, frozenset[str]] = {
    "core": frozenset(
        {
            "repositoryformatversion",
            "filemode",
            "bare",
            "logallrefupdates",
            "ignorecase",
            "precomposeunicode",
            "symlinks",
        }
    ),
    "remote": frozenset(
        {
            "url",
            "pushurl",
            "fetch",
            "mirror",
            "tagopt",
            "promisor",
            "partialclonefilter",
            "prune",
            "prunetags",
            "skipdefaultupdate",
            "skipfetchall",
        }
    ),
    "branch": frozenset({"remote", "merge", "rebase", "pushremote", "description"}),
    "extensions": frozenset({"objectformat", "refstorage", "worktreeconfig", "partialclone"}),
    "user": frozenset({"name", "email", "signingkey", "useconfigonly"}),
    "commit": frozenset({"gpgsign", "cleanup", "verbose", "status"}),
    "tag": frozenset({"gpgsign", "forcesignannotated"}),
    "push": frozenset({"default", "followtags", "autosetupremote"}),
    "pull": frozenset({"rebase", "ff"}),
    "fetch": frozenset(
        {
            "prune",
            "prunetags",
            "recursesubmodules",
            "writecommitgraph",
            "parallel",
            "negotiationalgorithm",
            "showforcedupdates",
        }
    ),
    "rebase": frozenset({"autosquash", "autostash", "updaterefs"}),
    "submodule": frozenset(
        {
            "path",
            "url",
            "branch",
            "update",
            "shallow",
            "fetchrecursesubmodules",
            "ignore",
            "active",
        }
    ),
}
_REMOTE_HELPER_URL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._-]*::")
_REMOTE_URL_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")
_BUILTIN_REMOTE_SCHEMES = frozenset({"file", "ftp", "ftps", "git", "http", "https", "ssh"})


def _uses_remote_helper(value: str) -> bool:
    unquoted = value.strip()
    if len(unquoted) >= 2 and unquoted[0] == unquoted[-1] and unquoted[0] in {'"', "'"}:
        unquoted = unquoted[1:-1].strip()
    if _REMOTE_HELPER_URL.match(unquoted):
        return True
    scheme = _REMOTE_URL_SCHEME.match(unquoted)
    return bool(scheme and scheme.group(1).casefold() not in _BUILTIN_REMOTE_SCHEMES)


def dangerous_git_config(
    text: str,
    *,
    repository_local: bool = False,
) -> list[dict[str, str]]:
    """return hash-only evidence for git configuration execution/redirection points."""

    parser = configparser.RawConfigParser(
        interpolation=None,
        strict=True,
        allow_no_value=True,
        default_section="__umzug_no_implicit_defaults__",
    )
    parser.optionxform = str
    parser.read_string(text)
    result: list[dict[str, str]] = []
    for section in parser.sections():
        base = section.split(None, 1)[0].split(".", 1)[0].casefold()
        for raw_key, raw_value in parser.items(section):
            key = raw_key.casefold()
            value = "" if raw_value is None else str(raw_value).strip()
            reason: str | None = None
            if base in {"include", "includeif"}:
                reason = "include"
            elif base == "core" and key in {
                "hookspath",
                "fsmonitor",
                "sshcommand",
                "pager",
                "editor",
                "gitproxy",
                "askpass",
            }:
                reason = "command-or-hook"
            elif base == "credential" and key == "helper":
                reason = "credential-helper"
            elif base == "filter" and key in {"clean", "smudge", "process"}:
                reason = "filter-command"
            elif base == "pager":
                reason = "pager-command"
            elif base == "diff" and key in {"external", "textconv", "command"}:
                reason = "diff-command"
            elif base in {"difftool", "mergetool"} and key in {"cmd", "path"}:
                reason = "tool-command"
            elif base == "merge" and key == "driver":
                reason = "merge-driver"
            elif base == "interactive" and key == "difffilter":
                reason = "interactive-diff-filter"
            elif base == "sendemail" and key == "sendmailcmd":
                reason = "sendmail-command"
            elif base == "tar" and key == "command":
                reason = "archive-command"
            elif base == "sequence" and key == "editor":
                reason = "sequence-editor"
            elif base == "submodule" and key == "update" and value.lstrip().startswith("!"):
                reason = "submodule-command"
            elif base == "alias" and value.lstrip().startswith("!"):
                reason = "shell-alias"
            elif base in {"gpg", "gpg.ssh"} and key == "program":
                reason = "signing-command"
            elif base == "url" and key in {"insteadof", "pushinsteadof"}:
                reason = "url-rewrite"
            elif base == "remote" and key in {"vcs", "uploadpack", "receivepack"}:
                reason = "remote-helper-or-command"
            elif base in {"remote", "submodule"} and key in {"url", "pushurl"} and _uses_remote_helper(value):
                reason = "external-remote-helper"
            elif repository_local and key not in _SAFE_REPOSITORY_KEYS.get(base, frozenset()):
                reason = "repository-key-not-allowlisted"
            if reason is not None:
                result.append(
                    {
                        "section": section,
                        "key": raw_key,
                        "reason": reason,
                        "value_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
                    }
                )
    return result
