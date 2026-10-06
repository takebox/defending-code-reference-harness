# Copyright 2026 Takebox AI, PBC
# SPDX-License-Identifier: Apache-2.0
import pytest

from harness.prompts.system_prompt import (
    PIPELINE_PREAMBLE,
    DEFAULT_ENGAGEMENT_CONTEXT,
    build_system_prompt,
    echo_engagement_source,
    load_engagement_context,
)


def test_default_has_preamble_and_engagement():
    out = build_system_prompt(None)
    assert out.startswith(PIPELINE_PREAMBLE)
    assert DEFAULT_ENGAGEMENT_CONTEXT.strip() in out


def test_override_block_replaces_engagement_only():
    # File loading is tested against the loader below; the builder takes
    # the pre-resolved block.
    out = build_system_prompt("Authorized by Acme PSIRT for internal binaries.")
    assert out.startswith(PIPELINE_PREAMBLE)
    assert "Authorized by Acme PSIRT" in out
    assert "open-source C/C++ target" not in out


def test_empty_block_falls_back_to_default():
    assert DEFAULT_ENGAGEMENT_CONTEXT.strip() in build_system_prompt("")


def test_override_file_returned(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("Authorized by Acme PSIRT for internal binaries.")
    assert load_engagement_context(f, default="D") == (
        "Authorized by Acme PSIRT for internal binaries.", True )


def test_empty_file_falls_back_to_default(tmp_path):
    f = tmp_path / "empty.txt"
    f.write_text("   \n")
    # used_override must be False: the file did not supply the block.
    assert load_engagement_context(f, default="D") == ("D", False)


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError, match="engagement-context"):
        load_engagement_context(tmp_path / "nope.txt", default="D")


def test_none_path_falls_back_to_default():
    assert load_engagement_context(None, default="D") == ("D", False)


def test_echo_no_path_returns_default(capsys):
    assert echo_engagement_source(None, "D") == "D"
    assert capsys.readouterr().err == "engagement context: built-in default\n"


def test_echo_override_file_returns_its_block(tmp_path, capsys):
    f = tmp_path / "scope.txt"
    f.write_text("Authorized by Acme PSIRT.")
    assert echo_engagement_source(f, "D") == "Authorized by Acme PSIRT."
    assert capsys.readouterr().err == (
        f"engagement context: --engagement-context {f}\n"
    )


def test_echo_empty_override_says_so_and_falls_back(tmp_path, capsys):
    f = tmp_path / "empty.txt"
    f.write_text("   \n")
    assert echo_engagement_source(f, "D") == "D"
    assert capsys.readouterr().err == (
        f"engagement context: built-in default "
        f"(--engagement-context file {f} is empty)\n"
    )


def test_echo_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError, match="engagement-context"):
        echo_engagement_source(tmp_path / "nope.txt", "D")
