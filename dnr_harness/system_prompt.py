# Copyright 2026 Juglow, PBC
# SPDX-License-Identifier: Apache-2.0
"""System-prompt construction for dnr-pipeline hunt and grade agents.

Same two-layer split as harness.prompts.system_prompt — fixed harness
preamble + overridable engagement block — but with detection & response
framing. The static track's preamble describes crafting inputs against a
C/C++ binary and observing sanitizer output; that's inaccurate for a log
hunt.
"""

from __future__ import annotations

DNR_HARNESS_PREAMBLE = """\
## Harness context

This agent is part of the dnr-pipeline detection & response tool. The
target is a deliberately vulnerable demo web application; it and this agent
run inside a gVisor sandbox with no network egress beyond the API. The agent
investigates a generated log corpus, confirms suspected flaws in the app's
own source, and fires proof-of-concept requests only at the loopback
instance it starts itself. Scope is narrow by construction: one demo app,
one log corpus, inside a sandboxed environment.
"""

DNR_DEFAULT_ENGAGEMENT_CONTEXT = """\
## Engagement context

This is an authorized detection & response exercise conducted as a
defensive security assessment on a purpose-built training target. Findings
are collected as structured incident records and graded against the
exercise's own answer key.
"""


def build_dnr_system_prompt(engagement_block: str | None = None) -> str:
    """dnr-pipeline variant: detection & response framing for hunt and grade
    agents. The static track's preamble describes crafting inputs against a
    C/C++ binary and observing sanitizer output — inaccurate framing for a
    log hunt. Same pre-resolved-block contract as build_system_prompt: the
    CLI resolves --engagement-context once at startup; None/empty uses the
    built-in default.
    """
    return DNR_HARNESS_PREAMBLE + "\n" + (engagement_block
                                          or DNR_DEFAULT_ENGAGEMENT_CONTEXT)
