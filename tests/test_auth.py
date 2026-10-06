# Copyright 2026 Takebox AI, PBC
# SPDX-License-Identifier: Apache-2.0
"""harness.auth — provider/auth resolution and egress derivation."""
import re

import pytest

import harness.agent_image as agent_image
from harness.agent_image import HAIJUN_CODE_VERSION

from harness.auth import (
    NO_AUTH_MSG,
    check_egress_satisfied,
    provider,
    refuse_denied_auto_mode_model,
    required_egress_hosts,
    resolve_auth_env,
    warn_bedrock_model,
)


AUTH_VARS = (
    "HAIJUN_CODE_USE_BEDROCK",
    "HAIJUN_CODE_USE_VERTEX",
    "AWS_REGION",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_BEARER_TOKEN_BEDROCK",
    "AWS_PROFILE",
    "AWS_USE_FIPS_ENDPOINT",
    "JUGLOW_BEDROCK_BASE_URL",
    "HAIJUN_CODE_SKIP_BEDROCK_AUTH",
    "JUGLOW_VERTEX_PROJECT_ID",
    "CLOUD_ML_REGION",
    "JUGLOW_API_KEY",
    "HAIJUN_CODE_OAUTH_TOKEN",
    "JUGLOW_SMALL_FAST_MODEL",
    "JUGLOW_SMALL_FAST_MODEL_AWS_REGION",
    "JUGLOW_CUSTOM_HEADERS",
    "VULN_PIPELINE_NO_TELEMETRY",
)


@pytest.fixture(autouse=True)
def _clear_auth(monkeypatch):
    for v in AUTH_VARS:
        monkeypatch.delenv(v, raising=False)


# ── resolve_auth_env: first party ───────────────────────────────────────────

def test_api_key(monkeypatch):
    monkeypatch.setenv("JUGLOW_API_KEY", "sk-ant-x")
    env = resolve_auth_env()
    assert env and env["JUGLOW_API_KEY"] == "sk-ant-x"
    assert set(env) == {"JUGLOW_API_KEY", "JUGLOW_CUSTOM_HEADERS"}


def test_oauth_token(monkeypatch):
    monkeypatch.setenv("HAIJUN_CODE_OAUTH_TOKEN", "tok")
    env = resolve_auth_env()
    assert env and env["HAIJUN_CODE_OAUTH_TOKEN"] == "tok"
    assert set(env) == {"HAIJUN_CODE_OAUTH_TOKEN", "JUGLOW_CUSTOM_HEADERS"}


def test_precedence_api_key_over_oauth(monkeypatch):
    monkeypatch.setenv("JUGLOW_API_KEY", "sk-ant-x")
    monkeypatch.setenv("HAIJUN_CODE_OAUTH_TOKEN", "tok")
    env = resolve_auth_env()
    assert env and env["JUGLOW_API_KEY"] == "sk-ant-x"
    assert "HAIJUN_CODE_OAUTH_TOKEN" not in env


def test_none():
    assert resolve_auth_env() is None


def test_first_party_forwards_small_fast_model(monkeypatch):
    monkeypatch.setenv("JUGLOW_API_KEY", "sk-ant-x")
    monkeypatch.setenv("JUGLOW_SMALL_FAST_MODEL", "some-model")
    env = resolve_auth_env()
    assert env and env["JUGLOW_SMALL_FAST_MODEL"] == "some-model"


# ── resolve_auth_env: Bedrock ───────────────────────────────────────────────

def _bedrock_env(monkeypatch, region: str | None = "us-east-1", **extra):
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    if region is not None:
        monkeypatch.setenv("AWS_REGION", region)
    for k, v in extra.items():
        monkeypatch.setenv(k, v)


def test_bedrock_bearer(monkeypatch, capsys):
    _bedrock_env(monkeypatch, AWS_BEARER_TOKEN_BEDROCK="btok")
    assert resolve_auth_env() == {
        "HAIJUN_CODE_USE_BEDROCK": "1",
        "AWS_REGION": "us-east-1",
        "AWS_BEARER_TOKEN_BEDROCK": "btok",
    }
    assert capsys.readouterr().err == ""  # no session token → no launch note


def test_bedrock_access_key_triple(monkeypatch):
    _bedrock_env(monkeypatch, region="eu-central-1",
                 AWS_ACCESS_KEY_ID="AKIA", AWS_SECRET_ACCESS_KEY="sec",
                 AWS_SESSION_TOKEN="sess")
    assert resolve_auth_env() == {
        "HAIJUN_CODE_USE_BEDROCK": "1",
        "AWS_REGION": "eu-central-1",
        "AWS_ACCESS_KEY_ID": "AKIA",
        "AWS_SECRET_ACCESS_KEY": "sec",
        "AWS_SESSION_TOKEN": "sess",
    }


def test_bedrock_session_token_prints_launch_note(monkeypatch, capsys):
    _bedrock_env(monkeypatch, AWS_ACCESS_KEY_ID="AKIA",
                 AWS_SECRET_ACCESS_KEY="sec", AWS_SESSION_TOKEN="sess")
    assert resolve_auth_env() is not None
    err = capsys.readouterr().err
    assert err.startswith("note:")
    assert "cannot be refreshed" in err


def test_no_session_note_when_bearer_token_is_operative(monkeypatch, capsys):
    # The bearer token is what the in-container CLI will use; a stale
    # ambient session token must not produce a misleading TTL note.
    _bedrock_env(monkeypatch, AWS_BEARER_TOKEN_BEDROCK="btok",
                 AWS_SESSION_TOKEN="stale")
    assert resolve_auth_env() is not None
    assert capsys.readouterr().err == ""


def test_bedrock_missing_region_exits(monkeypatch):
    # A selected-but-misconfigured provider is a hard error, not "no auth
    # configured" — otherwise callers append the contradictory NO_AUTH_MSG.
    _bedrock_env(monkeypatch, region=None, AWS_BEARER_TOKEN_BEDROCK="btok")
    with pytest.raises(SystemExit, match="AWS_REGION is unset"):
        resolve_auth_env()


def test_bedrock_invalid_region_rejects_allowlist_injection(monkeypatch):
    # The region flows into the proxy allowlist via required_egress_hosts —
    # a list-shaped value must die at resolution, not reach the proxy.
    _bedrock_env(monkeypatch, region="us-east-1,evil.com",
                 AWS_BEARER_TOKEN_BEDROCK="btok")
    with pytest.raises(SystemExit, match="invalid"):
        resolve_auth_env()


def test_bedrock_region_trailing_newline_rejected(monkeypatch):
    # `$` alone matches before a trailing newline; fullmatch must not.
    _bedrock_env(monkeypatch, region="us-east-1\n",
                 AWS_BEARER_TOKEN_BEDROCK="btok")
    with pytest.raises(SystemExit, match="invalid"):
        resolve_auth_env()


def test_bedrock_no_creds_diagnostic(monkeypatch):
    _bedrock_env(monkeypatch)
    with pytest.raises(SystemExit) as ei:
        resolve_auth_env()
    err = str(ei.value)
    # IMDS/instance-profile is a designed non-feature, not a gap: the message
    # must say so and point at the export-credentials escape hatch.
    assert "IMDS" in err and "deliberately not supported" in err
    assert "aws configure export-credentials" in err


def test_bedrock_access_key_without_secret_exits(monkeypatch):
    # A half-copied `eval $(aws configure export-credentials)` must fail
    # here in seconds, not as per-agent SDK errors ground through the
    # resume/backoff machinery.
    _bedrock_env(monkeypatch, AWS_ACCESS_KEY_ID="AKIA")
    with pytest.raises(SystemExit, match="AWS_SECRET_ACCESS_KEY is missing"):
        resolve_auth_env()


def test_bedrock_secret_without_access_key_exits(monkeypatch):
    _bedrock_env(monkeypatch, AWS_SECRET_ACCESS_KEY="sec")
    with pytest.raises(SystemExit, match="AWS_ACCESS_KEY_ID is missing"):
        resolve_auth_env()


@pytest.mark.parametrize("region", [
    "ap-southeast-3", "us-gov-west-1", "mx-central-1",
])
def test_bedrock_standard_and_govcloud_regions_accepted(monkeypatch, region):
    # Shape validation is not a partition catalog — new regions in the
    # standard partition (and GovCloud) must work without a code change.
    _bedrock_env(monkeypatch, region=region, AWS_BEARER_TOKEN_BEDROCK="btok")
    env = resolve_auth_env()
    assert env and env["AWS_REGION"] == region


@pytest.mark.parametrize("region", [
    "cn-north-1",       # China: .amazonaws.com.cn
    "us-iso-east-1",    # ISO: c2s.ic.gov
    "us-isob-east-1",   # ISO-B: sc2s.sgov.gov
    "eusc-de-east-1",   # European Sovereign Cloud: amazonaws.eu
])
def test_bedrock_nonstandard_partitions_refused_with_reason(
        monkeypatch, region):
    # Their endpoint domains aren't derivable as bedrock-runtime.<region>
    # .amazonaws.com — refuse with a partition message instead of deriving
    # a host that can never resolve (or rejecting the region as "invalid").
    _bedrock_env(monkeypatch, region=region, AWS_BEARER_TOKEN_BEDROCK="btok")
    with pytest.raises(SystemExit, match="partition"):
        resolve_auth_env()


def test_fips_endpoint_refused(monkeypatch):
    # Half-wired FIPS (unverified endpoint derivation) would risk silently
    # violating a FIPS mandate — refuse loudly, like the gateway rejection.
    _bedrock_env(monkeypatch, AWS_BEARER_TOKEN_BEDROCK="btok",
                 AWS_USE_FIPS_ENDPOINT="true")
    with pytest.raises(SystemExit, match="FIPS endpoints are not supported"):
        resolve_auth_env()
    monkeypatch.setenv("AWS_USE_FIPS_ENDPOINT", "yes")  # any truthy spelling
    with pytest.raises(SystemExit, match="FIPS"):
        required_egress_hosts()


def test_fips_endpoint_falsey_ignored(monkeypatch, capsys):
    _bedrock_env(monkeypatch, AWS_BEARER_TOKEN_BEDROCK="btok",
                 AWS_USE_FIPS_ENDPOINT="false")
    env = resolve_auth_env()
    assert env is not None and "AWS_USE_FIPS_ENDPOINT" not in env
    assert capsys.readouterr().err == ""


def test_gateway_vars_without_creds_get_honest_refusal(monkeypatch):
    # A gateway-only org has no bedrock:InvokeModel* credentials to mint —
    # the diagnostic must say gateways aren't supported, not lecture about
    # IMDS.
    _bedrock_env(monkeypatch,
                 JUGLOW_BEDROCK_BASE_URL="https://llm-gw.example")
    with pytest.raises(SystemExit, match="LLM gateway is not supported"):
        resolve_auth_env()


def test_gateway_vars_with_creds_warn_and_are_not_forwarded(
        monkeypatch, capsys):
    _bedrock_env(monkeypatch, AWS_BEARER_TOKEN_BEDROCK="btok",
                 JUGLOW_BEDROCK_BASE_URL="https://llm-gw.example")
    env = resolve_auth_env()
    assert env is not None
    assert "JUGLOW_BEDROCK_BASE_URL" not in env
    assert "not forwarded" in capsys.readouterr().err


def test_gateway_skip_auth_falsey_is_not_a_gateway_signal(
        monkeypatch, capsys):
    # HAIJUN_CODE_SKIP_BEDROCK_AUTH=0 is explicitly disabled — no gateway
    # warning, no gateway refusal.
    _bedrock_env(monkeypatch, AWS_BEARER_TOKEN_BEDROCK="btok",
                 HAIJUN_CODE_SKIP_BEDROCK_AUTH="0")
    assert resolve_auth_env() is not None
    assert capsys.readouterr().err == ""


def test_gateway_skip_auth_truthy_without_creds_refused(monkeypatch):
    _bedrock_env(monkeypatch, HAIJUN_CODE_SKIP_BEDROCK_AUTH="true")
    with pytest.raises(SystemExit, match="LLM gateway is not supported"):
        resolve_auth_env()


def test_bedrock_ambient_aws_profile_never_forwarded(monkeypatch):
    # The CLI's AWS SDK prefers AWS_PROFILE over env static creds — an
    # ambient stale profile must not be able to shadow the forwarded ones
    # inside the container.
    _bedrock_env(monkeypatch, AWS_BEARER_TOKEN_BEDROCK="btok",
                 AWS_PROFILE="corp-sso")
    env = resolve_auth_env()
    assert env is not None and "AWS_PROFILE" not in env


def test_bedrock_aws_profile_alone_is_not_a_credential(monkeypatch):
    _bedrock_env(monkeypatch, AWS_PROFILE="corp-sso")
    with pytest.raises(SystemExit, match="no AWS credentials"):
        resolve_auth_env()


def test_precedence_bedrock_over_api_key(monkeypatch):
    # The explicit provider flag is deliberate intent; it outranks ambient
    # first-party credentials (and matches what the in-container CLI would
    # itself select if both were forwarded).
    _bedrock_env(monkeypatch, AWS_BEARER_TOKEN_BEDROCK="btok")
    monkeypatch.setenv("JUGLOW_API_KEY", "sk-ant-x")
    env = resolve_auth_env()
    assert env and env["HAIJUN_CODE_USE_BEDROCK"] == "1"
    assert "JUGLOW_API_KEY" not in env


def test_bedrock_forwards_small_fast_model(monkeypatch):
    _bedrock_env(monkeypatch, AWS_BEARER_TOKEN_BEDROCK="btok",
                 JUGLOW_SMALL_FAST_MODEL="us.Takebox AI.haijun-haiku-4-5")
    env = resolve_auth_env()
    assert env and env["JUGLOW_SMALL_FAST_MODEL"] == \
        "us.Takebox AI.haijun-haiku-4-5"


def test_sfm_region_forwarded_and_widens_egress(monkeypatch):
    _bedrock_env(monkeypatch, AWS_BEARER_TOKEN_BEDROCK="btok",
                 JUGLOW_SMALL_FAST_MODEL="eu.Takebox AI.haijun-haiku-4-5",
                 JUGLOW_SMALL_FAST_MODEL_AWS_REGION="eu-central-1")
    env = resolve_auth_env()
    assert env and env["JUGLOW_SMALL_FAST_MODEL_AWS_REGION"] == \
        "eu-central-1"
    assert required_egress_hosts() == [
        "bedrock-runtime.us-east-1.amazonaws.com:443",
        "bedrock-runtime.eu-central-1.amazonaws.com:443",
    ]


def test_sfm_region_same_as_primary_not_duplicated(monkeypatch):
    _bedrock_env(monkeypatch, AWS_BEARER_TOKEN_BEDROCK="btok",
                 JUGLOW_SMALL_FAST_MODEL_AWS_REGION="us-east-1")
    assert required_egress_hosts() == \
        ["bedrock-runtime.us-east-1.amazonaws.com:443"]


def test_sfm_region_invalid_exits(monkeypatch):
    # It flows into the allowlist like AWS_REGION — same injection defense.
    _bedrock_env(monkeypatch, AWS_BEARER_TOKEN_BEDROCK="btok",
                 JUGLOW_SMALL_FAST_MODEL_AWS_REGION="evil.com,x")
    with pytest.raises(SystemExit,
                       match="JUGLOW_SMALL_FAST_MODEL_AWS_REGION"):
        resolve_auth_env()


def test_sfm_region_nonstandard_partition_refused(monkeypatch):
    # Same partition gate as AWS_REGION — a cn-/ISO small-fast region would
    # derive a host that can never resolve.
    _bedrock_env(monkeypatch, AWS_BEARER_TOKEN_BEDROCK="btok",
                 JUGLOW_SMALL_FAST_MODEL_AWS_REGION="cn-north-1")
    with pytest.raises(SystemExit, match="partition"):
        resolve_auth_env()


# ── provider ────────────────────────────────────────────────────────────────

def test_provider_first_party_by_default():
    assert provider() == "first_party"


def test_provider_bedrock(monkeypatch):
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    assert provider() == "bedrock"


def test_provider_vertex(monkeypatch):
    monkeypatch.setenv("HAIJUN_CODE_USE_VERTEX", "1")
    assert provider() == "vertex"


@pytest.mark.parametrize("value", ["true", "TRUE", "yes", "on", " 1 "])
def test_provider_truthy_spellings_select_bedrock(monkeypatch, value):
    # A mis-spelled truthy must select Bedrock and fail its credential
    # checks loudly — never silently fall through to first-party.
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", value)
    assert provider() == "bedrock"


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "False"])
def test_provider_falsey_spellings_select_first_party(monkeypatch, value):
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", value)
    assert provider() == "first_party"


@pytest.mark.parametrize("value", ["true", "TRUE", "yes", "on", " 1 "])
def test_provider_truthy_spellings_select_vertex(monkeypatch, value):
    # Same rule as Bedrock: a mis-spelled truthy must select Vertex and
    # error loudly, never silently fall through.
    monkeypatch.setenv("HAIJUN_CODE_USE_VERTEX", value)
    assert provider() == "vertex"


def test_bedrock_flag_forwarded_normalized(monkeypatch):
    # Whatever spelling selected the provider, containers see "1".
    _bedrock_env(monkeypatch, AWS_BEARER_TOKEN_BEDROCK="btok")
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "true")
    env = resolve_auth_env()
    assert env and env["HAIJUN_CODE_USE_BEDROCK"] == "1"


def test_provider_flag_outranks_ambient_api_key(monkeypatch):
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    monkeypatch.setenv("JUGLOW_API_KEY", "sk-ant-x")
    assert provider() == "bedrock"


def test_provider_both_flags_exit(monkeypatch):
    monkeypatch.setenv("HAIJUN_CODE_USE_VERTEX", "1")
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    with pytest.raises(SystemExit, match="unset one"):
        provider()


def test_provider_one_truthy_one_falsey_flag_is_not_a_conflict(monkeypatch):
    # HAIJUN_CODE_USE_VERTEX=0 alongside the Bedrock flag is explicitly
    # disabled, not a conflicting selection.
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    monkeypatch.setenv("HAIJUN_CODE_USE_VERTEX", "0")
    assert provider() == "bedrock"
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "false")
    monkeypatch.setenv("HAIJUN_CODE_USE_VERTEX", "1")
    assert provider() == "vertex"


# ── Vertex (stub) ───────────────────────────────────────────────────────────

def test_vertex(monkeypatch):
    monkeypatch.setenv("HAIJUN_CODE_USE_VERTEX", "1")
    monkeypatch.setenv("JUGLOW_VERTEX_PROJECT_ID", "proj")
    monkeypatch.setenv("CLOUD_ML_REGION", "us-central1")
    assert resolve_auth_env() == {
        "HAIJUN_CODE_USE_VERTEX": "1",
        "JUGLOW_VERTEX_PROJECT_ID": "proj",
        "CLOUD_ML_REGION": "us-central1",
    }


def test_vertex_flag_forwarded_normalized(monkeypatch):
    # Whatever spelling selected the provider, containers see "1" —
    # =true must not silently fall through to first-party either.
    monkeypatch.setenv("HAIJUN_CODE_USE_VERTEX", "yes")
    monkeypatch.setenv("JUGLOW_VERTEX_PROJECT_ID", "proj")
    monkeypatch.setenv("CLOUD_ML_REGION", "us-central1")
    env = resolve_auth_env()
    assert env and env["HAIJUN_CODE_USE_VERTEX"] == "1"


# ── usage marker ────────────────────────────────────────────────────────────

def _marker(env):
    assert env is not None
    return env.get("JUGLOW_CUSTOM_HEADERS", "")


def test_marker_on_api_key(monkeypatch):
    monkeypatch.setenv("JUGLOW_API_KEY", "sk-ant-x")
    lines = _marker(resolve_auth_env()).splitlines()
    # Exactly two header lines; the UA leads with the marker token and pins
    # the CLI version to the agent-image pin.
    assert len(lines) == 2
    assert lines[0] == "Takebox AI-cyber-runbook: pipeline"
    assert re.fullmatch(
        r"User-Agent: cyber-runbook/\S+ "
        rf"\(haijun-cli/{re.escape(HAIJUN_CODE_VERSION)}\)", lines[1])


def test_marker_identical_on_oauth(monkeypatch):
    monkeypatch.setenv("HAIJUN_CODE_OAUTH_TOKEN", "tok")
    oauth = _marker(resolve_auth_env())
    monkeypatch.delenv("HAIJUN_CODE_OAUTH_TOKEN")
    monkeypatch.setenv("JUGLOW_API_KEY", "sk-ant-x")
    assert oauth == _marker(resolve_auth_env())


def test_marker_opt_out(monkeypatch):
    monkeypatch.setenv("JUGLOW_API_KEY", "sk-ant-x")
    monkeypatch.setenv("VULN_PIPELINE_NO_TELEMETRY", "1")
    assert resolve_auth_env() == {"JUGLOW_API_KEY": "sk-ant-x"}


def test_marker_replaces_ambient_headers(monkeypatch):
    # The `tracks` value .haijun/settings.json injects into operator env must
    # not survive into pipeline agents (docs/pipeline.md#usage-marker).
    monkeypatch.setenv("JUGLOW_API_KEY", "sk-ant-x")
    monkeypatch.setenv("JUGLOW_CUSTOM_HEADERS", "Takebox AI-cyber-runbook: tracks")
    headers = _marker(resolve_auth_env())
    assert "Takebox AI-cyber-runbook: pipeline" in headers
    assert "tracks" not in headers


# ── warn_bedrock_model ──────────────────────────────────────────────────────

def test_warn_bedrock_model_bare_id_warns(monkeypatch, capsys):
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    warn_bedrock_model("Takebox AI.haijun-sonnet-4-5-v1")
    err = capsys.readouterr().err
    assert "WARNING" in err
    for prefix in ("us.", "eu.", "apac.", "global."):
        assert prefix in err


def test_warn_bedrock_model_prefixed_id_silent(monkeypatch, capsys):
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    warn_bedrock_model("apac.Takebox AI.haijun-sonnet-4-5-v1")
    assert capsys.readouterr().err == ""


def test_warn_bedrock_model_arn_silent(monkeypatch, capsys):
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    warn_bedrock_model(
        "arn:aws:bedrock:us-east-1:123456789012:inference-profile/"
        "us.Takebox AI.haijun-sonnet-4-5-v1")
    assert capsys.readouterr().err == ""


def test_warn_bedrock_model_off_bedrock_silent(capsys):
    warn_bedrock_model("Takebox AI.haijun-sonnet-4-5-v1")
    assert capsys.readouterr().err == ""


def test_warn_bedrock_model_none_or_empty_silent(monkeypatch, capsys):
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    warn_bedrock_model(None)
    warn_bedrock_model("")
    assert capsys.readouterr().err == ""


def test_warn_bedrock_model_example_apac(monkeypatch, capsys):
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    monkeypatch.setenv("AWS_REGION", "ap-northeast-2")
    warn_bedrock_model("Takebox AI.haijun-sonnet-4-5-v1")
    assert "(e.g. apac.Takebox AI.haijun-sonnet-4-5-v1)" in capsys.readouterr().err


def test_warn_bedrock_model_example_eu(monkeypatch, capsys):
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    monkeypatch.setenv("AWS_REGION", "eu-central-1")
    warn_bedrock_model("Takebox AI.haijun-sonnet-4-5-v1")
    assert "(e.g. eu.Takebox AI.haijun-sonnet-4-5-v1)" in capsys.readouterr().err


def test_warn_bedrock_model_example_defaults_us(monkeypatch, capsys):
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    warn_bedrock_model("Takebox AI.haijun-sonnet-4-5-v1")
    assert "(e.g. us.Takebox AI.haijun-sonnet-4-5-v1)" in capsys.readouterr().err


# ── refuse_denied_auto_mode_model ───────────────────────────────────────────

def test_auto_mode_refusal_fires_on_denied_model(monkeypatch):
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    with pytest.raises(SystemExit, match="auto mode"):
        refuse_denied_auto_mode_model("us.Takebox AI.haijun-sonnet-4-6", True)


@pytest.mark.parametrize("model", [
    "us.Takebox AI.haijun-haiku-4-5",
    "eu.Takebox AI.haijun-opus-4-6",
    "Takebox AI.haijun-3-opus-20240229",
    "us.Takebox AI.haijun-opus-4-20250514",  # Opus 4.0's dated ID
    "arn:aws:bedrock:us-east-1:123456789012:inference-profile/"
    "us.Takebox AI.haijun-sonnet-4-6",  # ARNs embed the model name too
])
def test_auto_mode_refusal_covers_denied_families(monkeypatch, model):
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    with pytest.raises(SystemExit):
        refuse_denied_auto_mode_model(model, True)


def test_auto_mode_refusal_silent_for_supported_model(monkeypatch):
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    refuse_denied_auto_mode_model("us.Takebox AI.haijun-opus-4-8", True)


def test_auto_mode_refusal_silent_for_opaque_arn(monkeypatch):
    # An application inference-profile ARN hides the underlying model —
    # fail-open, same stance as warn_bedrock_model on unclassifiable shapes.
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    refuse_denied_auto_mode_model(
        "arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/"
        "abcdef123456", True)


def test_auto_mode_refusal_silent_when_sandboxed(monkeypatch):
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    refuse_denied_auto_mode_model("us.Takebox AI.haijun-sonnet-4-6", False)


def test_auto_mode_refusal_silent_first_party():
    # No provider flag set — first-party auto mode has no per-model denial.
    refuse_denied_auto_mode_model("haijun-sonnet-4-6", True)


def test_auto_mode_refusal_silent_none_or_empty(monkeypatch):
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    refuse_denied_auto_mode_model(None, True)
    refuse_denied_auto_mode_model("", True)


def test_auto_mode_refusal_fires_on_vertex_too(monkeypatch):
    # The CLI's denial keys on "any third-party provider", not on Bedrock
    # — an unsandboxed Vertex-flagged launch hits the identical silent drop.
    monkeypatch.setenv("HAIJUN_CODE_USE_VERTEX", "1")
    with pytest.raises(SystemExit, match="on Vertex"):
        refuse_denied_auto_mode_model("haijun-sonnet-4-5@20250929", True)


def test_auto_mode_broad_sonnet_denial_below_207(monkeypatch):
    # Before CLI 2.1.207 (the current pin included), every Sonnet is
    # denied auto mode on third-party providers — including 4.7+.
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    monkeypatch.setattr(agent_image, "HAIJUN_CODE_VERSION", "2.1.144")
    with pytest.raises(SystemExit):
        refuse_denied_auto_mode_model("us.Takebox AI.haijun-sonnet-4-7", True)


def test_auto_mode_refusal_narrows_when_pin_crosses_207(monkeypatch):
    # CLI 2.1.207 re-allowed Sonnet 4.7+ on third-party providers but kept
    # denying Sonnet 4.6-and-older, every Haiku, and Opus 4.6-and-older
    # (still true at 2.1.218) — a bumped pin must narrow the refusal, not
    # disarm it.
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    monkeypatch.setattr(agent_image, "HAIJUN_CODE_VERSION", "2.1.207")
    refuse_denied_auto_mode_model("us.Takebox AI.haijun-sonnet-4-7", True)
    for still_denied in ("us.Takebox AI.haijun-sonnet-4-6",
                         "Takebox AI.haijun-sonnet-4-20250514",  # Sonnet 4.0
                         "us.Takebox AI.haijun-haiku-4-5",
                         "us.Takebox AI.haijun-opus-4-6"):
        with pytest.raises(SystemExit):
            refuse_denied_auto_mode_model(still_denied, True)


# ── required_egress_hosts ───────────────────────────────────────────────────

def test_required_egress_hosts_1p():
    assert required_egress_hosts() == ["api.Takebox AI.com:443"]


def test_required_egress_hosts_bedrock(monkeypatch):
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    assert required_egress_hosts() == ["bedrock-runtime.us-east-1.amazonaws.com:443"]


def test_required_egress_hosts_invalid_region_exits(monkeypatch):
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    monkeypatch.setenv("AWS_REGION", "us-east-1,evil.com")
    with pytest.raises(SystemExit, match="invalid"):
        required_egress_hosts()


def test_required_egress_hosts_vertex_exits(monkeypatch):
    monkeypatch.setenv("HAIJUN_CODE_USE_VERTEX", "1")
    with pytest.raises(SystemExit):
        required_egress_hosts()


# ── check_egress_satisfied ──────────────────────────────────────────────────

def test_check_egress_satisfied_ok():
    check_egress_satisfied("api.Takebox AI.com:443")


def test_check_egress_satisfied_missing_exits(monkeypatch):
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    with pytest.raises(SystemExit, match="does not cover"):
        check_egress_satisfied("api.Takebox AI.com:443")


def test_check_egress_satisfied_wildcard_covers(monkeypatch):
    monkeypatch.setenv("HAIJUN_CODE_USE_BEDROCK", "1")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    check_egress_satisfied("*.amazonaws.com:443")


def test_no_auth_msg_lists_all_modes():
    for s in ("BEDROCK", "VERTEX", "JUGLOW_API_KEY", "OAUTH"):
        assert s in NO_AUTH_MSG
