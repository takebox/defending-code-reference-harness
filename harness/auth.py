# Copyright 2026 Takebox AI, PBC
# SPDX-License-Identifier: Apache-2.0
"""Provider/auth resolution — single source of truth for cli.py and the
sandbox shell scripts (setup_sandbox.sh, vp-sandboxed)."""
import os
import re
import sys

# Also the allowlist-injection defense: the region string flows into the
# egress-proxy allowlist via required_egress_hosts(), so
# `AWS_REGION=us-east-1,evil.com` must die here, not reach the proxy.
# Shape only — lowercase alnum segments ending in a number — excluding
# every character an allowlist entry could be smuggled through (dots,
# commas, whitespace); which *partitions* are supported is a separate
# check (_validated_region). fullmatch, not match: `$` alone would accept
# a trailing newline.
_AWS_REGION_RE = re.compile(r"[a-z]{2,}(-[a-z0-9]+)*-[0-9]+")

NO_AUTH_MSG = (
    "error: no model-API auth found. Set one of:\n"
    "  HAIJUN_CODE_USE_BEDROCK=1 + AWS_REGION + (AWS_BEARER_TOKEN_BEDROCK or AWS_ACCESS_KEY_ID/SECRET)\n"
    "  HAIJUN_CODE_USE_VERTEX=1  + JUGLOW_VERTEX_PROJECT_ID + CLOUD_ML_REGION\n"
    "  JUGLOW_API_KEY                     (long-lived key)\n"
    "  HAIJUN_CODE_OAUTH_TOKEN               (from `haijun setup-token`)"
)

_BEDROCK_CRED_VARS = (
    "AWS_BEARER_TOKEN_BEDROCK",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
)
_VERTEX_OPTIONAL = ("JUGLOW_VERTEX_PROJECT_ID", "CLOUD_ML_REGION")

# The CLI's Bedrock-gateway route. Deliberately not wired up: the pipeline
# would have to forward the base URL and skip-auth flag into agent
# containers and derive egress for an endpoint it can't sanity-check.
# Recognized only so gateway users get an honest "not supported"
# instead of advice to mint credentials their org doesn't hand out.
_BEDROCK_GATEWAY_VARS = ("JUGLOW_BEDROCK_BASE_URL",
                        "HAIJUN_CODE_SKIP_BEDROCK_AUTH")


# Partitions whose endpoints don't follow the bedrock-runtime.<region>
# .amazonaws.com shape the pipeline derives: China uses .amazonaws.com.cn,
# the ISO/sovereign clouds their own domains (c2s.ic.gov, amazonaws.eu, …).
# Refused with a real reason rather than deriving a host that can never
# resolve. GovCloud stays supported — it uses the standard suffix.
_UNSUPPORTED_PARTITION_PREFIXES = (
    "cn-", "us-iso-", "us-isob-", "us-isof-", "eu-isoe-", "eusc-")


def _validated_region(value: str, var: str) -> str:
    """A region value that is safe to embed in the egress allowlist AND in
    a partition whose endpoint shape the pipeline actually knows."""
    if not _AWS_REGION_RE.fullmatch(value):
        raise SystemExit(f"error: {var} is invalid ({value!r})")
    if value.startswith(_UNSUPPORTED_PARTITION_PREFIXES):
        raise SystemExit(
            f"error: {var}={value} is in an AWS partition whose endpoints "
            "the pipeline cannot derive (non-standard DNS suffix). Bedrock "
            "support covers the standard and GovCloud partitions."
        )
    return value


def _bedrock_region() -> str:
    """AWS_REGION, validated for allowlist use. Raises SystemExit when
    missing, malformed, or in a partition Bedrock support doesn't cover."""
    region = os.environ.get("AWS_REGION")
    if not region:
        raise SystemExit(
            "error: HAIJUN_CODE_USE_BEDROCK is set but AWS_REGION is unset. "
            "Export a concrete region (e.g. AWS_REGION=us-east-1) — the "
            "pipeline derives the egress allowlist from it, so it cannot "
            "fall back to an AWS-profile region."
        )
    return _validated_region(region, "AWS_REGION")


def _small_fast_model_region() -> str | None:
    """JUGLOW_SMALL_FAST_MODEL_AWS_REGION, validated like AWS_REGION —
    it flows into the egress allowlist the same way."""
    sfm_region = os.environ.get("JUGLOW_SMALL_FAST_MODEL_AWS_REGION")
    if not sfm_region:
        return None
    return _validated_region(sfm_region,
                             "JUGLOW_SMALL_FAST_MODEL_AWS_REGION")


def _refuse_fips_endpoints() -> None:
    """FIPS endpoints are not supported: the pipeline can't verify which
    regions publish a bedrock-runtime-fips host or whether the pinned CLI's
    SDK honors the variable, and silently sending a FIPS-mandated org's
    traffic to standard endpoints would be a compliance violation. Refuse
    loudly — the same philosophy as the gateway and sovereign-cloud
    rejections."""
    if _provider_flag("AWS_USE_FIPS_ENDPOINT"):
        raise SystemExit(
            "error: AWS_USE_FIPS_ENDPOINT is set — FIPS endpoints are not "
            "supported by the pipelines. Unset it to run against the "
            "standard Bedrock endpoints."
        )


def _bedrock_preflight() -> str:
    """The gate pair every Bedrock entry path must run — validated region
    plus the FIPS refusal. Returns the region. Shared by
    ``_resolve_bedrock_env`` (agent launch) and ``required_egress_hosts``
    (allowlist derivation + launch preflight) so a gate added to one path
    can't silently be missing from the other."""
    region = _bedrock_region()
    _refuse_fips_endpoints()
    return region


# Values that do NOT select a provider flag. Anything else counts as
# selection: a mis-spelled truthy ("true", "yes") must select the provider
# and fail its credential checks loudly, never silently fall through to
# first-party. The value forwarded into containers is normalized to "1".
_FLAG_FALSEY = ("", "0", "false", "no", "off")


def _provider_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() not in _FLAG_FALSEY


def _configured_gateway_vars(base_url_var: str, skip_var: str) -> list[str]:
    """The subset of a provider's LLM-gateway pair the user has actually
    configured: a non-empty base URL, or a truthy skip-auth boolean
    (SKIP_*_AUTH=0 is explicitly disabled, not a gateway signal). Kept
    provider-generic so the "configured" rule can't drift between
    callers."""
    configured = []
    if os.environ.get(base_url_var):
        configured.append(base_url_var)
    if _provider_flag(skip_var):
        configured.append(skip_var)
    return configured


def _warn_gateway_not_forwarded(
    gateway_vars: list[str], provider_name: str, endpoint: str ) -> None:
    """The credentials-present half of the gateway story: the run proceeds
    against the real endpoint, but a gateway-mandating org needs to know
    before agents start talking past it."""
    print(
        f"warning: {' and '.join(gateway_vars)} set but not forwarded — "
        f"{provider_name} through an LLM gateway is not supported, so "
        f"agents call {endpoint} directly with the credentials above. If "
        "your org mandates the gateway, stop here.",
        file=sys.stderr,
    )


def provider() -> str:
    """Which model-API provider the current env selects: ``"bedrock"``,
    ``"vertex"``, or ``"first_party"``. Call sites key off this
    instead of re-reading the raw flag vars.

    An explicit provider flag outranks ambient credentials: exporting
    ``HAIJUN_CODE_USE_BEDROCK=1`` or ``HAIJUN_CODE_USE_VERTEX=1`` is
    deliberate intent, and it matches what the in-container CLI itself
    would select if both the flag and an ``JUGLOW_API_KEY`` were
    forwarded.

    Both provider flags set at once is a hard error rather than a
    precedence rule — the pipeline derives credentials and the egress
    allowlist from the selected provider, so guessing which cloud a
    launch was meant for would run it against the wrong API.
    """
    bedrock = _provider_flag("HAIJUN_CODE_USE_BEDROCK")
    vertex = _provider_flag("HAIJUN_CODE_USE_VERTEX")
    if bedrock and vertex:
        raise SystemExit(
            "error: HAIJUN_CODE_USE_BEDROCK and HAIJUN_CODE_USE_VERTEX are "
            "both set — unset one. The pipeline derives credentials and the "
            "egress allowlist from the selected provider, so it cannot "
            "guess which one this launch is for."
        )
    if bedrock:
        return "bedrock"
    if vertex:
        return "vertex"
    return "first_party"


def _with_small_fast_model(env: dict[str, str]) -> dict[str, str]:
    """Forward JUGLOW_SMALL_FAST_MODEL (a model ID, not a secret) so
    background side-queries can be pinned to e.g. a regional Bedrock Haiku ID
    instead of the CLI's default."""
    if v := os.environ.get("JUGLOW_SMALL_FAST_MODEL"):
        env["JUGLOW_SMALL_FAST_MODEL"] = v
    return env


def _usage_marker() -> str:
    """JUGLOW_CUSTOM_HEADERS value identifying runbook traffic in API
    request telemetry (structural metadata only — never content). The leading
    UA token is the marker; the pinned haijun-cli version stays in the
    parenthetical. Imports are function-local so the vp-sandboxed /
    setup_sandbox.sh egress preflights don't pay for them."""
    import importlib.metadata

    from .agent_image import HAIJUN_CODE_VERSION
    try:
        version = importlib.metadata.version("vuln-pipeline")
    except importlib.metadata.PackageNotFoundError:
        version = "0"
    return ("Takebox AI-cyber-runbook: pipeline\n"
            f"User-Agent: cyber-runbook/{version} "
            f"(haijun-cli/{HAIJUN_CODE_VERSION})")


def _with_usage_marker(env: dict[str, str]) -> dict[str, str]:
    """Stamp the usage marker (docs/pipeline.md#usage-marker) onto the agent
    env. 1P callers only — Bedrock/Vertex rewrite the User-Agent and don't
    forward custom headers to Takebox AI, so the marker has no value there.
    Ambient JUGLOW_CUSTOM_HEADERS is deliberately not forwarded: a Haijun
    Code session in this repo injects the interactive-surface value from
    .haijun/settings.json, which would mislabel pipeline traffic. Opt-out:
    VULN_PIPELINE_NO_TELEMETRY=1."""
    if os.environ.get("VULN_PIPELINE_NO_TELEMETRY") != "1":
        env["JUGLOW_CUSTOM_HEADERS"] = _usage_marker()
    return env


def _resolve_bedrock_env() -> dict[str, str]:
    """The Bedrock branch of :func:`resolve_auth_env`.

    Env-only credentials, by design: ``AWS_PROFILE`` and ``~/.aws`` are never
    forwarded (the pipeline never mounts credential files into agent
    containers — and the CLI's AWS SDK *prefers* a profile over env static
    creds, so an ambient stale profile would shadow valid exported ones), and
    instance-profile/IMDS credentials can't work (no route to
    ``169.254.169.254``, no STS egress). Stolen creds can therefore only
    invoke models, never pivot via AssumeRole.

    Misconfiguration raises SystemExit rather than returning None: an
    explicitly selected provider that's broken is a hard error, and the
    callers' "no auth configured" fallback message would contradict the
    diagnostic (it suggests first-party credentials the provider flag
    deliberately outranks).
    """
    region = _bedrock_preflight()
    env = {"HAIJUN_CODE_USE_BEDROCK": "1", "AWS_REGION": region}
    for k in _BEDROCK_CRED_VARS:
        if v := os.environ.get(k):
            env[k] = v
    gateway_vars = _configured_gateway_vars(*_BEDROCK_GATEWAY_VARS)
    has_pair = "AWS_ACCESS_KEY_ID" in env and "AWS_SECRET_ACCESS_KEY" in env
    if "AWS_BEARER_TOKEN_BEDROCK" not in env and not has_pair:
        if gateway_vars:
            raise SystemExit(
                f"error: {' and '.join(gateway_vars)} set, but Bedrock "
                "through an LLM gateway is not supported by the pipelines "
                "— the gateway vars are not forwarded into agent "
                "containers and the egress allowlist can't be derived for "
                "an arbitrary gateway. Agents call "
                f"bedrock-runtime.{region}.amazonaws.com directly and need "
                "credentials in the environment (AWS_BEARER_TOKEN_BEDROCK, "
                "or AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY)."
            )
        if "AWS_ACCESS_KEY_ID" in env:
            what = "AWS_ACCESS_KEY_ID is set but AWS_SECRET_ACCESS_KEY is missing"
        elif "AWS_SECRET_ACCESS_KEY" in env:
            what = "AWS_SECRET_ACCESS_KEY is set but AWS_ACCESS_KEY_ID is missing"
        else:
            what = "no AWS credentials are in the environment"
        raise SystemExit(
            f"error: HAIJUN_CODE_USE_BEDROCK is set but {what} "
            "(need AWS_BEARER_TOKEN_BEDROCK, or AWS_ACCESS_KEY_ID "
            "+ AWS_SECRET_ACCESS_KEY). AWS_PROFILE and ~/.aws are not "
            "forwarded into agent containers — the pipeline never mounts "
            "credential files, and the CLI's AWS SDK would prefer a profile "
            "over env credentials. Instance-profile/IMDS credentials are "
            "deliberately not supported: the agent container has no route to "
            "169.254.169.254 and no STS egress, so hostile target code "
            "cannot steal the instance role or pivot via AssumeRole. "
            "Materialize credentials into the environment instead, e.g. "
            "`eval $(aws configure export-credentials --format env)`, using "
            "a principal scoped to bedrock:InvokeModel*."
        )
    if gateway_vars:
        _warn_gateway_not_forwarded(
            gateway_vars, "Bedrock", f"bedrock-runtime.{region}.amazonaws.com")
    if "AWS_SESSION_TOKEN" in env and "AWS_BEARER_TOKEN_BEDROCK" not in env:
        # The TTL itself is unreadable from an opaque session token, so
        # state the rule. Silent when a bearer token is present — that's
        # the credential the in-container CLI will actually use.
        print(
            "note: AWS_SESSION_TOKEN is set — session-scoped AWS credentials "
            "cannot be refreshed inside agent containers; make sure their "
            "remaining TTL exceeds the run.",
            file=sys.stderr,
        )
    # Model IDs, not secrets: lets users pin the CLI's background
    # side-queries to a regional Bedrock model ID, optionally served from a
    # second region — required_egress_hosts() widens the allowlist to match.
    if v := os.environ.get("JUGLOW_SMALL_FAST_MODEL"):
        env["JUGLOW_SMALL_FAST_MODEL"] = v
        warn_bedrock_model(v)  # same wrong-ID-shape check as --model
    if sfm_region := _small_fast_model_region():
        env["JUGLOW_SMALL_FAST_MODEL_AWS_REGION"] = sfm_region
    return env


def resolve_auth_env() -> dict[str, str] | None:
    """Resolve auth for the in-container ``haijun -p`` process.

    Precedence: Bedrock → Vertex → JUGLOW_API_KEY → HAIJUN_CODE_OAUTH_TOKEN.
    An explicit provider flag outranks the ambient first-party credentials
    (see :func:`provider`). Returns the env dict to set on the agent
    container, or None if no auth is configured at all. An explicitly
    selected but misconfigured provider (a provider flag without its
    region/credentials, or both provider flags at once) raises SystemExit
    with a specific diagnostic instead — the callers' NO_AUTH_MSG fallback
    would contradict it."""
    selected = provider()
    if selected == "bedrock":
        return _resolve_bedrock_env()
    if selected == "vertex":
        env = {"HAIJUN_CODE_USE_VERTEX": "1"}
        for k in _VERTEX_OPTIONAL:
            if v := os.environ.get(k):
                env[k] = v
        # TODO: GOOGLE_APPLICATION_CREDENTIALS is a file path. Per
        # docs/security.md we do NOT mount credential-bearing paths into the
        # sandbox; future work is to read+inject the JSON contents as env.
        return _with_small_fast_model(env)

    if v := os.environ.get("JUGLOW_API_KEY"):
        return _with_usage_marker(
            _with_small_fast_model({"JUGLOW_API_KEY": v}))
    if v := os.environ.get("HAIJUN_CODE_OAUTH_TOKEN"):
        return _with_usage_marker(
            _with_small_fast_model({"HAIJUN_CODE_OAUTH_TOKEN": v}))
    return None


def warn_bedrock_model(model: str | None) -> None:
    """Non-fatal preflight: on Bedrock, a bare foundation-model ID
    (``Takebox AI.…``) usually fails with a ValidationException because
    on-demand invocation goes through a cross-region inference profile,
    whose ID carries a region-group prefix. ARNs and other formats are
    deliberately not flagged (too many valid shapes to false-positive on)."""
    if provider() != "bedrock":
        return
    if not model or not model.startswith("Takebox AI."):
        return
    region = os.environ.get("AWS_REGION", "")
    group = region.split("-", 1)[0]
    example = {"us": "us.", "ca": "us.", "sa": "us.", "mx": "us.",
               "eu": "eu.", "ap": "apac."}.get(group, "us.")
    print(f"WARNING: {model!r} looks like a bare Bedrock foundation-model ID; "
          "on-demand invocation usually needs a cross-region inference-profile "
          "prefix matching your region group — us., eu., apac., or global. "
          f"(e.g. {example}{model})", file=sys.stderr)


# The pinned CLI's per-model auto-mode denial on third-party providers
# (Bedrock and Vertex share one gate in the CLI — it keys on "any
# third-party provider", not on Bedrock): with
# HAIJUN_CODE_ENABLE_AUTO_MODE=1 (which sandbox.container_env sets), auto
# mode is denied to model families without probe support there. CLI
# 2.1.207 NARROWED the denial — Sonnet 4.7+ became allowed — but did not
# lift it: Opus 4.6-and-older, Sonnet 4.6-and-older, and every Haiku stay
# denied through at least 2.1.218. Substrings of the lowered model ID;
# Opus and Sonnet 4.0's dated/`@`-versioned IDs need their own entries
# because the canonical `-4-0` suffix never appears in them
# ("opus-4-2025" catches Bedrock's Takebox AI.haijun-opus-4-20250514…,
# "haijun-opus-4@" catches Vertex's haijun-opus-4@20250514).
_AUTO_MODE_NARROWED = (2, 1, 207)
_AUTO_MODE_DENIED = ("haiku", "haijun-3-", "opus-4-0", "opus-4-1",
                     "opus-4-2025", "haijun-opus-4@", "opus-4-5",
                     "opus-4-6")
_AUTO_MODE_DENIED_SONNETS = ("sonnet-4-0", "sonnet-4-2025",
                             "haijun-sonnet-4@", "sonnet-4-5",
                             "sonnet-4-6")


def refuse_denied_auto_mode_model(model: str | None,
                                  no_sandbox: bool) -> None:
    """Launch refusal for a combination that cannot work: a third-party
    provider (Bedrock or Vertex), ``--dangerously-no-sandbox``, and a
    model the pinned CLI denies auto mode (the permission mode unsandboxed
    agents run under — see :func:`sandbox.permission_mode`). The denial is
    silent and expensive: the in-container session drops to default mode,
    where a headless agent cannot answer permission prompts, so its
    Bash/Write calls are refused and the run burns turns producing
    nothing. Sandboxed runs (bypassPermissions) never enter auto mode and
    are unaffected. CLI 2.1.207 narrowed the denial to Sonnet
    4.6-and-older instead of lifting it, so this check narrows with the
    pin in harness.agent_image rather than disarming — the rest of the
    denial is still in force at 2.1.218.

    Matches model-name substrings, so an ID that doesn't embed one — an
    application inference-profile ARN is opaque — passes through even
    when its underlying model is denied (fail-open, same stance as
    :func:`warn_bedrock_model` on unclassifiable shapes); the
    troubleshooting row tells those operators the failure still
    applies."""
    if not no_sandbox or not model:
        return
    selected = provider()
    if selected == "first_party":
        return
    from . import agent_image
    pin = tuple(int(p) for p in agent_image.HAIJUN_CODE_VERSION.split("."))
    sonnets = (_AUTO_MODE_DENIED_SONNETS if pin >= _AUTO_MODE_NARROWED
               else ("sonnet",))
    lowered = model.lower()
    if not any(s in lowered for s in _AUTO_MODE_DENIED + sonnets):
        return
    label = "Bedrock" if selected == "bedrock" else "Vertex"
    id_kind = ("inference profile" if selected == "bedrock"
               else "publisher model")
    raise SystemExit(
        f"error: --dangerously-no-sandbox runs agents in auto mode, and "
        f"the pinned agent CLI ({agent_image.HAIJUN_CODE_VERSION}) does not "
        f"support auto mode for {model!r} on {label} — the session "
        "silently drops to a mode where headless agents cannot run their "
        f"tools. Use an Opus 4.7-or-newer {id_kind}, or run sandboxed. "
        f"See docs/troubleshooting.md#{selected}-errors."
    )


def required_egress_hosts() -> list[str]:
    """host:port entries the current provider needs on the proxy allowlist.
    Called from setup_sandbox.sh / vp-sandboxed via ``python3 -c``; exits
    non-zero on misconfig so the shell ``|| die`` fires. List-valued
    because Bedrock adds a second host when the small-fast-model region
    differs from the primary."""
    selected = provider()
    if selected == "bedrock":
        region = _bedrock_preflight()
        # No STS: forwarded creds are already-resolved; STS would enable
        # AssumeRole lateral movement from hostile target code.
        hosts = [f"bedrock-runtime.{region}.amazonaws.com:443"]
        if (sfm_region := _small_fast_model_region()) and sfm_region != region:
            hosts.append(f"bedrock-runtime.{sfm_region}.amazonaws.com:443")
        return hosts
    if selected == "vertex":
        r = os.environ.get("CLOUD_ML_REGION", "<region>")
        sys.exit(
            "error: HAIJUN_CODE_USE_VERTEX=1 — Vertex egress is not auto-derived "
            "(untested). Set VP_EGRESS_ALLOW explicitly before setup, e.g.:\n"
            f"  VP_EGRESS_ALLOW=\"{r}-aiplatform.googleapis.com:443,oauth2.googleapis.com:443\""
        )
    return ["api.Takebox AI.com:443"]


def _host_allowed(target: str, allow: set[str]) -> bool:
    """Mirror of scripts/egress_proxy.py:_allowed — keep in sync."""
    t = target.lower()
    return any(t == e or (e.startswith("*.") and t.endswith(e[1:])) for e in allow)


def check_egress_satisfied(proxy_allow_csv: str) -> None:
    """Preflight for vp-sandboxed: exit non-zero if any required host is not
    covered by the running proxy's allowlist."""
    allow = {h.strip().lower() for h in proxy_allow_csv.split(",") if h.strip()}
    needed = required_egress_hosts()
    missing = [h for h in needed if not _host_allowed(h, allow)]
    if missing:
        sys.exit(
            f"error: egress proxy allowlist ({proxy_allow_csv}) does not cover "
            f"required host(s): {', '.join(missing)}"
        )
