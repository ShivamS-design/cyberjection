"""Input-validation hardening: output-path containment, target-URL SSRF
guards, and payload size ceilings.

Each function here is a pure, synchronous check with no I/O of its own
(no network calls, no filesystem writes) so every one is cheap to call on
every request and trivial to hard-test with adversarial inputs.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from cyberjection.utils.exceptions import (
    PathTraversalError,
    PayloadTooLargeError,
    UnsafeTargetURLError,
)

DEFAULT_MAX_PAYLOAD_BYTES = 1_000_000  # 1 MB: generous for chat-turn text, bounded against abuse

# Hostnames that are always rejected regardless of how they resolve,
# because they're well-known non-routable or cloud-metadata endpoints
# rather than a legitimate model-serving target.
_BLOCKED_HOSTNAMES = frozenset({"localhost", "metadata.google.internal"})


def assert_safe_output_path(path: "Path | str", *, base_dir: "Path | str") -> Path:
    """Resolves `path`, rejecting it only if a *relative* input silently
    escapes `base_dir`.

    Guards the CLI's `--sarif-out` / `--json-out` / `--markdown-out` / `-o`
    flags against the failure mode this control actually exists for: a
    relative report path built from config values, templated strings, or a
    copy-pasted flag that contains an unexpected `..` segment (or passes
    through a symlink planted inside an otherwise-trusted output
    directory) and silently lands somewhere the caller didn't intend.
    `Path.resolve()` collapses `..` segments and follows symlinks, so the
    containment check below sees the *real* destination, not the literal
    string a caller typed.

    An *absolute* `path` is treated as the caller's explicit, deliberate
    choice and is returned as-is (after resolving symlinks) with no
    containment check against `base_dir` -- an operator who types
    `--sarif-out /mnt/ci-artifacts/out.sarif` has already chosen that exact
    destination as plainly as they would with `cp`, and forbidding it
    wouldn't prevent anything they couldn't already do directly; it would
    only break the common case of writing reports to a directory outside
    the current working tree (a CI artifacts mount, `/tmp`, ...). This
    mirrors how most CLI tools with output-path flags draw this line.

    Neither `path` nor `base_dir` need to exist yet -- `resolve()` (called
    without `strict=True`) works on paths that haven't been created, which
    is the normal case for an output file about to be written.
    """

    candidate = Path(path)
    if candidate.is_absolute():
        return candidate.resolve()

    base = Path(base_dir).resolve()
    resolved = (base / candidate).resolve()

    try:
        resolved.relative_to(base)
    except ValueError:
        raise PathTraversalError(
            f"output path {path!r} resolves to {resolved}, which is outside "
            f"the permitted directory {base}"
        ) from None

    return resolved


def assert_safe_target_url(url: str, *, allow_private_networks: bool = False) -> str:
    """Rejects target URLs that look unintentionally dangerous rather than
    deliberately configured, for `TargetConfig.api_base` / `custom_http`
    targets.

    This is a literal-value check, not a network-resolution check: it
    inspects the URL's scheme and, if the hostname is itself a literal IP
    address, whether that address is private/loopback/link-local/reserved.
    It deliberately does **not** perform DNS resolution -- doing so inside
    a pure validator would add a network call to every config load and
    still not fully close the gap, since the resolved address could differ
    between validation time and actual connection time (DNS rebinding).
    Pinning the resolved IP at connection time is a provider-adapter-level
    concern, out of scope for this phase (see Known Limitations).

    `allow_private_networks=True` is the intended escape hatch for
    legitimate local-network targets (Ollama at `http://localhost:11434`,
    an internal vLLM deployment, ...); it is the caller's responsibility
    to only set it for targets it trusts, not for user-supplied URLs.
    """

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeTargetURLError(f"unsupported URL scheme {parsed.scheme!r} in target URL {url!r}")

    hostname = parsed.hostname
    if not hostname:
        raise UnsafeTargetURLError(f"target URL {url!r} has no resolvable hostname")

    if allow_private_networks:
        return url

    if hostname.lower() in _BLOCKED_HOSTNAMES:
        raise UnsafeTargetURLError(
            f"target URL {url!r} uses hostname {hostname!r}, which is blocked by default; "
            "pass allow_private_networks=True if this target is intentional"
        )

    literal_ip = _parse_literal_ip(hostname)
    if literal_ip is not None and (
        literal_ip.is_private
        or literal_ip.is_loopback
        or literal_ip.is_link_local
        or literal_ip.is_reserved
        or literal_ip.is_multicast
    ):
        raise UnsafeTargetURLError(
            f"target URL {url!r} resolves to non-public address {literal_ip}, which is "
            "blocked by default; pass allow_private_networks=True if this target is intentional"
        )

    return url


def _parse_literal_ip(hostname: str) -> Optional["ipaddress.IPv4Address | ipaddress.IPv6Address"]:
    # A bracketed IPv6 literal ("[::1]") has its brackets stripped by
    # urlparse's .hostname already; ipaddress.ip_address handles the bare
    # form for both families.
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        return None


def enforce_payload_size_limit(
    text: str, *, max_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES, label: str = "payload"
) -> str:
    """Raises `PayloadTooLargeError` if `text`'s UTF-8 byte length exceeds
    `max_bytes`; otherwise returns `text` unchanged (so this composes as a
    pass-through step in a processing pipeline).

    Sized in encoded bytes, not `len(text)` characters, since multi-byte
    UTF-8 sequences (e.g. the zero-width and homoglyph mutators' output)
    would otherwise undercount the actual memory/storage footprint.
    """

    size = len(text.encode("utf-8"))
    if size > max_bytes:
        raise PayloadTooLargeError(f"{label} is {size} bytes, exceeding the {max_bytes}-byte limit")
    return text
