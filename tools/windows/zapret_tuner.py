#!/usr/bin/env python3
"""Safe Flowseal -> nfqws2 strategy tuner for Windows and Keenetic.

Downloaded BAT files are parsed as data and are never executed. Only a small
allowlisted subset of zapret1 options is translated to nfqws2 Lua functions.
Candidates run temporarily on the router; the active nfqws2 configuration file
is not changed and the original service is restored by a remote EXIT trap.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import random
import re
import secrets
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Iterable, Sequence


DEFAULT_REPOSITORY = "Flowseal/zapret-discord-youtube"
DEFAULT_REF = "main"
MAX_SEARCH_SEED = (1 << 32) - 1
DEFERRED_RANK = 200
TOKEN_RE = re.compile(
    r"--(?P<name>[A-Za-z0-9-]+)"
    r"(?:=(?P<value>\"[^\"]*\"|[^\s^]+))?"
)
SAFE_TOKEN_RE = re.compile(r"^--[a-z0-9-]+=[A-Za-z0-9_@/.,:+<>=!-]+$")
# Names accepted for cached and user-selected Flowseal strategy files.
SOURCE_NAME_RE = re.compile(r"general[A-Za-z0-9 ()_.-]*\.bat", re.IGNORECASE)

NATIVE_FAKE = (
    "--lua-desync=fake:blob=tls_clienthello:"
    "tls_mod=rnd,dupsid,sni=fonts.google.com:tcp_seq=10000"
)
NATIVE_SPLIT = (
    "--lua-desync=multisplit:pos=1,midsld:seqovl=1:"
    "seqovl_pattern=tls_clienthello:tcp_ts_up"
)
NATIVE_QUIC = (
    "--filter-udp=443",
    "--filter-l7=quic",
    "--hostlist=/opt/etc/nfqws2/lists/youtube.list",
    "--payload=quic_initial",
    "--lua-desync=fake:blob=youtube_quic:repeats=11",
)


@dataclasses.dataclass(frozen=True)
class SourceFile:
    name: str
    text: str
    sha: str
    url: str


@dataclasses.dataclass(frozen=True)
class Profile:
    source: SourceFile
    number: int
    options: tuple[tuple[str, str | None], ...]

    def values(self, name: str) -> list[str]:
        lowered = name.lower()
        return [
            value
            for key, value in self.options
            if key == lowered and value is not None
        ]

    def last(self, name: str, default: str = "") -> str:
        values = self.values(name)
        return values[-1] if values else default

    def has(self, name: str) -> bool:
        lowered = name.lower()
        return any(key == lowered for key, _ in self.options)


@dataclasses.dataclass(frozen=True)
class Candidate:
    candidate_id: str
    service: str
    source_name: str
    source_sha: str
    source_url: str
    family: str
    args: tuple[str, ...]
    notes: tuple[str, ...] = ()
    rank: int = 100

    def command_line(self) -> str:
        return " ".join(self.args)


def clean_value(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    return value.replace("^!", "!").replace("\\", "/")


def normalize_batch(text: str) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    normalized = re.sub(r"\^\s*\n", " ", normalized)
    return normalized.replace("^!", "!")


def parse_profiles(source: SourceFile) -> list[Profile]:
    profiles: list[Profile] = []
    current: list[tuple[str, str | None]] = []
    for match in TOKEN_RE.finditer(normalize_batch(source.text)):
        name = match.group("name").lower()
        raw_value = match.group("value")
        value = clean_value(raw_value) if raw_value is not None else None
        if name == "new":
            if current:
                profiles.append(
                    Profile(source, len(profiles) + 1, tuple(current))
                )
                current = []
            continue
        current.append((name, value))
    if current:
        profiles.append(Profile(source, len(profiles) + 1, tuple(current)))
    return profiles


def has_port(value: str, port: int) -> bool:
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        if "-" in item:
            left, right = item.split("-", 1)
            if left.isdigit() and right.isdigit() and int(left) <= port <= int(right):
                return True
        elif item.isdigit() and int(item) == port:
            return True
    return False


def basename_from_bat(value: str) -> str:
    value = value.replace("%BIN%", "").replace("%LISTS%", "")
    return value.replace("\\", "/").rsplit("/", 1)[-1].lower()


def profile_roles(profile: Profile) -> set[str]:
    roles: set[str] = set()
    tcp = profile.last("filter-tcp")
    udp = profile.last("filter-udp")
    l7 = ",".join(profile.values("filter-l7")).lower()
    hostlists = [basename_from_bat(value) for value in profile.values("hostlist")]
    host_domains = ",".join(profile.values("hostlist-domains")).lower()

    if tcp and has_port(tcp, 443):
        if any(name == "list-google.txt" for name in hostlists):
            roles.add("youtube")
        if (
            "discord.media" in host_domains
            or any(name == "list-general.txt" for name in hostlists)
        ):
            roles.add("discord-tcp")
    elif tcp and "discord.media" in host_domains:
        roles.add("discord-tcp")

    if udp and ("discord" in l7 or "stun" in l7):
        roles.add("discord-voice")
    if udp and has_port(udp, 443) and profile.has("dpi-desync-fake-quic"):
        roles.add("youtube-quic")
    return roles


def safe_marker(value: str, default: str) -> str:
    value = value.strip()
    if re.fullmatch(r"[A-Za-z0-9_+.,-]+", value):
        return value
    return default


def safe_tls_mod(value: str) -> str:
    if not value:
        return ""
    accepted: list[str] = []
    for part in value.split(","):
        part = part.strip()
        if part in {
            "rnd",
            "rndsni",
            "dupsid",
            "padencap",
            "none",
        }:
            accepted.append(part)
        elif re.fullmatch(r"sni=[A-Za-z0-9.-]+", part):
            accepted.append(part)
        else:
            return "rnd,dupsid"
    return ",".join(accepted)


def map_tls_blob(value: str) -> tuple[str, str | None]:
    lowered = value.lower()
    if not value or value == "!":
        return "fake_default_tls", None
    if lowered.startswith("0x"):
        if re.fullmatch(r"0x[0-9a-fA-F]+", value):
            return value, None
        return "fake_default_tls", "invalid hex fake replaced"
    name = basename_from_bat(value)
    if "google" in name:
        return "tls_clienthello", None
    if name.endswith(".bin"):
        return "tls_clienthello", f"{name} substituted with router Google TLS blob"
    return "fake_default_tls", f"unsupported fake {value!r} replaced"


def map_pattern_blob(value: str) -> tuple[str, str | None]:
    if not value:
        return "tls_clienthello", None
    if value.lower().startswith("0x") and re.fullmatch(
        r"0x[0-9a-fA-F]+", value
    ):
        return value, None
    name = basename_from_bat(value)
    if "google" in name:
        return "tls_clienthello", None
    return "tls_clienthello", f"{name} substituted with router Google TLS blob"


def fooling_params(profile: Profile) -> tuple[list[str], list[str]]:
    params: list[str] = []
    notes: list[str] = []
    fooling = ",".join(profile.values("dpi-desync-fooling")).lower()
    parts = {part.strip() for part in fooling.split(",") if part.strip()}
    if "ts" in parts:
        params.append("tcp_ts_up")
    if "md5sig" in parts:
        params.append("tcp_md5")
    if "badsum" in parts:
        params.append("badsum")
    if "datanoack" in parts:
        params.append("tcp_flags_unset=ack")
    if "badseq" in parts:
        increment = profile.last("dpi-desync-badseq-increment", "-10000")
        if re.fullmatch(r"-?[0-9]+", increment):
            params.append(f"tcp_seq={increment}")
        else:
            params.append("tcp_seq=-10000")
            notes.append("invalid badseq increment replaced with -10000")
    unsupported = sorted(parts - {"ts", "md5sig", "badsum", "datanoack", "badseq"})
    if unsupported:
        notes.append("ignored fooling: " + ",".join(unsupported))
    return params, notes


def lua_function(name: str, params: Iterable[str]) -> str:
    clean = [name, *(part for part in params if part)]
    return "--lua-desync=" + ":".join(clean)


def translate_tls_profile(profile: Profile, service: str) -> Candidate | None:
    chain = [
        part.strip().lower()
        for part in profile.last("dpi-desync").split(",")
        if part.strip()
    ]
    supported = {"fake", "multisplit", "multidisorder", "fakedsplit", "hostfakesplit"}
    if not chain or any(mode not in supported for mode in chain):
        return None

    notes: list[str] = []
    functions: list[str] = []
    fooling, fooling_notes = fooling_params(profile)
    notes.extend(fooling_notes)

    repeats = profile.last("dpi-desync-repeats")
    repeats_param = f"repeats={repeats}" if repeats.isdigit() else ""
    fake_values = profile.values("dpi-desync-fake-tls")
    fake_value = fake_values[-1] if fake_values else ""
    blob, blob_note = map_tls_blob(fake_value)
    if blob_note:
        notes.append(blob_note)
    if len(fake_values) > 1:
        notes.append("multiple BAT fake replacements collapsed to the last TLS fake")

    tls_mod = profile.last("dpi-desync-fake-tls-mod")
    if tls_mod.lower() == "none":
        tls_mod = ""

    for mode in chain:
        params: list[str] = []
        if mode == "fake":
            params.append(f"blob={blob}")
            if repeats_param:
                params.append(repeats_param)
            if tls_mod:
                params.append(f"tls_mod={safe_tls_mod(tls_mod)}")
            params.extend(fooling)
        elif mode in {"multisplit", "multidisorder"}:
            position = safe_marker(
                profile.last("dpi-desync-split-pos", "midsld"), "midsld"
            )
            params.append(f"pos={position}")
            if mode == "multisplit":
                overlap = profile.last("dpi-desync-split-seqovl")
                if overlap.isdigit():
                    params.append(f"seqovl={overlap}")
                    pattern, pattern_note = map_pattern_blob(
                        profile.last("dpi-desync-split-seqovl-pattern")
                    )
                    params.append(f"seqovl_pattern={pattern}")
                    if pattern_note:
                        notes.append(pattern_note)
            params.extend(fooling)
        elif mode == "fakedsplit":
            position = safe_marker(
                profile.last("dpi-desync-split-pos", "midsld"), "midsld"
            )
            params.append(f"pos={position}")
            pattern_value = profile.last("dpi-desync-fakedsplit-pattern")
            if pattern_value:
                pattern, pattern_note = map_pattern_blob(pattern_value)
                params.append(f"pattern={pattern}")
                if pattern_note:
                    notes.append(pattern_note)
            params.extend(fooling)
        elif mode == "hostfakesplit":
            modifier = profile.last("dpi-desync-hostfakesplit-mod")
            host_match = re.search(r"(?:^|,)host=([A-Za-z0-9.-]+)", modifier)
            if host_match:
                params.append(f"host={host_match.group(1)}")
            params.extend(fooling)
        functions.append(lua_function(mode, params))

    hostlist = (
        "/opt/etc/nfqws2/lists/youtube.list"
        if service == "youtube"
        else "/opt/etc/nfqws2/lists/user.list"
    )
    args = (
        "--filter-tcp=443",
        "--filter-l7=tls",
        f"--hostlist={hostlist}",
        "--out-range=-d10",
        "--payload=tls_client_hello",
        *functions,
    )
    return make_candidate(
        service=service,
        source=profile.source,
        family="+".join(chain),
        args=args,
        notes=tuple(dict.fromkeys(notes)),
        rank=100 + profile.number,
    )


def translate_voice_profile(profile: Profile) -> Candidate | None:
    chain = [
        part.strip().lower()
        for part in profile.last("dpi-desync").split(",")
        if part.strip()
    ]
    if chain != ["fake"]:
        return None
    repeats = profile.last("dpi-desync-repeats", "6")
    if not repeats.isdigit():
        repeats = "6"
    source_ports = profile.last(
        "filter-udp", "443,3478-3481,5349,19294-19344,50000-50100"
    )
    ports = safe_marker(
        source_ports, "443,3478-3481,5349,19294-19344,50000-50100"
    )
    args = (
        f"--filter-udp={ports}",
        "--filter-l7=stun,discord",
        "--out-range=<n2",
        "--payload=stun,discord_ip_discovery",
        f"--lua-desync=fake:blob=discord_udp:repeats={repeats}",
    )
    fake_names = [
        basename_from_bat(value)
        for value in (
            profile.values("dpi-desync-fake-discord")
            + profile.values("dpi-desync-fake-stun")
        )
    ]
    notes: list[str] = []
    if fake_names and any(name != "active_discord_udp.bin" for name in fake_names):
        notes.append("BAT UDP fake substituted with verified ACTIVE_DISCORD_UDP.bin")
    return make_candidate(
        service="discord-voice",
        source=profile.source,
        family="fake-udp",
        args=args,
        notes=tuple(notes),
        rank=100 + profile.number,
    )


def youtube_quic_for_source(profiles: Sequence[Profile]) -> tuple[str, ...]:
    for profile in profiles:
        if "youtube-quic" not in profile_roles(profile):
            continue
        repeats = profile.last("dpi-desync-repeats", "6")
        if not repeats.isdigit():
            repeats = "6"
        return (
            "--new",
            "--filter-udp=443",
            "--filter-l7=quic",
            "--hostlist=/opt/etc/nfqws2/lists/youtube.list",
            "--payload=quic_initial",
            f"--lua-desync=fake:blob=youtube_quic:repeats={repeats}",
        )
    return ("--new", *NATIVE_QUIC)


def make_candidate(
    *,
    service: str,
    source: SourceFile,
    family: str,
    args: Sequence[str],
    notes: Sequence[str] = (),
    rank: int,
) -> Candidate:
    serialized = "\n".join((service, source.name, family, *args))
    candidate_id = hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:12]
    validate_args(args)
    return Candidate(
        candidate_id=candidate_id,
        service=service,
        source_name=source.name,
        source_sha=source.sha,
        source_url=source.url,
        family=family,
        args=tuple(args),
        notes=tuple(notes),
        rank=rank,
    )


def validate_args(args: Sequence[str]) -> None:
    for token in args:
        if token == "--new":
            continue
        if not SAFE_TOKEN_RE.fullmatch(token):
            raise ValueError(f"unsafe generated nfqws2 token: {token!r}")


def known_candidate(service: str, sources: Sequence[SourceFile]) -> Candidate:
    preferred = next(
        (
            source
            for source in sources
            if source.name.lower() == "general (alt11).bat"
        ),
        sources[0] if sources else SourceFile("built-in", "", "", ""),
    )
    if service == "youtube":
        args = (
            "--filter-tcp=443",
            "--filter-l7=tls",
            "--hostlist=/opt/etc/nfqws2/lists/youtube.list",
            "--out-range=-d10",
            "--payload=tls_client_hello",
            NATIVE_FAKE,
            NATIVE_SPLIT,
            "--new",
            *NATIVE_QUIC,
        )
        family = "router-verified ALT11-like mix"
        notes = ("HTTP 200 on this router/provider on 2026-07-23",)
    elif service == "discord-tcp":
        args = (
            "--filter-tcp=443",
            "--filter-l7=tls",
            "--hostlist=/opt/etc/nfqws2/lists/user.list",
            "--out-range=-d10",
            "--payload=tls_client_hello",
            NATIVE_FAKE,
            NATIVE_SPLIT,
        )
        family = "router-native fake+multisplit"
        notes = ("current known-good TCP family",)
    else:
        args = (
            "--filter-udp=443,3478-3481,5349,19294-19344,50000-50100",
            "--filter-l7=stun,discord",
            "--out-range=<n2",
            "--payload=stun,discord_ip_discovery",
            "--lua-desync=fake:blob=discord_udp:repeats=6",
        )
        family = "Flowseal ACTIVE_DISCORD_UDP"
        notes = ("voice result still requires a real Discord reconnect",)
    return make_candidate(
        service=service,
        source=preferred,
        family=family,
        args=args,
        notes=notes,
        rank=0,
    )


def split_components(candidate: Candidate) -> tuple[list[str], str | None, str | None]:
    base: list[str] = []
    fake: str | None = None
    split: str | None = None
    for token in candidate.args:
        if token.startswith("--lua-desync=fake:") and fake is None:
            fake = token
        elif token.startswith(
            (
                "--lua-desync=multisplit:",
                "--lua-desync=multidisorder:",
                "--lua-desync=fakedsplit:",
                "--lua-desync=hostfakesplit:",
            )
        ) and split is None:
            split = token
        elif token != "--new" and not token.startswith("--lua-desync="):
            base.append(token)
    return base, fake, split


def candidate_source(candidate: Candidate) -> SourceFile:
    """Rebuild immutable source metadata for a generated candidate variant."""
    return SourceFile(
        candidate.source_name,
        "",
        candidate.source_sha,
        candidate.source_url,
    )


def profile_section(args: Sequence[str], section: str) -> tuple[int, int]:
    try:
        separator = args.index("--new")
    except ValueError:
        separator = len(args)
    if section == "tcp":
        return 0, separator
    if section == "udp" and separator < len(args):
        return separator + 1, len(args)
    if section == "all":
        return 0, len(args)
    return 0, 0


def replace_profile_option(
    args: Sequence[str],
    prefix: str,
    value: str,
    *,
    section: str,
) -> tuple[str, ...] | None:
    changed = list(args)
    start, end = profile_section(changed, section)
    for index in range(start, end):
        if changed[index].startswith(prefix):
            replacement = f"{prefix}{value}"
            if changed[index] == replacement:
                return None
            changed[index] = replacement
            return tuple(changed)
    return None


def replace_lua_parameter(
    args: Sequence[str],
    functions: set[str],
    parameter: str,
    value: str,
    *,
    section: str,
    required_companion: tuple[str, str] | None = None,
) -> tuple[str, ...] | None:
    changed = list(args)
    start, end = profile_section(changed, section)
    for index in range(start, end):
        token = changed[index]
        if not token.startswith("--lua-desync="):
            continue
        parts = token.removeprefix("--lua-desync=").split(":")
        if not parts or parts[0] not in functions:
            continue
        replacement = f"{parameter}={value}"
        found = False
        for part_index in range(1, len(parts)):
            if parts[part_index].split("=", 1)[0] == parameter:
                if parts[part_index] == replacement:
                    return None
                parts[part_index] = replacement
                found = True
                break
        if not found:
            parts.append(replacement)
        if required_companion:
            companion_name, companion_value = required_companion
            if not any(
                part.split("=", 1)[0] == companion_name
                for part in parts[1:]
            ):
                parts.append(f"{companion_name}={companion_value}")
        changed[index] = "--lua-desync=" + ":".join(parts)
        return tuple(changed)
    return None


def add_sweep_candidate(
    result: list[Candidate],
    base: Candidate,
    changed_args: tuple[str, ...] | None,
    label: str,
    rank: int,
) -> None:
    if changed_args is None or changed_args == base.args:
        return
    result.append(
        make_candidate(
            service=base.service,
            source=candidate_source(base),
            family=f"{base.family} | sweep {label}",
            args=changed_args,
            notes=(*base.notes, f"curated parameter sweep: {label}"),
            rank=rank,
        )
    )


def mutate_tls_recipe(
    args: Sequence[str],
    *,
    out_range: str | None = None,
    repeats: str | None = None,
    tcp_seq: str | None = None,
    position: str | None = None,
    seqovl: str | None = None,
    quic_repeats: str | None = None,
) -> tuple[str, ...] | None:
    changed: tuple[str, ...] = tuple(args)
    mutation_applied = False
    operations: list[tuple[str, str, str, set[str] | None]] = []
    if out_range is not None:
        operations.append(("option", "--out-range=", out_range, None))
    if repeats is not None:
        operations.append(("lua", "repeats", repeats, {"fake"}))
    if tcp_seq is not None:
        operations.append(("lua", "tcp_seq", tcp_seq, {"fake"}))
    if position is not None:
        operations.append(
            (
                "lua",
                "pos",
                position,
                {"multisplit", "multidisorder", "fakedsplit"},
            )
        )
    if seqovl is not None:
        operations.append(("seqovl", "seqovl", seqovl, {"multisplit"}))

    for kind, name, value, functions in operations:
        if kind == "option":
            next_args = replace_profile_option(
                changed,
                name,
                value,
                section="tcp",
            )
        else:
            next_args = replace_lua_parameter(
                changed,
                functions or set(),
                name,
                value,
                section="tcp",
                required_companion=(
                    ("seqovl_pattern", "tls_clienthello")
                    if kind == "seqovl"
                    else None
                ),
            )
        if next_args is not None:
            changed = next_args
            mutation_applied = True

    if quic_repeats is not None:
        next_args = replace_lua_parameter(
            changed,
            {"fake"},
            "repeats",
            quic_repeats,
            section="udp",
        )
        if next_args is not None:
            changed = next_args
            mutation_applied = True
    return changed if mutation_applied else None


def parameter_sweep_candidates(
    service: str,
    exact: Sequence[Candidate],
    sources: Sequence[SourceFile],
    level: str,
) -> list[Candidate]:
    """Build a bounded sweep without an uncontrolled Cartesian product."""
    if level == "off":
        return []

    native = known_candidate(service, sources)
    result: list[Candidate] = []
    rank = 20

    if service == "discord-voice":
        repeat_values = ("2", "3", "11")
        range_values = ("<n3", "<n4")
        for repeats in repeat_values:
            add_sweep_candidate(
                result,
                native,
                replace_lua_parameter(
                    native.args,
                    {"fake"},
                    "repeats",
                    repeats,
                    section="all",
                ),
                f"voice repeats={repeats}",
                rank,
            )
            rank += 1
        for out_range in range_values:
            add_sweep_candidate(
                result,
                native,
                replace_profile_option(
                    native.args,
                    "--out-range=",
                    out_range,
                    section="all",
                ),
                f"voice out-range={out_range}",
                rank,
            )
            rank += 1
        if level == "extended":
            for repeats in ("2", "3", "6", "11"):
                for out_range in ("<n2", "<n3", "<n4"):
                    changed = replace_lua_parameter(
                        native.args,
                        {"fake"},
                        "repeats",
                        repeats,
                        section="all",
                    ) or native.args
                    changed = replace_profile_option(
                        changed,
                        "--out-range=",
                        out_range,
                        section="all",
                    ) or changed
                    add_sweep_candidate(
                        result,
                        native,
                        tuple(changed),
                        f"voice repeats={repeats},range={out_range}",
                        rank,
                    )
                    rank += 1
        return result

    safe_axes = (
        ("out-range=-d4", {"out_range": "-d4"}),
        ("fake repeats=6", {"repeats": "6"}),
        ("tcp_seq=-10000", {"tcp_seq": "-10000"}),
        ("pos=1", {"position": "1"}),
        ("pos=midsld", {"position": "midsld"}),
        ("seqovl=5", {"seqovl": "5"}),
    )
    for label, values in safe_axes:
        add_sweep_candidate(
            result,
            native,
            mutate_tls_recipe(native.args, **values),
            label,
            rank,
        )
        rank += 1
    if service == "youtube":
        add_sweep_candidate(
            result,
            native,
            mutate_tls_recipe(native.args, quic_repeats="6"),
            "QUIC repeats=6",
            rank,
        )
        rank += 1

    if level != "extended":
        return result

    extended_axes = (
        ("out-range=-d2", {"out_range": "-d2"}),
        ("fake repeats=2", {"repeats": "2"}),
        ("fake repeats=11", {"repeats": "11"}),
        ("pos=sniext+1", {"position": "sniext+1"}),
        ("seqovl=1", {"seqovl": "1"}),
        ("seqovl=681", {"seqovl": "681"}),
    )
    if service == "youtube":
        extended_axes += (
            ("QUIC repeats=3", {"quic_repeats": "3"}),
            ("QUIC repeats=11", {"quic_repeats": "11"}),
        )
    for label, values in extended_axes:
        add_sweep_candidate(
            result,
            native,
            mutate_tls_recipe(native.args, **values),
            label,
            rank,
        )
        rank += 1

    recipes = (
        (
            "range=-d4,repeats=6,pos=midsld,seqovl=5",
            {
                "out_range": "-d4",
                "repeats": "6",
                "position": "midsld",
                "seqovl": "5",
            },
        ),
        (
            "range=-d2,repeats=11,tcp_seq=-10000,pos=1",
            {
                "out_range": "-d2",
                "repeats": "11",
                "tcp_seq": "-10000",
                "position": "1",
            },
        ),
    )
    if service == "youtube":
        recipes += (
            (
                "TCP repeats=6 + QUIC repeats=6",
                {"repeats": "6", "quic_repeats": "6"},
            ),
        )
    for label, values in recipes:
        add_sweep_candidate(
            result,
            native,
            mutate_tls_recipe(native.args, **values),
            label,
            rank,
        )
        rank += 1

    result.extend(source_sweep_candidates(exact))
    return result


def source_sweep_candidates(exact: Sequence[Candidate]) -> list[Candidate]:
    """Sweep a few axes on up to four translated BAT profiles (TCP services).

    Each family is represented once, so the sweep stays bounded.
    """
    result: list[Candidate] = []
    representative_bases: list[Candidate] = []
    represented_families: set[str] = set()
    for candidate in exact:
        if candidate.family in represented_families:
            continue
        represented_families.add(candidate.family)
        representative_bases.append(candidate)
        if len(representative_bases) == 4:
            break
    for base_index, base in enumerate(representative_bases):
        base_rank = max(125, base.rank + 25) + base_index * 8
        for offset, (label, values) in enumerate(
            (
                ("source range=-d4", {"out_range": "-d4"}),
                ("source repeats=6", {"repeats": "6"}),
                ("source pos=midsld", {"position": "midsld"}),
                ("source tcp_seq=-10000", {"tcp_seq": "-10000"}),
            )
        ):
            add_sweep_candidate(
                result,
                base,
                mutate_tls_recipe(base.args, **values),
                label,
                base_rank + offset,
            )
    return result


def mixed_candidates(
    service: str,
    exact: Sequence[Candidate],
    sources: Sequence[SourceFile],
    level: str,
) -> list[Candidate]:
    if service == "discord-voice" or level == "off":
        return []
    result: list[Candidate] = []
    native = known_candidate(service, sources)
    _, native_fake, native_split = split_components(native)

    for candidate in exact:
        base, source_fake, source_split = split_components(candidate)
        if service == "youtube":
            quic_start = candidate.args.index("--new") if "--new" in candidate.args else -1
            suffix = candidate.args[quic_start:] if quic_start >= 0 else ("--new", *NATIVE_QUIC)
        else:
            suffix = ()
        if source_split and native_fake:
            result.append(
                make_candidate(
                    service=service,
                    source=next(
                        (s for s in sources if s.name == candidate.source_name),
                        sources[0],
                    ),
                    family=f"native-fake + {candidate.family}-split",
                    args=(*base, native_fake, source_split, *suffix),
                    notes=(*candidate.notes, "bounded component mix"),
                    rank=candidate.rank + 40,
                )
            )
        if source_fake and native_split:
            result.append(
                make_candidate(
                    service=service,
                    source=next(
                        (s for s in sources if s.name == candidate.source_name),
                        sources[0],
                    ),
                    family=f"{candidate.family}-fake + native-split",
                    args=(*base, source_fake, native_split, *suffix),
                    notes=(*candidate.notes, "bounded component mix"),
                    rank=candidate.rank + 45,
                )
            )

    if level != "extended":
        return result

    component_rows = [(*split_components(candidate), candidate) for candidate in exact]
    for base_a, fake, _split_a, fake_candidate in component_rows[:10]:
        if fake is None:
            continue
        for _base_b, _fake_b, split, split_candidate in component_rows[:10]:
            if split is None or fake_candidate.source_name == split_candidate.source_name:
                continue
            suffix: tuple[str, ...] = ()
            if service == "youtube":
                if "--new" in fake_candidate.args:
                    offset = fake_candidate.args.index("--new")
                    suffix = fake_candidate.args[offset:]
                else:
                    suffix = ("--new", *NATIVE_QUIC)
            source = next(
                (s for s in sources if s.name == fake_candidate.source_name),
                sources[0],
            )
            result.append(
                make_candidate(
                    service=service,
                    source=source,
                    family=(
                        f"{fake_candidate.source_name}:fake + "
                        f"{split_candidate.source_name}:split"
                    ),
                    args=(*base_a, fake, split, *suffix),
                    notes=("extended cross-BAT mix",),
                    rank=300,
                )
            )
    return result


def select_source(sources: Sequence[SourceFile], name: str) -> list[SourceFile]:
    """Return only the BAT file called ``name`` (case-insensitive).

    Raises ValueError when the downloaded set has no such file.
    """
    wanted = name.casefold()
    chosen = [source for source in sources if source.name.casefold() == wanted]
    if not chosen:
        raise ValueError(f"BAT file not found in the Flowseal set: {name}")
    return chosen[:1]


def source_services(source: SourceFile) -> list[str]:
    """Services for which ``source`` yields at least one translated profile."""
    return sorted(
        service
        for service in ("youtube", "discord-tcp", "discord-voice")
        if build_candidates(service, [source], "off", include_builtin=False)
    )


def build_candidates(
    service: str,
    sources: Sequence[SourceFile],
    mix_level: str,
    *,
    include_builtin: bool = True,
) -> list[Candidate]:
    """Translate, sweep and mix candidates for ``service``.

    ``include_builtin=False`` leaves out the router-native known-good profile
    and everything built on it (native sweeps and native/source mixes), so
    that only profiles derived from ``sources`` are tested.
    """
    by_source = {
        source.name: parse_profiles(source)
        for source in sources
    }
    exact: list[Candidate] = []
    for source in sources:
        profiles = by_source[source.name]
        quic = youtube_quic_for_source(profiles)
        for profile in profiles:
            roles = profile_roles(profile)
            if service in {"youtube", "discord-tcp"} and service in roles:
                candidate = translate_tls_profile(profile, service)
                if candidate:
                    if service == "youtube":
                        candidate = make_candidate(
                            service=candidate.service,
                            source=profile.source,
                            family=candidate.family,
                            args=(*candidate.args, *quic),
                            notes=candidate.notes,
                            rank=candidate.rank,
                        )
                    exact.append(candidate)
            elif service == "discord-voice" and service in roles:
                candidate = translate_voice_profile(profile)
                if candidate:
                    exact.append(candidate)

    if include_builtin:
        candidates = [known_candidate(service, sources)]
        candidates.extend(
            parameter_sweep_candidates(service, exact, sources, mix_level)
        )
        candidates.extend(exact)
        candidates.extend(mixed_candidates(service, exact, sources, mix_level))
    else:
        # Only what the selected BAT file defines: its translated profiles and,
        # unless mixing is off, the per-source parameter sweep (TCP services).
        candidates = list(exact)
        if mix_level != "off" and service != "discord-voice":
            candidates.extend(source_sweep_candidates(exact))
    unique: dict[tuple[str, ...], Candidate] = {}
    for candidate in sorted(candidates, key=lambda item: (item.rank, item.source_name)):
        unique.setdefault(candidate.args, candidate)
    return list(unique.values())


def parse_search_seed(value: str) -> int:
    try:
        seed = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("search seed must be a decimal integer") from error
    if not 0 <= seed <= MAX_SEARCH_SEED:
        raise argparse.ArgumentTypeError(
            f"search seed must be between 0 and {MAX_SEARCH_SEED}"
        )
    return seed


def resolve_search_seed(seed: int | None) -> int:
    return secrets.randbits(32) if seed is None else seed


def select_candidates(
    candidates: Sequence[Candidate],
    maximum: int,
    search_seed: int,
) -> list[Candidate]:
    """Choose a reproducible randomized path through curated candidates.

    Rank 200+ recipes remain behind the primary allowlisted pool, but both
    pools are independently shuffled before the run limit is applied. This
    changes both order and, for short runs, the tested subset.
    """
    if maximum < 1:
        raise ValueError("maximum must be positive")
    rng = random.Random(search_seed)
    primary = [candidate for candidate in candidates if candidate.rank < DEFERRED_RANK]
    extended = [candidate for candidate in candidates if candidate.rank >= DEFERRED_RANK]
    rng.shuffle(primary)
    rng.shuffle(extended)
    return (primary + extended)[:maximum]


def github_json(url: str) -> object:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "keenetic-zapret-tuner/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(4 * 1024 * 1024 + 1)
        if len(data) > 4 * 1024 * 1024:
            raise RuntimeError("GitHub metadata exceeds 4 MiB")
        return json.loads(data)


def download_text(url: str) -> str:
    request = urllib.request.Request(
        url, headers={"User-Agent": "keenetic-zapret-tuner/1.0"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(262145)
        if len(data) > 262144:
            raise RuntimeError("Flowseal source exceeds 256 KiB")
        return data.decode("utf-8-sig", errors="replace")


def fetch_sources(repository: str, ref: str) -> tuple[list[SourceFile], str]:
    quoted_repo = urllib.parse.quote(repository, safe="/")
    quoted_ref = urllib.parse.quote(ref, safe="")
    commit_data = github_json(
        f"https://api.github.com/repos/{quoted_repo}/commits/{quoted_ref}"
    )
    if not isinstance(commit_data, dict) or not isinstance(commit_data.get("sha"), str):
        raise RuntimeError("GitHub returned no commit SHA")
    commit = commit_data["sha"]
    if not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        raise RuntimeError("invalid GitHub commit SHA")
    contents = github_json(
        f"https://api.github.com/repos/{quoted_repo}/contents?ref={commit}"
    )
    if not isinstance(contents, list):
        raise RuntimeError("GitHub root contents response is not a list")

    sources: list[SourceFile] = []
    for item in contents:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        download_url = item.get("download_url")
        sha = item.get("sha")
        if (
            isinstance(name, str)
            and name.lower().startswith("general")
            and name.lower().endswith(".bat")
            and isinstance(download_url, str)
            and isinstance(sha, str)
        ):
            if len(sources) >= 64:
                raise RuntimeError("too many Flowseal sources (limit 64)")
            sources.append(
                SourceFile(
                    name=name,
                    text=download_text(download_url),
                    sha=sha,
                    url=download_url,
                )
            )
    sources.sort(key=lambda item: item.name.lower())
    if not sources:
        raise RuntimeError("no general*.bat files found in repository root")
    return sources, commit


def read_source_cache(path: Path) -> tuple[list[SourceFile], str]:
    if path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024:
        raise RuntimeError("unsafe or oversized Flowseal cache")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("format") != 1 or data.get("repository") != DEFAULT_REPOSITORY:
        raise RuntimeError("invalid Flowseal cache")
    commit = data.get("commit", "")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise RuntimeError("invalid cached commit")
    items = data.get("sources")
    if not isinstance(items, list) or not 1 <= len(items) <= 64:
        raise RuntimeError("invalid cached sources")
    sources = []
    names = set()
    for item in items:
        if not isinstance(item, dict):
            raise RuntimeError("invalid cached source")
        name, text = item.get("name"), item.get("text")
        sha, url = item.get("sha"), item.get("url")
        if (not isinstance(name, str) or len(name) > 160
                or not SOURCE_NAME_RE.fullmatch(name)
                or name in names or not isinstance(text, str) or len(text.encode("utf-8")) > 262144
                or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha)
                or not isinstance(url, str) or len(url) > 1000
                or item.get("sha256") != hashlib.sha256(text.encode("utf-8")).hexdigest()):
            raise RuntimeError("corrupt cached source")
        names.add(name)
        sources.append(SourceFile(name=name, text=text, sha=sha, url=url))
    return sources, commit


def save_source_cache(path: Path, sources: Sequence[SourceFile], commit: str) -> None:
    data = {"format": 1, "repository": DEFAULT_REPOSITORY, "commit": commit,
            "sources": [{"name": s.name, "text": s.text, "sha": s.sha, "url": s.url,
                         "sha256": hashlib.sha256(s.text.encode("utf-8")).hexdigest()} for s in sources]}
    encoded = json.dumps(data, ensure_ascii=False).encode("utf-8")
    if len(encoded) > 4 * 1024 * 1024:
        raise RuntimeError("Flowseal cache exceeds 4 MiB")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".flowseal-sources-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        read_source_cache(temporary)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load_local_sources(directory: Path) -> tuple[list[SourceFile], str]:
    sources: list[SourceFile] = []
    for path in sorted(directory.glob("general*.bat")):
        data = path.read_bytes()
        sources.append(
            SourceFile(
                name=path.name,
                text=data.decode("utf-8-sig", errors="replace"),
                sha=hashlib.sha256(data).hexdigest(),
                url=str(path.resolve()),
            )
        )
    if not sources:
        raise RuntimeError(f"no general*.bat files found in {directory}")
    aggregate = hashlib.sha256(
        "".join(source.sha for source in sources).encode("ascii")
    ).hexdigest()
    return sources, aggregate


def candidate_data(candidates: Sequence[Candidate]) -> str:
    lines: list[str] = []
    for number, candidate in enumerate(candidates, 1):
        encoded = base64.b64encode(
            candidate.command_line().encode("utf-8")
        ).decode("ascii")
        lines.append(f"{number}|{candidate.candidate_id}|{encoded}")
    return "\n".join(lines)


def render_runner(
    template: str,
    *,
    service: str,
    candidates: Sequence[Candidate],
    client_ip: str,
    voice_duration: int,
    http_timeout: int,
) -> str:
    rendered = template
    replacements = {
        "@@SERVICE@@": service,
        "@@CLIENT_IP@@": client_ip,
        "@@VOICE_DURATION@@": str(voice_duration),
        "@@HTTP_TIMEOUT@@": str(http_timeout),
        "@@MIN_HTTP_SUCCESS@@": "3",
        "@@CANDIDATE_DATA@@": candidate_data(candidates),
    }
    for marker, value in replacements.items():
        rendered = rendered.replace(marker, value)
    if "@@" in rendered:
        raise RuntimeError("unresolved router runner template marker")
    return rendered


def ssh_command(args: argparse.Namespace) -> list[str]:
    command = [
        args.ssh,
        "-T",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=2",
        "-o",
        "StrictHostKeyChecking=accept-new",
    ]
    if args.ssh_key:
        command.extend(["-i", str(Path(args.ssh_key).expanduser())])
    if args.ssh_port != 22:
        command.extend(["-p", str(args.ssh_port)])
    command.extend(
        [
            f"{args.user}@{args.router}",
            (
                "IFS= read -r p; "
                "f=/opt/tmp/zapret-tuner-bootstrap.$$; "
                "trap 'rm -f \"$f\"' EXIT HUP INT TERM; "
                "printf '%s' \"$p\" | base64 -d >\"$f\" || exit 1; "
                "chmod 700 \"$f\"; sh \"$f\""
            ),
        ]
    )
    return command


def run_remote(
    args: argparse.Namespace,
    runner: str,
    candidates: Sequence[Candidate],
) -> tuple[Candidate | None, list[str]]:
    payload = base64.b64encode(runner.encode("utf-8")).decode("ascii") + "\n"
    process = subprocess.Popen(
        ssh_command(args),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    process.stdin.write(payload)
    process.stdin.flush()

    found: Candidate | None = None
    output: list[str] = []
    try:
        for raw_line in process.stdout:
            line = raw_line.rstrip("\r\n")
            output.append(line)
            print(line)
            if not line.startswith("EVENT|"):
                continue
            parts = line.split("|")
            event = parts[1] if len(parts) > 1 else ""
            if event == "VOICE_READY":
                try:
                    duration = parts[3]
                except IndexError:
                    duration = str(args.voice_duration)
                print(
                    "\aСейчас отключитесь и заново подключитесь к Discord Voice "
                    f"в течение {duration} секунд."
                )
            elif event == "VOICE_VERDICT":
                verdict = input(
                    "Голос и звук заработали с этим кандидатом? [y/N]: "
                ).strip()
                process.stdin.write(("yes" if verdict.lower() in {"y", "yes", "д", "да"} else "no") + "\n")
                process.stdin.flush()
            elif event == "FOUND" and len(parts) >= 3:
                number = int(parts[2])
                if 1 <= number <= len(candidates):
                    found = candidates[number - 1]
    except KeyboardInterrupt:
        print("\nПрерывание: закрываю SSH; trap на роутере восстановит nfqws2.")
        process.terminate()
        raise
    finally:
        try:
            process.stdin.close()
        except OSError:
            pass
    return_code = process.wait(timeout=30)
    if return_code != 0:
        raise RuntimeError(f"remote tuner exited with code {return_code}")
    if any(line.startswith("EVENT|RESTORE_ERROR|") for line in output):
        raise RuntimeError("nfqws2 restoration failed; inspect runner output")
    return found, output


def print_candidate(candidate: Candidate, number: int | None = None) -> None:
    prefix = f"{number:02d}. " if number is not None else ""
    print(
        f"{prefix}{candidate.source_name} | {candidate.family} | "
        f"id={candidate.candidate_id}"
    )
    if candidate.notes:
        print("    " + "; ".join(candidate.notes))


def router_recommendation(candidate: Candidate) -> str:
    args_block = "\n".join(candidate.args)
    if candidate.service == "youtube":
        variable = "NFQWS_ARGS_CUSTOM"
        route_help = (
            "YouTube only: sh set-zapret-mode.sh youtube --core xray "
            "--wan-interface eth3 --yes-router\n"
            "Both services: sh set-zapret-mode.sh both --core xray "
            "--wan-interface eth3 --yes-router"
        )
    elif candidate.service == "discord-voice":
        variable = "NFQWS_ARGS_UDP"
        route_help = (
            "Discord only: sh set-zapret-mode.sh discord --core xray "
            "--wan-interface eth3 --yes-router\n"
            "Both services: sh set-zapret-mode.sh both --core xray "
            "--wan-interface eth3 --yes-router"
        )
    else:
        variable = "NFQWS_ARGS (with NFQWS_EXTRA_ARGS=\"$MODE_LIST\")"
        route_help = (
            "Discord only: sh set-zapret-mode.sh discord --core xray "
            "--wan-interface eth3 --yes-router\n"
            "Both services: sh set-zapret-mode.sh both --core xray "
            "--wan-interface eth3 --yes-router"
        )
    return (
        f"BAT-источник: {candidate.source_name}\n"
        f"Семейство: {candidate.family}\n"
        f"Git blob SHA: {candidate.source_sha or 'built-in'}\n\n"
        f"Рекомендуемое значение {variable}:\n"
        f"-----\n{args_block}\n-----\n\n"
        "Маршрутизация XKeen/Xray (выберите нужное сочетание):\n"
        f"{route_help}\n\n"
        "Для постоянного применения перенесите профиль в генератор "
        "apply-discord-nfqws2.sh. Ручная правка управляемого блока "
        "nfqws2.conf будет перезаписана следующим apply."
    )


def parse_probe_event(line: str) -> dict | None:
    parts = line.split("|", 11)
    if len(parts) != 12 or parts[:2] != ["EVENT", "PROBE_DETAIL"]:
        return None
    try:
        return {
            "candidate": int(parts[2]), "phase": parts[3], "round": int(parts[4]),
            "role": parts[5], "http_code": parts[6], "seconds": float(parts[7]),
            "bytes": int(float(parts[8])), "exit_code": int(parts[9]),
            "status": parts[10], "url": parts[11][:500],
        }
    except ValueError:
        return None


def verification_report(service: str, output: Sequence[str]) -> dict:
    return {
        "method": "manual-duplex-voice" if service == "discord-voice" else "router-http-content-two-rounds",
        "voice_audio_automatic": False,
        "quic_verified": False,
        "video_playback_verified": False,
        "probes": [result for line in output if (result := parse_probe_event(line)) is not None],
        "suite_results": [line for line in output if line.startswith("EVENT|SUITE_RESULT|")],
        "voice_observations": [line for line in output if line.startswith("EVENT|VOICE_OBSERVATION|")],
    }


def write_report(
    path: Path,
    *,
    args: argparse.Namespace,
    commit: str,
    candidates: Sequence[Candidate],
    found: Candidate | None,
    output: Sequence[str],
) -> None:
    report = {
        "report_format": 1,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "repository": args.repository,
        "ref": args.ref,
        "commit": commit,
        "service": args.service,
        "router": args.router,
        "search_seed": args.search_seed,
        "source_file": args.source_file,
        "candidate_count": len(candidates),
        "found": dataclasses.asdict(found) if found else None,
        "remote_output": list(output),
        "verification": verification_report(args.service, output),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Download Flowseal BAT strategies, translate an allowlisted subset "
            "to nfqws2 and test them temporarily on a Keenetic router."
        )
    )
    result.add_argument(
        "service",
        choices=("youtube", "discord-tcp", "discord-voice"),
        help="service/protocol family to tune",
    )
    result.add_argument("--router", default="192.168.2.1")
    result.add_argument("--user", default="root")
    result.add_argument("--ssh-port", type=int, default=22)
    result.add_argument("--ssh-key")
    result.add_argument("--ssh", default="ssh.exe")
    result.add_argument("--client-ip", help="LAN IPv4; required for discord-voice")
    result.add_argument("--voice-duration", type=int, default=25)
    result.add_argument("--http-timeout", type=int, default=6)
    result.add_argument("--max-candidates", type=int, default=32)
    result.add_argument(
        "--search-seed",
        type=parse_search_seed,
        help=(
            "reproduce a randomized candidate order; omitted means a new "
            "32-bit seed for every run"
        ),
    )
    result.add_argument(
        "--mix-level",
        choices=("off", "safe", "extended"),
        default="safe",
    )
    result.add_argument("--repository", default=DEFAULT_REPOSITORY)
    result.add_argument("--ref", default=DEFAULT_REF)
    result.add_argument(
        "--source-dir",
        type=Path,
        help="read general*.bat from a local directory instead of GitHub",
    )
    result.add_argument(
        "--source-file",
        help=(
            "test only profiles translated from this general*.bat "
            "(for example \"general (ALT3).bat\"); the built-in profile is skipped"
        ),
    )
    result.add_argument(
        "--plan-only",
        action="store_true",
        help="download, parse and list candidates without connecting to router",
    )
    result.add_argument(
        "--yes-router",
        action="store_true",
        help="skip runtime-impact confirmation",
    )
    result.add_argument("--report", type=Path)
    return result


def validate_cli(args: argparse.Namespace) -> None:
    if args.service == "discord-voice":
        if not args.client_ip:
            raise SystemExit("--client-ip is required for discord-voice")
        try:
            address = ipaddress.ip_address(args.client_ip)
        except ValueError as error:
            raise SystemExit(f"invalid --client-ip: {error}") from error
        if address.version != 4:
            raise SystemExit("--client-ip must be IPv4")
    if not 5 <= args.voice_duration <= 60:
        raise SystemExit("--voice-duration must be between 5 and 60")
    if not 4 <= args.http_timeout <= 30:
        raise SystemExit("--http-timeout must be between 4 and 30")
    if not 1 <= args.max_candidates <= 100:
        raise SystemExit("--max-candidates must be between 1 and 100")
    if not 1 <= args.ssh_port <= 65535:
        raise SystemExit("--ssh-port must be between 1 and 65535")


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    validate_cli(args)
    args.search_seed = resolve_search_seed(args.search_seed)

    try:
        if args.source_dir:
            sources, commit = load_local_sources(args.source_dir)
        else:
            print(f"Получаю актуальные general*.bat из {args.repository}@{args.ref}...")
            sources, commit = fetch_sources(args.repository, args.ref)
        if args.source_file:
            sources = select_source(sources, args.source_file)
    except (OSError, RuntimeError, ValueError, urllib.error.URLError) as error:
        print(f"ERROR: не удалось получить стратегии: {error}", file=sys.stderr)
        return 1

    candidates = select_candidates(
        build_candidates(
            args.service,
            sources,
            args.mix_level,
            include_builtin=not args.source_file,
        ),
        args.max_candidates,
        args.search_seed,
    )
    if not candidates:
        print(
            f"ERROR: в {args.source_file} нет профиля для {args.service}.",
            file=sys.stderr,
        )
        return 1
    print(
        f"Источник зафиксирован на commit {commit[:12]}; "
        f"BAT-файлов: {len(sources)}; кандидатов: {len(candidates)}; "
        f"seed: {args.search_seed}."
    )
    for number, candidate in enumerate(candidates, 1):
        print_candidate(candidate, number)

    if args.plan_only:
        if args.report:
            write_report(
                args.report,
                args=args,
                commit=commit,
                candidates=candidates,
                found=None,
                output=[],
            )
        print("Plan-only: подключение к роутеру и изменение runtime не выполнялись.")
        return 0

    if not args.yes_router:
        print(
            "\nВо время теста nfqws2 будет временно перезапускаться. "
            "Файлы конфигурации не изменяются; EXIT trap восстановит службу."
        )
        answer = input("Продолжить? Введите YES: ").strip()
        if answer != "YES":
            print("Отменено.")
            return 2

    template_path = Path(__file__).with_name("router-candidate-runner.sh")
    template = template_path.read_text(encoding="utf-8")
    runner = render_runner(
        template,
        service=args.service,
        candidates=candidates,
        client_ip=args.client_ip or "127.0.0.1",
        voice_duration=args.voice_duration,
        http_timeout=args.http_timeout,
    )

    try:
        found, remote_output = run_remote(args, runner, candidates)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"ERROR: тест на роутере завершился ошибкой: {error}", file=sys.stderr)
        return 1

    if found:
        print("\nНАЙДЕН ПРОХОДНОЙ КАНДИДАТ\n")
        print(router_recommendation(found))
    else:
        print(
            "\nПроходной кандидат не найден. Активная конфигурация nfqws2 "
            "восстановлена. Увеличьте --max-candidates или используйте "
            "--mix-level extended."
        )

    if args.report:
        write_report(
            args.report,
            args=args,
            commit=commit,
            candidates=candidates,
            found=found,
            output=remote_output,
        )
        print(f"Отчёт: {args.report.resolve()}")
    return 0 if found else 3


if __name__ == "__main__":
    raise SystemExit(main())
