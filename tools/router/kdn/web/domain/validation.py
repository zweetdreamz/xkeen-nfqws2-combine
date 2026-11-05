"""Validation of tuner reports and of the nfqws2 candidates in them, before the panel hands them to the engine.

A candidate passes only with the options and Lua strategies of the allowlist, inside the ports and hostlists of
its service, and with the candidate_id that its content hashes to.
"""

import hashlib
import re

from kdn.state import nfqws
from kdn.web.infra import config as cfg
from kdn.web.infra import engine


SAFE_TOKEN = re.compile(r"^--[a-z0-9-]+=[A-Za-z0-9_@/.,:+<>=!-]+$")
SAFE_OPTIONS = {
    "filter-tcp",
    "filter-udp",
    "filter-l7",
    "hostlist",
    "out-range",
    "payload",
    "lua-desync",
}
SAFE_LUA = {"fake", "multisplit", "multidisorder", "multidisorder_legacy", "fakedsplit", "hostfakesplit"}


def bounded_text(value, field, maximum, *, allow_empty=True):
    if not isinstance(value, str) or len(value) > maximum or "\n" in value or "\r" in value:
        raise ValueError(f"некорректное поле {field}")
    if not allow_empty and not value:
        raise ValueError(f"пустое поле {field}")
    return value


def validate_candidate(candidate, report):
    if not isinstance(candidate, dict):
        raise ValueError("в отчёте нет найденного кандидата")
    if not isinstance(report, dict):
        raise ValueError("report должен быть JSON-объектом")
    service = candidate.get("service")
    if service not in cfg.SERVICES:
        raise ValueError("неподдерживаемый сервис")
    source_name = bounded_text(candidate.get("source_name"), "source_name", 160, allow_empty=False)
    source_sha = bounded_text(candidate.get("source_sha"), "source_sha", 128)
    source_url = bounded_text(candidate.get("source_url"), "source_url", 500)
    family = bounded_text(candidate.get("family"), "family", 240, allow_empty=False)
    candidate_id = bounded_text(candidate.get("candidate_id"), "candidate_id", 12, allow_empty=False)
    if not re.fullmatch(r"[0-9a-f]{12}", candidate_id):
        raise ValueError("некорректный candidate_id")
    rank = candidate.get("rank")
    if isinstance(rank, bool) or not isinstance(rank, int) or not 0 <= rank <= 100000:
        raise ValueError("некорректный rank")
    notes = candidate.get("notes")
    if not isinstance(notes, list) or len(notes) > 20:
        raise ValueError("некорректные notes")
    notes = [bounded_text(item, "notes", 500) for item in notes]
    args = candidate.get("args")
    if not isinstance(args, list) or not 1 <= len(args) <= 40:
        raise ValueError("некорректный список args")
    for token in args:
        bounded_text(token, "args", 600, allow_empty=False)
        if token == "--new":
            continue
        if not SAFE_TOKEN.fullmatch(token):
            raise ValueError(f"небезопасный токен: {token}")
        name, value = token[2:].split("=", 1)
        if name not in SAFE_OPTIONS:
            raise ValueError(f"неподдерживаемая опция: --{name}")
        if name == "lua-desync" and value.split(":", 1)[0] not in SAFE_LUA:
            raise ValueError("неподдерживаемая Lua-стратегия")
        if name == "lua-desync" and any(
                part.startswith("ip_id=") and part not in {"ip_id=zero", "ip_id=seq", "ip_id=rnd"}
                for part in value.split(":")[1:]):
            raise ValueError("неподдерживаемая IP ID policy")

    def values(prefix):
        return [token[len(prefix):] for token in args if token.startswith(prefix)]

    if service == "youtube":
        required = {
            "--filter-tcp=443",
            "--filter-udp=443",
            "--filter-l7=tls",
            "--filter-l7=quic",
            "--hostlist=/opt/etc/nfqws2/lists/youtube.list",
            "--payload=tls_client_hello",
            "--payload=quic_initial",
        }
        if args.count("--new") != 1 or not required.issubset(args):
            raise ValueError("неполный YouTube TCP/QUIC профиль")
        if set(values("--filter-tcp=")) != {"443"} or set(values("--filter-udp=")) != {"443"}:
            raise ValueError("YouTube профиль выходит за TCP/UDP 443")
        if set(values("--filter-l7=")) - {"tls", "quic"}:
            raise ValueError("лишний L7-фильтр YouTube")
        if set(values("--hostlist=")) != {"/opt/etc/nfqws2/lists/youtube.list"}:
            raise ValueError("лишний hostlist YouTube")
        if any("discord" in token or "user.list" in token for token in args):
            raise ValueError("YouTube профиль пересекается с Discord")
    elif service == "discord-tcp":
        required = {
            "--filter-tcp=443",
            "--filter-l7=tls",
            "--hostlist=/opt/etc/nfqws2/lists/user.list",
            "--payload=tls_client_hello",
        }
        if "--new" in args or not required.issubset(args):
            raise ValueError("неполный Discord TCP профиль")
        if set(values("--filter-tcp=")) != {"443"} or values("--filter-udp="):
            raise ValueError("Discord TCP профиль выходит за TCP 443")
        if set(values("--filter-l7=")) != {"tls"}:
            raise ValueError("лишний L7-фильтр Discord TCP")
        if set(values("--hostlist=")) != {"/opt/etc/nfqws2/lists/user.list"}:
            raise ValueError("лишний hostlist Discord TCP")
        if any("youtube" in token or "discord_udp" in token for token in args):
            raise ValueError("Discord TCP профиль пересекается с другим семейством")
    else:
        udp = values("--filter-udp=")
        lua = values("--lua-desync=")
        high, recorded = engine.recorded_voice_high()
        if len(udp) == 1 and nfqws.voice_ports_allowed(udp[0]) and not nfqws.voice_ports_allowed(udp[0], high):
            raise ValueError(
                f"Discord Voice порты {udp[0]} выходят за записанный диапазон range={recorded} "
                f"(до {high}): движок такой профиль не примет"
            )
        if (
            "--new" in args
            or len(udp) != 1
            or not nfqws.voice_ports_allowed(udp[0], high)
            or values("--filter-tcp=")
            or values("--hostlist=")
            or set(values("--filter-l7=")) != {"stun,discord"}
            or set(values("--payload=")) != {"stun,discord_ip_discovery"}
            or len(lua) != 1
            or not re.fullmatch(r"fake:blob=discord_udp:repeats=([1-9]|[1-9][0-9])", lua[0])
        ):
            raise ValueError("Discord Voice профиль выходит за безопасные UDP-границы")

    nfqws.validate_service_profiles(service, args, voice_high=high if service == "discord-voice" else 65535)

    serialized = "\n".join((service, source_name, family, *args))
    expected_id = hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:12]
    if candidate_id != expected_id:
        raise ValueError("candidate_id не соответствует содержимому")
    report_meta = {
        "repository": bounded_text(report.get("repository", ""), "repository", 200),
        "ref": bounded_text(report.get("ref", ""), "ref", 200),
        "commit": bounded_text(report.get("commit", ""), "commit", 128),
        "created_utc": bounded_text(report.get("created_utc", ""), "created_utc", 80),
    }
    search_seed = report.get("search_seed")
    if search_seed is not None and (
        isinstance(search_seed, bool)
        or not isinstance(search_seed, int)
        or not 0 <= search_seed <= 4294967295
    ):
        raise ValueError("некорректный search_seed")
    report_meta["search_seed"] = search_seed
    return {
        "format": 1,
        "service": service,
        "candidate_id": candidate_id,
        "source_name": source_name,
        "source_sha": source_sha,
        "source_url": source_url,
        "family": family,
        "args": args,
        "notes": notes,
        "rank": rank,
        "report": report_meta,
    }


def validate_report(report):
    if not isinstance(report, dict):
        raise ValueError("корень отчёта должен быть JSON-объектом")
    if report.get("report_format", 1) != 1:
        raise ValueError("неподдерживаемая версия отчёта")
    candidate = report.get("found")
    profile = validate_candidate(candidate, report)
    if report.get("service") != profile["service"]:
        raise ValueError("сервис отчёта не совпадает с кандидатом")
    return profile
