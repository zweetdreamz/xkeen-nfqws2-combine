"""nfqws2 profiles: the imported ones, their saved versions, and the effective profiles read from nfqws2.conf."""

import json
import re
import stat
import time

from kdn.common import fsutil
from kdn.state import nfqws
from kdn.web.infra import config as cfg
from kdn.web.infra import engine
from kdn.web.infra import jobfiles
from kdn.web.infra import toolmods
from kdn.web.domain import refusals
from kdn.web.domain import validation
from kdn.web.domain import history


def imported_profiles():
    result = []
    for service in cfg.SERVICES:
        path = cfg.IMPORTED_PROFILE_DIR / f"{service}.json"
        item = {"service": service, "installed": False}
        try:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise ValueError("необычный тип файла")
            if info.st_size > cfg.MAX_REPORT_BYTES:
                raise ValueError("файл слишком велик")
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("ожидается JSON-объект")
            profile = validation.validate_candidate(data, data.get("report", {}))
            if profile["service"] != service or data.get("format") != 1:
                raise ValueError("неверный сервис")
            item.update(
                installed=True,
                candidate_id=profile["candidate_id"],
                family=profile["family"],
                source_name=profile["source_name"],
                commit=profile["report"].get("commit", ""),
                created_utc=profile["report"].get("created_utc", ""),
                installed_utc=time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ",
                    time.gmtime(info.st_mtime),
                ),
            )
        except FileNotFoundError:
            pass
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            item["error"] = f"Некорректный профиль: {exc}"
        result.append(item)
    return result


def current_service_configs():
    """Read the effective nfqws2 profiles without exposing Xray credentials."""
    engine.require_supported_target()
    info = cfg.NFQWS_CONFIG.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > fsutil.MAX_JSON_BYTES:
        raise ValueError("необычный файл nfqws2.conf")
    config = cfg.NFQWS_CONFIG.read_text(encoding="utf-8", errors="replace")
    routes = nfqws.parse_active_routes(config) or {service: "unknown" for service in nfqws.ROUTE_SERVICES}
    diagnostics = toolmods.diagnostics_module()
    profiles = diagnostics.compose_profiles(diagnostics.parse_shell_values(config))
    result = {service: {"route": routes.get(service, "unknown"), "profiles": [], "note": ""}
              for service in nfqws.ROUTE_SERVICES}

    def profile_label(profile):
        tcp = diagnostics.option_values(profile, "filter-tcp")
        udp = diagnostics.option_values(profile, "filter-udp")
        l7 = diagnostics.option_values(profile, "filter-l7")
        protocol = "TCP" if tcp else "UDP" if udp else "Профиль"
        return protocol + (" · " + ", ".join(l7) if l7 else "")

    for profile in profiles:
        hostlists = diagnostics.option_values(profile, "hostlist")
        l7 = ",".join(diagnostics.option_values(profile, "filter-l7")).lower().split(",")
        udp = diagnostics.option_values(profile, "filter-udp")
        service = None
        if "/opt/etc/nfqws2/lists/youtube.list" in hostlists:
            service = "youtube"
        elif "/opt/etc/nfqws2/lists/kdn-telegram.list" in hostlists:
            service = "telegram"
        elif "/opt/etc/nfqws2/lists/user.list" in hostlists:
            service = "discord-tcp"
        elif udp and ("discord" in l7 or "stun" in l7):
            service = "discord-voice"
        if service and routes.get(service) in ({"ws"} if service == "telegram" else {"zapret"}):
            result[service]["profiles"].append({"label": profile_label(profile), "args": profile})

    for entry in result.values():
        if entry["profiles"]:
            continue
        route = entry["route"]
        if route == "vless":
            entry["note"] = "Через общую VPN-ноду Xray; профиль nfqws2 не используется. Параметры VPN здесь не раскрываются."
        elif route == "direct":
            entry["note"] = "Напрямую через WAN; профиль nfqws2 не используется."
        elif route == "unmanaged":
            entry["note"] = "Правила проекта отключены; маршрут определяется остальной конфигурацией XKeen."
        elif route in {"zapret", "ws"}:
            entry["note"] = "Активный профиль nfqws2 не найден — проверьте конфигурацию в диагностике."
        else:
            entry["note"] = "Не удалось определить маршрут."
    return {"ok": True, "services": result}


def profile_versions():
    active = {
        item["service"]: item.get("candidate_id")
        for item in imported_profiles()
        if item.get("installed")
    }
    result = []
    pattern = re.compile(
        r"^(\d{8}T\d{6}Z)-([0-9a-f]{12})-"
        r"(applied|replaced|cleared)-(\d+)(?:-(\d+))?\.json$"
    )
    for service in cfg.SERVICES:
        directory = cfg.PROFILE_VERSION_DIR / service
        try:
            paths = sorted(fsutil.bounded_files(directory), reverse=True)
        except OSError:
            continue
        for path in paths[:200]:
            match = pattern.fullmatch(path.name)
            if not match:
                continue
            try:
                data = fsutil.safe_json_file(path)
                profile = validation.validate_candidate(data, data.get("report", {}))
                if profile["service"] != service or profile["candidate_id"] != match.group(2):
                    raise ValueError("метаданные версии не совпадают")
                stamp = match.group(1)
                created = (
                    f"{stamp[0:4]}-{stamp[4:6]}-{stamp[6:8]}T"
                    f"{stamp[9:11]}:{stamp[11:13]}:{stamp[13:15]}Z"
                )
                result.append(
                    {
                        "id": path.name[:-5],
                        "service": service,
                        "candidate_id": profile["candidate_id"],
                        "family": profile["family"],
                        "source_name": profile["source_name"],
                        "commit": profile["report"].get("commit", ""),
                        "created_utc": created,
                        "reason": match.group(3),
                        "active": active.get(service) == profile["candidate_id"],
                    }
                )
            except (OSError, ValueError, json.JSONDecodeError):
                continue
    result.sort(key=lambda item: item["created_utc"], reverse=True)
    return result[:300]


def profile_version_path(service, version_id):
    if service not in cfg.SERVICES:
        raise ValueError("неподдерживаемый сервис")
    if not re.fullmatch(
        r"\d{8}T\d{6}Z-[0-9a-f]{12}-(applied|replaced|cleared)-\d+(?:-\d+)?",
        version_id,
    ):
        raise ValueError("некорректный ID версии")
    path = cfg.PROFILE_VERSION_DIR / service / f"{version_id}.json"
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError("необычный файл версии")
    data = fsutil.safe_json_file(path)
    profile = validation.validate_candidate(data, data.get("report", {}))
    if profile["service"] != service:
        raise ValueError("сервис версии не совпадает")
    return path, profile


def delete_profile_version(service, version_id):
    with jobfiles.COORDINATOR.exclusive(refusals.VERSION_DELETE):
        path, profile = profile_version_path(service, version_id)
        if any(item["service"] == service and item.get("installed") and
               item.get("candidate_id") == profile["candidate_id"]
               for item in imported_profiles()):
            raise ValueError("активную версию удалять нельзя")
        history.archive_record(path, "versions", service)
        return {"ok": True, "archived": True}
