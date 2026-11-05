#!/usr/bin/env python3
"""Inventory router Xray DAT categories and compare them with routing.json.

The input is read-only. Output files are a generated Markdown report and a
complete machine-readable category index; no router settings are changed.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

import dat_reader


FEATURED = (
    "anthropic", "openai", "discord", "youtube", "telegram", "github",
    "gitlab", "docker", "steam", "twitch", "reddit", "spotify", "netflix",
    "twitter", "instagram", "whatsapp", "cloudflare", "fastly", "google",
    "amazon", "azure", "akamai",
)
BROAD_NETWORKS = {"cloudflare", "fastly", "google", "amazon", "azure", "akamai"}


def files_in(directory: Path) -> tuple[list[Path], dict[str, str]]:
    files: list[Path] = []
    aliases: dict[str, str] = {}
    for path in sorted(directory.glob("*.dat"), key=lambda item: item.name.casefold()):
        if path.is_symlink():
            aliases[path.name] = path.resolve().name
        elif path.is_file():
            files.append(path)
    if not files:
        raise ValueError(f"no .dat files in {directory}")
    return files, aliases


def category_index(directory: Path) -> tuple[list[dict], dict[str, dict], dict[str, str]]:
    paths, aliases = files_in(directory)
    records: list[dict] = []
    lookup: dict[str, dict] = {}
    for path in paths:
        database = dat_reader.read_dat(path)
        categories = []
        for category in database.categories:
            count = (len(category.domains) if isinstance(category, dat_reader.DomainCategory)
                     else category.network_count)
            categories.append({"name": category.name, "count": count})
        categories.sort(key=lambda item: item["name"].casefold())
        record = {
            "file": path.name, "format": database.format,
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "categories": categories,
            "category_count": len(categories),
            "entry_count": sum(item["count"] for item in categories),
        }
        records.append(record)
        lookup[path.name.casefold()] = record
    return records, lookup, aliases


def routing_selectors(routing_path: Path, lookup: dict[str, dict], aliases: dict[str, str]) -> list[dict]:
    data = json.loads(routing_path.read_text(encoding="utf-8"))
    rules = data.get("routing", {}).get("rules", [])
    if not isinstance(rules, list):
        raise ValueError("routing.rules is not an array")
    rows = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        for field in ("domain", "ip"):
            values = rule.get(field, [])
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, list):
                continue
            for value in values:
                if not isinstance(value, str) or not value.startswith("ext:"):
                    continue
                parts = value.split(":", 2)
                if len(parts) != 3:
                    continue
                filename, selector = parts[1], parts[2]
                resolved = aliases.get(filename, filename)
                record = lookup.get(resolved.casefold())
                category = selector.split("@", 1)[0]
                exists = bool(record and any(item["name"].casefold() == category.casefold()
                                             for item in record["categories"]))
                expected_field = ({"geosite": "domain", "geoip": "ip"}.get(record["format"])
                                  if record else None)
                rows.append({
                    "rule_index": index, "rule_tag": rule.get("ruleTag"),
                    "outbound": rule.get("outboundTag"), "field": field,
                    "selector": value, "file": filename, "resolved_file": resolved,
                    "category": category, "category_exists": exists,
                    "expected_field": expected_field,
                    "field_correct": expected_field == field if expected_field else None,
                })
    return rows


def markdown_report(records: list[dict], selectors: list[dict], aliases: dict[str, str], source: str) -> str:
    used = {(item["resolved_file"].casefold(), item["category"].casefold()) for item in selectors}
    lines = [
        "# Категории DAT на роутере",
        "",
        f"Источник: `{source}`; снимок: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}.",
        "Файлы проверены по SHA-256. Скрипт только читает DAT и routing.json.",
        "",
        "## Файлы",
        "",
        "| Файл | Тип | Категорий | Записей | Размер | SHA-256 |",
        "|---|---|---:|---:|---:|---|",
    ]
    for record in records:
        lines.append(f"| `{record['file']}` | {record['format']} | {record['category_count']} | "
                     f"{record['entry_count']} | {record['bytes']} Б | `{record['sha256']}` |")
    if aliases:
        lines += ["", "Ссылки-алиасы (не отдельные базы): " + ", ".join(
            f"`{name}` → `{target}`" for name, target in sorted(aliases.items())) + "."]

    anomalies = [item for item in selectors if item["field_correct"] is False or not item["category_exists"]]
    lines += ["", "## Использование в текущем routing", "",
              f"Найдено {len(selectors)} селекторов `ext:`. Категории, уже используемые правилами, "
              "помечены в полном перечне ниже.", ""]
    if anomalies:
        lines += ["Несовпадения, требующие проверки:", ""]
        for item in anomalies:
            problem = ("не та колонка (ожидается " + str(item["expected_field"]) + ")"
                       if item["field_correct"] is False else "категория/файл не найдены в снимке")
            lines.append(f"- `{item['selector']}`: rule {item['rule_index']}, `{item['field']}` → "
                         f"`{item['outbound']}` — {problem}.")
    else:
        lines.append("Несовпадений типа geosite-в-IP/geoip-в-domain и отсутствующих категорий не найдено.")

    lines += ["", "## Категории, которые стоит рассмотреть", "",
              "Это варианты для ручной оценки, не предложения включить все сразу. "
              "Фактическая доступность сервисов этими данными не проверяется.", "",
              "| Категория | База | Записей | Уже в routing | Примечание |",
              "|---|---|---:|---|---|"]
    for target in FEATURED:
        for record in records:
            for category in record["categories"]:
                if category["name"].casefold() != target:
                    continue
                active = (record["file"].casefold(), target) in used
                caution = ("Широкая сеть/CDN: затронет другие сайты" if record["format"] == "geoip"
                           and target in BROAD_NETWORKS else
                           "Точечная категория доменов" if record["format"] == "geosite" else
                           "IP-сети сервиса; проверьте пересечения")
                lines.append(f"| `{category['name']}` | `{record['file']}` | {category['count']} | "
                             f"{'да' if active else 'нет'} | {caution} |")

    lines += ["", "## Полный перечень категорий", "",
              "Число рядом с категорией — количество доменных правил или IP-сетей в базе.", ""]
    for record in records:
        lines += [f"<details><summary>{record['file']} — {record['category_count']} категорий</summary>", "",
                  "| Категория | Записей | В routing |", "|---|---:|---|"]
        for item in record["categories"]:
            active = (record["file"].casefold(), item["name"].casefold()) in used
            lines.append(f"| `{item['name']}` | {item['count']} | {'да' if active else '—'} |")
        lines += ["", "</details>", ""]
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dat_dir", type=Path)
    parser.add_argument("--routing", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--source", default="router /opt/etc/xray/dat")
    parser.add_argument("--alias", action="append", default=[], metavar="ALIAS=TARGET")
    args = parser.parse_args(argv)
    records, lookup, aliases = category_index(args.dat_dir)
    for value in args.alias:
        name, separator, target = value.partition("=")
        if not separator or not name.endswith(".dat") or not target.endswith(".dat"):
            parser.error(f"invalid --alias: {value}")
        aliases[name] = target
    selectors = routing_selectors(args.routing, lookup, aliases)
    report = markdown_report(records, selectors, aliases, args.source)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "categories.json").write_text(
        json.dumps({"files": records, "aliases": aliases, "routing_selectors": selectors},
                   ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "report.md").write_text(report, encoding="utf-8")
    print(f"DAT files: {len(records)}; categories: {sum(item['category_count'] for item in records)}; "
          f"routing selectors: {len(selectors)}; report: {args.output_dir / 'report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
