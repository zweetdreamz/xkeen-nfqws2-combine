#!/usr/bin/env python3
"""Inspect Xray/V2Ray geosite.dat and geoip.dat protobuf databases."""

from __future__ import annotations

import argparse
import glob
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence


DOMAIN_TYPES = {
    0: "plain",
    1: "regex",
    2: "domain",
    3: "full",
}


class DatFormatError(ValueError):
    """Raised when a file is not a supported Xray/V2Ray geo database."""


@dataclass(frozen=True)
class Attribute:
    key: str
    value: bool | int | None = None


@dataclass(frozen=True)
class DomainRule:
    type: str
    value: str
    attributes: tuple[Attribute, ...] = ()


@dataclass(frozen=True)
class DomainCategory:
    name: str
    domains: tuple[DomainRule, ...]


@dataclass(frozen=True)
class IpCategory:
    name: str
    network_count: int


@dataclass(frozen=True)
class DatDatabase:
    path: Path
    format: str
    categories: tuple[DomainCategory | IpCategory, ...]


WireField = tuple[int, int, int | bytes]


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(10):
        if offset >= len(data):
            raise DatFormatError("truncated protobuf varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7
    raise DatFormatError("protobuf varint is too long")


def _wire_fields(data: bytes) -> Iterator[WireField]:
    offset = 0
    while offset < len(data):
        key, offset = _read_varint(data, offset)
        number = key >> 3
        wire_type = key & 7
        if number == 0:
            raise DatFormatError("invalid protobuf field number 0")

        if wire_type == 0:
            value, offset = _read_varint(data, offset)
        elif wire_type == 1:
            end = offset + 8
            if end > len(data):
                raise DatFormatError("truncated fixed64 protobuf field")
            value = data[offset:end]
            offset = end
        elif wire_type == 2:
            length, offset = _read_varint(data, offset)
            end = offset + length
            if end > len(data):
                raise DatFormatError("truncated length-delimited protobuf field")
            value = data[offset:end]
            offset = end
        elif wire_type == 5:
            end = offset + 4
            if end > len(data):
                raise DatFormatError("truncated fixed32 protobuf field")
            value = data[offset:end]
            offset = end
        else:
            raise DatFormatError(f"unsupported protobuf wire type {wire_type}")
        yield number, wire_type, value


def _decode_text(value: bytes, field_name: str) -> str:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DatFormatError(f"{field_name} is not valid UTF-8") from exc
    if not text or any(ord(char) < 0x20 for char in text):
        raise DatFormatError(f"{field_name} is empty or contains control characters")
    return text


def _signed_int64(value: int) -> int:
    return value - (1 << 64) if value >= (1 << 63) else value


def _parse_attribute(data: bytes) -> Attribute:
    key: str | None = None
    typed_value: bool | int | None = None
    for number, wire_type, value in _wire_fields(data):
        if number == 1:
            if wire_type != 2:
                raise DatFormatError("attribute key has an invalid wire type")
            key = _decode_text(value, "attribute key")  # type: ignore[arg-type]
        elif number == 2:
            if wire_type != 0:
                raise DatFormatError("boolean attribute has an invalid wire type")
            typed_value = bool(value)
        elif number == 3:
            if wire_type != 0:
                raise DatFormatError("integer attribute has an invalid wire type")
            typed_value = _signed_int64(value)  # type: ignore[arg-type]
    if key is None:
        raise DatFormatError("domain attribute has no key")
    return Attribute(key=key, value=typed_value)


def _parse_domain(data: bytes) -> DomainRule:
    domain_type = 0
    value: str | None = None
    attributes: list[Attribute] = []
    for number, wire_type, raw_value in _wire_fields(data):
        if number == 1:
            if wire_type != 0 or raw_value not in DOMAIN_TYPES:
                raise DatFormatError("domain rule has an invalid type")
            domain_type = int(raw_value)
        elif number == 2:
            if wire_type != 2:
                raise DatFormatError("domain value has an invalid wire type")
            value = _decode_text(raw_value, "domain value")  # type: ignore[arg-type]
        elif number == 3:
            if wire_type != 2:
                raise DatFormatError("domain attribute has an invalid wire type")
            attributes.append(_parse_attribute(raw_value))  # type: ignore[arg-type]
    if value is None:
        raise DatFormatError("domain rule has no value")
    return DomainRule(
        type=DOMAIN_TYPES[domain_type],
        value=value,
        attributes=tuple(attributes),
    )


def _parse_geosite_entry(data: bytes) -> DomainCategory:
    name: str | None = None
    domains: list[DomainRule] = []
    for number, wire_type, value in _wire_fields(data):
        if number == 1:
            if wire_type != 2:
                raise DatFormatError("geosite category has an invalid name")
            name = _decode_text(value, "geosite category name")  # type: ignore[arg-type]
        elif number == 2:
            if wire_type != 2:
                raise DatFormatError("geosite domain has an invalid wire type")
            domains.append(_parse_domain(value))  # type: ignore[arg-type]
    if name is None:
        raise DatFormatError("geosite category has no name")
    return DomainCategory(name=name, domains=tuple(domains))


def _validate_cidr(data: bytes) -> None:
    address: bytes | None = None
    prefix = 0
    for number, wire_type, value in _wire_fields(data):
        if number == 1:
            if wire_type != 2:
                raise DatFormatError("GeoIP address has an invalid wire type")
            address = value  # type: ignore[assignment]
        elif number == 2:
            if wire_type != 0:
                raise DatFormatError("GeoIP prefix has an invalid wire type")
            prefix = int(value)
    if address is None or len(address) not in (4, 16):
        raise DatFormatError("GeoIP address is not 4 or 16 bytes long")
    max_prefix = 32 if len(address) == 4 else 128
    if prefix > max_prefix:
        raise DatFormatError("GeoIP prefix is outside the address width")


def _parse_geoip_entry(data: bytes) -> IpCategory:
    name: str | None = None
    network_count = 0
    validated_network = False
    for number, wire_type, value in _wire_fields(data):
        if number == 1:
            if wire_type != 2:
                raise DatFormatError("GeoIP category has an invalid name")
            name = _decode_text(value, "GeoIP category name")  # type: ignore[arg-type]
        elif number == 2:
            if wire_type != 2:
                raise DatFormatError("GeoIP CIDR has an invalid wire type")
            network_count += 1
            # One CIDR is sufficient to distinguish GeoIP from a Domain
            # message. Avoid decoding millions of networks that are not part
            # of the domain-reader output.
            if not validated_network:
                _validate_cidr(value)  # type: ignore[arg-type]
                validated_network = True
    if name is None:
        raise DatFormatError("GeoIP category has no name")
    return IpCategory(name=name, network_count=network_count)


def _root_entries(data: bytes) -> list[bytes]:
    entries: list[bytes] = []
    for number, wire_type, value in _wire_fields(data):
        if number == 1:
            if wire_type != 2:
                raise DatFormatError("database entry has an invalid wire type")
            entries.append(value)  # type: ignore[arg-type]
    if not entries:
        raise DatFormatError("database contains no entries")
    return entries


def read_dat_bytes(data: bytes, path: Path = Path("<stdin>")) -> DatDatabase:
    """Decode an Xray/V2Ray geosite or geoip protobuf database."""
    entries = _root_entries(data)
    geosite: tuple[DomainCategory, ...] | None = None
    geoip: tuple[IpCategory, ...] | None = None

    try:
        candidate = tuple(_parse_geosite_entry(entry) for entry in entries)
        if any(category.domains for category in candidate):
            geosite = candidate
    except DatFormatError:
        pass

    try:
        candidate_ip = tuple(_parse_geoip_entry(entry) for entry in entries)
        if any(category.network_count for category in candidate_ip):
            geoip = candidate_ip
    except DatFormatError:
        pass

    if geosite is not None and geoip is None:
        return DatDatabase(path=path, format="geosite", categories=geosite)
    if geoip is not None and geosite is None:
        return DatDatabase(path=path, format="geoip", categories=geoip)
    if geosite is not None and geoip is not None:
        domain_count = sum(len(category.domains) for category in geosite)
        network_count = sum(category.network_count for category in geoip)
        if domain_count >= network_count:
            return DatDatabase(path=path, format="geosite", categories=geosite)
        return DatDatabase(path=path, format="geoip", categories=geoip)
    raise DatFormatError("not a supported Xray/V2Ray geosite.dat or geoip.dat")


def read_dat(path: Path) -> DatDatabase:
    """Read one Xray/V2Ray geosite or geoip protobuf database."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise DatFormatError(str(exc)) from exc
    return read_dat_bytes(data, path)


def _expand_paths(arguments: Sequence[str]) -> tuple[list[Path], list[str]]:
    paths: list[Path] = []
    errors: list[str] = []
    seen: set[str] = set()
    for argument in arguments or ["."]:
        if argument == "-":
            if "<stdin>" not in seen:
                seen.add("<stdin>")
                paths.append(Path("-"))
            continue
        wildcard_matches = glob.glob(argument, recursive=True)
        candidates = [Path(item) for item in wildcard_matches] or [Path(argument)]
        for candidate in candidates:
            try:
                if candidate.is_dir():
                    items = sorted(candidate.rglob("*.dat"))
                else:
                    items = [candidate]
            except OSError as exc:
                errors.append(f"{candidate}: {exc}")
                continue
            for item in items:
                try:
                    key = str(item.resolve()).casefold()
                except OSError as exc:
                    errors.append(f"{item}: {exc}")
                    continue
                if key not in seen:
                    seen.add(key)
                    paths.append(item)
    return paths, errors


def _attribute_text(attributes: Iterable[Attribute]) -> str:
    parts: list[str] = []
    for attribute in attributes:
        if attribute.value is None:
            parts.append(f"@{attribute.key}")
        else:
            parts.append(f"@{attribute.key}={str(attribute.value).lower()}")
    return ",".join(parts)


def _rule_matches(rule: DomainRule, domain: str) -> bool:
    query = domain.casefold().rstrip(".")
    value = rule.value.casefold().rstrip(".")
    if rule.type == "full":
        return query == value
    if rule.type == "domain":
        return query == value or query.endswith("." + value)
    if rule.type == "plain":
        return value in query
    try:
        return re.search(rule.value, domain, re.IGNORECASE) is not None
    except re.error:
        return False


def _domain_rows(
    databases: Sequence[DatDatabase],
    *,
    categories: set[str] | None = None,
    search: str | None = None,
    match: str | None = None,
) -> list[tuple[DatDatabase, DomainCategory, DomainRule]]:
    rows: list[tuple[DatDatabase, DomainCategory, DomainRule]] = []
    needle = search.casefold() if search is not None else None
    for database in databases:
        if database.format != "geosite":
            continue
        for category in database.categories:
            assert isinstance(category, DomainCategory)
            if categories is not None and category.name.casefold() not in categories:
                continue
            for rule in category.domains:
                if needle is not None and needle not in rule.value.casefold():
                    continue
                if match is not None and not _rule_matches(rule, match):
                    continue
                rows.append((database, category, rule))
    return rows


def _print_summary(databases: Sequence[DatDatabase]) -> None:
    for database in databases:
        if database.format == "geosite":
            total = sum(
                len(category.domains)
                for category in database.categories
                if isinstance(category, DomainCategory)
            )
            print(
                f"{database.path}  geosite  "
                f"categories={len(database.categories)} domains={total}"
            )
            for category in database.categories:
                assert isinstance(category, DomainCategory)
                print(f"  {category.name}\t{len(category.domains)}")
        else:
            total = sum(
                category.network_count
                for category in database.categories
                if isinstance(category, IpCategory)
            )
            print(
                f"{database.path}  geoip  "
                f"categories={len(database.categories)} networks={total}"
            )
            print("  (IP database: it contains no domain rules)")
            for category in database.categories:
                assert isinstance(category, IpCategory)
                print(f"  {category.name}\t{category.network_count}")


def _print_rows(rows: Sequence[tuple[DatDatabase, DomainCategory, DomainRule]]) -> None:
    for database, category, rule in rows:
        attributes = _attribute_text(rule.attributes)
        suffix = f"\t{attributes}" if attributes else ""
        print(f"{database.path}\t{category.name}\t{rule.type}\t{rule.value}{suffix}")


def _json_summary(databases: Sequence[DatDatabase]) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for database in databases:
        if database.format == "geosite":
            categories = [
                {"name": category.name, "domains": len(category.domains)}
                for category in database.categories
                if isinstance(category, DomainCategory)
            ]
        else:
            categories = [
                {"name": category.name, "networks": category.network_count}
                for category in database.categories
                if isinstance(category, IpCategory)
            ]
        output.append(
            {
                "file": str(database.path),
                "format": database.format,
                "categories": categories,
            }
        )
    return output


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect Xray/V2Ray .dat files. With no action, prints categories "
            "and the number of rules in every file."
        )
    )
    parser.add_argument(
        "paths",
        nargs="*",
        metavar="PATH",
        help="a .dat file, wildcard, or directory (default: current directory)",
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--domains",
        action="store_true",
        help="list every domain rule",
    )
    action.add_argument(
        "-c",
        "--category",
        action="append",
        metavar="NAME",
        help="list rules from this category (repeatable)",
    )
    action.add_argument(
        "-s",
        "--search",
        metavar="TEXT",
        help="find TEXT inside stored domain values",
    )
    action.add_argument(
        "-m",
        "--match",
        metavar="DOMAIN",
        help="show rules that would match DOMAIN using Xray semantics",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="write machine-readable JSON",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    args = build_parser().parse_args(argv)
    paths, path_errors = _expand_paths(args.paths)
    for error in path_errors:
        print(f"error: {error}", file=sys.stderr)
    if not paths:
        print("error: no .dat files found", file=sys.stderr)
        return 1

    databases: list[DatDatabase] = []
    had_errors = bool(path_errors)
    for path in paths:
        if str(path) == "-":
            try:
                databases.append(read_dat_bytes(sys.stdin.buffer.read()))
            except DatFormatError as exc:
                print(f"error: <stdin>: {exc}", file=sys.stderr)
                had_errors = True
            continue
        if not path.is_file():
            print(f"error: {path}: file not found", file=sys.stderr)
            had_errors = True
            continue
        try:
            databases.append(read_dat(path))
        except DatFormatError as exc:
            print(f"error: {path}: {exc}", file=sys.stderr)
            had_errors = True

    if not databases:
        return 1

    has_domain_action = bool(
        args.domains or args.category or args.search is not None or args.match is not None
    )
    if has_domain_action:
        categories = (
            {name.casefold() for name in args.category}
            if args.category is not None
            else None
        )
        rows = _domain_rows(
            databases,
            categories=categories,
            search=args.search,
            match=args.match,
        )
        if args.json:
            result = [
                {
                    "file": str(database.path),
                    "category": category.name,
                    **asdict(rule),
                }
                for database, category, rule in rows
            ]
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            _print_rows(rows)
        if not rows:
            print("No matching domain rules found.", file=sys.stderr)
            had_errors = True
    elif args.json:
        print(json.dumps(_json_summary(databases), ensure_ascii=False, indent=2))
    else:
        _print_summary(databases)

    return 1 if had_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
