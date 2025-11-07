#!/usr/bin/env python3
"""
批量 IP 段查询脚本

读取 ip.txt（或指定文件）中的 CIDR 段，查询每个 IP 的归属地，
并按照地区缩写（默认国家代码）聚合成精简的 CIDR 列表，写入 output 目录。
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import DefaultDict, Dict, Iterable, List, MutableMapping, Set, Union

from ip_lookup import DBManager, IPInfoParser, set_logger as set_lookup_logger


VALID_REGION_FIELDS = ("country_code", "country", "country_zh", "continent_code")
IPvAnyNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IPvAnyAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


def build_logger() -> logging.Logger:
    logger = logging.getLogger("ip_range_exporter")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


LOGGER = build_logger()
set_lookup_logger(LOGGER)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="批量查询 IP 段并按地区缩写聚合。")
    parser.add_argument(
        "--ip-file",
        default="ip.txt",
        help="包含 IP 段（CIDR）的文件路径，默认读取 ip.txt。",
    )
    parser.add_argument(
        "--output-dir",
        default="output",
        help="存放结果文件的目录，默认 output。",
    )
    parser.add_argument(
        "--region-field",
        default="country_code",
        choices=VALID_REGION_FIELDS,
        help="用于分类的字段，默认按国家代码。",
    )
    parser.add_argument(
        "--keep-existing",
        action="store_true",
        help="保留 output 目录中已有的 txt/json 文件，默认会清理旧文件。",
    )
    return parser.parse_args()


def load_networks(ip_file: Path) -> List[IPvAnyNetwork]:
    if not ip_file.exists():
        raise FileNotFoundError(f"找不到 IP 列表文件：{ip_file}")
    networks: List[ipaddress._BaseNetwork] = []
    with ip_file.open("r", encoding="utf-8") as handle:
        for idx, raw_line in enumerate(handle, start=1):
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                networks.append(ipaddress.ip_network(line, strict=False))
            except ValueError as err:
                LOGGER.warning("第 %d 行解析失败（已跳过）：%s → %s", idx, line, err)
    if not networks:
        raise ValueError(f"{ip_file} 中没有有效的 IP 段")
    return networks


def sanitize_region_label(value: str | None, region_field: str) -> str:
    if not value:
        return "UNKNOWN"
    label = value.strip()
    if not label:
        return "UNKNOWN"
    if region_field.endswith("code"):
        label = label.upper()
        if label == "XX":
            return "UNKNOWN"
    safe_label = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in label)
    return safe_label or "UNKNOWN"


def collapse_addresses(addresses: Iterable[IPvAnyAddress]) -> List[str]:
    return [str(net) for net in ipaddress.collapse_addresses(sorted(addresses))]


def collect_unique_ips(
    networks: Iterable[IPvAnyNetwork],
) -> tuple[Dict[int, Set[IPvAnyAddress]], int, int]:
    unique: Dict[int, Set[IPvAnyAddress]] = {4: set(), 6: set()}
    raw_total = 0
    for network in networks:
        LOGGER.info("读取网段 %s（共 %d 个地址）", network, network.num_addresses)
        for ip in network:
            raw_total += 1
            unique[ip.version].add(ip)
    unique_total = sum(len(addresses) for addresses in unique.values())
    LOGGER.info(
        "完成去重：原始 %d 个 IP，唯一 %d 个，剔除重复 %d 个",
        raw_total,
        unique_total,
        raw_total - unique_total,
    )
    return unique, raw_total, unique_total


def prepare_output_dir(output_dir: Path, clean: bool) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    if not clean:
        return
    for pattern in ("*.txt", "summary.json"):
        for existing in output_dir.glob(pattern):
            try:
                existing.unlink()
            except OSError as err:
                LOGGER.warning("无法删除旧文件 %s：%s", existing, err)


def query_and_group(
    networks: Iterable[IPvAnyNetwork],
    region_field: str,
) -> tuple[
    DefaultDict[str, DefaultDict[int, Set[IPvAnyAddress]]],
    Dict[str, int],
    int,
]:
    unique_ips, raw_total, unique_total = collect_unique_ips(networks)
    db_manager = DBManager()
    if not db_manager.load_database():
        raise RuntimeError("数据库加载失败，无法继续")

    regions: DefaultDict[str, DefaultDict[int, Set[IPvAnyAddress]]] = defaultdict(
        lambda: defaultdict(set)
    )
    counts: Dict[str, int] = defaultdict(int)
    start_time = time.perf_counter()
    try:
        for version in (4, 6):
            ips = unique_ips.get(version)
            if not ips:
                continue
            LOGGER.info("开始查询 IPv%s 唯一地址 %d 个", version, len(ips))
            for ip in sorted(ips):
                ip_str = str(ip)
                try:
                    raw = db_manager.query_ip(ip_str)
                    parsed = IPInfoParser.parse(ip_str, raw)
                    region = sanitize_region_label(str(parsed.get(region_field, "")), region_field)
                except Exception as err:
                    LOGGER.warning("IP %s 查询失败（使用 UNKNOWN 分类）：%s", ip_str, err)
                    region = "UNKNOWN"
                regions[region][version].add(ip)
                counts[region] = counts.get(region, 0) + 1
    finally:
        db_manager.close_database()
        elapsed = time.perf_counter() - start_time
        LOGGER.info(
            "全部查询完成，原始 %d 个 IP，唯一 %d 个，耗时 %.2f 秒",
            raw_total,
            unique_total,
            elapsed,
        )

    return regions, counts, unique_total


def write_region_files(
    region_data: MutableMapping[str, MutableMapping[int, Set[IPvAnyAddress]]],
    counts: Dict[str, int],
    output_dir: Path,
) -> Dict[str, Dict[str, int]]:
    summary: Dict[str, Dict[str, int]] = {}
    for region in sorted(region_data.keys()):
        file_path = output_dir / f"{region}.txt"
        ranges: List[str] = []
        range_count = 0
        for version in sorted(region_data[region].keys()):
            collapsed = collapse_addresses(region_data[region][version])
            ranges.extend(collapsed)
            range_count += len(collapsed)
        with file_path.open("w", encoding="utf-8") as handle:
            handle.write("\n".join(ranges))
            if ranges:
                handle.write("\n")
        summary[region] = {
            "ip_count": counts.get(region, 0),
            "range_count": range_count,
        }
        LOGGER.info("写入 %s：%d 个 IP，合并为 %d 个网段", file_path, counts.get(region, 0), range_count)

    summary_path = output_dir / "summary.json"
    with summary_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2)
    LOGGER.info("汇总信息已写入 %s", summary_path)
    return summary


def main() -> None:
    args = parse_args()
    ip_file = Path(args.ip_file)
    output_dir = Path(args.output_dir)

    networks = load_networks(ip_file)
    prepare_output_dir(output_dir, clean=not args.keep_existing)
    region_data, counts, total_ips = query_and_group(networks, args.region_field)

    if not total_ips:
        LOGGER.warning("没有可处理的 IP，脚本结束")
        return

    summary = write_region_files(region_data, counts, output_dir)
    LOGGER.info("共写入 %d 个地区文件", len(summary))


if __name__ == "__main__":
    main()
