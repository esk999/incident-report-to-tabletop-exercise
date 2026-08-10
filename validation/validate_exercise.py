#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
validate_exercise_generic.py

目的:
  攻撃内容の妥当性ではなく、以下の内部整合性だけを検証する。
  - network.json / pcap_design.json / answer_key.json が読めること
  - pcap_design.json に書いた通信が training.pcap に存在すること
  - answer_key.json に書いた証拠通信が training.pcap に存在すること
  - PCAP内IPが network.json の内部資産・ネットワーク、または pcap_design.json の external_hosts に含まれること

方針:
  - 外部IPは pcap_design.json の external_hosts に明示されたものだけ扱う
  - 未知のプロトコルは成功扱いしない。未検証として警告に出す
  - answer_key.json は related_traffic_id / related_traffic_ids 参照型を優先する
  - related_traffic_id がなければ、finding内の src_ip / dst_ip / protocol / port で直接検証する

使用例:

# JSON事前検証
python3 validate_exercise_generic.py pre \
  --network network.json \
  --pcap-design pcap_design.json \
  --answer-key answer_key.json \
  --out pre_validation_report.md

# PCAP本検証
python3 validate_exercise_generic.py post \
  --network network.json \
  --pcap-design pcap_design.json \
  --answer-key answer_key.json \
  --pcap training.pcap \
  --out validation_report.md
"""

import argparse
import json
import ipaddress
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


# 検証で扱える代表的なプロトコル。
# ここにないものは「未知のプロトコル」として未検証扱いにする。
TCP_LIKE_PROTOCOLS = {
    "tcp",
    "http",
    "https",
    "tls",
    "ssl",
    "smb",
    "ldap",
    "ldaps",
    "rdp",
    "ssh",
    "smtp",
    "smtps",
    "imap",
    "imaps",
    "pop3",
    "pop3s",
}

UDP_LIKE_PROTOCOLS = {
    "udp",
    "ntp",
    "snmp",
    "syslog",
}

BOTH_TCP_UDP_PROTOCOLS = {
    "dns",
    "kerberos",
}

IP_ONLY_PROTOCOLS = {
    "",
    "ip",
    "any",
    "*",
}

NON_PCAP_KEYWORDS = [
    "認証成功",
    "ログオン成功",
    "ファイルを開いた",
    "ファイル閲覧",
    "ファイル窃取",
    "情報窃取",
    "データ窃取",
    "コマンド実行",
    "マルウェア実行",
    "侵害されたと断定",
    "感染したと断定",
    "暗号化実行",
    "C2成立",
]


def load_json(path: str) -> Tuple[Optional[Any], Optional[str]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f), None
    except Exception as e:
        return None, str(e)


def is_ip(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def to_ip(value: Any):
    try:
        return ipaddress.ip_address(value)
    except Exception:
        return None


def normalize_protocol(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def normalize_port(value: Any) -> Optional[int]:
    if value in [None, "", "unknown", "any", "*"]:
        return None
    try:
        return int(value)
    except Exception:
        return None


def get_field(d: Dict[str, Any], candidates: Iterable[str]) -> Any:
    for c in candidates:
        if c in d and d[c] not in [None, ""]:
            return d[c]
    return ""


def walk_dict(obj: Any):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from walk_dict(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from walk_dict(item)


def collect_all_ips(obj: Any) -> Set[str]:
    ips = set()
    for d in walk_dict(obj):
        for v in d.values():
            if is_ip(v):
                ips.add(v)
            elif isinstance(v, list):
                for item in v:
                    if is_ip(item):
                        ips.add(item)
    return ips


def collect_network_info(network_json: Dict[str, Any]) -> Tuple[Set[str], List[ipaddress._BaseNetwork]]:
    """
    network.json から内部資産IPと内部ネットワークを収集する。
    allowed_internal_ips_for_pcap_validation などの明示リストも扱う。
    """
    asset_ips: Set[str] = set()
    internal_networks: List[ipaddress._BaseNetwork] = []

    explicit_ip_keys = {
        "ip",
        "gateway",
        "allowed_internal_ips_for_pcap_validation",
        "allowed_public_placeholder_ips_for_pcap_validation",
    }

    network_keys = {
        "cidr",
        "network",
        "network_range",
    }

    for d in walk_dict(network_json):
        for key, value in d.items():
            key_l = str(key).lower()

            if key_l in explicit_ip_keys:
                if is_ip(value):
                    asset_ips.add(value)
                elif isinstance(value, list):
                    for item in value:
                        if is_ip(item):
                            asset_ips.add(item)

            if key_l in network_keys and isinstance(value, str):
                try:
                    internal_networks.append(ipaddress.ip_network(value, strict=False))
                except Exception:
                    pass

    return asset_ips, internal_networks


def ip_in_networks(ip_str: str, networks: List[ipaddress._BaseNetwork]) -> bool:
    ip = to_ip(ip_str)
    if ip is None:
        return False
    return any(ip in net for net in networks)


def classify_ip(
    ip_str: str,
    asset_ips: Set[str],
    internal_networks: List[ipaddress._BaseNetwork],
    external_ips: Set[str],
) -> str:
    """
    戻り値:
      - external: pcap_design.external_hosts に明示されたIP
      - internal_asset: network.json に明示された資産IP
      - internal_network: network.json のCIDR内だが資産一覧にはないIP
      - unknown: どちらにも分類できないIP
    """
    if ip_str in external_ips:
        return "external"
    if ip_str in asset_ips:
        return "internal_asset"
    if ip_in_networks(ip_str, internal_networks):
        return "internal_network"
    return "unknown"


def collect_external_hosts(pcap_design: Dict[str, Any]) -> Tuple[Set[str], Set[str]]:
    """
    外部ホストは pcap_design.json の external_hosts に明示されたものだけ扱う。
    説明文に「外部」と書かれているだけでは外部扱いしない。
    """
    external_ips: Set[str] = set()
    external_names: Set[str] = set()

    external_hosts = pcap_design.get("external_hosts", [])
    if not isinstance(external_hosts, list):
        return external_ips, external_names

    for host in external_hosts:
        if not isinstance(host, dict):
            continue

        ip = host.get("ip")
        hostname = host.get("hostname")

        if is_ip(ip):
            external_ips.add(ip)

        if isinstance(hostname, str) and hostname:
            external_names.add(hostname)

    return external_ips, external_names


def collect_traffic_items(pcap_design: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    pcap_design.json から traffic_id を持つ通信設計を取得する。
    原則 traffic_plan を見る。なければフォールバックとして全体探索する。
    """
    raw_items: List[Any] = []

    if isinstance(pcap_design.get("traffic_plan"), list):
        raw_items = pcap_design["traffic_plan"]
    else:
        for d in walk_dict(pcap_design):
            if get_field(d, ["traffic_id", "id"]):
                raw_items.append(d)

    items: List[Dict[str, Any]] = []
    seen = set()

    for d in raw_items:
        if not isinstance(d, dict):
            continue

        traffic_id = str(get_field(d, ["traffic_id", "id"]))
        if not traffic_id or traffic_id in seen:
            continue
        seen.add(traffic_id)

        src_ip = get_field(d, ["src_ip", "src", "source_ip"])
        dst_ip = get_field(d, ["dst_ip", "dst", "destination_ip"])
        protocol = normalize_protocol(get_field(d, ["protocol", "proto"]))
        port = normalize_port(get_field(d, ["port", "dst_port", "destination_port"]))

        items.append({
            "traffic_id": traffic_id,
            "situation_id": str(get_field(d, ["situation_id", "related_situation_id"])),
            "src_ip": src_ip if is_ip(src_ip) else "",
            "dst_ip": dst_ip if is_ip(dst_ip) else "",
            "protocol": protocol,
            "port": port,
            "description": str(get_field(d, ["traffic_purpose", "description", "reason_for_inclusion"])),
        })

    return items


def listify(value: Any) -> List[str]:
    if value in [None, ""]:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v not in [None, ""]]
    return [str(value)]


def collect_findings(answer_key: Dict[str, Any]) -> List[Dict[str, Any]]:
    possible_keys = [
        "pcap_observable_findings",
        "findings",
        "observable_findings",
    ]

    raw: List[Any] = []
    if isinstance(answer_key, dict):
        for k in possible_keys:
            if isinstance(answer_key.get(k), list):
                raw.extend(answer_key[k])

    findings: List[Dict[str, Any]] = []

    for d in raw:
        if not isinstance(d, dict):
            continue

        related_traffic_ids = []
        related_traffic_ids.extend(listify(get_field(d, ["related_traffic_id", "traffic_id"])))
        related_traffic_ids.extend(listify(get_field(d, ["related_traffic_ids", "traffic_ids"])))

        # 重複を維持しない
        related_traffic_ids = list(dict.fromkeys(related_traffic_ids))

        findings.append({
            "finding_id": str(get_field(d, ["finding_id", "id"])),
            "related_situation_id": str(get_field(d, ["related_situation_id", "situation_id"])),
            "related_traffic_ids": related_traffic_ids,
            "description": str(get_field(d, ["description"])),
            "src_ip": get_field(d, ["src_ip", "src", "source_ip"]),
            "dst_ip": get_field(d, ["dst_ip", "dst", "destination_ip"]),
            "protocol": normalize_protocol(get_field(d, ["protocol", "proto"])),
            "port": normalize_port(get_field(d, ["port", "dst_port", "destination_port"])),
            "evidence_to_observe": str(get_field(d, ["evidence_to_observe", "evidence"])),
            "wireshark_filter_hint": str(get_field(d, ["wireshark_filter_hint", "filter"])),
        })

    return findings


def is_supported_protocol(protocol: str) -> bool:
    proto = normalize_protocol(protocol)
    return (
        proto in IP_ONLY_PROTOCOLS
        or proto in TCP_LIKE_PROTOCOLS
        or proto in UDP_LIKE_PROTOCOLS
        or proto in BOTH_TCP_UDP_PROTOCOLS
        or proto == "icmp"
    )


def check_unknown_protocols(specs: List[Dict[str, Any]], id_key: str) -> List[str]:
    messages = []
    for spec in specs:
        proto = normalize_protocol(spec.get("protocol"))
        if proto and not is_supported_protocol(proto):
            messages.append(
                f"{spec.get(id_key, '')}: 未知のプロトコル '{proto}' が指定されています。この項目は厳密なPCAP照合では未検証扱いにします。"
            )
    return messages


def check_non_pcap_content_in_findings(findings: List[Dict[str, Any]]) -> List[str]:
    warnings = []
    for f in findings:
        text = f"{f.get('description', '')} {f.get('evidence_to_observe', '')}"
        hit = [kw for kw in NON_PCAP_KEYWORDS if kw in text]
        if hit:
            warnings.append(
                f"{f.get('finding_id', '')}: PCAPだけでは断定しにくい表現がfindingに含まれている可能性があります。該当語: {', '.join(hit)}"
            )
    return warnings


def spec_has_enough_tuple(spec: Dict[str, Any]) -> bool:
    return bool(spec.get("src_ip") or spec.get("dst_ip")) and bool(spec.get("protocol") or spec.get("port") is not None)


def validate_json_stage(network: Dict[str, Any], pcap_design: Dict[str, Any], answer_key: Dict[str, Any]) -> Dict[str, Any]:
    errors: List[str] = []
    warnings: List[str] = []
    ok: List[str] = []

    asset_ips, internal_networks = collect_network_info(network)
    external_ips, external_names = collect_external_hosts(pcap_design)
    traffic_items = collect_traffic_items(pcap_design)
    findings = collect_findings(answer_key)

    traffic_by_id = {t["traffic_id"]: t for t in traffic_items}

    if not traffic_items:
        errors.append("pcap_design.json から traffic_id を持つ通信設計を取得できませんでした。")
    else:
        ok.append(f"pcap_design.json から {len(traffic_items)} 件の通信設計を取得しました。")

    if not findings:
        errors.append("answer_key.json に pcap_observable_findings / findings が見つかりません。")
    else:
        ok.append(f"answer_key.json から {len(findings)} 件のfindingを取得しました。")

    if not external_ips:
        warnings.append("pcap_design.json の external_hosts に外部IPが明示されていません。外部通信がある場合は定義してください。")

    # IP分類チェック
    design_ips = collect_all_ips(pcap_design)
    answer_ips = collect_all_ips(answer_key)
    unknown_ips = []
    cidr_only_ips = []

    for ip in sorted(design_ips | answer_ips):
        cls = classify_ip(ip, asset_ips, internal_networks, external_ips)
        if cls == "unknown":
            unknown_ips.append(ip)
        elif cls == "internal_network":
            cidr_only_ips.append(ip)

    for ip in cidr_only_ips:
        warnings.append(f"{ip} は network.json のCIDR内ですが、資産IPとしては明示されていません。")

    for ip in unknown_ips:
        warnings.append(f"{ip} は network.json の内部定義にも external_hosts にも含まれていません。")

    # answer_key が traffic_id 参照の場合の参照整合性
    missing_refs = []
    direct_tuple_findings = []

    for f in findings:
        refs = f.get("related_traffic_ids", [])
        if refs:
            for tid in refs:
                if tid not in traffic_by_id:
                    missing_refs.append(f"{f.get('finding_id', '')} -> {tid}")
        else:
            direct_tuple_findings.append(f.get("finding_id", ""))

    if missing_refs:
        errors.append(
            "answer_key.json の related_traffic_id が pcap_design.json に存在しません: "
            + ", ".join(missing_refs)
        )

    if direct_tuple_findings:
        warnings.append(
            "traffic_id参照ではなくfinding内の5タプルで直接検証する項目があります: "
            + ", ".join(direct_tuple_findings)
        )

    # 未知プロトコル
    warnings.extend(check_unknown_protocols(traffic_items, "traffic_id"))
    warnings.extend(check_unknown_protocols(findings, "finding_id"))

    # PCAPだけで断定しにくい表現の簡易チェック
    warnings.extend(check_non_pcap_content_in_findings(findings))

    # situation_id の簡易対応
    situation_ids_in_findings = {f.get("related_situation_id") for f in findings if f.get("related_situation_id")}
    situation_ids_in_traffic = {t.get("situation_id") for t in traffic_items if t.get("situation_id")}
    if situation_ids_in_findings and situation_ids_in_traffic:
        missing_situations = situation_ids_in_findings - situation_ids_in_traffic
        if missing_situations:
            warnings.append(
                "answer_key.json の related_situation_id が pcap_design.json 側に見つからない可能性があります: "
                + ", ".join(sorted(missing_situations))
            )

    return {
        "errors": errors,
        "warnings": warnings,
        "ok": ok,
        "summary": {
            "asset_ips": sorted(asset_ips),
            "internal_networks": [str(n) for n in internal_networks],
            "external_ips_from_external_hosts": sorted(external_ips),
            "external_names_from_external_hosts": sorted(external_names),
            "finding_count": len(findings),
            "traffic_item_count": len(traffic_items),
            "traffic_id_reference_findings": sum(1 for f in findings if f.get("related_traffic_ids")),
            "direct_tuple_findings": len(direct_tuple_findings),
        },
    }


def load_pcap(path: str):
    try:
        from scapy.all import rdpcap
        return rdpcap(path), None
    except ImportError:
        return None, "scapy がインストールされていません。pip install scapy を実行してください。"
    except Exception as e:
        return None, str(e)


def packet_matches(pkt: Any, spec: Dict[str, Any]) -> Tuple[bool, str]:
    """
    戻り値: (matched, status)
      status:
        - matched
        - not_matched
        - unknown_protocol
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
    except Exception:
        return False, "not_matched"

    if IP not in pkt:
        return False, "not_matched"

    src_ip = spec.get("src_ip", "")
    dst_ip = spec.get("dst_ip", "")
    proto = normalize_protocol(spec.get("protocol", ""))
    target_port = normalize_port(spec.get("port", None))

    ip = pkt[IP]

    if src_ip and ip.src != src_ip:
        return False, "not_matched"
    if dst_ip and ip.dst != dst_ip:
        return False, "not_matched"

    if proto in IP_ONLY_PROTOCOLS:
        return True, "matched"

    if proto in TCP_LIKE_PROTOCOLS:
        if TCP not in pkt:
            return False, "not_matched"
        if target_port is None:
            return True, "matched"
        tcp = pkt[TCP]
        return (tcp.dport == target_port), "matched" if tcp.dport == target_port else "not_matched"

    if proto in UDP_LIKE_PROTOCOLS:
        if UDP not in pkt:
            return False, "not_matched"
        if target_port is None:
            return True, "matched"
        udp = pkt[UDP]
        return (udp.dport == target_port), "matched" if udp.dport == target_port else "not_matched"

    if proto in BOTH_TCP_UDP_PROTOCOLS:
        if TCP in pkt:
            if target_port is None:
                return True, "matched"
            tcp = pkt[TCP]
            return (tcp.dport == target_port), "matched" if tcp.dport == target_port else "not_matched"
        if UDP in pkt:
            if target_port is None:
                return True, "matched"
            udp = pkt[UDP]
            return (udp.dport == target_port), "matched" if udp.dport == target_port else "not_matched"
        return False, "not_matched"

    if proto == "icmp":
        return (ICMP in pkt), "matched" if ICMP in pkt else "not_matched"

    return False, "unknown_protocol"


def match_packets(packets: Any, spec: Dict[str, Any]) -> Tuple[List[Any], Optional[str]]:
    proto = normalize_protocol(spec.get("protocol", ""))

    if proto and not is_supported_protocol(proto):
        return [], "unknown_protocol"

    matched = []
    for pkt in packets:
        ok, status = packet_matches(pkt, spec)
        if status == "unknown_protocol":
            return [], "unknown_protocol"
        if ok:
            matched.append(pkt)

    return matched, None


def summarize_pcap(packets: Any) -> Dict[str, Any]:
    from scapy.layers.inet import IP, TCP, UDP, ICMP

    ips: Set[str] = set()
    pairs = Counter()
    protocols = Counter()

    first_time = None
    last_time = None

    for pkt in packets:
        t = float(pkt.time)
        if first_time is None or t < first_time:
            first_time = t
        if last_time is None or t > last_time:
            last_time = t

        if IP in pkt:
            ip = pkt[IP]
            ips.add(ip.src)
            ips.add(ip.dst)
            pairs[(ip.src, ip.dst)] += 1

            if TCP in pkt:
                protocols["TCP"] += 1
            elif UDP in pkt:
                protocols["UDP"] += 1
            elif ICMP in pkt:
                protocols["ICMP"] += 1
            else:
                protocols[f"IP_PROTO_{ip.proto}"] += 1

    duration = 0
    if first_time is not None and last_time is not None:
        duration = last_time - first_time

    return {
        "packet_count": len(packets),
        "duration_seconds": round(duration, 3),
        "unique_ip_count": len(ips),
        "unique_ips": sorted(ips),
        "top_pairs": [
            {"src": src, "dst": dst, "count": count}
            for (src, dst), count in pairs.most_common(20)
        ],
        "protocols": dict(protocols),
    }


def resolve_finding_specs(
    finding: Dict[str, Any],
    traffic_by_id: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    finding をPCAP照合用specへ変換する。
    related_traffic_id がある場合は pcap_design.json 側のtrafficを優先する。
    なければ finding 内の5タプルを使う。
    """
    specs = []
    errors = []

    refs = finding.get("related_traffic_ids", [])

    if refs:
        for tid in refs:
            if tid not in traffic_by_id:
                errors.append(f"{finding.get('finding_id', '')}: related_traffic_id '{tid}' が pcap_design.json に存在しません。")
            else:
                spec = dict(traffic_by_id[tid])
                spec["source"] = f"traffic_id:{tid}"
                spec["finding_id"] = finding.get("finding_id", "")
                specs.append(spec)
        return specs, errors

    spec = {
        "traffic_id": "",
        "source": "finding_tuple",
        "finding_id": finding.get("finding_id", ""),
        "src_ip": finding.get("src_ip", "") if is_ip(finding.get("src_ip", "")) else "",
        "dst_ip": finding.get("dst_ip", "") if is_ip(finding.get("dst_ip", "")) else "",
        "protocol": normalize_protocol(finding.get("protocol", "")),
        "port": normalize_port(finding.get("port", None)),
        "description": finding.get("description", ""),
    }

    if not spec_has_enough_tuple(spec):
        errors.append(f"{finding.get('finding_id', '')}: related_traffic_id も検証可能な5タプルもありません。")
    else:
        specs.append(spec)

    return specs, errors


def validate_pcap_stage(
    network: Dict[str, Any],
    pcap_design: Dict[str, Any],
    answer_key: Dict[str, Any],
    pcap_path: str,
) -> Dict[str, Any]:
    errors: List[str] = []
    warnings: List[str] = []
    ok: List[str] = []

    packets, err = load_pcap(pcap_path)
    if err:
        return {
            "errors": [f"PCAPを読み込めません: {err}"],
            "warnings": [],
            "ok": [],
            "summary": {},
        }

    summary = summarize_pcap(packets)
    ok.append(f"PCAPを読み込めました。パケット数: {summary['packet_count']}")

    asset_ips, internal_networks = collect_network_info(network)
    external_ips, external_names = collect_external_hosts(pcap_design)

    # PCAP内IPの分類
    unknown_pcap_ips = []
    cidr_only_pcap_ips = []

    for ip in summary.get("unique_ips", []):
        cls = classify_ip(ip, asset_ips, internal_networks, external_ips)
        if cls == "unknown":
            unknown_pcap_ips.append(ip)
        elif cls == "internal_network":
            cidr_only_pcap_ips.append(ip)

    if unknown_pcap_ips:
        errors.append(
            "PCAP内に network.json の内部定義にも external_hosts にも含まれないIPがあります: "
            + ", ".join(unknown_pcap_ips)
        )

    for ip in cidr_only_pcap_ips:
        warnings.append(f"PCAP内IP {ip} は network.json のCIDR内ですが、資産IPとしては明示されていません。")

    traffic_items = collect_traffic_items(pcap_design)
    traffic_by_id = {t["traffic_id"]: t for t in traffic_items}
    findings = collect_findings(answer_key)

    traffic_success = []
    traffic_failed = []
    traffic_unverified = []

    for t in traffic_items:
        matched, status = match_packets(packets, t)

        if status == "unknown_protocol":
            traffic_unverified.append({
                "traffic_id": t.get("traffic_id", ""),
                "reason": f"未知のプロトコル: {t.get('protocol', '')}",
                "description": t.get("description", ""),
            })
            continue

        if matched:
            traffic_success.append({
                "traffic_id": t.get("traffic_id", ""),
                "matched_packets": len(matched),
                "description": t.get("description", ""),
            })
        else:
            traffic_failed.append(t)

    if traffic_failed:
        errors.append(
            f"pcap_design.json の通信設計のうち {len(traffic_failed)} 件がPCAP内で確認できませんでした。"
        )
    else:
        ok.append("pcap_design.json の検証可能な通信設計はPCAP内で確認できました。")

    if traffic_unverified:
        warnings.append(
            f"未知プロトコルのため未検証の通信設計があります: {len(traffic_unverified)} 件"
        )

    finding_success = []
    finding_failed = []
    finding_unverified = []

    for f in findings:
        specs, ref_errors = resolve_finding_specs(f, traffic_by_id)

        if ref_errors:
            for msg in ref_errors:
                errors.append(msg)
            continue

        all_specs_ok = True
        any_unverified = False
        matched_total = 0

        for spec in specs:
            matched, status = match_packets(packets, spec)

            if status == "unknown_protocol":
                any_unverified = True
                finding_unverified.append({
                    "finding_id": f.get("finding_id", ""),
                    "source": spec.get("source", ""),
                    "reason": f"未知のプロトコル: {spec.get('protocol', '')}",
                    "description": f.get("description", ""),
                })
                continue

            if not matched:
                all_specs_ok = False
                finding_failed.append({
                    "finding_id": f.get("finding_id", ""),
                    "source": spec.get("source", ""),
                    "src_ip": spec.get("src_ip", ""),
                    "dst_ip": spec.get("dst_ip", ""),
                    "protocol": spec.get("protocol", ""),
                    "port": spec.get("port", None),
                    "description": f.get("description", ""),
                })
            else:
                matched_total += len(matched)

        if any_unverified:
            continue

        if all_specs_ok:
            finding_success.append({
                "finding_id": f.get("finding_id", ""),
                "matched_packets": matched_total,
                "description": f.get("description", ""),
            })

    if finding_failed:
        errors.append(f"{len(finding_failed)} 件のfindingがPCAP内で確認できませんでした。")
    else:
        ok.append("answer_key.json の検証可能なfindingはPCAP内で確認できました。")

    if finding_unverified:
        warnings.append(
            f"未知プロトコルのため未検証のfindingがあります: {len(finding_unverified)} 件"
        )

    # PCAPだけで断定しにくい表現の簡易チェック
    warnings.extend(check_non_pcap_content_in_findings(findings))

    return {
        "errors": errors,
        "warnings": warnings,
        "ok": ok,
        "summary": {
            **summary,
            "external_ips_from_external_hosts": sorted(external_ips),
            "external_names_from_external_hosts": sorted(external_names),
            "traffic_total": len(traffic_items),
            "traffic_success": len(traffic_success),
            "traffic_failed": len(traffic_failed),
            "traffic_unverified": len(traffic_unverified),
            "finding_total": len(findings),
            "finding_success": len(finding_success),
            "finding_failed": len(finding_failed),
            "finding_unverified": len(finding_unverified),
        },
        "traffic_success": traffic_success,
        "traffic_failed": traffic_failed,
        "traffic_unverified": traffic_unverified,
        "finding_success": finding_success,
        "finding_failed": finding_failed,
        "finding_unverified": finding_unverified,
    }


def write_report(path: str, title: str, result: Dict[str, Any], mode: str) -> None:
    lines: List[str] = []

    lines.append(f"# {title}")
    lines.append("")

    lines.append("## 検証の目的")
    lines.append("")
    lines.append("この検証は、攻撃内容の妥当性や教育的効果を判定するものではありません。")
    lines.append("目的は、`network.json`、`pcap_design.json`、`answer_key.json`、`training.pcap` の間に矛盾がないかを確認することです。")
    lines.append("")

    lines.append("## 検証種別")
    lines.append("")
    lines.append("JSON事前検証" if mode == "pre" else "PCAP本検証")
    lines.append("")

    lines.append("## 結果概要")
    lines.append("")
    lines.append(f"- エラー数: {len(result.get('errors', []))}")
    lines.append(f"- 警告数: {len(result.get('warnings', []))}")
    lines.append(f"- OK項目数: {len(result.get('ok', []))}")
    lines.append("")

    if result.get("errors"):
        lines.append("## エラー")
        lines.append("")
        for e in result["errors"]:
            lines.append(f"- {e}")
        lines.append("")

    if result.get("warnings"):
        lines.append("## 警告")
        lines.append("")
        for w in result["warnings"]:
            lines.append(f"- {w}")
        lines.append("")

    if result.get("ok"):
        lines.append("## 問題なし")
        lines.append("")
        for o in result["ok"]:
            lines.append(f"- {o}")
        lines.append("")

    lines.append("## サマリ")
    lines.append("")
    summary = result.get("summary", {})
    for k, v in summary.items():
        if isinstance(v, list):
            lines.append(f"### {k}")
            lines.append("")
            for item in v[:80]:
                lines.append(f"- `{item}`")
            if len(v) > 80:
                lines.append(f"- ... 他 {len(v) - 80} 件")
            lines.append("")
        else:
            lines.append(f"- {k}: `{v}`")
    lines.append("")

    if mode == "post":
        lines.append("## 通信設計検証結果")
        lines.append("")

        lines.append("### 成功")
        lines.append("")
        for s in result.get("traffic_success", []):
            lines.append(f"- {s['traffic_id']}: {s['matched_packets']} packets / {s['description']}")
        lines.append("")

        lines.append("### 失敗")
        lines.append("")
        for f in result.get("traffic_failed", []):
            lines.append(
                f"- {f.get('traffic_id', '')}: {f.get('src_ip', '')} -> {f.get('dst_ip', '')} "
                f"{f.get('protocol', '')}/{f.get('port', None)} / {f.get('description', '')}"
            )
        lines.append("")

        lines.append("### 未検証")
        lines.append("")
        for u in result.get("traffic_unverified", []):
            lines.append(f"- {u.get('traffic_id', '')}: {u.get('reason', '')} / {u.get('description', '')}")
        lines.append("")

        lines.append("## Finding検証結果")
        lines.append("")

        lines.append("### 成功")
        lines.append("")
        for s in result.get("finding_success", []):
            lines.append(f"- {s['finding_id']}: {s['matched_packets']} packets / {s['description']}")
        lines.append("")

        lines.append("### 失敗")
        lines.append("")
        for f in result.get("finding_failed", []):
            lines.append(
                f"- {f.get('finding_id', '')}: {f.get('source', '')} / "
                f"{f.get('src_ip', '')} -> {f.get('dst_ip', '')} "
                f"{f.get('protocol', '')}/{f.get('port', None)} / {f.get('description', '')}"
            )
        lines.append("")

        lines.append("### 未検証")
        lines.append("")
        for u in result.get("finding_unverified", []):
            lines.append(
                f"- {u.get('finding_id', '')}: {u.get('source', '')} / "
                f"{u.get('reason', '')} / {u.get('description', '')}"
            )
        lines.append("")

    lines.append("## 判定")
    lines.append("")
    if result.get("errors"):
        lines.append("JSONとPCAPの間に矛盾または未解決の不整合があります。次Stepへ進む前に修正してください。")
    elif result.get("warnings"):
        lines.append("重大な矛盾は確認されませんでしたが、警告または未検証項目があります。人間が確認してください。")
    else:
        lines.append("JSONとPCAPの間に重大な矛盾は確認されませんでした。次Stepへ進めます。")

    Path(path).write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)

    pre = sub.add_parser("pre")
    pre.add_argument("--network", required=True)
    pre.add_argument("--pcap-design", required=True)
    pre.add_argument("--answer-key", required=True)
    pre.add_argument("--out", default="pre_validation_report.md")

    post = sub.add_parser("post")
    post.add_argument("--network", required=True)
    post.add_argument("--pcap-design", required=True)
    post.add_argument("--answer-key", required=True)
    post.add_argument("--pcap", required=True)
    post.add_argument("--out", default="validation_report.md")

    args = parser.parse_args()

    network, err = load_json(args.network)
    if err:
        print(f"network.json 読み込み失敗: {err}", file=sys.stderr)
        sys.exit(1)

    pcap_design, err = load_json(args.pcap_design)
    if err:
        print(f"pcap_design.json 読み込み失敗: {err}", file=sys.stderr)
        sys.exit(1)

    answer_key, err = load_json(args.answer_key)
    if err:
        print(f"answer_key.json 読み込み失敗: {err}", file=sys.stderr)
        sys.exit(1)

    if args.mode == "pre":
        result = validate_json_stage(network, pcap_design, answer_key)
        write_report(args.out, "pre_validation_report", result, "pre")
        print(f"事前検証レポートを出力しました: {args.out}")

    elif args.mode == "post":
        result = validate_pcap_stage(network, pcap_design, answer_key, args.pcap)
        write_report(args.out, "validation_report", result, "post")
        print(f"PCAP本検証レポートを出力しました: {args.out}")


if __name__ == "__main__":
    main()
