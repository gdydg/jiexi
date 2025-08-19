#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
resolve_ips.py
定时解析指定域名，收集所有 A/AAAA IP，输出到 ips.txt 和 output/<domain>.txt
支持：环境变量 DOMAINS（必填）、DNS_SERVERS（可选，逗号分隔）
"""

import os
import sys
import datetime
from pathlib import Path

try:
    import dns.resolver
    import dns.exception
except ImportError:
    print("缺少依赖 dnspython，请先 pip install dnspython", file=sys.stderr)
    sys.exit(2)


def parse_domains(raw: str) -> list[str]:
    if not raw:
        return []
    # 支持逗号、空格、换行分隔
    parts = []
    for sep in [",", "\n", " "]:
        raw = raw.replace(sep, "\n")
    for line in raw.splitlines():
        d = line.strip()
        if d:
            parts.append(d)
    # 去重同时保持稳定顺序
    seen = set()
    result = []
    for d in parts:
        if d not in seen:
            seen.add(d)
            result.append(d)
    return result
def resolve_domain_ips(domain: str, nameservers: list[str] | None = None,
                       record_types: tuple[str, ...] = ("A", "AAAA")) -> list[str]:
    resolver = dns.resolver.Resolver()
    # 超时设置更保守一些
    resolver.timeout = 5.0
    resolver.lifetime = 10.0
    if nameservers:
        resolver.nameservers = nameservers

    ips = set()
    for rtype in record_types:
        try:
            # 普通解析会自动跟随 CNAME 链，拿到最终的 A/AAAA 集合
            answer = resolver.resolve(domain, rtype, raise_on_no_answer=False)
            if answer.rrset:
                for rdata in answer:
                    ips.add(str(rdata))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # 没有记录或域名不存在：跳过该类型
            continue
        except (dns.resolver.Timeout, dns.exception.DNSException) as e:
            print(f"[WARN] 解析 {domain} {rtype} 失败：{e}", file=sys.stderr)
            continue

    return sorted(ips, key=lambda x: (":" in x, x))  # 先 IPv4 后 IPv6，并按字符串排序
def main():
    raw_domains = os.environ.get("DOMAINS", "").strip()
    dns_servers = os.environ.get("DNS_SERVERS", "").strip()

    domains = parse_domains(raw_domains)
    if not domains:
        print("请通过环境变量 DOMAINS 提供至少一个域名，例如：example.com", file=sys.stderr)
        sys.exit(1)

    ns_list = []
    if dns_servers:
        # 允许逗号/空格分隔
        for sep in [",", " "]:
            dns_servers = dns_servers.replace(sep, "\n")
        ns_list = [x.strip() for x in dns_servers.splitlines() if x.strip()]

    out_dir = Path("output")
    out_dir.mkdir(parents=True, exist_ok=True)
    now_utc = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    # 汇总内容
    summary_lines = [f"# Generated at {now_utc}", "# Record types: A, AAAA", ""]

    for domain in domains:
        ips = resolve_domain_ips(domain, nameservers=ns_list or None)
        # 每域名单独文件
        per_file = out_dir / (domain.replace("/", "_") + ".txt")
        per_lines = [f"# {domain}", f"# Generated at {now_utc}"]
        per_lines.extend(ips)
        per_file.write_text("\n".join(per_lines) + "\n", encoding="utf-8")

        # 汇总
        summary_lines.append(f"{domain}:")
        if ips:
            summary_lines.extend(ips)
        else:
            summary_lines.append("# (no A/AAAA records found)")
        summary_lines.append("")  # 空行分隔

    Path("ips.txt").write_text("\n".join(summary_lines), encoding="utf-8")
    print("完成：生成 ips.txt 与 output/*.txt")


if __name__ == "__main__":
    main()
