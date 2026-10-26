#!/usr/bin/env python3
"""Vérification rapide de PcapKit sur la capture de démonstration."""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SAMPLE = HERE / "sample.pcap"
sys.path.insert(0, str(ROOT))
import pcapkit

EXPECTED = [
    "Résolution ARP",
    "DNS",
    "Connexion TCP",
    "Transport TCP",
    "Web (HTTP)",
    "ICMP",
    "TLS (chiffré)",
    "DHCP",
]


def packet(**overrides) -> dict:
    p = {
        "no": 0, "t": 0.0, "epoch": 0.0, "length": 100, "protos": set(),
        "proto": "TCP", "info": "", "eth_src": None, "eth_dst": None,
        "ip_src": None, "ip_dst": None, "ipv6_src": None, "ipv6_dst": None,
        "arp_op": None, "arp_src": None, "arp_dst": None, "dns_resp": None,
        "dns_rcode": None, "dns_name": None, "http_req": False, "http_resp": False,
        "http_method": None, "http_host": None, "http_uri": None, "http_code": None,
        "icmp_type": None, "tls_type": None, "dhcp_type": None,
        "tcp_syn": False, "tcp_ack": False, "tcp_rst": False, "tcp_stream": None,
        "sport": None, "dport": None, "cat": "Autre", "role": "", "dir": "n/a",
        "src_host": "?", "dst_host": "?", "src": "?", "dst": "?",
    }
    p.update(overrides)
    return p


def stats_for(packets: list[dict]) -> dict:
    return {
        "cat_counts": Counter(p["cat"] for p in packets),
        "bytes": sum(p["length"] for p in packets),
    }


def has_anomaly(anomalies: list[tuple[str, str, str]], needle: str) -> bool:
    return any(needle in title for _, title, _ in anomalies)


def check_rules() -> int:
    scan = [
        packet(
            no=i, t=i * 0.1, protos={"tcp"}, cat="Connexion TCP",
            tcp_syn=True, tcp_ack=False, sport=40000 + i, dport=1000 + i,
            src_host="10.0.0.5", dst_host="10.0.0.9", dir="client → serveur",
        )
        for i in range(12)
    ]
    anomalies = pcapkit.build_anomalies(scan, stats_for(scan))
    if not has_anomaly(anomalies, "Scan de ports"):
        print("Règle scan de ports : échec.", file=sys.stderr)
        return 1

    dns = [
        packet(
            no=i, t=i * 0.1, length=70, protos={"dns"}, cat="DNS",
            dns_resp=False, src_host="10.0.0.5", dst_host="10.0.0.53",
            dir="client → serveur",
        )
        for i in range(60)
    ]
    anomalies = pcapkit.build_anomalies(dns, stats_for(dns))
    if not has_anomaly(anomalies, "Pic de requêtes DNS"):
        print("Règle pic DNS : échec.", file=sys.stderr)
        return 1

    exfil = [
        packet(
            no=i, t=i * 0.1, length=100_000, protos={"tcp"}, cat="Transport TCP",
            src_host="10.0.0.5", dst_host="10.0.0.9", dir="client → serveur",
        )
        for i in range(20)
    ]
    exfil.append(packet(
        no=20, t=2.0, length=1_000, protos={"tcp"}, cat="Transport TCP",
        src_host="10.0.0.9", dst_host="10.0.0.5", dir="serveur → client",
    ))
    anomalies = pcapkit.build_anomalies(exfil, stats_for(exfil))
    if not has_anomaly(anomalies, "Transfert sortant important"):
        print("Règle transfert sortant : échec.", file=sys.stderr)
        return 1

    suspicious = [packet(
        protos={"tcp"}, cat="Transport TCP", dport=4444,
        src_host="10.0.0.5", dst_host="10.0.0.9", dir="client → serveur",
    )]
    anomalies = pcapkit.build_anomalies(suspicious, stats_for(suspicious))
    if not has_anomaly(anomalies, "ports inhabituels"):
        print("Règle ports inhabituels : échec.", file=sys.stderr)
        return 1

    print("Règles de détection : OK")
    return 0


def main() -> int:
    if not SAMPLE.exists():
        subprocess.run([sys.executable, str(HERE / "make_sample.py")], check=True)

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "rapport.html"
        result = subprocess.run(
            [sys.executable, str(ROOT / "pcapkit.py"), str(SAMPLE), "-o", str(out)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(result.stdout)
            print(result.stderr, file=sys.stderr)
            return 1
        html = out.read_text(encoding="utf-8")
        missing = [cat for cat in EXPECTED if cat not in html]
        if missing:
            print(f"Catégories absentes du rapport : {missing}", file=sys.stderr)
            return 1
        if "13 paquets" not in html:
            print("Le rapport n'annonce pas 13 paquets.", file=sys.stderr)
            return 1
        print("Rapport HTML : OK")

        dry_out = Path(tmp) / "dry-run.html"
        result = subprocess.run(
            [
                sys.executable, str(ROOT / "pcapkit.py"), str(SAMPLE),
                "--ai-dry-run", "-o", str(dry_out),
            ],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(result.stdout)
            print(result.stderr, file=sys.stderr)
            return 1
        if "--- Résumé qui serait envoyé au modèle ---" not in result.stdout:
            print("Le dry-run n'affiche pas l'aperçu du résumé.", file=sys.stderr)
            return 1
        if "Aucun payload" not in result.stdout:
            print("Le dry-run ne contient pas le résumé attendu.", file=sys.stderr)
            return 1
        if "aucun appel effectué" not in result.stdout:
            print("Le dry-run ne confirme pas l'absence d'appel au modèle.", file=sys.stderr)
            return 1
        print("Dry-run IA : OK")

    if check_rules() != 0:
        return 1

    if shutil.which("tshark"):
        result = subprocess.run(
            [
                "tshark", "-r", str(SAMPLE), "-T", "fields",
                "-e", "frame.number", "-e", "pcapkit.cat", "-e", "pcapkit.dir",
            ],
            capture_output=True, text=True,
        )
        if result.returncode == 0 and "Résolution ARP" in result.stdout:
            lines = [line for line in result.stdout.splitlines() if line.strip()]
            if len(lines) != 13:
                print(f"Plugin Lua : {len(lines)} lignes au lieu de 13.", file=sys.stderr)
                return 1
            print("Plugin Lua : OK")
        else:
            print("Plugin Lua : non chargé (normal si Wireshark tourne en root).")
    else:
        print("tshark absent : test du plugin ignoré.")

    print("Tout est OK.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
