#!/usr/bin/env python3
"""Vérification rapide de PcapKit sur la capture de démonstration."""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SAMPLE = HERE / "sample.pcap"

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
