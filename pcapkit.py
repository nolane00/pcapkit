#!/usr/bin/env python3
"""PcapKit - transforme une capture en rapport HTML pedagogique.

Usage :
    python3 pcapkit.py capture.pcap
    python3 pcapkit.py capture.pcap -o rapport.html --open
    python3 pcapkit.py capture.pcap --max-packets 0

Le script s'appuie sur tshark (deja fourni avec Wireshark) et ne demande
aucune dependance Python supplementaire.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
import webbrowser
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

C2S = "client → serveur"
S2C = "serveur → client"

SERVER_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 139, 143,
    161, 162, 389, 443, 445, 465, 514, 587, 636, 993, 995, 1433, 1521,
    1883, 2049, 3306, 3389, 5060, 5061, 5432, 5672, 6379, 8080, 8443,
    9200, 27017,
}

SUSPICIOUS_PORTS = {
    1080: "proxy SOCKS",
    1337: "backdoor",
    4444: "Metasploit/backdoor",
    5555: "ADB/backdoor",
    6667: "IRC",
    9001: "Tor",
    9050: "Tor",
    31337: "backdoor",
}

ROLES = {
    "Résolution ARP": "Associe une adresse IP à une adresse MAC sur le réseau local",
    "DHCP": "Attribue automatiquement une IP et la configuration réseau",
    "DNS": "Traduit les noms de domaine en adresses IP",
    "TLS (chiffré)": "Chiffre et authentifie une connexion (HTTPS, etc.)",
    "QUIC / HTTP3": "Transport chiffré moderne, base de HTTP/3",
    "Web (HTTP)": "Échange de pages et d'API web en clair",
    "Messagerie": "Envoi ou récupération de courriels",
    "Transfert de fichiers": "Transfert de fichiers (souvent en clair)",
    "Administration (SSH)": "Administration distante chiffrée",
    "Telnet (en clair)": "Administration distante en clair (déconseillé)",
    "Supervision (SNMP)": "Supervision et gestion d'équipements réseau",
    "Temps (NTP)": "Synchronisation de l'horloge",
    "Industriel (Modbus)": "Communication industrielle avec des automates",
    "ICMP": "Diagnostic réseau (ping, erreurs)",
    "Partage SMB": "Partage de fichiers et d'imprimantes Windows",
    "Bureau à distance (RDP)": "Prise en main à distance Windows",
    "Connexion TCP": "Demande d'ouverture de connexion TCP",
    "Transport TCP": "Transport fiable, orienté connexion",
    "Transport UDP": "Transport rapide, sans connexion",
    "IP": "Acheminement des paquets sur le réseau",
    "Autre": "Protocole non classé",
}

DETAILS = {
    "Résolution ARP": (
        "ARP fait le lien entre une adresse IP et une adresse MAC sur le réseau local. "
        "Une requête ARP est envoyée en diffusion ; la machine qui possède l'IP répond "
        "avec son adresse MAC. Deux réponses différentes pour la même IP peuvent signaler "
        "une attaque ARP spoofing."
    ),
    "DHCP": (
        "DHCP attribue automatiquement une adresse IP, une passerelle et des serveurs DNS. "
        "Le client émet Discover puis Request ; le serveur répond Offer puis Ack. "
        "Le trafic est local et souvent en diffusion."
    ),
    "DNS": (
        "DNS traduit un nom (ex. example.com) en adresse IP. La requête part du client vers "
        "le résolveur, la réponse revient avec l'adresse. Un code de retour différent de 0 "
        "indique une erreur (nom inexistant, refus, etc.)."
    ),
    "TLS (chiffré)": (
        "TLS négocie des clés puis chiffre la connexion. Le ClientHello et le ServerHello "
        "restent visibles, mais le contenu applicatif ne l'est pas sans les clés. "
        "Pour déchiffrer, configurez SSLKEYLOGFILE dans les préférences TLS de Wireshark."
    ),
    "QUIC / HTTP3": (
        "QUIC est un transport chiffré basé sur UDP, utilisé notamment par HTTP/3. "
        "La poignée de main et une grande partie du trafic sont chiffrées."
    ),
    "Web (HTTP)": (
        "HTTP transporte les pages web et les API. La requête contient une méthode "
        "(GET, POST...), l'hôte et l'URI ; la réponse contient un code (200, 404...). "
        "Les identifiants et cookies circulent en clair si le site est en HTTP."
    ),
    "Messagerie": (
        "SMTP sert à envoyer du courrier, IMAP et POP à le consulter. Vérifiez si la "
        "connexion est chiffrée (ports 465, 993, 995) ou en clair (25, 110, 143)."
    ),
    "Transfert de fichiers": (
        "FTP transfère des fichiers. Le canal de contrôle (port 21) et les données "
        "(port 20 ou dynamique) sont souvent en clair : identifiants et fichiers peuvent "
        "être interceptés."
    ),
    "Administration (SSH)": (
        "SSH ouvre un shell ou un tunnel chiffré vers une machine distante, généralement "
        "sur le port 22. C'est le remplaçant recommandé de Telnet."
    ),
    "Telnet (en clair)": (
        "Telnet transporte une session distante sans chiffrement : identifiants et commandes "
        "sont lisibles par quiconque capture le réseau. À remplacer par SSH."
    ),
    "Supervision (SNMP)": (
        "SNMP interroge ou configure des équipements réseau (ports 161/162). Les versions 1 "
        "et 2c circulent en clair ; SNMPv3 ajoute l'authentification et le chiffrement."
    ),
    "Temps (NTP)": (
        "NTP synchronise l'horloge des machines, généralement sur UDP 123. Une horloge "
        "fausse complique l'analyse des journaux et des captures."
    ),
    "Industriel (Modbus)": (
        "Modbus échange des registres avec des automates et capteurs, souvent sans "
        "authentification ni chiffrement. À isoler dans un VLAN dédié."
    ),
    "ICMP": (
        "ICMP transporte les messages de diagnostic : echo request/reply (ping), destination "
        "unreachable, TTL dépassé, etc. Les erreurs ICMP révèlent souvent un problème de "
        "routage ou de pare-feu."
    ),
    "Partage SMB": (
        "SMB partage des fichiers et imprimantes, typiquement sous Windows (port 445). "
        "Les versions anciennes (SMB1) sont vulnérables ; vérifiez aussi les accès invités."
    ),
    "Bureau à distance (RDP)": (
        "RDP permet de prendre la main sur un poste Windows à distance (port 3389). "
        "À exposer uniquement derrière un VPN ou une passerelle sécurisée."
    ),
    "Connexion TCP": (
        "Le client envoie SYN, le serveur répond SYN-ACK, le client confirme par ACK : "
        "la connexion TCP est ouverte. Un SYN sans réponse peut indiquer un port fermé, "
        "un pare-feu ou une machine hors service."
    ),
    "Transport TCP": (
        "TCP fournit un transport fiable, ordonné et orienté connexion. Il gère les "
        "retransmissions, le contrôle de flux et la segmentation des données."
    ),
    "Transport UDP": (
        "UDP est un transport simple, sans connexion ni garantie de livraison. Il est "
        "utilisé par DNS, DHCP, VoIP, jeux, vidéo et de nombreux protocoles industriels."
    ),
    "IP": (
        "IP achemine les paquets entre réseaux grâce aux adresses source et destination. "
        "Le TTL limite le nombre de sauts et permet de détecter les boucles."
    ),
    "Autre": (
        "Ce protocole n'est pas encore décrit par PcapKit. Ajoutez-le dans la table ROLES "
        "du fichier pcapkit.py (et dans pcapkit.lua pour Wireshark)."
    ),
}

CAT_COLORS = {
    "Résolution ARP": ("#fef3c7", "#92400e"),
    "DHCP": ("#ffedd5", "#9a3412"),
    "DNS": ("#dbeafe", "#1e40af"),
    "Web (HTTP)": ("#dcfce7", "#166534"),
    "TLS (chiffré)": ("#ede9fe", "#5b21b6"),
    "QUIC / HTTP3": ("#e0e7ff", "#3730a3"),
    "Messagerie": ("#fce7f3", "#9d174d"),
    "Transfert de fichiers": ("#fef9c3", "#854d0e"),
    "Administration (SSH)": ("#cffafe", "#155e75"),
    "Telnet (en clair)": ("#fee2e2", "#991b1b"),
    "Supervision (SNMP)": ("#ccfbf1", "#115e59"),
    "Temps (NTP)": ("#e5e7eb", "#374151"),
    "Industriel (Modbus)": ("#fde68a", "#78350f"),
    "ICMP": ("#fae8ff", "#86198f"),
    "Partage SMB": ("#e2e8f0", "#334155"),
    "Bureau à distance (RDP)": ("#e0f2fe", "#075985"),
    "Connexion TCP": ("#cffafe", "#0e7490"),
    "Transport TCP": ("#f1f5f9", "#475569"),
    "Transport UDP": ("#f8fafc", "#64748b"),
    "IP": ("#f1f5f9", "#475569"),
    "Autre": ("#f3f4f6", "#4b5563"),
}

FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.time_relative",
    "frame.len",
    "frame.protocols",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.reset",
    "udp.srcport",
    "udp.dstport",
    "dns.flags.response",
    "dns.flags.rcode",
    "dns.qry.name",
    "http.request",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.response",
    "http.response.code",
    "arp.opcode",
    "arp.src.proto_ipv4",
    "arp.dst.proto_ipv4",
    "icmp.type",
    "tls.handshake.type",
    "dhcp.option.dhcp",
    "_ws.col.Protocol",
    "_ws.col.Info",
]


def layer_value(layers: dict, key: str):
    value = layers.get(key)
    if value is None:
        return None
    if isinstance(value, list):
        return value[0] if value else None
    return value


def to_int(value):
    if value is None:
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def to_float(value):
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def is_true(value) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def port_direction(sport, dport) -> str:
    if sport is None or dport is None:
        return "n/a"
    if dport in SERVER_PORTS and sport not in SERVER_PORTS:
        return C2S
    if sport in SERVER_PORTS and dport not in SERVER_PORTS:
        return S2C
    if dport < 1024 <= sport:
        return C2S
    if sport < 1024 <= dport:
        return S2C
    return "sens indéterminé"


def classify(protos: set[str], p: dict) -> str:
    if "arp" in protos:
        return "Résolution ARP"
    if "dhcp" in protos or "bootp" in protos:
        return "DHCP"
    if "dns" in protos:
        return "DNS"
    if "http" in protos or "http2" in protos or "http3" in protos:
        return "Web (HTTP)"
    if "tls" in protos:
        return "TLS (chiffré)"
    if "quic" in protos:
        return "QUIC / HTTP3"
    if "smtp" in protos or "imap" in protos or "pop" in protos:
        return "Messagerie"
    if "ftp" in protos or "ftp-data" in protos:
        return "Transfert de fichiers"
    if "ssh" in protos:
        return "Administration (SSH)"
    if "telnet" in protos:
        return "Telnet (en clair)"
    if "snmp" in protos:
        return "Supervision (SNMP)"
    if "ntp" in protos:
        return "Temps (NTP)"
    if "modbus" in protos or "mbtcp" in protos:
        return "Industriel (Modbus)"
    if "icmp" in protos or "icmpv6" in protos:
        return "ICMP"
    if "smb" in protos or "smb2" in protos or "nbss" in protos or "netbios" in protos:
        return "Partage SMB"
    if "rdp" in protos:
        return "Bureau à distance (RDP)"
    if "tcp" in protos:
        return "Connexion TCP" if p["tcp_syn"] else "Transport TCP"
    if "udp" in protos:
        return "Transport UDP"
    if "ip" in protos or "ipv6" in protos:
        return "IP"
    return "Autre"


def direction(p: dict) -> str:
    cat = p["cat"]
    if cat == "Résolution ARP":
        if p["arp_op"] == 1:
            return "diffusion"
        if p["arp_op"] == 2:
            return "réponse"
        return "local"
    if cat == "DHCP":
        if p["dhcp_type"] in {1, 3, 4, 7, 8}:
            return C2S
        if p["dhcp_type"] in {2, 5, 6}:
            return S2C
        return port_direction(p["sport"], p["dport"])
    if cat == "DNS":
        if p["dns_resp"] is True:
            return S2C
        if p["dns_resp"] is False:
            return C2S
        return port_direction(p["sport"], p["dport"])
    if cat == "Web (HTTP)":
        if p["http_req"]:
            return C2S
        if p["http_resp"]:
            return S2C
        return port_direction(p["sport"], p["dport"])
    if cat == "ICMP":
        if p["icmp_type"] == 8:
            return C2S
        if p["icmp_type"] == 0:
            return S2C
        if p["icmp_type"] in {3, 11, 12}:
            return "réseau → client"
        return "diagnostic"
    if cat == "TLS (chiffré)":
        if p["tls_type"] == 1:
            return C2S
        if p["tls_type"] == 2:
            return S2C
        return port_direction(p["sport"], p["dport"])
    if cat == "Connexion TCP":
        return S2C if p["tcp_ack"] else C2S
    return port_direction(p["sport"], p["dport"])


def endpoint(host: str, port: int | None) -> str:
    if not host:
        host = "?"
    if port is None:
        return host
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def parse_packet(layers: dict) -> dict:
    protos = set((layer_value(layers, "frame.protocols") or "").split(":"))
    p = {
        "no": to_int(layer_value(layers, "frame.number")) or 0,
        "t": to_float(layer_value(layers, "frame.time_relative")) or 0.0,
        "epoch": to_float(layer_value(layers, "frame.time_epoch")) or 0.0,
        "length": to_int(layer_value(layers, "frame.len")) or 0,
        "protos": protos,
        "proto": layer_value(layers, "_ws.col.protocol") or (list(protos)[-1] if protos else "?"),
        "info": layer_value(layers, "_ws.col.info") or "",
        "eth_src": layer_value(layers, "eth.src"),
        "eth_dst": layer_value(layers, "eth.dst"),
        "ip_src": layer_value(layers, "ip.src"),
        "ip_dst": layer_value(layers, "ip.dst"),
        "ipv6_src": layer_value(layers, "ipv6.src"),
        "ipv6_dst": layer_value(layers, "ipv6.dst"),
        "arp_op": to_int(layer_value(layers, "arp.opcode")),
        "arp_src": layer_value(layers, "arp.src.proto_ipv4"),
        "arp_dst": layer_value(layers, "arp.dst.proto_ipv4"),
        "dns_resp": None,
        "dns_rcode": to_int(layer_value(layers, "dns.flags.rcode")),
        "dns_name": layer_value(layers, "dns.qry.name"),
        "http_req": is_true(layer_value(layers, "http.request")),
        "http_resp": is_true(layer_value(layers, "http.response")),
        "http_method": layer_value(layers, "http.request.method"),
        "http_host": layer_value(layers, "http.host"),
        "http_uri": layer_value(layers, "http.request.uri"),
        "http_code": layer_value(layers, "http.response.code"),
        "icmp_type": to_int(layer_value(layers, "icmp.type")),
        "tls_type": to_int(layer_value(layers, "tls.handshake.type")),
        "dhcp_type": to_int(layer_value(layers, "dhcp.option.dhcp")),
        "tcp_syn": is_true(layer_value(layers, "tcp.flags.syn")),
        "tcp_ack": is_true(layer_value(layers, "tcp.flags.ack")),
        "tcp_rst": is_true(layer_value(layers, "tcp.flags.reset")),
        "tcp_stream": to_int(layer_value(layers, "tcp.stream")),
        "sport": to_int(layer_value(layers, "tcp.srcport")) or to_int(layer_value(layers, "udp.srcport")),
        "dport": to_int(layer_value(layers, "tcp.dstport")) or to_int(layer_value(layers, "udp.dstport")),
    }
    dns_resp = layer_value(layers, "dns.flags.response")
    if dns_resp is not None:
        p["dns_resp"] = is_true(dns_resp)
    p["cat"] = classify(protos, p)
    p["role"] = ROLES.get(p["cat"], ROLES["Autre"])
    p["dir"] = direction(p)
    p["src_host"] = p["ip_src"] or p["ipv6_src"] or p["arp_src"] or p["eth_src"] or "?"
    p["dst_host"] = p["ip_dst"] or p["ipv6_dst"] or p["arp_dst"] or p["eth_dst"] or "?"
    p["src"] = endpoint(p["src_host"], p["sport"])
    p["dst"] = endpoint(p["dst_host"], p["dport"])
    return p


def esc(value) -> str:
    return html.escape(str(value), quote=True)


def fmt_bytes(n: int) -> str:
    for unit, size in (("Go", 1024**3), ("Mo", 1024**2), ("Ko", 1024)):
        if n >= size:
            return f"{n / size:.1f} {unit}"
    return f"{n} o"


def fmt_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.2f} s"
    minutes, rest = divmod(seconds, 60)
    return f"{int(minutes)} min {rest:.0f} s"


def fmt_time(epoch: float) -> str:
    if not epoch:
        return "?"
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")


def read_capture(path: Path, max_packets: int) -> tuple[list[dict], bool, str]:
    tshark = shutil.which("tshark")
    if not tshark:
        raise RuntimeError("tshark est introuvable. Installez Wireshark/tshark puis reessayez.")

    cmd = [tshark, "-r", str(path), "-T", "json"]
    for field in FIELDS:
        cmd += ["-e", field]
    if max_packets > 0:
        cmd += ["-c", str(max_packets)]

    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "erreur tshark inconnue").strip()
        raise RuntimeError(f"tshark a echoue :\n{message}")
    if not result.stdout.strip():
        return [], False, result.stderr.strip()

    raw = json.loads(result.stdout)
    packets = []
    for item in raw:
        layers = item.get("_source", {}).get("layers", {})
        if layers:
            packets.append(parse_packet(layers))
    limited = max_packets > 0 and len(packets) >= max_packets
    return packets, limited, result.stderr.strip()


def build_stats(packets: list[dict]) -> dict:
    cat_counts = Counter(p["cat"] for p in packets)
    dir_counts = Counter(p["dir"] for p in packets)
    proto_counts = Counter()
    proto_bytes = Counter()
    for p in packets:
        proto_counts[p["proto"]] += 1
        proto_bytes[p["proto"]] += p["length"]

    talkers = Counter(
        (p["src_host"], p["dst_host"]) for p in packets if p["src_host"] != "?" and p["dst_host"] != "?"
    )
    hosts = Counter()
    for p in packets:
        if p["src_host"] != "?":
            hosts[p["src_host"]] += 1
        if p["dst_host"] != "?":
            hosts[p["dst_host"]] += 1

    return {
        "cat_counts": cat_counts,
        "dir_counts": dir_counts,
        "proto_counts": proto_counts,
        "proto_bytes": proto_bytes,
        "talkers": talkers,
        "hosts": hosts,
        "duration": max((p["t"] for p in packets), default=0.0),
        "bytes": sum(p["length"] for p in packets),
        "start": min((p["epoch"] for p in packets if p["epoch"]), default=0.0),
    }


def build_anomalies(packets: list[dict], stats: dict) -> list[tuple[str, str, str]]:
    anomalies: list[tuple[str, str, str]] = []

    rst = sum(1 for p in packets if p["tcp_rst"])
    if rst:
        anomalies.append(("warn", f"{rst} paquet(s) TCP RST",
                          "Connexions refusées ou coupées brutalement. Vérifiez le service visé et le pare-feu."))

    dns_err = sum(1 for p in packets if p["dns_rcode"] not in (None, 0))
    if dns_err:
        anomalies.append(("warn", f"{dns_err} réponse(s) DNS en erreur",
                          "Un nom n'a pas pu être résolu (NXDOMAIN, refus, etc.). Vérifiez le nom et le résolveur."))

    icmp_err = sum(1 for p in packets if p["icmp_type"] in {3, 11, 12})
    if icmp_err:
        anomalies.append(("warn", f"{icmp_err} message(s) d'erreur ICMP",
                          "Destination unreachable ou TTL dépassé : problème de routage, de pare-feu ou de boucle."))

    cleartext = sum(stats["cat_counts"].get(c, 0) for c in ("Telnet (en clair)", "Transfert de fichiers", "Web (HTTP)"))
    if cleartext:
        anomalies.append(("info", f"{cleartext} paquet(s) en clair",
                          "HTTP, FTP ou Telnet peuvent exposer des identifiants et des données. Préférez HTTPS, SFTP et SSH."))

    dns_queries: dict[str, list[float]] = defaultdict(list)
    for p in packets:
        if p["cat"] == "DNS" and p["dns_resp"] is False and p["src_host"] != "?":
            dns_queries[p["src_host"]].append(p["t"])
    dns_floods = []
    for host, times in dns_queries.items():
        if len(times) < 50:
            continue
        span = max(times) - min(times)
        rate = len(times) / max(span, 1.0)
        if rate >= 5:
            dns_floods.append((host, len(times), span, rate))
    if dns_floods:
        dns_floods.sort(key=lambda item: item[3], reverse=True)
        details = "; ".join(
            f"{host} ({n} requêtes en {fmt_duration(span)}, {rate:.0f}/s)"
            for host, n, span, rate in dns_floods[:5]
        )
        anomalies.append((
            "warn",
            f"Pic de requêtes DNS ({len(dns_floods)} hôte(s))",
            f"Volume anormal de requêtes DNS : {details}. Vérifiez un client mal configuré, "
            "un scan DNS ou une tentative d'exfiltration.",
        ))

    client_sent: Counter[str] = Counter()
    client_recv: Counter[str] = Counter()
    for p in packets:
        if p["src_host"] == "?" or p["dst_host"] == "?":
            continue
        if p["dir"] == C2S:
            client_sent[p["src_host"]] += p["length"]
        elif p["dir"] == S2C:
            client_recv[p["dst_host"]] += p["length"]
    total_bytes = max(stats["bytes"], 1)
    exfil = []
    for host, sent in client_sent.items():
        if sent < 1_000_000:
            continue
        recv = client_recv.get(host, 0)
        ratio = sent / max(recv, 1)
        if ratio >= 3 and sent >= total_bytes * 0.25:
            exfil.append((host, sent, recv, ratio))
    if exfil:
        exfil.sort(key=lambda item: item[1], reverse=True)
        details = "; ".join(
            f"{host} ({fmt_bytes(sent)} envoyés / {fmt_bytes(recv)} reçus, ratio {ratio:.1f})"
            for host, sent, recv, ratio in exfil[:5]
        )
        anomalies.append((
            "warn",
            f"Transfert sortant important ({len(exfil)} hôte(s))",
            f"Volume sortant inhabituel : {details}. À confirmer : sauvegarde légitime, "
            "envoi de fichier ou exfiltration.",
        ))

    suspicious_hits: set[tuple[str, str, int]] = set()
    for p in packets:
        if p["dport"] in SUSPICIOUS_PORTS:
            suspicious_hits.add((p["src_host"], p["dst_host"], p["dport"]))
        if p["sport"] in SUSPICIOUS_PORTS:
            suspicious_hits.add((p["dst_host"], p["src_host"], p["sport"]))
    suspicious: dict[tuple[str, str], set[int]] = defaultdict(set)
    for src, dst, port in suspicious_hits:
        suspicious[(src, dst)].add(port)
    if suspicious:
        details = "; ".join(
            f"{src} → {dst} ({', '.join(f'{port} {SUSPICIOUS_PORTS[port]}' for port in sorted(ports))})"
            for (src, dst), ports in list(suspicious.items())[:5]
        )
        anomalies.append((
            "warn",
            f"Connexion(s) vers des ports inhabituels ({len(suspicious)})",
            f"Ports rarement légitimes : {details}. Vérifiez le service, l'utilisateur et l'heure.",
        ))

    arp_map: dict[str, set[str]] = defaultdict(set)
    for p in packets:
        if "arp" in p["protos"] and p["arp_op"] == 2 and p["arp_src"] and p["eth_src"]:
            arp_map[p["arp_src"]].add(p["eth_src"])
    spoofed = {ip: macs for ip, macs in arp_map.items() if len(macs) > 1}
    if spoofed:
        details = ", ".join(f"{ip} → {', '.join(sorted(macs))}" for ip, macs in list(spoofed.items())[:5])
        anomalies.append(("warn", f"{len(spoofed)} IP avec plusieurs adresses MAC (ARP)",
                          f"À vérifier : {details}. Cela peut être normal (redondance) ou révéler un ARP spoofing."))

    syn = set()
    synack = set()
    syn_ports: dict[tuple[str, str], set[int]] = defaultdict(set)
    for p in packets:
        if p["cat"] != "Connexion TCP":
            continue
        if p["tcp_syn"] and not p["tcp_ack"]:
            syn.add((p["src_host"], p["dst_host"], p["dport"]))
            if p["dport"] is not None:
                syn_ports[(p["src_host"], p["dst_host"])].add(p["dport"])
        elif p["tcp_syn"] and p["tcp_ack"]:
            synack.add((p["dst_host"], p["src_host"], p["sport"]))

    scans = []
    for (src, dst), ports in syn_ports.items():
        if len(ports) < 10:
            continue
        established = sum(1 for port in ports if (dst, src, port) in synack)
        if established <= len(ports) // 3:
            scans.append((src, dst, len(ports), established))
    if scans:
        details = "; ".join(
            f"{src} → {dst} ({n} ports, {est} établi(s))"
            for src, dst, n, est in scans[:5]
        )
        anomalies.append((
            "warn",
            f"Scan de ports probable ({len(scans)} source(s))",
            f"Tentatives SYN vers de nombreux ports : {details}. Vérifiez l'origine, "
            "la cible et le pare-feu ; un scan précède souvent une exploitation.",
        ))

    unanswered = syn - synack
    if unanswered and not scans:
        anomalies.append(("info", f"{len(unanswered)} SYN sans SYN-ACK",
                          "Port fermé, pare-feu ou capture commencée au milieu d'une connexion. À confirmer."))

    if not anomalies:
        anomalies.append(("ok", "Aucune anomalie évidente",
                          "Aucun RST, erreur DNS/ICMP ou trafic en clair détecté dans les paquets analysés."))
    return anomalies


class HostAnonymizer:
    """Remplace les adresses par H1, H2... avant tout envoi a un modele."""

    def __init__(self) -> None:
        self._labels: dict[str, str] = {}

    def label(self, host: str) -> str:
        if not host or host == "?":
            return "?"
        if host not in self._labels:
            self._labels[host] = f"H{len(self._labels) + 1}"
        return self._labels[host]


SYSTEM_PROMPT = (
    "Tu es un ingénieur réseau pédagogue. Tu analyses un résumé agrégé de capture "
    "réseau (aucun payload, aucune donnée brute) et tu expliques en français, "
    "simplement, ce qui se passe. Tu ne prétends pas avoir vu les paquets. "
    "Tu distingues clairement les faits des hypothèses. Tu termines par 2 ou 3 "
    "vérifications concrètes à faire dans Wireshark. Réponds en texte brut, "
    "en 6 à 10 puces maximum, sans HTML."
)


def build_ai_context(stats: dict, packets: list[dict], anomalies: list[tuple[str, str, str]],
                     anonymize: bool, question: str | None) -> str:
    anon = HostAnonymizer() if anonymize else None

    def host(value: str) -> str:
        return anon.label(value) if anon else value

    cat_text = ", ".join(f"{c} ({n})" for c, n in stats["cat_counts"].most_common())
    proto_text = ", ".join(f"{p} ({n})" for p, n in stats["proto_counts"].most_common(12))
    dir_text = ", ".join(f"{d} ({n})" for d, n in stats["dir_counts"].most_common())
    talkers = "; ".join(
        f"{host(a)} → {host(b)} ({n})" for (a, b), n in stats["talkers"].most_common(10)
    ) or "aucune"
    alerts = "; ".join(title for sev, title, _ in anomalies if sev != "ok") or "aucun"

    lines = [
        "Résumé agrégé d'une capture réseau. Aucun payload et aucune donnée brute ne sont inclus.",
        f"Paquets : {len(packets)} ; durée : {fmt_duration(stats['duration'])} ; volume : {fmt_bytes(stats['bytes'])}.",
        f"Catégories : {cat_text}.",
        f"Protocoles : {proto_text}.",
        f"Sens des flux : {dir_text}.",
        f"Principales conversations : {talkers}.",
        f"Points d'attention : {alerts}.",
        (
            "Les hôtes sont anonymisés en H1, H2, etc. Ne demande pas les adresses réelles."
            if anonymize else
            "Les adresses réelles sont incluses dans ce résumé."
        ),
    ]
    if question:
        lines.append(f"Question de l'utilisateur : {question}")
    return "\n".join(lines)


def call_ollama(base_url: str, model: str, prompt: str, timeout: int) -> str:
    url = base_url.rstrip("/") + "/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2},
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:600]
        raise RuntimeError(f"Ollama a répondu HTTP {exc.code} : {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Impossible de joindre Ollama sur {base_url} : {exc.reason}") from exc

    text = data.get("response") or data.get("message", {}).get("content") or ""
    if not text.strip():
        raise RuntimeError("Ollama a renvoyé une réponse vide.")
    return text.strip()


def call_openai(base_url: str, model: str, api_key: str, system: str, user: str,
                timeout: int) -> str:
    url = base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:600]
        raise RuntimeError(f"API compatible OpenAI : HTTP {exc.code} — {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Impossible de joindre l'API sur {base_url} : {exc.reason}") from exc

    try:
        text = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError("Réponse inattendue de l'API compatible OpenAI.") from exc
    if not text.strip():
        raise RuntimeError("Le modèle a renvoyé une réponse vide.")
    return text.strip()


def call_model(args, context: str) -> str:
    model = args.ai_model or ("llama3.1" if args.ai_provider == "ollama" else "gpt-4o-mini")
    if args.ai_provider == "ollama":
        base = args.ai_url or "http://localhost:11434"
        return call_ollama(base, model, SYSTEM_PROMPT + "\n\n" + context, args.ai_timeout)
    if args.ai_provider == "openai":
        base = args.ai_url or "https://api.openai.com/v1"
        key = args.ai_key or os.environ.get("OPENAI_API_KEY", "")
        if not key and "api.openai.com" in base:
            raise RuntimeError("Clé API absente : utilise --ai-key ou la variable OPENAI_API_KEY.")
        return call_openai(base, model, key, SYSTEM_PROMPT, context, args.ai_timeout)
    raise RuntimeError(f"Fournisseur IA inconnu : {args.ai_provider}")


def badge(cat: str) -> str:
    bg, fg = CAT_COLORS.get(cat, CAT_COLORS["Autre"])
    return f'<span class="badge" style="background:{bg};color:{fg}">{esc(cat)}</span>'


def render_rows(packets: list[dict]) -> str:
    rows = []
    for p in packets:
        rows.append(
            '<tr class="pkt" tabindex="0" '
            f'data-cat="{esc(p["cat"])}" data-dir="{esc(p["dir"])}" '
            f'data-role="{esc(p["role"])}" data-no="{p["no"]}" '
            f'data-info="{esc(p["info"])}">'
            f'<td class="num">{p["no"]}</td>'
            f'<td class="time">+{p["t"]:.3f} s</td>'
            f'<td class="host">{esc(p["src"])}</td>'
            f'<td class="host">{esc(p["dst"])}</td>'
            f'<td class="proto">{esc(p["proto"])}</td>'
            f'<td>{badge(p["cat"])}</td>'
            f'<td class="dir">{esc(p["dir"])}</td>'
            f'<td class="info" title="{esc(p["info"])}">{esc(p["info"])}</td>'
            '</tr>'
        )
    return "\n".join(rows)


def render_cards(stats: dict, packets: list[dict], anomalies: list[tuple[str, str, str]]) -> str:
    alerts = sum(1 for sev, _, _ in anomalies if sev != "ok")
    cards = [
        ("Paquets analysés", f"{len(packets)}"),
        ("Durée", fmt_duration(stats["duration"])),
        ("Volume", fmt_bytes(stats["bytes"])),
        ("Catégories", f"{len(stats['cat_counts'])}"),
        ("Points d'attention", f"{alerts}"),
    ]
    return "".join(
        f'<div class="card"><span class="card-label">{esc(label)}</span>'
        f'<span class="card-value">{esc(value)}</span></div>'
        for label, value in cards
    )


def render_chips(stats: dict, total: int) -> str:
    chips = [("", "Toutes", total)]
    chips += [(cat, cat, count) for cat, count in stats["cat_counts"].most_common()]
    return "".join(
        f'<button class="chip{" active" if cat == "" else ""}" data-cat="{esc(cat)}">'
        f'{esc(label)} <span class="cnt">{count}</span></button>'
        for cat, label, count in chips
    )


def render_stats(stats: dict) -> str:
    talkers = stats["talkers"].most_common(10)
    talkers_html = "".join(
        f'<li><span class="rank-name">{esc(src)} → {esc(dst)}</span>'
        f'<span class="rank-val">{n}</span></li>'
        for (src, dst), n in talkers
    ) or '<li class="muted">Aucune conversation IP.</li>'

    proto_max = max(stats["proto_counts"].values(), default=1)
    proto_html = "".join(
        f'<div class="bar-row"><span class="bar-label">{esc(name)}</span>'
        f'<div class="bar-track"><div class="bar-fill" style="width:{count / proto_max * 100:.1f}%"></div></div>'
        f'<span class="bar-val">{count}</span></div>'
        for name, count in stats["proto_counts"].most_common(12)
    ) or '<p class="muted">Aucun protocole détecté.</p>'

    times = stats.get("timeline", [])
    max_bin = max(times, default=1) or 1
    bars = "".join(
        f'<div class="tbar" style="height:{max(4, value / max_bin * 100):.0f}%" title="{value} paquet(s)"></div>'
        for value in times
    ) or '<div class="tbar" style="height:4%"></div>'

    return f"""
<section class="panel">
  <h2>Qui parle à qui ?</h2>
  <ol class="rank">{talkers_html}</ol>
</section>
<section class="panel">
  <h2>Hiérarchie des protocoles</h2>
  {proto_html}
</section>
<section class="panel">
  <h2>Chronologie</h2>
  <div class="timeline">{bars}</div>
  <div class="time-axis"><span>0 s</span><span>{esc(fmt_duration(stats['duration']))}</span></div>
</section>
"""


def render_anomalies(anomalies: list[tuple[str, str, str]]) -> str:
    icons = {"warn": "!", "info": "i", "ok": "OK"}
    return "".join(
        f'<div class="alert {sev}"><span class="alert-icon">{icons.get(sev, "i")}</span>'
        f'<div><strong>{esc(title)}</strong><p>{esc(desc)}</p></div></div>'
        for sev, title, desc in anomalies
    )


def render_fiches(stats: dict) -> str:
    fiches = []
    for i, (cat, count) in enumerate(stats["cat_counts"].most_common()):
        role = ROLES.get(cat, ROLES["Autre"])
        detail = DETAILS.get(cat, DETAILS["Autre"])
        open_attr = " open" if i == 0 else ""
        fiches.append(
            f'<details class="fiche"{open_attr}>'
            f'<summary>{badge(cat)} <span class="muted">{count} paquet(s)</span></summary>'
            f'<p><strong>Rôle :</strong> {esc(role)}</p>'
            f'<p>{esc(detail)}</p>'
            '</details>'
        )
    return "\n".join(fiches)


CSS = """
:root {
  --bg:#f4f6fb; --card:#ffffff; --ink:#182230; --muted:#667085;
  --line:#e4e7ec; --accent:#1d4ed8; --accent-soft:#e8efff;
  --warn:#b42318; --warn-bg:#fef3f2; --info:#175cd3; --info-bg:#eff8ff;
  --ok:#027a48; --ok-bg:#ecfdf3;
}
* { box-sizing: border-box; }
[hidden] { display: none !important; }
body {
  margin:0; color:var(--ink); background:var(--bg);
  font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
  line-height:1.5;
}
.hero {
  background: linear-gradient(135deg,#0f172a 0%,#1e3a8a 55%,#1d4ed8 100%);
  color:#fff; padding:30px 34px 34px;
}
.kicker { margin:0 0 4px; text-transform:uppercase; letter-spacing:.16em; font-size:12px; opacity:.75; }
.hero h1 { margin:0; font-size:30px; letter-spacing:-.02em; }
.hero .file { margin:8px 0 0; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:14px; opacity:.9; }
.hero .meta { margin-top:14px; font-size:13px; opacity:.85; }
.wrap { max-width:1500px; margin:0 auto; padding:24px 28px 60px; }
.cards { display:grid; grid-template-columns:repeat(5,1fr); gap:14px; margin-bottom:20px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:14px; padding:16px 18px; }
.card-label { display:block; color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em; }
.card-value { display:block; font-size:26px; font-weight:700; margin-top:6px; }
.banner { margin:0 0 18px; padding:12px 16px; border:1px solid #fedf89; background:#fffaeb; color:#93370d; border-radius:12px; font-size:14px; }
.controls { display:flex; flex-wrap:wrap; gap:10px; align-items:center; background:var(--card); border:1px solid var(--line); border-radius:14px; padding:14px; margin-bottom:12px; }
.controls input, .controls select {
  font:inherit; padding:9px 12px; border:1px solid var(--line); border-radius:10px; background:#fff; color:var(--ink);
}
.controls input { flex:1 1 320px; min-width:220px; }
.controls select { flex:0 1 220px; }
.controls input:focus, .controls select:focus { outline:2px solid #bfd3ff; border-color:var(--accent); }
.btn-ghost { font:inherit; padding:9px 14px; border:1px solid var(--line); border-radius:10px; background:#fff; cursor:pointer; color:var(--ink); }
.btn-ghost:hover { background:#f8fafc; }
.shown { font-size:13px; color:var(--muted); margin-left:auto; }
.chips { display:flex; flex-wrap:wrap; gap:8px; margin:0 0 18px; }
.chip { font:inherit; font-size:13px; padding:7px 11px; border-radius:999px; border:1px solid var(--line); background:#fff; color:var(--ink); cursor:pointer; }
.chip:hover { border-color:#b9c6e6; }
.chip.active { background:var(--accent); border-color:var(--accent); color:#fff; }
.chip .cnt { opacity:.7; margin-left:4px; }
.table-wrap { background:var(--card); border:1px solid var(--line); border-radius:14px; overflow:auto; max-height:70vh; }
table { border-collapse:collapse; width:100%; font-size:13px; }
thead th { position:sticky; top:0; z-index:1; text-align:left; background:#f8fafc; color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.07em; padding:10px 12px; border-bottom:1px solid var(--line); white-space:nowrap; }
tbody td { padding:8px 12px; border-bottom:1px solid #f1f3f7; vertical-align:top; }
tbody tr.pkt:hover { background:var(--accent-soft); cursor:pointer; }
tbody tr.pkt:focus { outline:2px solid #bfd3ff; outline-offset:-2px; }
td.num, td.time { white-space:nowrap; color:var(--muted); font-variant-numeric:tabular-nums; }
td.host, td.proto, td.dir { white-space:nowrap; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px; }
td.info { max-width:520px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.badge { display:inline-block; padding:3px 8px; border-radius:999px; font-size:11px; font-weight:600; white-space:nowrap; }
.grid { display:grid; grid-template-columns:1.15fr .85fr; gap:18px; margin-top:18px; }
.panel { background:var(--card); border:1px solid var(--line); border-radius:14px; padding:18px; margin-bottom:18px; }
.panel h2 { margin:0 0 12px; font-size:16px; }
.rank { list-style:none; margin:0; padding:0; }
.rank li { display:flex; gap:12px; align-items:baseline; padding:7px 0; border-bottom:1px solid #f1f3f7; font-size:13px; }
.rank li:last-child { border-bottom:0; }
.rank-name { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.rank-val { margin-left:auto; font-weight:700; font-variant-numeric:tabular-nums; }
.bar-row { display:grid; grid-template-columns:110px 1fr 44px; gap:10px; align-items:center; margin:7px 0; font-size:12px; }
.bar-label { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.bar-track { background:#eef1f6; border-radius:999px; height:8px; overflow:hidden; }
.bar-fill { background:linear-gradient(90deg,#60a5fa,#1d4ed8); height:100%; border-radius:999px; }
.bar-val { text-align:right; color:var(--muted); font-variant-numeric:tabular-nums; }
.timeline { display:flex; align-items:flex-end; gap:2px; height:96px; padding-top:8px; }
.tbar { flex:1; min-width:2px; background:linear-gradient(180deg,#93c5fd,#1d4ed8); border-radius:3px 3px 0 0; opacity:.9; }
.tbar:hover { opacity:1; }
.time-axis { display:flex; justify-content:space-between; color:var(--muted); font-size:11px; margin-top:4px; }
.alert { display:flex; gap:12px; padding:12px 14px; border-radius:12px; margin:9px 0; border:1px solid var(--line); background:#fff; }
.alert p { margin:3px 0 0; color:var(--muted); font-size:13px; }
.alert-icon { flex:0 0 26px; height:26px; border-radius:999px; display:grid; place-items:center; font-weight:800; font-size:12px; }
.alert.warn { background:var(--warn-bg); border-color:#fecdca; }
.alert.warn .alert-icon { background:#fee4e2; color:var(--warn); }
.alert.info { background:var(--info-bg); border-color:#b2ddff; }
.alert.info .alert-icon { background:#d1e9ff; color:var(--info); }
.alert.ok { background:var(--ok-bg); border-color:#abefc6; }
.alert.ok .alert-icon { background:#d1fadf; color:var(--ok); }
.fiche { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:12px 16px; margin:10px 0; }
.fiche summary { cursor:pointer; display:flex; gap:10px; align-items:center; }
.fiche p { margin:10px 0 4px; }
.muted { color:var(--muted); }
.modal { position:fixed; inset:0; background:rgba(15,23,42,.55); display:flex; align-items:center; justify-content:center; padding:22px; z-index:50; }
.modal-box { position:relative; background:#fff; border-radius:16px; max-width:680px; width:100%; padding:24px; box-shadow:0 24px 60px rgba(15,23,42,.3); max-height:84vh; overflow:auto; }
.modal-box h2 { margin:0 0 6px; font-size:20px; }
.modal-box .close { position:absolute; top:12px; right:14px; border:0; background:transparent; font-size:26px; line-height:1; cursor:pointer; color:var(--muted); }
.modal-box .sub { color:var(--muted); font-size:13px; margin:0 0 14px; }
.modal-box p { margin:10px 0; }
.modal-box .btn { font:inherit; margin-top:10px; padding:9px 14px; border:1px solid var(--accent); background:var(--accent); color:#fff; border-radius:10px; cursor:pointer; }
.modal-box code { background:#f1f5f9; padding:2px 6px; border-radius:6px; font-size:12px; }
.ai-panel { border-color:#d6bbfb; background:linear-gradient(180deg,#fcfaff,#fff); }
.ai-head { display:flex; align-items:center; gap:10px; }
.ai-head h2 { margin:0; }
.ai-meta { color:var(--muted); font-size:12px; margin:6px 0 10px; }
.ai-text { white-space:pre-wrap; font-size:14px; background:#fff; border:1px solid #ede9fe; border-radius:12px; padding:14px 16px; }
.ai-note { color:var(--muted); font-size:12px; margin:10px 0 0; }
footer { color:var(--muted); font-size:12px; text-align:center; margin-top:28px; }
@media (max-width: 1000px) {
  .cards { grid-template-columns:repeat(2,1fr); }
  .grid { grid-template-columns:1fr; }
  .shown { margin-left:0; }
}
@media print {
  .controls, .chips, .modal { display:none !important; }
  .table-wrap { max-height:none; overflow:visible; }
  body { background:#fff; }
  .hero { background:#111827; }
}
"""

SCRIPT = """
const DETAILS = __DETAILS__;
const rows = Array.from(document.querySelectorAll('tr.pkt'));
const chips = Array.from(document.querySelectorAll('.chip'));
const search = document.getElementById('search');
const dirSel = document.getElementById('dir');
const shown = document.getElementById('shown');
const total = document.getElementById('total');
let activeCat = '';
let currentRow = null;

total.textContent = rows.length;

function applyFilters() {
  const q = search.value.trim().toLowerCase();
  const dir = dirSel.value;
  let count = 0;
  for (const row of rows) {
    const ok = (!activeCat || row.dataset.cat === activeCat)
      && (!dir || row.dataset.dir === dir)
      && (!q || row.textContent.toLowerCase().includes(q));
    row.hidden = !ok;
    if (ok) count++;
  }
  shown.textContent = count;
}

function setCat(cat) {
  activeCat = cat;
  chips.forEach(c => c.classList.toggle('active', c.dataset.cat === cat));
  applyFilters();
}

function openModal(row) {
  currentRow = row;
  const cat = row.dataset.cat;
  document.getElementById('m-title').innerHTML = row.querySelector('.badge').outerHTML;
  document.getElementById('m-sub').textContent = 'Paquet ' + row.dataset.no + ' — ' + row.dataset.dir;
  document.getElementById('m-role').textContent = row.dataset.role;
  document.getElementById('m-detail').textContent = DETAILS[cat] || DETAILS['Autre'] || '';
  document.getElementById('m-info').textContent = row.dataset.info;
  document.getElementById('modal').hidden = false;
}

function closeModal() {
  document.getElementById('modal').hidden = true;
  currentRow = null;
}

chips.forEach(c => c.addEventListener('click', () => setCat(c.dataset.cat)));
search.addEventListener('input', applyFilters);
dirSel.addEventListener('change', applyFilters);
document.getElementById('reset').addEventListener('click', () => {
  search.value = '';
  dirSel.value = '';
  setCat('');
  search.focus();
});
rows.forEach(row => {
  row.addEventListener('click', () => openModal(row));
  row.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openModal(row); }
  });
});
document.querySelector('.modal-box .close').addEventListener('click', closeModal);
document.getElementById('modal').addEventListener('click', e => {
  if (e.target.id === 'modal') closeModal();
});
document.getElementById('m-filter').addEventListener('click', () => {
  if (currentRow) setCat(currentRow.dataset.cat);
  closeModal();
  document.querySelector('.table-wrap').scrollIntoView({behavior: 'smooth', block: 'start'});
});
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
applyFilters();
"""


def render_ai_panel(ai_text: str | None, ai_error: str | None, ai_meta: str | None) -> str:
    if ai_text:
        meta = f'<p class="ai-meta">{esc(ai_meta or "")}</p>' if ai_meta else ""
        return (
            '<section class="panel ai-panel">'
            '<div class="ai-head"><h2>Analyse assistée par IA</h2>'
            '<span class="badge" style="background:#fef3c7;color:#92400e">à vérifier</span></div>'
            f'{meta}'
            f'<div class="ai-text">{esc(ai_text)}</div>'
            "<p class=\"ai-note\">Analyse générée à partir d'un résumé agrégé. "
            "Un modèle peut se tromper : confirmez chaque point dans la liste des paquets.</p>"
            "</section>"
        )
    if ai_error:
        return (
            '<section class="panel ai-panel">'
            '<h2>Analyse assistée par IA</h2>'
            f'<div class="alert warn"><span class="alert-icon">!</span><div>'
            f'<strong>Modèle indisponible</strong><p>{esc(ai_error)}</p>'
            "<p>Le rapport reste utilisable sans IA. Vérifiez Ollama ou la configuration de l'API.</p>"
            '</div></div></section>'
        )
    return ""


def build_html(packets: list[dict], stats: dict, anomalies: list[tuple[str, str, str]],
               capture: Path, limited: bool, max_packets: int,
               ai_text: str | None = None, ai_error: str | None = None,
               ai_meta: str | None = None) -> str:
    start = fmt_time(stats["start"])
    duration = fmt_duration(stats["duration"])
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")
    limit_note = ""
    if limited:
        limit_note = (
            f'<div class="banner">Analyse limitée aux {max_packets} premiers paquets. '
            'Relancez avec <code>--max-packets 0</code> pour analyser toute la capture.</div>'
        )

    stats_block = render_stats(stats)
    anomalies_block = render_anomalies(anomalies)
    fiches_block = render_fiches(stats)
    ai_panel = render_ai_panel(ai_text, ai_error, ai_meta)
    details_json = json.dumps(DETAILS, ensure_ascii=False).replace("</", "<\\/")
    script = SCRIPT.replace("__DETAILS__", details_json)
    chips = render_chips(stats, len(packets))

    return f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PcapKit — {esc(capture.name)}</title>
<style>{CSS}</style>
</head>
<body>
<header class="hero">
  <p class="kicker">PcapKit</p>
  <h1>Rapport de capture</h1>
  <p class="file">{esc(capture.name)}</p>
  <p class="meta">Début : {esc(start)} &nbsp;·&nbsp; Durée : {esc(duration)} &nbsp;·&nbsp; {len(packets)} paquets</p>
</header>
<div class="wrap">
  {limit_note}
  <div class="cards">{render_cards(stats, packets, anomalies)}</div>

  {ai_panel}

  <div class="controls">
    <input id="search" type="search" placeholder="Rechercher une IP, un port, un protocole, une info..." aria-label="Rechercher">
    <select id="dir" aria-label="Filtrer par sens">
      <option value="">Tous les sens</option>
      {''.join(f'<option value="{esc(d)}">{esc(d)} ({n})</option>' for d, n in stats['dir_counts'].most_common())}
    </select>
    <button id="reset" class="btn-ghost">Réinitialiser</button>
    <span class="shown" aria-live="polite"><strong id="shown">0</strong> / <span id="total"></span> paquets affichés</span>
  </div>
  <div class="chips" id="chips">{chips}</div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>N°</th>
          <th>Temps</th>
          <th>Source</th>
          <th>Destination</th>
          <th>Proto</th>
          <th>Catégorie</th>
          <th>Sens</th>
          <th>Infos</th>
        </tr>
      </thead>
      <tbody>
        {render_rows(packets)}
      </tbody>
    </table>
  </div>

  <div class="grid">
    <div>
      {stats_block}
    </div>
    <div>
      <section class="panel">
        <h2>Points d'attention</h2>
        {anomalies_block}
      </section>
      <section class="panel">
        <h2>Comment lire ce rapport</h2>
        <p><strong>Catégorie</strong> : famille du paquet (DNS, Web, TLS...).</p>
        <p><strong>Sens</strong> : qui initie et qui répond. « client → serveur » va de la machine qui demande vers celle qui sert.</p>
        <p><strong>Rôle</strong> : à quoi sert le protocole en une phrase.</p>
        <p>Cliquez sur une ligne pour afficher l'explication complète du protocole.</p>
      </section>
    </div>
  </div>

  <section class="panel">
    <h2>Fiches protocoles</h2>
    {fiches_block}
  </section>

  <footer>Généré par PcapKit le {esc(generated)} · analyse via tshark · {len(packets)} paquets</footer>
</div>

<div id="modal" class="modal" hidden>
  <div class="modal-box" role="dialog" aria-modal="true" aria-labelledby="m-title">
    <button class="close" aria-label="Fermer">×</button>
    <h2 id="m-title"></h2>
    <p class="sub" id="m-sub"></p>
    <p id="m-role"></p>
    <p id="m-detail"></p>
    <p class="muted">Info du paquet : <span id="m-info"></span></p>
    <button id="m-filter" class="btn">Filtrer cette catégorie</button>
  </div>
</div>

<script>{script}</script>
</body>
</html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Transforme une capture réseau en rapport HTML pédagogique (PcapKit).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemples :\n"
            "  python3 pcapkit.py capture.pcap\n"
            "  python3 pcapkit.py capture.pcap -o rapport.html --open\n"
            "  python3 pcapkit.py capture.pcap --max-packets 0\n"
            "  python3 pcapkit.py capture.pcap --ai --ai-provider ollama --ai-model llama3.1\n"
            "  python3 pcapkit.py capture.pcap --ai-dry-run\n"
        ),
    )
    parser.add_argument("capture", type=Path, help="fichier .pcap / .pcapng à analyser")
    parser.add_argument("-o", "--output", type=Path, help="rapport HTML à produire")
    parser.add_argument("--max-packets", type=int, default=20000,
                        help="nombre maximum de paquets analysés (0 = tous, défaut : 20000)")
    parser.add_argument("--open", action="store_true", help="ouvrir le rapport dans le navigateur")

    ai = parser.add_argument_group("Analyse assistée par IA (optionnelle, désactivée par défaut)")
    ai.add_argument("--ai", action="store_true", help="activer l'analyse par un modèle")
    ai.add_argument("--ai-provider", choices=["ollama", "openai"], default="ollama",
                    help="ollama (local, défaut) ou openai (API compatible)")
    ai.add_argument("--ai-model", default=None,
                    help="nom du modèle (défaut : llama3.1 pour Ollama, gpt-4o-mini pour OpenAI)")
    ai.add_argument("--ai-url", default=None,
                    help="URL du serveur (défaut : http://localhost:11434 ou https://api.openai.com/v1)")
    ai.add_argument("--ai-key", default=None,
                    help="clé API (ou variable OPENAI_API_KEY) ; inutile avec Ollama local")
    ai.add_argument("--ai-timeout", type=int, default=90, help="délai maximal en secondes (défaut : 90)")
    ai.add_argument("--ai-anonymize", dest="ai_anonymize", action="store_true", default=True,
                    help="anonymiser les hôtes en H1, H2... (activé par défaut)")
    ai.add_argument("--no-ai-anonymize", dest="ai_anonymize", action="store_false",
                    help="envoyer les adresses réelles au modèle (déconseillé)")
    ai.add_argument("--ai-question", default=None,
                    help="question précise à poser au modèle en plus du résumé")
    ai.add_argument("--ai-dry-run", action="store_true",
                    help="afficher le résumé qui serait envoyé, sans appeler de modèle (implique --ai)")
    args = parser.parse_args()

    if args.ai_dry_run:
        args.ai = True

    capture: Path = args.capture
    if not capture.is_file():
        print(f"Erreur : capture introuvable : {capture}", file=sys.stderr)
        return 1

    output = args.output or capture.with_name(capture.stem + ".pcapkit.html")

    try:
        packets, limited, _ = read_capture(capture, args.max_packets)
    except (RuntimeError, json.JSONDecodeError) as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 1

    if not packets:
        print("Erreur : aucun paquet lisible dans cette capture.", file=sys.stderr)
        return 1

    stats = build_stats(packets)
    stats["timeline"] = []
    if packets:
        tmin = min(p["t"] for p in packets)
        tmax = max(p["t"] for p in packets)
        bins = [0] * 40
        if tmax > tmin:
            for p in packets:
                idx = min(39, int((p["t"] - tmin) / (tmax - tmin) * 39))
                bins[idx] += 1
        else:
            bins[0] = len(packets)
        stats["timeline"] = bins

    anomalies = build_anomalies(packets, stats)

    ai_text = None
    ai_error = None
    ai_meta = None
    if args.ai:
        context = build_ai_context(stats, packets, anomalies, args.ai_anonymize, args.ai_question)
        if args.ai_dry_run:
            print("--- Résumé qui serait envoyé au modèle ---")
            print(context)
            print("--- Fin du résumé (aucun appel effectué) ---")
            ai_meta = "Mode dry-run : aucun appel au modèle n'a été effectué."
        else:
            model = args.ai_model or ("llama3.1" if args.ai_provider == "ollama" else "gpt-4o-mini")
            try:
                ai_text = call_model(args, context)
                ai_meta = (
                    f"Fournisseur : {args.ai_provider} · modèle : {model} · "
                    f"anonymisation : {'oui' if args.ai_anonymize else 'non'}"
                )
                print(f"Analyse IA générée ({args.ai_provider}/{model}).")
            except Exception as exc:
                ai_error = str(exc)
                print(f"Attention : analyse IA indisponible : {exc}", file=sys.stderr)

    html_text = build_html(packets, stats, anomalies, capture, limited, args.max_packets,
                           ai_text=ai_text, ai_error=ai_error, ai_meta=ai_meta)
    output.write_text(html_text, encoding="utf-8")
    print(f"Rapport écrit : {output}")
    print(f"  {len(packets)} paquets · {len(stats['cat_counts'])} catégories · {len(anomalies)} point(s) d'attention")

    if args.open:
        webbrowser.open(output.resolve().as_uri())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
