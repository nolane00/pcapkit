-- PcapKit : classification pédagogique pour Wireshark
-- Ajoute trois champs (utilisables en colonnes) :
--   pcapkit.cat   catégorie du paquet
--   pcapkit.dir   sens du flux (client → serveur, etc.)
--   pcapkit.role  rôle du protocole en une phrase
-- Ajoute aussi deux menus : légende et explication du paquet sélectionné.

local pcapkit = Proto("pcapkit", "PcapKit - classification pédagogique")

local f_cat  = ProtoField.string("pcapkit.cat",  "Catégorie")
local f_dir  = ProtoField.string("pcapkit.dir",  "Sens")
local f_role = ProtoField.string("pcapkit.role", "Rôle")
pcapkit.fields = { f_cat, f_dir, f_role }

local ef_protos   = Field.new("frame.protocols")
local ef_tcp_syn  = Field.new("tcp.flags.syn")
local ef_tcp_ack  = Field.new("tcp.flags.ack")
local ef_tcp_sport = Field.new("tcp.srcport")
local ef_tcp_dport = Field.new("tcp.dstport")
local ef_udp_sport = Field.new("udp.srcport")
local ef_udp_dport = Field.new("udp.dstport")
local ef_dns_resp = Field.new("dns.flags.response")
local ef_http_req = Field.new("http.request")
local ef_http_resp = Field.new("http.response")
local ef_arp_op   = Field.new("arp.opcode")
local ef_icmp_type = Field.new("icmp.type")
local ef_tls_type = Field.new("tls.handshake.type")
local ef_dhcp_type = Field.new("dhcp.option.dhcp")
local ef_eth_dst  = Field.new("eth.dst")

local SERVER_PORTS = {
  [20]=true,[21]=true,[22]=true,[23]=true,[25]=true,[53]=true,[67]=true,[68]=true,
  [69]=true,[80]=true,[110]=true,[111]=true,[123]=true,[135]=true,[139]=true,
  [143]=true,[161]=true,[162]=true,[389]=true,[443]=true,[445]=true,[465]=true,
  [514]=true,[587]=true,[636]=true,[993]=true,[995]=true,[1433]=true,[1521]=true,
  [1883]=true,[2049]=true,[3306]=true,[3389]=true,[5060]=true,[5061]=true,
  [5432]=true,[5672]=true,[6379]=true,[8080]=true,[8443]=true,[9200]=true,[27017]=true,
}

local ROLES = {
  ["Résolution ARP"] = "Associe une adresse IP à une adresse MAC sur le réseau local",
  ["DHCP"] = "Attribue automatiquement une IP et la configuration réseau",
  ["DNS"] = "Traduit les noms de domaine en adresses IP",
  ["TLS (chiffré)"] = "Chiffre et authentifie une connexion (HTTPS, etc.)",
  ["QUIC / HTTP3"] = "Transport chiffré moderne, base de HTTP/3",
  ["Web (HTTP)"] = "Échange de pages et d'API web en clair",
  ["Messagerie"] = "Envoi ou récupération de courriels",
  ["Transfert de fichiers"] = "Transfert de fichiers (souvent en clair)",
  ["Administration (SSH)"] = "Administration distante chiffrée",
  ["Telnet (en clair)"] = "Administration distante en clair (déconseillé)",
  ["Supervision (SNMP)"] = "Supervision et gestion d'équipements réseau",
  ["Temps (NTP)"] = "Synchronisation de l'horloge",
  ["Industriel (Modbus)"] = "Communication industrielle avec des automates",
  ["ICMP"] = "Diagnostic réseau (ping, erreurs)",
  ["Partage SMB"] = "Partage de fichiers et d'imprimantes Windows",
  ["Bureau à distance (RDP)"] = "Prise en main à distance Windows",
  ["Connexion TCP"] = "Demande d'ouverture de connexion TCP",
  ["Transport TCP"] = "Transport fiable, orienté connexion",
  ["Transport UDP"] = "Transport rapide, sans connexion",
  ["IP"] = "Acheminement des paquets sur le réseau",
  ["Autre"] = "Protocole non classé",
}

local function first(field)
  if not field then return nil end
  local v = field()
  if v == nil then return nil end
  return tostring(v)
end

local function num(field)
  local v = first(field)
  if v == nil then return nil end
  return tonumber(v)
end

local function truthy(field)
  local v = first(field)
  return v == "True" or v == "1"
end

local function protocol_set()
  local set = {}
  local protos = first(ef_protos) or ""
  for p in string.gmatch(protos, "[^:]+") do set[p] = true end
  return set
end

local function port_direction(sport, dport)
  if sport == nil or dport == nil then return "n/a" end
  if SERVER_PORTS[dport] and not SERVER_PORTS[sport] then return "client → serveur" end
  if SERVER_PORTS[sport] and not SERVER_PORTS[dport] then return "serveur → client" end
  if dport < 1024 and sport >= 1024 then return "client → serveur" end
  if sport < 1024 and dport >= 1024 then return "serveur → client" end
  return "sens indéterminé"
end

local function classify()
  local set = protocol_set()
  local category = "Autre"

  if set["arp"] then
    category = "Résolution ARP"
  elseif set["dhcp"] or set["bootp"] then
    category = "DHCP"
  elseif set["dns"] then
    category = "DNS"
  elseif set["tls"] then
    category = "TLS (chiffré)"
  elseif set["quic"] then
    category = "QUIC / HTTP3"
  elseif set["http"] or set["http2"] then
    category = "Web (HTTP)"
  elseif set["smtp"] or set["imap"] or set["pop"] then
    category = "Messagerie"
  elseif set["ftp"] or set["ftp-data"] then
    category = "Transfert de fichiers"
  elseif set["ssh"] then
    category = "Administration (SSH)"
  elseif set["telnet"] then
    category = "Telnet (en clair)"
  elseif set["snmp"] then
    category = "Supervision (SNMP)"
  elseif set["ntp"] then
    category = "Temps (NTP)"
  elseif set["modbus"] or set["mbtcp"] then
    category = "Industriel (Modbus)"
  elseif set["icmp"] or set["icmpv6"] then
    category = "ICMP"
  elseif set["smb"] or set["smb2"] or set["nbss"] then
    category = "Partage SMB"
  elseif set["rdp"] then
    category = "Bureau à distance (RDP)"
  elseif set["tcp"] then
    local syn = truthy(ef_tcp_syn)
    local ack = truthy(ef_tcp_ack)
    if syn then
      category = "Connexion TCP"
    else
      category = "Transport TCP"
    end
  elseif set["udp"] then
    category = "Transport UDP"
  elseif set["ip"] or set["ipv6"] then
    category = "IP"
  end

  local direction = "n/a"

  if category == "Résolution ARP" then
    local op = num(ef_arp_op)
    if op == 1 then direction = "diffusion"
    elseif op == 2 then direction = "réponse"
    else direction = "local" end
  elseif category == "DHCP" then
    local t = num(ef_dhcp_type)
    if t == 1 or t == 3 or t == 4 or t == 7 or t == 8 then
      direction = "client → serveur"
    elseif t == 2 or t == 5 or t == 6 then
      direction = "serveur → client"
    else
      direction = port_direction(num(ef_udp_sport), num(ef_udp_dport))
    end
  elseif category == "DNS" then
    local resp = first(ef_dns_resp)
    if resp == "True" or resp == "1" then
      direction = "serveur → client"
    elseif resp == "False" or resp == "0" then
      direction = "client → serveur"
    else
      direction = port_direction(num(ef_udp_sport), num(ef_udp_dport))
    end
  elseif category == "Web (HTTP)" then
    if first(ef_http_req) ~= nil then
      direction = "client → serveur"
    elseif first(ef_http_resp) ~= nil then
      direction = "serveur → client"
    else
      direction = port_direction(num(ef_tcp_sport), num(ef_tcp_dport))
    end
  elseif category == "ICMP" then
    local t = num(ef_icmp_type)
    if t == 8 then direction = "client → serveur"
    elseif t == 0 then direction = "serveur → client"
    elseif t == 3 or t == 11 or t == 12 then direction = "réseau → client"
    else direction = "diagnostic" end
  elseif category == "TLS (chiffré)" then
    local t = num(ef_tls_type)
    if t == 1 then direction = "client → serveur"
    elseif t == 2 then direction = "serveur → client"
    else direction = port_direction(num(ef_tcp_sport), num(ef_tcp_dport)) end
  elseif category == "Connexion TCP" then
    if truthy(ef_tcp_ack) then direction = "serveur → client" else direction = "client → serveur" end
  else
    local sport = num(ef_tcp_sport) or num(ef_udp_sport)
    local dport = num(ef_tcp_dport) or num(ef_udp_dport)
    direction = port_direction(sport, dport)
  end

  return category, direction, ROLES[category] or ROLES["Autre"]
end

function pcapkit.dissector(buffer, pinfo, tree)
  local category, direction, role = classify()
  local subtree = tree:add(pcapkit, buffer(), "PcapKit")
  subtree:add(f_cat, category)
  subtree:add(f_dir, direction)
  subtree:add(f_role, role)
end

register_postdissector(pcapkit)

local LEGEND = [[
PcapKit - lire une capture plus facilement

CATÉGORIES
  Résolution ARP        Qui possède cette IP sur le réseau local ?
  DHCP                  Distribution automatique des adresses IP
  DNS                   Annuaire : nom de domaine → adresse IP
  TLS (chiffré)         Connexion chiffrée (HTTPS, SMTPS, etc.)
  QUIC / HTTP3          Transport chiffré récent, base de HTTP/3
  Web (HTTP)            Requêtes et réponses web en clair
  Messagerie            SMTP, IMAP, POP
  Transfert de fichiers FTP
  Administration (SSH)  Shell distant chiffré
  Telnet (en clair)     Shell distant non chiffré, à éviter
  Supervision (SNMP)    Monitoring d'équipements
  Temps (NTP)           Synchronisation des horloges
  Industriel (Modbus)   Protocole d'automatisme
  ICMP                  Ping et messages d'erreur
  Partage SMB           Fichiers/imprimantes Windows
  Bureau à distance     RDP
  Connexion TCP         SYN / SYN-ACK : ouverture de session
  Transport TCP/UDP     Acheminement des données
  IP                    Routage de niveau 3
  Autre                 Non classé

SENS DU FLUX
  client → serveur     La machine qui initie la demande
  serveur → client     La machine qui répond
  diffusion             Envoi à toutes les machines du réseau local
  réponse               Réponse locale (ARP)
  réseau → client      Message d'erreur d'un routeur ou d'un serveur
  n/a                   Pas de notion client/serveur

ASTUCES
  - Ajoutez les colonnes pcapkit.cat, pcapkit.dir et pcapkit.role :
    Préférences > Apparence > Colonnes > Ajouter.
  - Clic droit sur un paquet > PcapKit > Expliquer ce paquet.
  - Filtrez une catégorie avec : pcapkit.cat == "DNS"
]]

local DETAILS = {
  ["Résolution ARP"] = "ARP fait le lien entre une adresse IP et une adresse MAC sur le réseau local. Une requête ARP est envoyée en diffusion ; la machine qui possède l'IP répond avec son adresse MAC.",
  ["DHCP"] = "DHCP attribue automatiquement une adresse IP, une passerelle et des serveurs DNS. Le client émet Discover/Request, le serveur répond Offer/Ack.",
  ["DNS"] = "DNS traduit un nom (ex. example.com) en adresse IP. La requête part du client vers le résolveur, la réponse revient avec l'adresse.",
  ["TLS (chiffré)"] = "TLS négocie des clés puis chiffre la connexion. Le ClientHello et le ServerHello sont visibles, mais le contenu applicatif ne l'est pas sans les clés.",
  ["QUIC / HTTP3"] = "QUIC est un transport chiffré basé sur UDP, utilisé notamment par HTTP/3. Une grande partie du trafic est chiffrée.",
  ["Web (HTTP)"] = "HTTP transporte les pages web et les API. La requête contient une méthode (GET, POST...), l'hôte et l'URI ; la réponse contient un code (200, 404...).",
  ["Messagerie"] = "SMTP sert à envoyer du courrier, IMAP et POP à le consulter. Vérifiez si la connexion est chiffrée (ports 465/993/995) ou en clair (25/110/143).",
  ["Transfert de fichiers"] = "FTP transfère des fichiers. Le canal de contrôle (port 21) et les données (port 20 ou dynamique) sont souvent en clair.",
  ["Administration (SSH)"] = "SSH ouvre un shell ou un tunnel chiffré vers une machine distante, généralement sur le port 22.",
  ["Telnet (en clair)"] = "Telnet transporte une session distante sans chiffrement : identifiants et commandes sont lisibles. À remplacer par SSH.",
  ["Supervision (SNMP)"] = "SNMP interroge ou configure des équipements réseau (ports 161/162). Les versions 1 et 2c circulent en clair.",
  ["Temps (NTP)"] = "NTP synchronise l'horloge des machines, généralement sur UDP 123.",
  ["Industriel (Modbus)"] = "Modbus échange des registres avec des automates et capteurs, souvent sans authentification ni chiffrement.",
  ["ICMP"] = "ICMP transporte les messages de diagnostic : echo request/reply (ping), destination unreachable, TTL dépassé, etc.",
  ["Partage SMB"] = "SMB partage des fichiers et imprimantes, typiquement sous Windows (port 445). Les versions anciennes sont vulnérables.",
  ["Bureau à distance (RDP)"] = "RDP permet de prendre la main sur un poste Windows à distance (port 3389). À exposer uniquement derrière un VPN.",
  ["Connexion TCP"] = "Le client envoie SYN, le serveur répond SYN-ACK, le client confirme par ACK : la connexion TCP est ouverte.",
  ["Transport TCP"] = "TCP fournit un transport fiable, ordonné et orienté connexion. Il gère les retransmissions et le contrôle de flux.",
  ["Transport UDP"] = "UDP est un transport simple, sans connexion ni garantie de livraison. Il est utilisé par DNS, DHCP, VoIP, jeux, etc.",
  ["IP"] = "IP achemine les paquets entre réseaux grâce aux adresses source et destination. Le TTL limite le nombre de sauts.",
  ["Autre"] = "Ce protocole n'est pas encore décrit par PcapKit. Ajoutez-le dans la table ROLES du fichier pcapkit.lua.",
}

if gui_enabled() then
  local function show_legend()
    local win = TextWindow.new("PcapKit - légende")
    win:set(LEGEND)
  end

  local function explain_packet(...)
    local cat, dir, role
    for i = 1, select("#", ...) do
      local fi = select(i, ...)
      local name = fi.name or "?"
      if name == "pcapkit.cat" then cat = tostring(fi)
      elseif name == "pcapkit.dir" then dir = tostring(fi)
      elseif name == "pcapkit.role" then role = tostring(fi)
      end
    end
    cat = cat or "?"
    dir = dir or "?"
    role = role or "?"
    local detail = DETAILS[cat] or DETAILS["Autre"]
    local text = string.format(
      "Catégorie : %s\nSens      : %s\nRôle      : %s\n\n%s\n\n" ..
      "Filtre associé : pcapkit.cat == \"%s\"", cat, dir, role, detail, cat)
    local win = TextWindow.new("PcapKit - " .. cat)
    win:set(text)
  end

  register_menu("PcapKit/Légende des catégories", show_legend, MENU_TOOLS_UNSORTED)
  register_packet_menu("PcapKit/Expliquer ce paquet", explain_packet,
    "pcapkit.cat,pcapkit.dir,pcapkit.role")
end
