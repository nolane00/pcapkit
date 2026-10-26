# PcapKit

Rendre Wireshark plus lisible : catégories, sens des flux, rôle des protocoles,
et un rapport HTML autonome. Le tout sans modifier le cœur de Wireshark.

PcapKit ajoute trois choses :

1. **Un profil Wireshark** avec les colonnes `Catégorie`, `Sens` et `Rôle`,
   des couleurs par famille de trafic et des boutons de filtres.
2. **Un plugin Lua** qui remplit ces colonnes et ajoute un menu
   `Clic droit > PcapKit > Expliquer ce paquet`.
3. **Un outil en ligne de commande** qui transforme un `.pcap` en rapport HTML
   interactif, avec statistiques, conversations, chronologie, points d'attention
   et fiches protocoles.

Une connexion optionnelle à un modèle (Ollama local ou API compatible OpenAI)
peut ajouter une synthèse en français. Elle est désactivée par défaut.

---

## Prérequis

- **Wireshark / tshark 4.x** (le plugin utilise l'API Lua de Wireshark).
- **Python 3.8+** pour le rapport HTML. Le générateur n'utilise que la
  bibliothèque standard.
- **Scapy** uniquement pour régénérer la capture de démonstration
  (`python3 tests/make_sample.py`).
- **Ollama** ou une API compatible OpenAI uniquement pour l'option IA.

---

## Contenu

```
pcapkit/
├── install.sh              installation / désinstallation
├── pcapkit.py              générateur de rapport HTML + connecteur IA
├── profile/
│   ├── preferences         colonnes personnalisées
│   ├── colorfilters        couleurs par catégorie
│   └── dfilters            boutons de filtres
├── lua/
│   └── pcapkit.lua         plugin Wireshark
├── tests/
│   ├── make_sample.py      génère une capture de démonstration
│   ├── check.py            tests automatiques
│   └── sample.pcap
├── LICENSE                 licence MIT
└── README.md
```

---

## Installation

### Automatique

```bash
cd ~/pcapkit
./install.sh
```

Si vous installez pour un autre utilisateur (ou via `sudo`) :

```bash
sudo ./install.sh --user <utilisateur>
```

L'installateur copie le profil dans
`~/.config/wireshark/profiles/PcapKit`, le plugin dans
`~/.local/lib/wireshark/plugins/pcapkit.lua`, et crée la commande
`~/.local/bin/pcapkit`.

Redémarrez Wireshark, puis choisissez le profil **PcapKit** en bas à droite de
la fenêtre.

### Manuelle

```bash
mkdir -p ~/.config/wireshark/profiles/PcapKit
cp profile/preferences profile/colorfilters profile/dfilters \
   ~/.config/wireshark/profiles/PcapKit/

mkdir -p ~/.local/lib/wireshark/plugins
cp lua/pcapkit.lua ~/.local/lib/wireshark/plugins/

chmod +x pcapkit.py
ln -sf "$PWD/pcapkit.py" ~/.local/bin/pcapkit
```

Les chemins exacts sont affichés par :

```bash
tshark -G folders | grep -E 'Personal configuration|Personal Lua Plugins'
```

### Désinstallation

```bash
./install.sh --uninstall
```

---

## Utilisation dans Wireshark

1. Ouvrez une capture.
2. En bas à droite, sélectionnez le profil **PcapKit**.
3. La liste affiche maintenant :

   | Colonne | Exemple |
   |---|---|
   | Catégorie | `DNS`, `Web (HTTP)`, `TLS (chiffré)`, `Connexion TCP` |
   | Sens | `client → serveur`, `serveur → client`, `diffusion` |
   | Rôle | `Traduit les noms de domaine en adresses IP` |

4. Clic droit sur un paquet > **PcapKit > Expliquer ce paquet** :
   une fiche en français décrit le protocole, le sens et les points à vérifier.
5. Menu **Outils > PcapKit > Légende des catégories** : rappel des catégories,
   des sens et des astuces.

### Filtres utiles

```
dns
http || http2 || tcp.port == 80
tls || quic
arp
dhcp || bootp
icmp || icmpv6
tcp.flags.syn == 1
tcp.analysis.flags || tcp.flags.reset == 1
dns.flags.rcode != 0
pcapkit.cat == "DNS"
```

Les boutons de filtres du profil reprennent ces requêtes. Ils sont modifiables
dans `profile/dfilters`.

### Couleurs

Les règles sont dans `profile/colorfilters`. Elles sont évaluées de haut en bas :
la première qui correspond gagne. Les erreurs (RST, DNS en erreur, ICMP) sont
placées avant les catégories générales.

---

## Rapport HTML

```bash
pcapkit ma-capture.pcap
pcapkit ma-capture.pcap -o rapport.html --open
pcapkit ma-capture.pcap --max-packets 0
```

Sans `-o`, le rapport est écrit à côté de la capture :
`ma-capture.pcapkit.html`.

Options :

| Option | Effet |
|---|---|
| `-o, --output` | chemin du rapport HTML |
| `--max-packets N` | limite l'analyse aux N premiers paquets (défaut : 20000 ; `0` = tous) |
| `--open` | ouvre le rapport dans le navigateur |

Le rapport contient :

- des cartes de synthèse (paquets, durée, volume, catégories, alertes) ;
- une analyse assistée par IA si demandée ;
- un tableau filtrable par catégorie, sens et recherche libre ;
- les conversations les plus actives ;
- la hiérarchie des protocoles ;
- une chronologie ;
- des points d'attention (RST, erreurs DNS/ICMP, trafic en clair, ARP suspect,
  SYN sans réponse) ;
- une fiche explicative par catégorie présente.

Cliquer sur une ligne ouvre l'explication complète du protocole.

### Exemple avec la capture de démonstration

```bash
python3 tests/make_sample.py
pcapkit tests/sample.pcap --open
```

Catégories attendues : `Résolution ARP`, `DNS`, `Connexion TCP`,
`Transport TCP`, `Web (HTTP)`, `ICMP`, `TLS (chiffré)`, `DHCP`.

---

## Connexion à un modèle (optionnelle)

Deux modes sont pris en charge :

- **Ollama** en local : rien ne quitte la machine, aucune clé API.
- **API compatible OpenAI** : OpenAI, LM Studio, vLLM, etc.

### Ollama local

```bash
ollama serve
ollama pull llama3.1

pcapkit ma-capture.pcap \
  --ai --ai-provider ollama --ai-model llama3.1 --open
```

### API compatible OpenAI

```bash
pcapkit ma-capture.pcap \
  --ai --ai-provider openai \
  --ai-url http://localhost:1234/v1 \
  --ai-model nom-du-modele \
  --ai-key facultatif
```

Pour l'API OpenAI officielle :

```bash
export OPENAI_API_KEY="..."
pcapkit ma-capture.pcap --ai --ai-provider openai --ai-model gpt-4o-mini --open
```

### Voir ce qui serait envoyé

```bash
pcapkit ma-capture.pcap --ai --ai-dry-run
```

Cette commande affiche le résumé exact et n'appelle aucun modèle. C'est le moyen
le plus simple de vérifier la confidentialité avant un envoi.

### Ce qui est envoyé

Par défaut, le modèle reçoit uniquement un **résumé agrégé** :

- nombre de paquets, durée, volume ;
- répartition par catégorie, protocole et sens ;
- principales conversations, avec des hôtes anonymisés `H1`, `H2`, etc. ;
- titres des points d'attention.

Ne sont **pas** envoyés : payloads, URL, identifiants, cookies, adresses MAC,
contenu des paquets. L'anonymisation est active par défaut ; `--no-ai-anonymize`
envoie les adresses réelles et est déconseillé.

### Limites

- Un modèle peut inventer des détails. Le rapport affiche un badge « à vérifier »
  et chaque point doit être confirmé dans la liste des paquets.
- Le trafic TLS 1.3 reste chiffré sans les clés. Pour le déchiffrer, configurez
  `SSLKEYLOGFILE` dans Wireshark (`Préférences > Protocoles > TLS`).
- Un modèle local peut être lent sur une petite machine. Utilisez `--ai-timeout`.

---

## Catégories

| Catégorie | Rôle |
|---|---|
| Résolution ARP | IP ↔ MAC sur le réseau local |
| DHCP | Attribution automatique des adresses IP |
| DNS | Nom de domaine → adresse IP |
| TLS (chiffré) | Chiffrement et authentification |
| QUIC / HTTP3 | Transport chiffré basé sur UDP |
| Web (HTTP) | Pages et API web en clair |
| Messagerie | SMTP, IMAP, POP |
| Transfert de fichiers | FTP |
| Administration (SSH) | Shell distant chiffré |
| Telnet (en clair) | Shell distant non chiffré |
| Supervision (SNMP) | Monitoring d'équipements |
| Temps (NTP) | Synchronisation des horloges |
| Industriel (Modbus) | Automatismes |
| ICMP | Ping et erreurs réseau |
| Partage SMB | Fichiers/imprimantes Windows |
| Bureau à distance (RDP) | Prise en main Windows |
| Connexion TCP | SYN / SYN-ACK |
| Transport TCP | Transport fiable |
| Transport UDP | Transport sans connexion |
| IP | Routage de niveau 3 |
| Autre | Non classé |

---

## Personnalisation

### Ajouter une catégorie

Trois endroits à mettre à jour :

1. `pcapkit.py` : `ROLES`, `DETAILS` et la fonction `classify`.
2. `lua/pcapkit.lua` : `ROLES`, `DETAILS` et la fonction `classify`.
3. `profile/colorfilters` et `profile/dfilters` : une règle de couleur et un
   bouton de filtre.

Exemple de règle de couleur :

```
@PcapKit MonProtocole@monproto@[0,0,0][65535,64250,55255]
```

### Changer les colonnes

Éditez `profile/preferences`, section `gui.column.format`. Le format d'une
colonne personnalisée est `%Cus:champ:occurrence:R`, par exemple
`%Cus:pcapkit.cat:0:R`.

### Changer le prompt IA

Le prompt système est la constante `SYSTEM_PROMPT` dans `pcapkit.py`.

---

## Dépannage

**Les colonnes Catégorie/Sens/Rôle sont vides**
- Vérifiez que le profil **PcapKit** est sélectionné en bas à droite.
- Vérifiez que le plugin est bien dans le dossier « Personal Lua Plugins »
  affiché par `tshark -G folders`.
- Redémarrez Wireshark.

**Le menu PcapKit n'apparaît pas**
- Wireshark désactive les scripts Lua utilisateur lorsqu'il est lancé en
  **root**. Lancez-le avec votre utilisateur normal.
- Vérifiez `Outils > PcapKit > Légende des catégories`.

**`pcapkit : command not found`**
- `~/.local/bin` n'est peut-être pas dans le `PATH`. Utilisez :
  `python3 ~/pcapkit/pcapkit.py ma-capture.pcap`.

**`tshark` introuvable**
- Installez Wireshark ; le paquet fournit `tshark`. Vérifiez avec
  `tshark --version`.

**Le rapport est très long à ouvrir**
- Réduisez `--max-packets` (par défaut 20000) ou découpez la capture avec
  `editcap -c 50000 grosse.pcap partie.pcap`.

**L'IA ne répond pas**
- Vérifiez qu'Ollama tourne : `ollama list`.
- Vérifiez l'URL : par défaut `http://localhost:11434`.
- En cas d'échec, le rapport est quand même généré, avec un encart explicatif.

---

## Tests

```bash
python3 tests/make_sample.py
python3 tests/check.py
python3 pcapkit.py tests/sample.pcap -o /tmp/sample.html
python3 pcapkit.py tests/sample.pcap --ai --ai-dry-run
```

Vérification du plugin :

```bash
tshark -r tests/sample.pcap -T fields \
  -e frame.number -e pcapkit.cat -e pcapkit.dir -e pcapkit.role
```

---

## Confidentialité

- Le rapport HTML est généré localement, sans réseau.
- Le plugin Wireshark ne fait aucun appel réseau.
- L'IA est optionnelle et n'envoie qu'un résumé agrégé, anonymisé par défaut.
- Utilisez `--ai --ai-dry-run` pour inspecter le texte avant tout envoi.
- Pour des captures sensibles, préférez Ollama en local à une API cloud.

---

## Licence

PcapKit est publié sous licence **MIT**. Voir le fichier [LICENSE](LICENSE).
Vous pouvez l'utiliser, le modifier et le redistribuer, y compris dans un cadre
professionnel, en conservant l'avis de copyright et la licence.
