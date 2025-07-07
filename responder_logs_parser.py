import os
import re
import argparse
import csv
from collections import defaultdict
from datetime import datetime

# Liste complète des protocoles gérés
PROTOCOL_PATTERNS = {
    "llmnr": r"\[LLMNR\]",
    "nbt_ns": r"\[NBT-NS\]",
    "mdns": r"\[MDNS\]",
    "dns": r"\[DNS\]",
    "dhcp": r"\[DHCP\]",
    "http": r"\[HTTP\]",
    "https": r"\[HTTPS\]",
    "wpad_proxy": r"\[WPAD\]",
    "auth_proxy": r"\[AUTH\]",
    "smb": r"\[SMB\]",
    "kerberos": r"\[Kerberos\]",
    "sql": r"\[SQL\]",
    "ftp": r"\[FTP\]",
    "imap": r"\[IMAP\]",
    "pop3": r"\[POP3\]",
    "smtp": r"\[SMTP\]",
    "ldap": r"\[LDAP\]",
    "mqtt": r"\[MQTT\]",
    "rdp": r"\[RDP\]",
    "dce_rpc": r"\[DCE-RPC\]",
    "winrm": r"\[WINRM\]",
    "snmp": r"\[SNMP\]"
}

PROTOCOL_CHOICES = ["all"] + list(PROTOCOL_PATTERNS.keys())
 
# Parser CLI
parser = argparse.ArgumentParser(
    description="Analyse les logs Responder et génère un fichier par protocole listant les IPs et noms de machines associés.",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter
)
 
parser.add_argument("-l", "--log-dir", default="/opt/tools/Responder/logs", help="Répertoire contenant les logs Responder")
parser.add_argument("-o", "--output-dir", default="./responder_machines", help="Répertoire de sortie des fichiers générés")
parser.add_argument("-p", "--protocols", nargs="+", choices=PROTOCOL_CHOICES, default="all", metavar="PROTO", help="Protocoles à extraire parmi : {}. Utiliser 'all' pour tous.".format(', '.join(PROTOCOL_PATTERNS)))
# parser.add_argument("-c", "--csv", action="store_true", help="Générer un fichier CSV en plus du .txt pour chaque protocole")
parser.add_argument("-c", "--single-csv", action="store_true", help="Générer un fichier CSV global (tous protocoles)")
parser.add_argument("-d", "--date-suffix", action="store_true", help="Ajouter la date (YYYYMMDD) en suffixe aux fichiers générés")
parser.add_argument("-s", "--summary", action="store_true", help="Afficher un résumé des résultats à la fin de l'éxécution")
parser.add_argument("-g", "--graph", action="store_true", help="Générer un graphe interactif des IPs et noms par protocole (format HTML)")
parser.add_argument("-q", "--quiet", action="store_true", help="Désactiver les messages d'avancement (mode silencieux)")

args = parser.parse_args()
 
responder_log_dir = args.log_dir
output_dir = args.output_dir
# generate_summary = args.summary
# generate_csv = args.csv
use_suffix = args.date_suffix
generate_single_csv = args.single_csv
 
# Protocoles sélectionnés
if "all" in args.protocols:
    selected_protocols = list(PROTOCOL_PATTERNS.keys())
else:
    selected_protocols = args.protocols

protocols = {proto: PROTOCOL_PATTERNS[proto] for proto in selected_protocols}
 
# Structure de stockage: { protocole : { ip : set(noms) } }
data = defaultdict(lambda: defaultdict(set))

suffix = "_" + datetime.now().strftime("%Y%m%d") if use_suffix else ""


# MAIN
def main():
    banner()

    # # Chargement des fichiers existants
    # for proto in protocols:
    #     filepath = os.path.join(output_dir, f"{proto}.txt")
    #     if os.path.exists(filepath):
    #         with open(filepath, "r") as f:
    #             for line in f:
    #                 parts = line.strip().split(":")
    #                 if len(parts) >= 1:
    #                     ip = parts[0].strip()
    #                     names = set()
    #                     if len(parts) == 2 and parts[1].strip():
    #                         names = {n.strip() for n in parts[1].split(",")}
    #                     data[proto][ip].update(names)

    # Analyse des logs
    log("\n🔍 Analyse des fichiers de logs Responder...")

    for proto, pattern in protocols.items():
        log(f"  🔎 Analyse {proto.upper()}...")
        # count_before = len(data[proto])

        for root, _, files in os.walk(responder_log_dir):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if re.search(pattern, line):
                                ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                                name_match = re.search(r"for name ([\w\.\-]+)", line, re.IGNORECASE)
     
                                if ip_match:
                                    ip = ip_match.group(1).strip()
                                    name = name_match.group(1).strip() if name_match else None
                                    if name:
                                        data[proto][ip].add(name)
                                    else:
                                        data[proto][ip]
                except Exception as e:
                    print(f"Erreur lecture fichier {filepath}: {e}")

        # count_after = len(data[proto])
        # new_ips = count_after - count_before
        # log(f"    → {count_after} IP(s) détectées ({'+' + str(new_ips) if new_ips > 0 else 'aucune nouvelle IP'})")

    has_data = any(data[proto] for proto in protocols)

    if not has_data:
        log("\nℹ️ Aucun résultat trouvé dans les logs pour les protocoles sélectionnés.")
        exit(0)

    os.makedirs(output_dir, exist_ok=True)

    # Écriture .txt et .csv
    log("\n📄 Écriture des fichiers TXT et CSV...")

    for proto, ip_dict in data.items():
        txt_path = os.path.join(output_dir, f"{proto}{suffix}.txt")
        with open(txt_path, "w") as f:
            for ip in sorted(ip_dict):
                names = sorted(ip_dict[ip])
                line = f"{ip}: {', '.join(names)}" if names else f"{ip}:"
                f.write(line + "\n")
     
        # if generate_csv:
        csv_path = os.path.join(output_dir, f"{proto}{suffix}.csv")
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["ip", "name"])
            for ip in sorted(ip_dict):
                names = sorted(ip_dict[ip]) or [""]
                for name in names:
                    writer.writerow([ip, name])

    # CSV global
    if generate_single_csv:
        single_csv_rows = []
        csv_path = os.path.join(output_dir, f"responder_all{suffix}.csv")
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["protocole", "ip", "name"])
            for proto, ip_dict in data.items():
                for ip, names in ip_dict.items():
                    if names:
                        for name in names:
                            writer.writerow([proto, ip, name])
                    else:
                        writer.writerow([proto, ip, ""])

    # Résumé
    if args.summary:
        generate_summary(data)

    log(f"\n✅ Extraction terminée pour les protocoles : {', '.join(selected_protocols)}")
    log(f"📁 Fichiers disponibles dans : {output_dir}")

    if args.graph:
        generate_graph(data)


# Fonctions utiles

def log(message):
    if not args.quiet:
        print(message)

def banner():
    log("╔════════════════════════════════════════╗")
    log("║     🛠️ Responder Log Parser v1.0       ║")
    log("╚════════════════════════════════════════╝")

def generate_summary(data):
    line = "\n📊 Résumé des résultats :"
    summary_lines = [line]
    log(line)

    for proto in selected_protocols:
        ip_count = len(data[proto])
        name_count = sum(len(names) for names in data[proto].values())
        line = f"  - {proto.upper():8} : {ip_count} IP(s), {name_count} nom(s)"
        summary_lines.append(line)
        log(line)

    summary_path = os.path.join(output_dir, f"responder_summary{suffix}.txt")
    with open(summary_path, "w") as f:
        f.write("\n".join  (summary_lines))

    log(f"\n📝 Résumé enregistré dans : {summary_path}")

# def generate_graph_static(data):
#     try:
#         from pyvis.network import Network
#     except ImportError:
#         print("❌ L'option --graph nécessite la bibliothèque pyvis.")
#         print("👉 Installe-la avec : pip install pyvis")
#         return
 
#     log("\n🕸️ Génération du graphe interactif (HTML)...")
 
#     net = Network(height="750px", width="100%", directed=True)
 
#     # Couleurs par protocole (cycle si besoin)
#     protocol_colors = [
#         "#f87171", "#facc15", "#34d399", "#60a5fa",
#         "#a78bfa", "#f472b6", "#f97316", "#10b981",
#         "#818cf8", "#eab308", "#fb923c", "#4ade80",
#         "#22d3ee", "#c084fc", "#f43f5e", "#06b6d4"
#     ]
#     proto_color_map = {}
 
#     for i, proto in enumerate(data.keys()):
#         proto_color_map[proto] = protocol_colors[i % len(protocol_colors)]
 
#     x_ip = -200
#     x_name = 200
#     y = 0
#     step = 100  # Espacement vertical
 
#     for proto, ip_dict in data.items():
#         for ip, names in ip_dict.items():
#             ip_node = f"{ip}"
#             net.add_node(ip_node, label=ip_node, color="#3b82f6", shape="dot", x=x_ip, y=y, fixed=True)
 
#             if names:
#                 for name in names:
#                     name_node = f"{name}"
#                     net.add_node(name_node, label=name_node, color="#22c55e", shape="ellipse", x=x_name, y=y, fixed=True)
#                     net.add_edge(ip_node, name_node, title=proto, label=proto, color=proto_color_map[proto])
#                     y += step
#             else:
#                 empty_node = f"{ip}_?"
#                 net.add_node(empty_node, label="?", color="#e5e7eb", shape="box", x=x_name, y=y, fixed=True)
#                 net.add_edge(ip_node, empty_node, title=proto, label=proto, color=proto_color_map[proto])
#                 y += step
 
#     # Légende : un nœud fictif par protocole (non relié)
#     legend_x = 500
#     legend_y = 0
#     for proto, color in proto_color_map.items():
#         net.add_node(f"legend_{proto}", label=proto.upper(), shape="box", color=color, x=legend_x, y=legend_y, fixed=True)
#         legend_y -= 50
 
#     # Désactiver physique automatique
#     net.set_options("""
#     {
#       "physics": {
#         "enabled": false
#       },
#       "interaction": {
#         "dragNodes": true,
#         "zoomView": true,
#         "dragView": true
#       }
#     }
#     """)
 
#     graph_path = os.path.join(output_dir, f"responder_graph{suffix}.html")
#     net.save_graph(graph_path)
#     log(f"🌐 Graphe interactif enregistré dans : {graph_path}")

# def generate_graph_static_grouped(data):

#     def get_subnet(ip):
#         # suppose IPv4, retourne les 3 premiers octets
#         parts = ip.split('.')
#         if len(parts) == 4:
#             return '.'.join(parts[:3]) + '.0/24'
#         return "unknown"

#     try:
#         from pyvis.network import Network
#     except ImportError:
#         print("❌ L'option --graph nécessite la bibliothèque pyvis.")
#         print("👉 Installe-la avec : pip install pyvis")
#         return
 
#     from os.path import join
 
#     log("\n🕸️ Génération du graphe interactif (HTML)...")
 
#     net = Network(height="750px", width="100%", directed=True)
 
#     protocol_colors = [
#         "#f87171", "#facc15", "#34d399", "#60a5fa",
#         "#a78bfa", "#f472b6", "#f97316", "#10b981",
#         "#818cf8", "#eab308", "#fb923c", "#4ade80",
#         "#22d3ee", "#c084fc", "#f43f5e", "#06b6d4"
#     ]
#     proto_color_map = {proto: protocol_colors[i % len(protocol_colors)] for i, proto in enumerate(data.keys())}
 
#     def get_subnet(ip):
#         parts = ip.split('.')
#         if len(parts) == 4:
#             return '.'.join(parts[:3]) + '.0/24'
#         return "unknown"
 
#     # Trouver tous les sous-réseaux
#     all_subnets = set()
#     for ip_dict in data.values():
#         for ip in ip_dict.keys():
#             all_subnets.add(get_subnet(ip))
#     all_subnets = sorted(all_subnets)
 
#     # Map sous-réseau → x coordonnée
#     subnet_x_map = {subnet: -300 + i * 150 for i, subnet in enumerate(all_subnets)}
 
#     x_name = 200
 
#     # Position des noms par IP pour ne pas chevaucher
#     ip_name_y_offsets = {}
 
#     # Parcours et ajout nœuds
#     y_spacing = 80  # vertical spacing between IPs in same subnet
 
#     # pour gérer y par sous réseau
#     subnet_y_counters = {subnet: 0 for subnet in all_subnets}
 
#     for proto, ip_dict in data.items():
#         for ip, names in ip_dict.items():
#             subnet = get_subnet(ip)
#             x_ip = subnet_x_map.get(subnet, -300)
#             y_ip = subnet_y_counters[subnet]
 
#             # Ajouter noeud IP
#             net.add_node(ip, label=ip, color="#3b82f6", shape="dot", x=x_ip, y=y_ip, fixed=True)
 
#             # Position de base pour les noms reliés à cette IP
#             ip_name_y_offsets[ip] = y_ip
 
#             if names:
#                 name_y = y_ip
#                 for name in names:
#                     net.add_node(name, label=name, color="#22c55e", shape="ellipse", x=x_name, y=name_y, fixed=True)
#                     net.add_edge(ip, name, title=proto, label=proto, color=proto_color_map[proto])
#                     name_y += 30
#             else:
#                 empty_node = f"{ip}_?"
#                 net.add_node(empty_node, label="?", color="#e5e7eb", shape="box", x=x_name, y=y_ip, fixed=True)
#                 net.add_edge(ip, empty_node, title=proto, label=proto, color=proto_color_map[proto])
 
#             subnet_y_counters[subnet] += y_spacing
 
#     # Légende des protocoles
#     legend_x = max(subnet_x_map.values()) + 250
#     legend_y = 0
#     for proto, color in proto_color_map.items():
#         net.add_node(f"legend_{proto}", label=proto.upper(), shape="box", color=color, x=legend_x, y=legend_y, fixed=True)
#         legend_y -= 50
 
#     net.set_options("""
#     {
#       "physics": {
#         "enabled": false
#       },
#       "interaction": {
#         "dragNodes": true,
#         "zoomView": true,
#         "dragView": true
#       }
#     }
#     """)
 
#     graph_path = join(output_dir, f"responder_graph{suffix}.html")
#     net.save_graph(graph_path)
#     log(f"🌐 Graphe interactif enregistré dans : {graph_path}")

# def generate_graph_animated_old(data):
#     try:
#         from pyvis.network import Network
#     except ImportError:
#         print("\n❌ L'option --graph nécessite la bibliothèque pyvis.")
#         print("👉 Installe-la avec : pip install pyvis")
#         return  # ou exit(1) si tu préfères arrêter le script ici
 
#     log("\n🕸️ Génération du graphe interactif (HTML)...")
 
#     net = Network(height="750px", width="100%", directed=True, notebook=False)
 
#     for proto, ip_dict in data.items():
#         for ip, names in ip_dict.items():
#             ip_node = f"{ip}"
#             net.add_node(ip_node, label=ip_node, color="#3b82f6", shape="dot")
 
#             if names:
#                 for name in names:
#                     name_node = f"{name}"
#                     net.add_node(name_node, label=name_node, color="#22c55e", shape="ellipse")
#                     net.add_edge(ip_node, name_node, title=proto, label=proto)
#             else:
#                 empty_node = f"{ip}_?"
#                 net.add_node(empty_node, label="?", color="#e5e7eb", shape="box")
#                 net.add_edge(ip_node, empty_node, title=proto, label=proto)
 
#     net.force_atlas_2based()
#     graph_path = os.path.join(output_dir, f"responder_graph{suffix}.html")
#     net.save_graph(graph_path)
#     log(f"🌐 Graphe interactif enregistré dans : {graph_path}")

def generate_graph(data):
    try:
        from pyvis.network import Network
    except ImportError:
        print("❌ L'option --graph nécessite la bibliothèque pyvis.")
        print("👉 Installe-la avec : pip install pyvis")
        return
 
    log("\n🕸️ Génération du graphe interactif (HTML)...")
 
    net = Network(height="750px", width="100%", directed=True)
 
    # Palette de couleurs pour les protocoles
    protocol_colors = [
        "#f87171", "#facc15", "#34d399", "#60a5fa",
        "#a78bfa", "#f472b6", "#f97316", "#10b981",
        "#818cf8", "#eab308", "#fb923c", "#4ade80",
        "#22d3ee", "#c084fc", "#f43f5e", "#06b6d4"
    ]
    proto_color_map = {proto: protocol_colors[i % len(protocol_colors)] for i, proto in enumerate(data.keys())}
 
    added_nodes = set()
 
    for proto, ip_dict in data.items():
        for ip, names in ip_dict.items():
            if ip not in added_nodes:
                net.add_node(ip, label=ip, color="#3b82f6", shape="dot")
                added_nodes.add(ip)
 
            if names:
                for name in names:
                    if name not in added_nodes:
                        net.add_node(name, label=name, color="#22c55e", shape="ellipse")
                        added_nodes.add(name)
                    net.add_edge(ip, name, title=proto, label=proto, color=proto_color_map[proto])
            else:
                empty_node = f"{ip}_?"
                if empty_node not in added_nodes:
                    net.add_node(empty_node, label="?", color="#e5e7eb", shape="box")
                    added_nodes.add(empty_node)
                net.add_edge(ip, empty_node, title=proto, label=proto, color=proto_color_map[proto])
 
    # Légende des protocoles
    legend_x = 500
    legend_y = 0
    for proto, color in proto_color_map.items():
        legend_node = f"legend_{proto}"
        net.add_node(legend_node, label=proto.upper(), shape="box", color=color)
        # Pas besoin de coordonnées fixes, ils seront placés automatiquement
 
    # Activer une physique douce
    net.set_options("""
    {
      "physics": {
        "enabled": true,
        "forceAtlas2Based": {
          "gravitationalConstant": -50,
          "centralGravity": 0.01,
          "springLength": 100,
          "springConstant": 0.08
        },
        "minVelocity": 0.75,
        "solver": "forceAtlas2Based",
        "timestep": 0.35
      },
      "interaction": {
        "dragNodes": true,
        "zoomView": true,
        "dragView": true
      }
    }
    """)
 
    graph_path = os.path.join(output_dir, f"responder_graph{suffix}.html")
    net.save_graph(graph_path)
    log(f"🌐 Graphe interactif enregistré dans : {graph_path}")


if __name__ == "__main__":
    main()