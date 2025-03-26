import argparse
import socket
import ipaddress
import os
from scapy.all import *

DEFAULT_PORT = 873
RSYNC_BANNER = b"@RSYNCD: "

def is_rsync_installed():
    return os.system("command -v rsync >/dev/null 2>&1") == 0

def scan_ips(target, port=DEFAULT_PORT):
    open_hosts = []
    print(f"\n[INFO] Scanning {target} on port {port}...")

    try:
        network = ipaddress.ip_network(target, strict=False)
        for ip in network.hosts():
            ip = str(ip)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:
                print(f"[✔] Port {port} OUVERT sur {ip}")
                open_hosts.append(ip)
            else:
                print(f"[X] Port {port} FERMÉ sur {ip}")
    except ValueError:
        print(f"[ERROR] Cible invalide: {target}")

    return open_hosts

def check_rsync_anonymous(host, port=DEFAULT_PORT):
    try:
        with socket.create_connection((host, port), timeout=2) as conn:
            conn.sendall(b"\n")
            response = conn.recv(1024)

            if response.startswith(RSYNC_BANNER):
                print(f"[✔] Accès RSYNC anonyme OUVERT sur {host}:{port} !")
                return True
    except:
        pass

    print(f"[-] Accès RSYNC refusé sur {host}:{port}.")
    return False

def list_rsync_modules(host):
    if not is_rsync_installed():
        print(f"[ERROR] La commande 'rsync' n'est pas installée.")
        print(f"[INFO] Installez-la avec : sudo apt install rsync")
        print(f"[INFO] Essayez directement : rsync rsync://{host}/")
        return

    try:
        output = os.popen(f"rsync rsync://{host}/").read()

        if output.strip():
            print(f"\n📂 [INFO] Liste des répertoires RSYNC accessibles sur {host}:")
            print("-" * 50)
            for line in output.splitlines():
                if line.strip():
                    print(f"  📁 {line.strip()}")
            print("-" * 50)
    except:
        print(f"[ERROR] Impossible d'obtenir la liste RSYNC pour {host}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RSYNC Scanner")
    parser.add_argument("-t", "--target", required=True, help="IP ou subnet à scanner (ex: 192.168.1.0/24)")
    parser.add_argument("-p", "--port", default=DEFAULT_PORT, type=int, help="Port RSYNC (par défaut: 873)")

    args = parser.parse_args()

    open_hosts = scan_ips(args.target, args.port)

    for host in open_hosts:
        if check_rsync_anonymous(host, args.port):
            list_rsync_modules(host)
