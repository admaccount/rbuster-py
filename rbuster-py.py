import argparse
import os


def scan(RHOST, port=873):
    """
    Scans a host or IP range to detect open RSYNC ports using nmap.

    Args:
        RHOST (str): Host or IP range in CIDR format (e.g., "192.168.1.0/24").
        port (int): Port to scan (default: 873).

    Returns:
        list: List of hosts with the RSYNC port open.
    """
    open_hosts = []
    print(f"[INFO] Scanning {RHOST} on port {port} using nmap...")

    try:
        result = os.popen(f"nmap -p {port} {RHOST} -oG -").read()
        for line in result.splitlines():
            if "/open/" in line:
                host = line.split()[1]
                print(f"[+] Port {port} open on {host}")
                open_hosts.append(host)
    except Exception as e:
        print(f"[ERROR] Failed to scan with nmap: {e}")

    return open_hosts


def try_anonymous_access(RHOST, port=873):
    """
    Checks if an RSYNC service on a host allows anonymous access using nmap.

    Args:
        RHOST (str): IP address of the host.
        port (int): RSYNC port (default: 873).

    Returns:
        bool: True if anonymous access is allowed, False otherwise.
    """
    print(f"[INFO] Attempting anonymous access to {RHOST}:{port} using nmap...")
    try:
        banner_command = f"nmap -p {port} --script=banner {RHOST}"
        result = os.popen(banner_command).read()

        if "@RSYNCD" in result:
            print(f"[+] RSYNC is anonymously accessible on {RHOST}:{port}!")
            return True
    except Exception as e:
        print(f"[ERROR] Error checking anonymous access: {e}")

    print(f"[-] No anonymous access detected on {RHOST}:{port}.")
    return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="rbuster-py: RSYNC scanning tool.")
    parser.add_argument("-t", "--target", required=True, help="Host or IP range to scan (e.g., 192.168.1.0/24).")
    parser.add_argument("-p", "--port", default=873, type=int, help="RSYNC port (default: 873).")

    args = parser.parse_args()

    open_hosts = scan(args.target, args.port)
    for host in open_hosts:
        if try_anonymous_access(host, args.port):
            print(f"[INFO] RSYNC anonymously accessible on {host}.")

