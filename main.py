import argparse
import hashlib
import multiprocessing
import os
import platform
import random
import socket
import string
import sys
import time
import ctypes
import requests
import psutil
import networkx as nx

# Educational Intent: The ASCII banner clearly marks the tool as a simulation for educational purposes,
# reinforcing the ethical boundaries of cybersecurity research and practice.
ASCII_BANNER = """
███████╗██████╗ ██╗   ██╗ ██████╗  ██████╗ █████╗ ████████╗ ██╗ ██╗      ███████╗██╗███╗   ██╗
██╔════╝██╔══██╗██║   ██║██╔════╝ ██╔════╝██╔══██╗╚══██╔══╝ ██║ ██║      ██╔════╝██║████╗  ██║
█████╗  ██████╔╝██║   ██║██║  ███╗██║     ███████║   ██║    ███████║      █████╗  ██║██╔██╗ ██║
██╔══╝  ██╔══██╗██║   ██║██║   ██║██║     ██╔══██║   ██║    ██╔════╝      ██╔══╝  ██║██║╚██╗██║
███████╗██║  ██║╚██████╔╝╚██████╔╝╚██████╗██║  ██║   ██║    ██║      ██╗███████╗██║██║ ╚████║
╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝  ╚═════╝╚═╝  ╚═╝   ╚═╝    ╚═╝      ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝
=============================================================================================
          >>> EDUCATIONAL SIMULATOR ONLY - DO NOT USE FOR ANY MALICIOUS ACTIVITIES <<<
=============================================================================================
A Jack-of-All-Trades Security Simulator for demonstrating defensive security concepts."


# --- 1. Automated Network Ping Simulator ---
def ping_simulator(ip_range):
    """
    Educational Intent: This function simulates a basic network ping sweep. In a real scenario,
    attackers use this for initial reconnaissance to discover live hosts on a network. For students,
    this demo teaches them to recognize sweep patterns in network logs and understand the importance
    of firewalls and ICMP traffic monitoring. This is a safe, simulated version for a lab environment.
    """
    print("[*] --- Starting Automated Network Ping Simulator ---")
    print(f"[*] Simulating pings for fictional IP range: {ip_range}.0/24")
    print("[*] Educational Goal: Demonstrate network reconnaissance & latency analysis.")

    # In a real script, this would be a subnet calculation. Here we hardcode for the story.
    for i in range(1, 11): # Pinging 10 dummy IPs for demonstration
        target_ip = f"{ip_range}.{i}"
        # Use the appropriate ping command based on the OS
        param = '-n 1' if platform.system().lower() == 'windows' else '-c 1'
        command = f"ping {param} {target_ip}"
        print(f"\n[>] Simulating: {command}")
        # In this simulation, we don't actually run the command to avoid real network traffic.
        # Instead, we print what would happen and generate fake latency.
        # To make it runnable for a demo, you could uncomment the os.system call.
        # os.system(command)
        simulated_latency = random.uniform(5, 50)
        if simulated_latency < 40:
            print(f"  [+] HOST ONLINE: {target_ip} | Simulated Latency: {simulated_latency:.2f}ms")
        else:
            print(f"  [-] HOST OFFLINE: {target_ip} | Request timed out")
        time.sleep(0.5)
    print("\n[*] --- Ping Simulation Complete ---")


# --- 2. Proxy Chain Runner ---
def proxy_chain_runner():
    """
    Educational Intent: This module demonstrates how proxy chains are used to anonymize traffic.
    By routing requests through multiple servers, an actor can obscure their true IP address.
    This is vital for teaching students about privacy, operational security (OPSEC), and how to
    trace sophisticated threats that use similar methods. The disclaimer reinforces that this is
    a tool for understanding, not for malicious use.
    """
    print("\n[*] --- Starting Proxy Chain Runner ---")
    print("[!] FOR SIMULATION ONLY—DO NOT USE ON REAL TARGETS.")
    print("[*] Educational Goal: Teach anonymous browsing concepts for privacy awareness.")

    # A list of fictional or public test proxies for demonstration purposes.
    # In a real-world scenario, these would be sourced from reliable providers.
    test_proxies = [
        "socks5://user:pass@192.0.2.1:1080",  # Fictional
        "socks5://45.77.53.112:1080", # Public test proxy
        "socks5://198.51.100.5:1080"   # Fictional
    ]
    target_url = "http://httpbin.org/ip"
    
    for proxy_url in test_proxies:
        print(f"\n[>] Attempting to route traffic through proxy: {proxy_url}")
        try:
            proxies = {
                "http": proxy_url,
                "https": proxy_url
            }
            # The 'requests' library with 'PySocks' support makes this straightforward.
            response = requests.get(target_url, proxies=proxies, timeout=10)
            print(f"  [+] SUCCESS: Connected via {proxy_url}")
            print(f"  [+] Simulated Public IP: {response.json()['origin']}")
        except (requests.exceptions.ProxyError, requests.exceptions.ConnectTimeout) as e:
            print(f"  [-] FAILED: Could not connect to proxy {proxy_url}")
            print(f"  [-] Reason: {e}")
        except requests.exceptions.RequestException as e:
            print(f"  [-] An unexpected error occurred: {e}")
        time.sleep(1)
        
    print("\n[*] --- Proxy Chain Simulation Complete ---")


# --- 3. Basic Identity Shield ---
def identity_shield():
    """
    Educational Intent: This simulates a personal security tool for a researcher.
    1. Process Monitoring: It shows how antivirus software or EDR (Endpoint Detection & Response)
       tools look for signatures of known malware (here, fake hashes).
    2. Self-Obfuscation: It demonstrates how red-team tools might try to hide from defenders,
       for example, by changing window titles to blend in. This teaches students to look beyond
       obvious process names.
    """
    print("\n[*] --- Initializing Basic Identity Shield ---")
    print("[*] Educational Goal: Demonstrate endpoint monitoring and obfuscation techniques.")

    # 1. Obfuscate the script's own fingerprint
    try:
        if platform.system().lower() == 'windows':
            new_title = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
            ctypes.windll.kernel32.SetConsoleTitleW(new_title)
            print(f"[+] Obfuscation: Console window title randomized to '{new_title}'")
    except Exception as e:
        print(f"[-] Obfuscation failed (non-Windows or error): {e}")

    # 2. Monitor local processes for "suspicious patterns" (fake malware signatures)
    print("\n[*] Scanning local processes for fake malware signatures...")
    # These are fake hashes for demonstration. A real tool would have a large, updated database.
    fake_malware_signatures = {
        "e4d909c290d0fb1ca068ffaddf22cbd0": "FakeTrojan.exe",
        "a3a76da2f87b83592a853744e99b4d8f": "TotallyNotMalware.dll"
    }
    
    found_suspicious = False
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            if proc.info['exe']:
                # In a real tool, we would hash the file content. Here we just hash the name for speed.
                process_name = os.path.basename(proc.info['exe'])
                # Using MD5 for speed, but real AVs use more robust hashes (SHA-256).
                m = hashlib.md5()
                m.update(process_name.encode('utf-8'))
                proc_hash = m.hexdigest()

                if proc_hash in fake_malware_signatures:
                    print(f"[!] Suspicious Process DETECTED:")
                    print(f"  - PID: {proc.info['pid']}")
                    print(f"  - Name: {proc.info['name']}")
                    print(f"  - Path: {proc.info['exe']}")
                    print(f"  - Matched Signature: {fake_malware_signatures[proc_hash]}")
                    found_suspicious = True

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
            
    if not found_suspicious:
        print("[+] No suspicious processes found based on the dummy signature list.")
        
    print("\n[*] --- Identity Shield Scan Complete ---")


# --- 4. Social Media Footprint Mapper ---
def footprint_mapper(username):
    """
    Educational Intent: This function simulates Open-Source Intelligence (OSINT) gathering from
    social media. It demonstrates how publicly available information can be mapped to reveal
    connections and activities. It uses networkx to build a graph, a common technique in data
    analysis and intelligence. The explicit warning emphasizes the need for consent and ethical
    conduct in real-world OSINT work.
    """
    print("\n[*] --- Starting Social Media Footprint Mapper ---")
    print("[!] This is for red-team training on privacy leaks—always get consent in real life.")
    print(f"[*] Simulating OSINT crawl for dummy username: '{username}'")

    # Create a graph to represent the social network
    G = nx.Graph()
    G.add_node(username, type='target_user')

    # Simulate finding friends/followers
    print("[>] Simulating friend list discovery...")
    simulated_friends = [f"friend_{i}" for i in range(5)]
    for friend in simulated_friends:
        G.add_node(friend, type='friend')
        G.add_edge(username, friend, type='friendship')
    print(f"  [+] Found {len(simulated_friends)} simulated friends.")
    
    # Simulate finding posts and tagged locations
    print("[>] Simulating post analysis for location data...")
    simulated_posts = [
        {"id": "post1", "location": "Downtown Cafe"},
        {"id": "post2", "location": None},
        {"id": "post3", "location": "University Library"},
    ]
    locations = []
    for post in simulated_posts:
        if post['location']:
            locations.append(post['location'])
            G.add_node(post['location'], type='location')
            G.add_edge(username, post['location'], type='check_in', post_id=post['id'])
    print(f"  [+] Found {len(locations)} check-ins at: {', '.join(locations)}")
    
    # Display the fictional graph data
    print("\n--- Simulated OSINT Graph Data ---")
    print(f"Target: {username}")
    print("Connections:")
    for edge in G.edges(data=True):
        print(f"  - {edge[0]} <--> {edge[1]} (Type: {edge[2].get('type', 'N/A')})")
        
    print("\n[*] --- Footprint Mapping Simulation Complete ---")


# --- 5. Distributed Stress Testing Botnet Simulator ---
def http_stress_worker(target, stop_event):
    """Worker process for the botnet simulator."""
    pid = os.getpid()
    print(f"[BOT {pid}] Activated. Targeting {target}...")
    while not stop_event.is_set():
        try:
            # Send a harmless GET request to a test endpoint
            requests.get(target, timeout=5)
            print(f"[BOT {pid}] Sent GET request to {target}")
        except requests.RequestException:
            print(f"[BOT {pid}] Target not responding.")
        # Rate-limiting to ensure this is a low-volume, safe simulation
        time.sleep(random.uniform(2, 5))
    print(f"[BOT {pid}] Deactivated.")


def botnet_simulator():
    """
    Educational Intent: This simulates a small-scale Distributed Denial of Service (DDoS) attack
    to teach defensive principles. By creating a "virtual botnet" with multiprocessing, students
    can understand how multiple machines coordinate to overwhelm a target. The use of httpbin.org
    provides a safe, real-time reflection of the incoming requests. The built-in rate-limiting
    makes it clear this is a "DDoS Defense Trainer," not a real attack tool.
    """
    print("\n[*] --- DDoS Defense Trainer: Botnet Simulator ---")
    print("[*] Educational Goal: Demonstrate DDoS mechanics and amplification risks safely.")
    
    target_url = "http://httpbin.org/get"
    num_bots = 5
    simulation_duration = 15  # seconds

    print(f"[*] Simulating a botnet of {num_bots} nodes for {simulation_duration} seconds.")
    print(f"[*] Target endpoint: {target_url} (A safe, reflective endpoint)")

    stop_event = multiprocessing.Event()
    processes = []

    for i in range(num_bots):
        # Each process acts as an "infected" machine in the botnet.
        process = multiprocessing.Process(target=http_stress_worker, args=(target_url, stop_event))
        processes.append(process)
        process.start()

    # Let the simulation run for the specified duration
    print(f"\n[*] Botnet is active. Monitoring for {simulation_duration} seconds...")
    time.sleep(simulation_duration)
    
    # Signal all bots to stop
    print("\n[*] Halting simulation. Sending stop signal to all bots...")
    stop_event.set()

    # Wait for all processes to terminate
    for process in processes:
        process.join()

    print("\n[*] --- Botnet Simulation Complete ---")


def main():
    """Main function to parse arguments and run the selected module."""
    print(ASCII_BANNER)
    
    parser = argparse.ArgumentParser(
        description="Jack-of-All-Trades Security Simulator - For Educational Use Only.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=["ping", "proxy", "shield", "osint", "botnet"],
        help=(
            "Select the simulation module to run:\n"
            "  ping   - Simulate a network ping sweep.\n"
            "  proxy  - Simulate chaining through public proxies.\n"
            "  shield - Simulate a local process/identity shield.\n"
            "  osint  - Simulate mapping a social media footprint.\n"
            "  botnet - Simulate a small-scale DDoS botnet."
        )
    )
    parser.add_argument("--ip-range", default="192.0.2", help="Fictional IP range for ping scan (e.g., 192.0.2).")
    parser.add_argument("--username", default="john_doe", help="Dummy username for OSINT scan.")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()

    if args.mode == 'ping':
        ping_simulator(args.ip_range)
    elif args.mode == 'proxy':
        proxy_chain_runner()
    elif args.mode == 'shield':
        identity_shield()
    elif args.mode == 'osint':
        footprint_mapper(args.username)
    elif args.mode == 'botnet':
        botnet_simulator()

if __name__ == "__main__":
    # The multiprocessing library requires this check on Windows
    if platform.system() == "Windows":
        multiprocessing.freeze_support()
    main()

