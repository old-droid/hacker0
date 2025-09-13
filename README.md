# hacker0
an powerful jack of all trades hacking and OSNIT tool for  noobs

## Overview

## Installation

1.  **Clone the repository or download the files.**
2.  **Install the required Python packages:**

    ```bash
    pip install -r requirements.txt
    ```

## How to Run

1.  Navigate to the script directory in your terminal.
2.  Run the simulator:

    ```bash
    python simulator.py
    ```

3.  You will be prompted to enter the admin password (`gamma`) to access the main menu.

## Features

Upon successful authentication, the tool presents an interactive menu with the following modules:

1.  **Live Network Ping Scanner**: Performs a live ICMP ping sweep across a given IP range to identify online hosts.
2.  **Proxy Chain Runner**: Attempts to route traffic through a list of public SOCKS5 proxies to test anonymity and network tracing.
3.  **Live Identity Shield**: A defensive module that a) obfuscates the script's console window title and b) scans local running processes by hashing their executables against a list of dummy malware signatures.
4.  **Automated OSINT Mapper**: Gathers intelligence on a target username by:
    *   Querying the GitHub API for user details.
    *   Performing an automated DuckDuckGo search for professional links.
    *   Simulating an advanced scrape of Facebook and Twitter to find fictional data points.
5.  **Live DDoS Traffic Generator**: A DDoS defense trainer that spawns a small botnet of processes to send low-volume HTTP GET requests to a safe test server (`httpbin.org`).

### Emergency Shutdown

-   **Menu Option**: Selecting option `6` from the main menu will initiate a system shutdown sequence.
-   **Hotkey**: Pressing `Ctrl+E` at any point while the menu is active will trigger the same shutdown sequence.

**A final confirmation is required for all shutdown commands.** This is an extremely dangerous feature and is included purely as a narrative device for the story.

