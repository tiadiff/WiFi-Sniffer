# NetSniff: Advanced Network Analysis & MITM Suite

**NetSniff** is a professional framework for real-time network traffic interception and analysis. Featuring a modern and intuitive dashboard interface, this software allows you to monitor, inspect, and manipulate data from other devices connected to the local network.

## Key Features

*   **Smart Discovery:** Network scanning with automatic identification of vendors (Apple, Samsung, etc.) and hosts.
*   **Traffic Sniffing:** Real-time monitoring of DNS queries and HTTP requests with integrated packet inspector.
*   **JS Injection Engine:** Custom JavaScript code injector to modify the web experience of target devices (on HTTP sites).
*   **Security Bypass:** SSL Stripping and HTTPS Blocking techniques to force traffic onto readable protocols.
*   **DNS Mapping:** Automatic association between IP addresses and real domains for total log readability, even on encrypted traffic.

*NetSniff transforms your computer into a powerful control center for network security monitoring and testing.*

## Disclaimer ⚠️

**THIS SOFTWARE WAS CREATED FOR EDUCATIONAL PURPOSES ONLY.**
The author assumes no responsibility for the improper use of this tool. Intercepting data traffic on third-party networks without authorization is a punishable offense. Use only on networks you own or with explicit consent.

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/tiadiff/WiFi-Sniffer.git
    cd WiFi-Sniffer
    ```

2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3.  (Optional) Ensure you have administrative permissions, required for `scapy` and `pfctl`.

## Usage

Simply double-click the `sniffer.command` file to start the program.

> **Note:** A terminal window will open asking for your password (sudo access is required for network operations).  
> **Closing this terminal window will automatically shut down the server and stop the attack.**

## Requirements

*   Python 3.8+
*   macOS (Recommended for native `pfctl` support) or Linux
*   Root/Sudo permissions

## License

MIT License.
