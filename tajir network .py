#!/usr/bin/env python3
import sys
import os
import time
import threading
import sqlite3
from datetime import datetime
import requests
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw, ARP, Ether, srp

if os.geteuid() != 0:
    print("[-] Error: Tajir Network Monitor must be run with root privileges (sudo).")
    sys.exit(1)

blocked_macs = set()
blocked_devices_info = {} 
whitelist_macs = set()
is_monitoring = True

class TajirApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Tajir Network Monitor v4.9.1 - Enterprise SOC Edition")
        self.root.geometry("1400x900")
        self.root.configure(bg="#0b0f19")

        # Clean up any stale iptables rules on startup
        os.system("sudo iptables -F FORWARD 2>/dev/null")
        os.system("sudo iptables -F INPUT 2>/dev/null")

        self.init_db()
        self.setup_styles()

        # Main Header Banner (Heavy SOC Style)
        header_frame = tk.Frame(root, bg="#111827", pady=12, padx=15)
        header_frame.pack(fill=tk.X)
        
        title_label = tk.Label(header_frame, text="🛡️ TAJIR NETWORK MONITOR v4.9.1 [ENTERPRISE SOC GATEWAY]", 
                               font=("Consolas", 15, "bold"), fg="#38bdf8", bg="#111827")
        title_label.pack(side=tk.LEFT)

        self.status_badge = tk.Label(header_frame, text=" ● STATUS: ACTIVE & GUARDING ", 
                                     font=("Consolas", 10, "bold"), fg="#22c55e", bg="#1f2937", padx=10, pady=5)
        self.status_badge.pack(side=tk.RIGHT)

        # ----------------- TOP METRICS CARDS FRAME -----------------
        metrics_frame = tk.Frame(root, bg="#0b0f19", pady=8, padx=10)
        metrics_frame.pack(fill=tk.X)

        self.card_devices = self.create_metric_card(metrics_frame, "ACTIVE HOSTS", "0", "#38bdf8")
        self.card_wifi = self.create_metric_card(metrics_frame, "WI-FI CLIENTS", "0", "#a855f7")
        self.card_wired = self.create_metric_card(metrics_frame, "WIRED CLIENTS", "0", "#eab308")
        self.card_blocked = self.create_metric_card(metrics_frame, "ISOLATED THREATS", "0", "#ef4444")

        # ----------------- TABS SETUP (NOTEBOOK) -----------------
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Tab 1: Live Monitoring & Inventory
        self.tab_monitor = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_monitor, text="  🌐 Live Security Operations & Inventory  ")

        # Tab 2: Blocked Devices & Firewall Management
        self.tab_blocked = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_blocked, text="  🔒 Firewall Blocklist & Isolation Control  ")

        # ================= BUILD TAB 1 =================
        tab1_paned = ttk.PanedWindow(self.tab_monitor, orient=tk.VERTICAL)
        tab1_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        top_paned = ttk.PanedWindow(tab1_paned, orient=tk.HORIZONTAL)
        tab1_paned.add(top_paned, weight=3)

        # 1. Left Frame: Live Traffic
        left_frame = tk.LabelFrame(top_paned, text=" 🌐 Live Network Packet & DNS Traffic Stream ", 
                                   font=("Consolas", 10, "bold"), fg="#22c55e", bg="#0f172a", bd=2)
        top_paned.add(left_frame, weight=1)

        self.traffic_log = scrolledtext.ScrolledText(left_frame, wrap=tk.WORD, bg="#020617", fg="#22c55e", 
                                                    font=("Consolas", 9), insertbackground="white")
        self.traffic_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.traffic_log.insert(tk.END, "[*] Tajir Traffic Engine Active & Sniffing Subnet...\n")

        # 2. Right Frame: AI Security Alerts
        right_frame = tk.LabelFrame(top_paned, text=" 🤖 AI Bot Threat Detection & Malware Feed ", 
                                    font=("Consolas", 10, "bold"), fg="#ef4444", bg="#0f172a", bd=2)
        top_paned.add(right_frame, weight=1)

        self.alert_log = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, bg="#020617", fg="#fca5a5", 
                                                   font=("Consolas", 9), insertbackground="white")
        self.alert_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.alert_log.insert(tk.END, "[*] AI Security Bot guarding against malware, APKs & tunnels...\n")

        # Bottom Section: Active Devices Inventory
        bottom_frame = tk.LabelFrame(tab1_paned, text=" 📡 Subnet Inventory Classification (Wi-Fi vs Wired) ", 
                                     font=("Consolas", 10, "bold"), fg="#38bdf8", bg="#0f172a", bd=2)
        tab1_paned.add(bottom_frame, weight=2)

        device_paned = ttk.PanedWindow(bottom_frame, orient=tk.HORIZONTAL)
        device_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Wi-Fi Devices Sub-frame
        wifi_frame = tk.LabelFrame(device_paned, text=" 📶 Wi-Fi Clients (UniFi AP Access Points) ", 
                                   font=("Consolas", 9, "bold"), fg="#a855f7", bg="#0f172a")
        device_paned.add(wifi_frame, weight=1)

        self.wifi_tree = ttk.Treeview(wifi_frame, columns=("IP", "MAC", "Vendor"), show="headings", height=5)
        self.wifi_tree.heading("IP", text="IP Address")
        self.wifi_tree.heading("MAC", text="MAC Address")
        self.wifi_tree.heading("Vendor", text="Device Vendor")
        self.wifi_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Wired Devices Sub-frame
        wired_frame = tk.LabelFrame(device_paned, text=" 🔌 Wired Clients (Switches & LAN) ", 
                                    font=("Consolas", 9, "bold"), fg="#eab308", bg="#0f172a")
        device_paned.add(wired_frame, weight=1)

        self.wired_tree = ttk.Treeview(wired_frame, columns=("IP", "MAC", "Vendor"), show="headings", height=5)
        self.wired_tree.heading("IP", text="IP Address")
        self.wired_tree.heading("MAC", text="MAC Address")
        self.wired_tree.heading("Vendor", text="Device Vendor")
        self.wired_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # ================= BUILD TAB 2 =================
        tab2_frame = tk.Frame(self.tab_blocked, bg="#0f172a", padx=10, pady=10)
        tab2_frame.pack(fill=tk.BOTH, expand=True)

        lbl_blocked_title = tk.Label(tab2_frame, text="🔒 Active Isolation Firewall Control (iptables Dropped Hosts)", 
                                     font=("Consolas", 11, "bold"), fg="#ef4444", bg="#0f172a")
        lbl_blocked_title.pack(anchor=tk.W, pady=5)

        blocked_table_frame = tk.Frame(tab2_frame, bg="#0f172a")
        blocked_table_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.blocked_tree = ttk.Treeview(blocked_table_frame, columns=("IP", "MAC", "Vendor", "Reason"), show="headings", height=12)
        self.blocked_tree.heading("IP", text="IP Address")
        self.blocked_tree.heading("MAC", text="MAC Address")
        self.blocked_tree.heading("Vendor", text="Device Vendor")
        self.blocked_tree.heading("Reason", text="Threat / Reason")
        self.blocked_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        blocked_scroll = ttk.Scrollbar(blocked_table_frame, orient="vertical", command=self.blocked_tree.yview)
        blocked_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.blocked_tree.configure(yscrollcommand=blocked_scroll.set)

        btn_unblock_frame = tk.Frame(tab2_frame, bg="#0f172a", pady=10)
        btn_unblock_frame.pack(fill=tk.X)

        btn_unblock = tk.Button(btn_unblock_frame, text="🔓 Unblock Selected Host & Restore Network", font=("Consolas", 10, "bold"), 
                                bg="#22c55e", fg="black", padx=10, pady=5, command=self.unblock_selected_device)
        btn_unblock.pack(side=tk.LEFT, padx=5)

        # Control Panel Bottom (Global Exit)
        control_frame = tk.Frame(root, bg="#111827", pady=10, padx=15)
        control_frame.pack(fill=tk.X)

        footer_label = tk.Label(control_frame, text="Tajir Security Engine v4.9.1 | Real-Time Automated Threat Mitigation", 
                                font=("Consolas", 9), fg="#94a3b8", bg="#111827")
        footer_label.pack(side=tk.LEFT)

        btn_stop = tk.Button(control_frame, text="🛑 Stop & Flush Firewall Rules", font=("Consolas", 10, "bold"), 
                             bg="#ef4444", fg="white", padx=10, pady=5, command=self.stop_monitor)
        btn_stop.pack(side=tk.RIGHT)

        # Start Background Sniffing Thread
        self.monitor_thread = threading.Thread(target=self.start_backend_engine)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background='#0b0f19', borderwidth=0)
        style.configure('TNotebook.Tab', background='#1f2937', foreground='#94a3b8', font=('Consolas', 10, 'bold'), padding=[15, 8])
        style.map('TNotebook.Tab', background=[('selected', '#3b82f6')], foreground=[('selected', '#ffffff')])
        style.configure('Treeview', background='#020617', foreground='#e2e8f0', fieldbackground='#020617', font=('Consolas', 9), rowheight=26)
        style.configure('Treeview.Heading', background='#1e293b', foreground='#38bdf8', font=('Consolas', 9, 'bold'))
        style.map('Treeview', background=[('selected', '#1d4ed8')], foreground=[('selected', '#ffffff')])

    def create_metric_card(self, parent, title, initial_val, accent_color):
        card = tk.Frame(parent, bg="#111827", bd=1, relief=tk.SOLID, padx=15, pady=8)
        card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        lbl_title = tk.Label(card, text=title, font=("Consolas", 8, "bold"), fg="#94a3b8", bg="#111827")
        lbl_title.pack(anchor=tk.W)
        lbl_val = tk.Label(card, text=initial_val, font=("Consolas", 16, "bold"), fg=accent_color, bg="#111827")
        lbl_val.pack(anchor=tk.W, pady=2)
        return lbl_val

    def init_db(self):
        try:
            conn = sqlite3.connect('tajir_logs.db')
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    ip TEXT,
                    mac TEXT,
                    vendor TEXT,
                    target_info TEXT,
                    score INTEGER,
                    details TEXT,
                    action TEXT
                )
            ''')
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[-] DB Init Error: {e}")

    def log_to_db(self, ip, mac, vendor, target_info, score, details, action):
        try:
            conn = sqlite3.connect('tajir_logs.db')
            cursor = conn.cursor()
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute('''
                INSERT INTO audit_logs (timestamp, ip, mac, vendor, target_info, score, details, action)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, ip, mac, vendor, target_info, score, details, action))
            conn.commit()
            conn.close()
        except:
            pass

    def get_mac_details(self, mac_address):
        try:
            url = f"https://api.macvendors.com/{mac_address}"
            response = requests.get(url, timeout=0.8)
            if response.status_code == 200:
                return response.text
        except:
            pass
        return "Generic / Unknown"

    def classify_device_type(self, mac, vendor):
        vendor_lower = vendor.lower()
        wifi_keywords = ['samsung', 'xiaomi', 'apple', 'huawei', 'oppo', 'vivo', 'oneplus', 'realtek', 'wireless', 'intel wireless', 'lg electronics', 'motorola']
        if any(kw in vendor_lower for kw in wifi_keywords) or mac.lower().startswith(('5a:', '80:', '0a:', 'be:', 'e8:')):
            return "WiFi"
        return "Wired"

    def scan_live_devices(self, subnet):
        devices = []
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), timeout=2, verbose=False)
            for _, received in ans:
                mac = received.hwsrc
                ip = received.psrc
                vendor = self.get_mac_details(mac)
                dev_type = self.classify_device_type(mac, vendor)
                devices.append({'ip': ip, 'mac': mac, 'vendor': vendor, 'type': dev_type})
        except Exception as e:
            print(f"[-] Scan Error: {e}")
        return devices

    def update_device_ui(self, devices):
        for row in self.wifi_tree.get_children():
            self.wifi_tree.delete(row)
        for row in self.wired_tree.get_children():
            self.wired_tree.delete(row)

        wifi_count = 0
        wired_count = 0
        for d in devices:
            if d['type'] == 'WiFi':
                self.wifi_tree.insert("", tk.END, values=(d['ip'], d['mac'], d['vendor']))
                wifi_count += 1
            else:
                self.wired_tree.insert("", tk.END, values=(d['ip'], d['mac'], d['vendor']))
                wired_count += 1

        self.card_devices.config(text=str(len(devices)))
        self.card_wifi.config(text=str(wifi_count))
        self.card_wired.config(text=str(wired_count))

    def update_blocked_ui(self):
        for row in self.blocked_tree.get_children():
            self.blocked_tree.delete(row)

        for mac, info in blocked_devices_info.items():
            self.blocked_tree.insert("", tk.END, values=(info['ip'], mac, info['vendor'], info['reason']))

        self.card_blocked.config(text=str(len(blocked_devices_info)))

    def unblock_selected_device(self):
        selected_item = self.blocked_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a host from the firewall blocklist to unblock.")
            return

        item_values = self.blocked_tree.item(selected_item, "values")
        ip = item_values[0]
        mac = item_values[1]

        os.system(f"sudo iptables -D FORWARD -s {ip} -m mac --mac-source {mac} -j DROP 2>/dev/null")
        os.system(f"sudo iptables -D INPUT -s {ip} -m mac --mac-source {mac} -j DROP 2>/dev/null")

        if mac in blocked_macs:
            blocked_macs.remove(mac)
        whitelist_macs.add(mac)

        if mac in blocked_devices_info:
            del blocked_devices_info[mac]

        self.update_blocked_ui()
        success_msg = f"🔓 [UNBLOCKED & WHITELISTED] Host IP: {ip} | MAC: {mac} restored.\n"
        self.safe_insert_alert(success_msg)
        messagebox.showinfo("Success", f"Host {ip} ({mac}) has been successfully unblocked and whitelisted!")

    def analyze_traffic(self, content_str):
        score = 0
        threats_found = []
        content_lower = content_str.lower()
        
        phishing_indicators = ['password=', 'passwd=', 'credential=', 'pin=', 'card_number=', 'otp=']
        matched_phishing = [pi for pi in phishing_indicators if pi in content_lower]
        if matched_phishing and ('post' in content_lower or 'action=' in content_lower):
            score += 85
            threats_found.append(f"Credential Harvesting Post: {matched_phishing}")
            
        tunnel_keywords = ['trycloudflare.com', 'ngrok.io', 'loca.lt', 'serveo.net']
        matched_tunnels = [tk for tk in tunnel_keywords if tk in content_lower]
        if matched_tunnels:
            score += 90
            threats_found.append(f"Unauthorized Tunnel: {matched_tunnels}")

        malware_extensions = ['.exe', '.apk', '.bat', '.scr', '.msi', '.iso', '.cmd', '.torrent']
        matched_downloads = [me for me in malware_extensions if me in content_lower]
        if matched_downloads and ('download' in content_lower or 'dl.' in content_lower or 'apkpure' in content_lower):
            score += 95
            threats_found.append(f"Malicious Executable/APK Download: {matched_downloads}")

        return score, "; ".join(threats_found)

    def safe_insert_traffic(self, msg):
        def _insert():
            scroll_pos = self.traffic_log.yview()[1]
            self.traffic_log.insert(tk.END, msg)
            if scroll_pos >= 0.95:
                self.traffic_log.see(tk.END)
        self.root.after(0, _insert)

    def safe_insert_alert(self, msg):
        def _insert():
            scroll_pos = self.alert_log.yview()[1]
            self.alert_log.insert(tk.END, msg)
            if scroll_pos >= 0.95:
                self.alert_log.see(tk.END)
        self.root.after(0, _insert)

    def auto_block_device(self, src_ip, src_mac, vendor, target_info, score, details):
        if src_mac in blocked_macs or src_mac in whitelist_macs:
            return

        blocked_macs.add(src_mac)
        blocked_devices_info[src_mac] = {'ip': src_ip, 'vendor': vendor, 'reason': details}
        
        os.system(f"sudo iptables -I FORWARD 1 -s {src_ip} -m mac --mac-source {src_mac} -j DROP")
        os.system(f"sudo iptables -I INPUT 1 -s {src_ip} -m mac --mac-source {src_mac} -j DROP")
        
        alert_msg = (f"🚨 [CRITICAL THREAT MITIGATION] Time: {datetime.now().strftime('%H:%M:%S')}\n"
                     f"  > IP      : {src_ip}\n"
                     f"  > MAC     : {src_mac} ({vendor})\n"
                     f"  > Threat  : {details}\n"
                     f"  > Action  : Host Isolated via iptables Drop Rules!\n"
                     f"{'='*50}\n")
        
        self.safe_insert_alert(alert_msg)
        self.root.after(0, self.update_blocked_ui)
        self.log_to_db(src_ip, src_mac, vendor, target_info, score, details, "AUTO-BLOCKED")

    def packet_callback(self, packet):
        src_ip = "Unknown-IP"
        src_mac = "Unknown-MAC"
        target_info = "Unknown Target"
        payload_text = ""
        
        if packet.haslayer(IP):
            src_ip = packet[IP].src
        if packet.haslayer(Ether):
            src_mac = packet[Ether].src
            
        if src_mac in blocked_macs or src_mac in whitelist_macs:
            return

        if packet.haslayer(UDP) and packet.haslayer(DNSQR):
            try:
                qname = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                target_info = f"DNS -> {qname}"
                payload_text = qname
            except:
                pass

        elif packet.haslayer(TCP) and packet.haslayer(Raw):
            try:
                payload_text = packet[Raw].load.decode('utf-8', errors='ignore')
                dport = packet[TCP].dport
                if dport in [80, 8080]:
                    target_info = f"HTTP (Port {dport})"
                elif dport == 443:
                    target_info = "HTTPS SNI"
                else:
                    target_info = f"TCP Port {dport}"
            except:
                pass

        if target_info != "Unknown Target":
            log_msg = f"[{datetime.now().strftime('%H:%M:%S')}] IP: {src_ip} | MAC: {src_mac} | Action: {target_info}\n"
            self.safe_insert_traffic(log_msg)

        if payload_text:
            score, threat_details = self.analyze_traffic(payload_text)
            if score >= 50:
                vendor = self.get_mac_details(src_mac)
                self.auto_block_device(src_ip, src_mac, vendor, target_info, score, threat_details)

    def start_backend_engine(self):
        subnet = "10.30.0.0/24"
        os.system("sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1")
        
        active_devices = self.scan_live_devices(subnet)
        self.root.after(0, lambda: self.update_device_ui(active_devices))
        
        try:
            sniff(filter="tcp port 80 or tcp port 443 or tcp port 8080 or udp port 53", prn=self.packet_callback, store=0)
        except Exception as e:
            print(f"[-] Sniffing Engine Error: {e}")

    def stop_monitor(self):
        global is_monitoring
        is_monitoring = False
        os.system("sudo iptables -F FORWARD 2>/dev/null")
        os.system("sudo iptables -F INPUT 2>/dev/null")
        self.root.destroy()
        sys.exit(0)

if __name__ == "__main__":
    root = tk.Tk()
    app = TajirApp(root)
    root.mainloop()