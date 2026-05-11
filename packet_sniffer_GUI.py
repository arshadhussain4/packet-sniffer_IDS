import sys, os, threading, tkinter as tk
from tkinter import scrolledtext, ttk
os.environ["PYTHONUTF8"] = "1"
os.environ['PYTHONIOENCODING'] = 'utf-8'

import scapy.config
scapy.config.conf.verb = 0
import logging
for name in ['scapy', 'scapy.runtime', 'scapy.loading', 'scapy.utils']:
    logging.getLogger(name).setLevel(logging.CRITICAL)

_original_stderr_write = sys.stderr.write
def safe_stderr_write(message):
    try:
        enc = sys.stderr.encoding or 'utf-8'
        _original_stderr_write(message.encode(enc, errors='replace').decode(enc))
    except Exception:
        pass
sys.stderr.write = safe_stderr_write

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
import csv, socket
from datetime import datetime
from collections import defaultdict

MAX_PACKETS = 1000

class SnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.geometry("900x600")
        
        self.running = False
        self.sniffer_thread = None
        self.count = 0
        self.port_map = defaultdict(set)
        self.flagged = set()
        self.stats = defaultdict(int)
        
        # ---- File handling with fallback if permission denied ----
        try:
            self.csv_file = open("packets.csv", 'a', newline='', encoding='utf-8')
            self.csv_writer = csv.writer(self.csv_file, quoting=csv.QUOTE_ALL)
            csv_path = "packets.csv"
        except PermissionError:
            import tempfile
            csv_path = os.path.join(tempfile.gettempdir(), "packets.csv")
            self.csv_file = open(csv_path, 'a', newline='', encoding='utf-8')
            self.csv_writer = csv.writer(self.csv_file, quoting=csv.QUOTE_ALL)
            print(f"Using fallback CSV: {csv_path}")
        
        if os.path.getsize(csv_path) == 0:
            self.csv_writer.writerow(["#","Timestamp","Src IP","Dst IP","Hostname","Protocol","Src Port","Dst Port","DNS Query","Payload","Alert"])
        
        try:
            self.alert_file = open("alerts.txt", 'a', encoding='utf-8')
        except PermissionError:
            import tempfile
            alert_path = os.path.join(tempfile.gettempdir(), "alerts.txt")
            self.alert_file = open(alert_path, 'a', encoding='utf-8')
            print(f"Using fallback alerts: {alert_path}")
        
        # ---- GUI Layout ----
        top_frame = tk.Frame(root)
        top_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.start_btn = tk.Button(top_frame, text="Start Sniffing", command=self.start_sniffing, bg="green", fg="white")
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = tk.Button(top_frame, text="Stop Sniffing", command=self.stop_sniffing, bg="red", fg="white", state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.status_label = tk.Label(top_frame, text=f"Status: Stopped (Limit: {MAX_PACKETS} packets)", fg="red")
        self.status_label.pack(side=tk.LEFT, padx=20)
        
        stats_frame = tk.Frame(root)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        self.stats_label = tk.Label(stats_frame, text="Packets: 0 | TCP:0 UDP:0 ICMP:0 | Alerts:0", font=("Arial", 10))
        self.stats_label.pack()
        
        log_frame = tk.LabelFrame(root, text="Live Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=20)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def log(self, message, alert=False):
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}\n"
        self.log_text.insert(tk.END, line)
        self.log_text.see(tk.END)
        if alert:
            self.log_text.tag_add("alert", f"end-2l", "end-1l")
            self.log_text.tag_config("alert", foreground="red")
        self.root.update_idletasks()
    
    def update_stats(self):
        self.stats_label.config(text=f"Packets: {self.count}/{MAX_PACKETS} | TCP:{self.stats['TCP']} UDP:{self.stats['UDP']} ICMP:{self.stats['ICMP']} | Alerts:{len(self.flagged)}")
    
    def resolve(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Unknown"
    
    def check_threat(self, src, dst, sport, dport):
        BAD_PORTS = {22:"SSH",23:"Telnet",3389:"RDP",4444:"Metasploit",6667:"IRC-Botnet",31337:"Backdoor"}
        for p in (sport, dport):
            if p and p in BAD_PORTS:
                return f"BAD PORT {p} ({BAD_PORTS[p]}) {src}->{dst}"
        if dport and src not in self.flagged:
            self.port_map[src].add(dport)
            if len(self.port_map[src]) >= 5:
                self.flagged.add(src)
                return f"PORT SCAN from {src} ({len(self.port_map[src])} ports)"
        return ""
    
    def handle_packet(self, pkt):
        # Exit immediately if sniffer stopped
        if not self.running or IP not in pkt:
            return
        self.count += 1
        if self.count > MAX_PACKETS:
            # Signal to stop on GUI thread
            self.root.after(0, self.stop_sniffing)
            return
        
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src, dst = pkt[IP].src, pkt[IP].dst
        proto, sport, dport = "OTHER", None, None
        if TCP in pkt:
            proto, sport, dport = "TCP", pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            proto, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
        elif ICMP in pkt:
            proto = "ICMP"
        self.stats[proto] += 1
        
        dns_q = ""
        if DNS in pkt and pkt[DNS].qr == 0:
            try:
                dns_q = pkt[DNSQR].qname.decode().rstrip(".")
            except:
                pass
        
        payload = ""
        if Raw in pkt:
            try:
                payload = pkt[Raw].load.decode('utf-8', errors='replace')[:60]
            except:
                payload = "[binary]"
        
        hostname = dns_q if dns_q else self.resolve(dst)
        alert = self.check_threat(src, dst, sport, dport)
        
        if alert:
            self.alert_file.write(f"[{ts}] {alert}\n")
            self.alert_file.flush()
            self.log(f"ALERT: {alert}", alert=True)
        else:
            self.log(f"#{self.count} {proto} | {src} -> {dst} ({hostname}) | {sport}->{dport}")
        
        self.csv_writer.writerow([self.count, ts, src, dst, hostname, proto, sport, dport, dns_q, payload, alert])
        self.csv_file.flush()
        self.update_stats()
        
        if self.count >= MAX_PACKETS:
            self.log(f"Reached limit of {MAX_PACKETS} packets. Stopping...")
            self.root.after(0, self.stop_sniffing)
    
    def sniff_loop(self):
        """Runs in a separate thread. Stops quickly when self.running becomes False."""
        # Use timeout loop so we can check self.running frequently
        while self.running and self.count < MAX_PACKETS:
            sniff(
                prn=self.handle_packet,
                store=False,
                timeout=0.2,                # Check every 0.2 seconds
                stop_filter=lambda pkt: not self.running  # Extra safety
            )
        # When loop exits (either stop requested or limit reached)
        if not self.running:
            # Stop was requested – show final message on GUI thread
            self.root.after(0, self._on_sniffer_stopped)
        elif self.count >= MAX_PACKETS:
            # Limit reached – auto stop will be called from handle_packet
            pass
    
    def _on_sniffer_stopped(self):
        """Called when the sniffing thread has actually finished."""
        self.log("Sniffer stopped.")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text=f"Status: Stopped (Limit: {MAX_PACKETS})", fg="red")
        self.update_stats()
    
    def start_sniffing(self):
        if self.running:
            return
        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_label.config(text=f"Status: Running (Limit: {MAX_PACKETS})", fg="green")
        self.log(f"Sniffer started. Capturing up to {MAX_PACKETS} packets...")
        self.sniffer_thread = threading.Thread(target=self.sniff_loop, daemon=True)
        self.sniffer_thread.start()
    
    def stop_sniffing(self):
        if not self.running:
            return
        self.running = False
        # Disable stop button immediately to prevent double-click
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Stopping...", fg="orange")
        # Do NOT log "Sniffer stopped" here – the thread will log it when it actually exits
    
    def on_closing(self):
        self.running = False
        self.csv_file.close()
        self.alert_file.close()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferGUI(root)
    root.mainloop()