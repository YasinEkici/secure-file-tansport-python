#!/usr/bin/env python3
"""
gui.py - Advanced, Non-Blocking GUI (with Stop Feature & Automatic Server Start)
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import subprocess
import sys
import os
import threading
import queue
import re
import time

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Gelişmiş Güvenli Dosya Transferi")
        self.geometry("650x600")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Variables
        self.host_ip = tk.StringVar(value="192.168.1.6")
        self.password = tk.StringVar(value="parola")
        self.interface_name = tk.StringVar(value="Wi-Fi")
        self.file_path = tk.StringVar()
        self.transfer_mode = tk.StringVar(value="auto")
        self.auto_start_server = tk.BooleanVar(value=True)

        # Process management
        self.log_queue = queue.Queue()
        self.is_running = False
        self.server_process = None
        self.client_process = None

        self.create_widgets()
        # Schedule the queue check (will only run while is_running=True)
        self.process_queue()

    def create_widgets(self):
        main = ttk.Frame(self, padding=15)
        main.pack(fill="both", expand=True)
        main.columnconfigure(1, weight=1)

        # Server IP
        ttk.Label(main, text="Sunucu IP Adresi:").grid(row=0, column=0, sticky="w", pady=5, padx=5)
        ttk.Entry(main, textvariable=self.host_ip, width=40).grid(row=0, column=1, sticky="ew", pady=5, padx=5)
        # Password
        ttk.Label(main, text="Şifre:").grid(row=1, column=0, sticky="w", pady=5, padx=5)
        ttk.Entry(main, textvariable=self.password, show="*", width=40).grid(row=1, column=1, sticky="ew", pady=5, padx=5)
        # Network Interface
        ttk.Label(main, text="Ağ Arayüzü (UDP için):").grid(row=2, column=0, sticky="w", pady=5, padx=5)
        ttk.Entry(main, textvariable=self.interface_name, width=40).grid(row=2, column=1, sticky="ew", pady=5, padx=5)

        # File Selection
        file_frame = ttk.Frame(main)
        file_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=10)
        file_frame.columnconfigure(0, weight=1)
        self.file_label = ttk.Label(file_frame, text="Henüz dosya seçilmedi.", style='Italic.TLabel')
        self.file_label.grid(row=0, column=0, sticky="w", padx=5)
        ttk.Button(file_frame, text="Dosya Seç", command=self.select_file).grid(row=0, column=1, padx=5)

        # Mode Selection and Auto-Start
        opt = ttk.Frame(main)
        opt.grid(row=4, column=0, columnspan=2, sticky="ew", pady=5)
        for txt, val in [("UDP","udp"),("TCP","tcp"),("Otomatik","auto")]:
            ttk.Radiobutton(opt, text=txt, variable=self.transfer_mode, value=val).pack(side="left", padx=5)
        ttk.Checkbutton(main, text="Alıcıyı Otomatik Başlat", variable=self.auto_start_server).grid(row=5, column=0, columnspan=2, sticky="w", padx=5)

        # Send / Stop Buttons
        btn_frame = ttk.Frame(main)
        btn_frame.grid(row=6, column=0, columnspan=2, pady=10, sticky="ew")
        self.send_button = ttk.Button(btn_frame, text="Gönder", command=self.start_transfer, style='Accent.TButton')
        self.send_button.pack(side="left", expand=True, fill="x", padx=5)
        self.stop_button = ttk.Button(btn_frame, text="Durdur", command=self.stop_transfer, state="disabled")
        self.stop_button.pack(side="left", expand=True, fill="x", padx=5)

        # Progress Bar
        self.progress = ttk.Progressbar(main, orient="horizontal", mode="determinate")
        self.progress.grid(row=7, column=0, columnspan=2, sticky="ew", padx=5, pady=5)

        # Log Area
        log_frame = ttk.Labelframe(main, text="Gerçek Zamanlı Log", padding=5)
        log_frame.grid(row=8, column=0, columnspan=2, sticky="nsew", pady=5)
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)
        self.rowconfigure(8, weight=1)
        self.log_text = scrolledtext.ScrolledText(log_frame, state="disabled", height=15, bg="#f0f0f0")
        self.log_text.grid(row=0, column=0, sticky="nsew")

    def select_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path.set(path)
            self.file_label.config(text=os.path.basename(path))

    def start_transfer(self):
        if self.is_running:
            messagebox.showwarning("Uyarı", "Zaten bir transfer çalışıyor.")
            return

        # **We pull all values from the GUI here** (to make it thread-safe)
        host   = self.host_ip.get().strip()
        pwd    = self.password.get().strip()
        iface  = self.interface_name.get().strip()
        fp     = self.file_path.get().strip()
        mode   = self.transfer_mode.get()
        auto_s = self.auto_start_server.get()

        if not host or not pwd or not fp:
            messagebox.showerror("Hata", "Lütfen tüm alanları doldurun ve bir dosya seçin.")
            return

        # UI preparation
        self.log_text.config(state="normal"); self.log_text.delete(1.0, tk.END); self.log_text.config(state="disabled")
        self.progress["value"] = 0
        self.send_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.is_running = True

        # We pass all parameters when starting the thread
        th = threading.Thread(
            target=self.transfer_worker,
            args=(host, pwd, fp, mode, iface, auto_s),
            daemon=True
        )
        th.start()
        self.process_queue()

    def stop_transfer(self):
        if not self.is_running: return
        if messagebox.askokcancel("Durdur", "Transferi durdurmak istediğinize emin misiniz?"):
            self.is_running = False
            if self.client_process: self.client_process.terminate()
            if self.server_process: self.server_process.terminate()
            self.send_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.log_queue.put(('log', "[Kullanıcı] Transfer iptal edildi."))

    # NO more tkinter calls here, only using the local variable auto_s.
    def transfer_worker(self, host, pwd, fp, mode, iface, auto_s):
        try:
            # Start the receiver automatically
            if auto_s:
                final_mode = mode if mode != 'auto' else 'udp'
                if final_mode == 'tcp':
                    srv_cmd = [sys.executable, '-u', 'server.py', '-P', pwd, '-p', '5001']
                else:
                    srv_cmd = [sys.executable, '-u', 'ip_receiver.py', '-P', pwd, '-i', iface]
                self.log_queue.put(('log', f"[Auto-Start] {' '.join(srv_cmd)}"))
                self.server_process = subprocess.Popen(
                    srv_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1, errors='replace'
                )
                time.sleep(1)

            # Client command
            cli_cmd = [sys.executable, '-u', 'hybrid_main.py', host, fp, '--password', pwd, '--mode', mode, '--verbose']
            if mode in ('udp', 'auto'):
                cli_cmd += ['--iface-udp', iface]
            self.log_queue.put(('log', f"[Client] {' '.join(cli_cmd)}"))
            self.client_process = subprocess.Popen(
                cli_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, errors='replace'
            )

            prog_re = re.compile(r'Sent chunk (\d+)/(\d+)')
            for line in self.client_process.stdout:
                if not self.is_running:
                    break
                txt = line.rstrip()
                self.log_queue.put(('log', txt))
                m = prog_re.search(txt)
                if m:
                    c, t = map(int, m.groups())
                    self.log_queue.put(('progress', c, t))

            code = self.client_process.wait()
            if self.is_running:
                if code == 0:
                    self.log_queue.put(('done', "Başarılı", "Transfer tamamlandı."))
                else:
                    self.log_queue.put(('done', "Hata", f"Client çıkış kodu {code}."))
        except Exception as e:
            self.log_queue.put(('done', "Kritik Hata", str(e)))
        finally:
            if self.server_process:
                self.server_process.terminate()
                self.server_process = None
            self.is_running = False

    def process_queue(self):
        while not self.log_queue.empty():
            typ, *payload = self.log_queue.get()
            if typ == 'log':
                self.log_text.config(state="normal")
                self.log_text.insert(tk.END, payload[0]+"\n")
                self.log_text.see(tk.END)
                self.log_text.config(state="disabled")
            elif typ == 'progress':
                cur, tot = payload
                self.progress["maximum"] = tot
                self.progress["value"] = cur
            elif typ == 'done':
                title, msg = payload
                messagebox.showinfo(title, msg)
                self.send_button.config(state="normal")
                self.stop_button.config(state="disabled")
        if self.is_running:
            self.after(100, self.process_queue)

    def on_closing(self):
        if self.is_running and not messagebox.askokcancel("Çıkış", "Transfer devam ediyor. Yine de çıkmak istiyor musunuz?"):
            return
        # Ensure stop_transfer is called to terminate subprocesses before destroying the window
        if self.is_running:
            self.stop_transfer()
        self.destroy()

if __name__ == "__main__":
    style = ttk.Style()
    style.configure('Italic.TLabel', font=('Segoe UI',9,'italic'))
    style.configure('Accent.TButton', font=('Segoe UI',10,'bold'), foreground='white', background='#0078D7')
    app = App()
    app.mainloop()