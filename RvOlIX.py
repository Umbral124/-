import requests
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from urllib.parse import urlparse
import json

class ProxyCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Прокси Чекер от GPT")
        self.root.geometry("600x400")

        self.file_path = ""
        self.proxy_type = tk.StringVar(value="http")
        self.thread_count = tk.IntVar(value=10)
        self.timeout = tk.IntVar(value=5)
        self.test_url = tk.StringVar(value="https://www.google.com")
        self.results = []

        self.build_gui()

    def build_gui(self):
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Файл с прокси:").pack(anchor="w")
        self.file_entry = ttk.Entry(frame)
        self.file_entry.pack(fill=tk.X)
        ttk.Button(frame, text="Выбрать файл", command=self.browse_file).pack()

        ttk.Label(frame, text="Тип прокси:").pack(anchor="w")
        ttk.Combobox(frame, textvariable=self.proxy_type, values=["http", "socks4", "socks5"]).pack()

        ttk.Label(frame, text="Потоки:").pack(anchor="w")
        ttk.Entry(frame, textvariable=self.thread_count).pack()

        ttk.Label(frame, text="Таймаут (сек):").pack(anchor="w")
        ttk.Entry(frame, textvariable=self.timeout).pack()

        ttk.Label(frame, text="Проверять доступ к сайту:").pack(anchor="w")
        ttk.Entry(frame, textvariable=self.test_url).pack(fill=tk.X)

        ttk.Button(frame, text="Начать проверку", command=self.start_checking).pack(pady=10)
        self.progress = ttk.Label(frame, text="")
        self.progress.pack()

    def browse_file(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if path:
            self.file_path = path
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, path)

    def start_checking(self):
        if not self.file_path or not os.path.exists(self.file_path):
            messagebox.showerror("Ошибка", "Файл не выбран или не найден!")
            return

        with open(self.file_path, 'r') as f:
            proxies = [line.strip() for line in f if line.strip()]

        if not proxies:
            messagebox.showerror("Ошибка", "Файл пустой!")
            return

        self.results = []
        self.progress.config(text="Проверка...")

        threading.Thread(target=self.check_proxies, args=(proxies,)).start()

    def check_proxies(self, proxies):
        valid_by_country = {}
        response_times = []
        proxy_type = self.proxy_type.get()

        def check(proxy):
            start_time = time.time()
            proxies_dict = {"http": f"{proxy_type}://{proxy}", "https": f"{proxy_type}://{proxy}"}
            try:
                r = requests.get(self.test_url.get(), proxies=proxies_dict, timeout=self.timeout.get())
                if r.status_code == 200:
                    ip_info = requests.get(f"http://ip-api.com/json/{proxy.split(':')[0]}").json()
                    country = ip_info.get("country", "Unknown")
                    response_times.append(time.time() - start_time)
                    valid_by_country.setdefault(country, []).append(proxy)
            except:
                pass

        with ThreadPoolExecutor(max_workers=self.thread_count.get()) as executor:
            executor.map(check, proxies)

        avg_time = sum(response_times)/len(response_times) if response_times else 0
        self.save_results(valid_by_country)

        summary = f"Готово! Валидных прокси: {sum(len(lst) for lst in valid_by_country.values())}\n"
        summary += f"Среднее время отклика: {avg_time:.2f} сек.\n"
        summary += "Разбивка по странам:\n" + "\n".join(f"{k}: {len(v)}" for k, v in valid_by_country.items())

        self.progress.config(text=summary)

    def save_results(self, data):
        for country, proxies in data.items():
            with open(f"valid_proxies_{country}.txt", "w") as f:
                for proxy in proxies:
                    f.write(proxy + "\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = ProxyCheckerApp(root)
    root.mainloop()
