import os
import shutil
import hashlib
from PIL import Image, ImageTk
import imagehash
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import datetime
import imghdr

# Config
HASH_TYPE = 'phash'  # Options: 'md5', 'sha256', 'phash'
SUPPORTED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.webp']
LOG_FILE = 'deduplicator_log.txt'

# Compute hash for an image file
def compute_hash(filepath):
    try:
        if HASH_TYPE == 'phash':
            with Image.open(filepath) as img:
                img.verify()  # Check if it opens
            with Image.open(filepath) as img:
                return str(imagehash.phash(img))
        else:
            hash_func = hashlib.md5() if HASH_TYPE == 'md5' else hashlib.sha256()
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
    except Exception as e:
        log(f"Error hashing {filepath}: {e}")
        return None

# Log actions
def log(message):
    with open(LOG_FILE, 'a') as f:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        f.write(f"[{timestamp}] {message}\n")

# Scan folder for duplicates
def find_duplicates(folder):
    hashes = {}
    duplicates = []
    for root, _, files in os.walk(folder):
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in SUPPORTED_EXTENSIONS:
                path = os.path.join(root, file)
                hash_value = compute_hash(path)
                if not hash_value:
                    continue
                if hash_value in hashes:
                    duplicates.append((path, hashes[hash_value]))  # (duplicate, original)
                else:
                    hashes[hash_value] = path
    return duplicates

# GUI Class
class DeduplicatorGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Photo Deduplicator")
        self.folder_path = tk.StringVar()

        self.setup_ui()

    def setup_ui(self):
        frame = ttk.Frame(self.master, padding=10)
        frame.pack(fill='both', expand=True)

        ttk.Label(frame, text="Select Folder to Scan:").grid(row=0, column=0, sticky="w")

        entry = ttk.Entry(frame, textvariable=self.folder_path, width=60)
        entry.grid(row=1, column=0, pady=5, sticky="we")

        ttk.Button(frame, text="Browse...", command=self.select_folder).grid(row=1, column=1, padx=5)

        self.scan_btn = ttk.Button(frame, text="Scan for Duplicates", command=self.scan)
        self.scan_btn.grid(row=2, column=0, columnspan=2, pady=10)

        self.result_frame = ttk.Frame(frame)
        self.result_frame.grid(row=3, column=0, columnspan=2, sticky="nsew")

        self.result_list = tk.Listbox(self.result_frame, width=90, height=10)
        self.result_list.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(self.result_frame, orient="vertical", command=self.result_list.yview)
        scrollbar.pack(side="right", fill="y")
        self.result_list.config(yscrollcommand=scrollbar.set)

        self.move_btn = ttk.Button(frame, text="Move Duplicates to Folder", command=self.move_duplicates, state='disabled')
        self.move_btn.grid(row=4, column=0, columnspan=2, pady=10)

        frame.columnconfigure(0, weight=1)

    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_path.set(folder)

    def scan(self):
        self.result_list.delete(0, tk.END)
        folder = self.folder_path.get()
        if not folder or not os.path.isdir(folder):
            messagebox.showerror("Error", "Please select a valid folder.")
            return
        self.result_list.insert(tk.END, "Scanning for duplicates...")
        self.master.update()

        self.duplicates = find_duplicates(folder)

        self.result_list.delete(0, tk.END)
        if self.duplicates:
            for dup, original in self.duplicates:
                self.result_list.insert(tk.END, f"DUPLICATE: {os.path.basename(dup)}  |  ORIGINAL: {os.path.basename(original)}")
            self.move_btn.config(state='normal')
            log(f"Found {len(self.duplicates)} duplicates in '{folder}'")
        else:
            self.result_list.insert(tk.END, "No duplicates found.")
            self.move_btn.config(state='disabled')

    def move_duplicates(self):
        folder = self.folder_path.get()
        target = os.path.join(folder, "Duplicates")
        os.makedirs(target, exist_ok=True)

        for dup, _ in self.duplicates:
            filename = os.path.basename(dup)
            dest = os.path.join(target, filename)
            i = 1
            while os.path.exists(dest):
                name, ext = os.path.splitext(filename)
                dest = os.path.join(target, f"{name}_{i}{ext}")
                i += 1
            shutil.move(dup, dest)
            log(f"Moved {dup} -> {dest}")

        messagebox.showinfo("Done", f"Moved {len(self.duplicates)} duplicates to: {target}")
        self.scan()  # Refresh view

# Run GUI
if __name__ == '__main__':
    with open(LOG_FILE, 'w') as f:
        f.write("Photo Deduplicator Log\n")
        f.write("======================\n")
    root = tk.Tk()
    app = DeduplicatorGUI(root)
    root.mainloop()
