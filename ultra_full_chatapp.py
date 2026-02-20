# ultra_full_chatapp.py
import os
import base64
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class UltraKI:
    def __init__(self):
        self.lifesphere_level = 7
    def create_key(self):
        return os.urandom(32)
    def transform(self, data: bytes):
        transformed = base64.b64encode(data[::-1])
        transformed = base64.b64encode(transformed[::-1])
        transformed = base64.b64encode(transformed[::-1])
        return transformed
    def inverse_transform(self, data: bytes):
        tmp = base64.b64decode(data)[::-1]
        tmp = base64.b64decode(tmp)[::-1]
        tmp = base64.b64decode(tmp)[::-1]
        return tmp
    def adaptive_key(self):
        keys = [os.urandom(32) for _ in range(self.lifesphere_level)]
        mixed_key = keys[0]
        for k in keys[1:]:
            mixed_key = bytes(a ^ b for a, b in zip(mixed_key, k))
        return mixed_key
    def analyze_text(self, text: str):
        return f"UltraKI analysiert: '{text}'"

class UltraEncryptApp:
    def __init__(self):
        self.ki = UltraKI()
    def encrypt_text(self, plaintext: str):
        key = self.ki.adaptive_key()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        transformed = self.ki.transform(ciphertext)
        return {"key": base64.b64encode(key).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": transformed.decode()}
    def decrypt_text(self, encrypted_data: dict):
        key = base64.b64decode(encrypted_data["key"])
        nonce = base64.b64decode(encrypted_data["nonce"])
        ciphertext = self.ki.inverse_transform(encrypted_data["ciphertext"].encode())
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode()
    def encrypt_file(self, filepath: str):
        with open(filepath, "rb") as f:
            data = f.read()
        key = self.ki.adaptive_key()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        transformed = self.ki.transform(ciphertext)
        out_path = filepath + ".enc"
        with open(out_path, "wb") as f:
            f.write(transformed)
        return {"key": base64.b64encode(key).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "file": out_path}
    def decrypt_file(self, encrypted_file: str, key: str, nonce: str):
        with open(encrypted_file, "rb") as f:
            data = f.read()
        ciphertext = self.ki.inverse_transform(data)
        aesgcm = AESGCM(base64.b64decode(key))
        plaintext = aesgcm.decrypt(base64.b64decode(nonce), ciphertext, None)
        out_path = encrypted_file.replace(".enc", ".dec")
        with open(out_path, "wb") as f:
            f.write(plaintext)
        return out_path

class UltraChatAppGUI:
    def __init__(self, root):
        self.app = UltraEncryptApp()
        self.root = root
        root.title("Ultra ChatApp - Spiegel KI Design")
        root.configure(bg="#111111")
        root.geometry("900x600")
        self.chat_window = scrolledtext.ScrolledText(root, width=100, height=25, bg="#222222", fg="#FFFFFF", font=("Consolas", 12))
        self.chat_window.pack(padx=10, pady=10)
        self.entry = tk.Entry(root, width=80, bg="#333333", fg="#FFFFFF", insertbackground='white', font=("Consolas", 12))
        self.entry.pack(side=tk.LEFT, padx=(10,0), pady=(0,10))
        self.entry.bind("<Return>", self.send_text)
        self.send_button = tk.Button(root, text="Senden", command=self.send_text, bg="#444444", fg="#FFFFFF", font=("Consolas", 12))
        self.send_button.pack(side=tk.LEFT, padx=(5,0), pady=(0,10))
        self.file_button = tk.Button(root, text="Datei verschlüsseln", command=self.encrypt_file_gui, bg="#555555", fg="#FFFFFF", font=("Consolas", 12))
        self.file_button.pack(side=tk.LEFT, padx=(5,10), pady=(0,10))

    def send_text(self, event=None):
        text = self.entry.get()
        if text.strip() == "":
            return
        self.chat_window.insert(tk.END, f"Du: {text}\n")
        self.entry.delete(0, tk.END)
        enc = self.app.encrypt_text(text)
        analysis = self.app.ki.analyze_text(text)
        self.chat_window.insert(tk.END, f"{analysis}\n")
        self.chat_window.insert(tk.END, f"Ultra KI verschlüsselt: {enc}\n\n")
        self.chat_window.see(tk.END)

    def encrypt_file_gui(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                result = self.app.encrypt_file(file_path)
                messagebox.showinfo("Datei verschlüsselt", f"Datei gespeichert: {result['file']}\nKey: {result['key']}\nNonce: {result['nonce']}")
            except Exception as e:
                messagebox.showerror("Fehler", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    gui = UltraChatAppGUI(root)
    root.mainloop()
# ultra_full_chatapp.py
import os
import base64
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ==============================
# Ultra KI + Lebensblume KI + neuartige KI
# ==============================
class UltraKI:
    """Haupt-Klasse für alle KI-Funktionen"""
    def __init__(self):
        self.lifesphere_level = 7  # adaptive Verschlüsselungsschichten

    def create_key(self):
        # Generiert 256-Bit Schlüssel
        return os.urandom(32)

    def transform(self, data: bytes):
        # Spiegel-Effekt: dreifache Base64 + Invertierung
        transformed = base64.b64encode(data[::-1])
        transformed = base64.b64encode(transformed[::-1])
        transformed = base64.b64encode(transformed[::-1])
        return transformed

    def inverse_transform(self, data: bytes):
        tmp = base64.b64decode(data)[::-1]
        tmp = base64.b64decode(tmp)[::-1]
        tmp = base64.b64decode(tmp)[::-1]
        return tmp

    def adaptive_key(self):
        # Lebensblume Key-Mix aus mehreren Schichten
        keys = [os.urandom(32) for _ in range(self.lifesphere_level)]
        mixed_key = keys[0]
        for k in keys[1:]:
            mixed_key = bytes(a ^ b for a, b in zip(mixed_key, k))
        return mixed_key

    def analyze_text(self, text: str):
        # KI-Textanalyse Placeholder
        return f"UltraKI analysiert: '{text}'"

# ==============================
# Verschlüsselungs-Engine
# ==============================
class UltraEncryptApp:
    def __init__(self):
        self.ki = UltraKI()

    # Text verschlüsseln
    def encrypt_text(self, plaintext: str):
        key = self.ki.adaptive_key()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        transformed = self.ki.transform(ciphertext)
        return {"key": base64.b64encode(key).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": transformed.decode()}

    # Text entschlüsseln
    def decrypt_text(self, encrypted_data: dict):
        key = base64.b64decode(encrypted_data["key"])
        nonce = base64.b64decode(encrypted_data["nonce"])
        ciphertext = self.ki.inverse_transform(encrypted_data["ciphertext"].encode())
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode()

    # Datei verschlüsseln
    def encrypt_file(self, filepath: str):
        with open(filepath, "rb") as f:
            data = f.read()
        key = self.ki.adaptive_key()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        transformed = self.ki.transform(ciphertext)
        out_path = filepath + ".enc"
        with open(out_path, "wb") as f:
            f.write(transformed)
        return {"key": base64.b64encode(key).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "file": out_path}

    # Datei entschlüsseln
    def decrypt_file(self, encrypted_file: str, key: str, nonce: str):
        with open(encrypted_file, "rb") as f:
            data = f.read()
        ciphertext = self.ki.inverse_transform(data)
        aesgcm = AESGCM(base64.b64decode(key))
        plaintext = aesgcm.decrypt(base64.b64decode(nonce), ciphertext, None)
        out_path = encrypted_file.replace(".enc", ".dec")
        with open(out_path, "wb") as f:
            f.write(plaintext)
        return out_path

# ==============================
# GUI im Spiegel-Design
# ==============================
class UltraChatAppGUI:
    def __init__(self, root):
        self.app = UltraEncryptApp()
        self.root = root
        root.title("Ultra ChatApp - Spiegel KI Design")
        root.configure(bg="#111111")
        root.geometry("900x600")

        # Chat-Fenster
        self.chat_window = scrolledtext.ScrolledText(root, width=100, height=25, bg="#222222", fg="#FFFFFF", font=("Consolas", 12))
        self.chat_window.pack(padx=10, pady=10)

        # Eingabefeld
        self.entry = tk.Entry(root, width=80, bg="#333333", fg="#FFFFFF", insertbackground='white', font=("Consolas", 12))
        self.entry.pack(side=tk.LEFT, padx=(10,0), pady=(0,10))
        self.entry.bind("<Return>", self.send_text)

        # Buttons
        self.send_button = tk.Button(root, text="Senden", command=self.send_text, bg="#444444", fg="#FFFFFF", font=("Consolas", 12))
        self.send_button.pack(side=tk.LEFT, padx=(5,0), pady=(0,10))

        self.file_button = tk.Button(root, text="Datei verschlüsseln", command=self.encrypt_file_gui, bg="#555555", fg="#FFFFFF", font=("Consolas", 12))
        self.file_button.pack(side=tk.LEFT, padx=(5,10), pady=(0,10))

    # Text senden
    def send_text(self, event=None):
        text = self.entry.get()
        if text.strip() == "":
            return
        self.chat_window.insert(tk.END, f"Du: {text}\n")
        self.entry.delete(0, tk.END)

        enc = self.app.encrypt_text(text)
        analysis = self.app.ki.analyze_text(text)

        self.chat_window.insert(tk.END, f"{analysis}\n")
        self.chat_window.insert(tk.END, f"Ultra KI verschlüsselt: {enc}\n\n")
        self.chat_window.see(tk.END)

    # Datei verschlüsseln
    def encrypt_file_gui(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                result = self.app.encrypt_file(file_path)
                messagebox.showinfo("Datei verschlüsselt", f"Datei gespeichert: {result['file']}\nKey: {result['key']}\nNonce: {result['nonce']}")
            except Exception as e:
                messagebox.showerror("Fehler", str(e))

# ==============================
# Start GUI
# ==============================
if __name__ == "__main__":
    root = tk.Tk()
    gui = UltraChatAppGUI(root)
    root.mainloop()

