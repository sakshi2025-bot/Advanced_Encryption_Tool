import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import tkinter as tk
from tkinter import filedialog, messagebox

# ----------------- AES-256 Encryption & Decryption ----------------- #
class AESFileCrypto:
    def __init__(self, password):
        self.password = password.encode()
        self.salt = b'\x12\x34\x56\x78\x90\xab\xcd\xef'  # Fixed salt (can randomize)
        self.key = PBKDF2(self.password, self.salt, dkLen=32)  # AES-256 key

    def encrypt_file(self, input_file, output_file=None):
        if not output_file:
            output_file = input_file + ".enc"

        cipher = AES.new(self.key, AES.MODE_GCM)
        with open(input_file, "rb") as f:
            plaintext = f.read()
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        with open(output_file, "wb") as f:
            f.write(cipher.nonce)
            f.write(tag)
            f.write(ciphertext)
        return output_file

    def decrypt_file(self, input_file, output_file=None):
        if not output_file:
            if input_file.endswith(".enc"):
                output_file = input_file[:-4]
            else:
                output_file = input_file + ".dec"

        with open(input_file, "rb") as f:
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()

        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            raise ValueError("Incorrect password or corrupted file")

        with open(output_file, "wb") as f:
            f.write(plaintext)
        return output_file

# ----------------- GUI ----------------- #
class CryptoApp:
    def __init__(self, master):
        self.master = master
        master.title("AES-256 File Encryption Tool")
        master.geometry("450x250")

        # Labels
        tk.Label(master, text="Password:").pack(pady=5)
        self.password_entry = tk.Entry(master, show="*", width=40)
        self.password_entry.pack(pady=5)

        # Buttons
        tk.Button(master, text="Encrypt File", width=30, command=self.encrypt_file).pack(pady=10)
        tk.Button(master, text="Decrypt File", width=30, command=self.decrypt_file).pack(pady=10)

    def encrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select file to encrypt")
        if not file_path:
            return
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Error", "Please enter a password!")
            return
        crypto = AESFileCrypto(password)
        try:
            output_file = crypto.encrypt_file(file_path)
            messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as: {output_file}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select file to decrypt")
        if not file_path:
            return
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Error", "Please enter a password!")
            return
        crypto = AESFileCrypto(password)
        try:
            output_file = crypto.decrypt_file(file_path)
            messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as: {output_file}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

# ----------------- Run App ----------------- #
if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
