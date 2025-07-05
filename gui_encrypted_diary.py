import os
import base64
import hashlib
from datetime import datetime
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

DATA_FILE = "diary.txt"
SALT_FILE = "salt.bin"
PASS_HASH_FILE = "password.hash"

# Password setup
def create_password():
    while True:
        password = simpledialog.askstring("Set Password", "Set a new password:", show='*')
        confirm = simpledialog.askstring("Confirm Password", "Confirm password:", show='*')
        if not password or not confirm:
            return None, None
        if password == confirm:
            break
        else:
            messagebox.showerror("Error", "Passwords do not match. Try again.")
    
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)

    hash_digest = hashlib.sha256((password + salt.hex()).encode()).hexdigest()
    with open(PASS_HASH_FILE, "w") as f:
        f.write(hash_digest)

    return password, salt

# Validate entered password
def validate_password(salt):
    password = simpledialog.askstring("Enter Password", "Enter your diary password:", show='*')
    if not password:
        return None
    hash_check = hashlib.sha256((password + salt.hex()).encode()).hexdigest()
    with open(PASS_HASH_FILE, "r") as f:
        stored_hash = f.read()
    if hash_check == stored_hash:
        return password
    else:
        messagebox.showerror("Access Denied", "Incorrect password.")
        return None

# Create Fernet cipher from password
def get_cipher(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key)

# Write diary entry
def write_entry(cipher, text_widget):
    entry = text_widget.get("1.0", tk.END).strip()
    if not entry:
        messagebox.showwarning("Empty", "Diary entry is empty.")
        return
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_entry = f"[{timestamp}]\n{entry}"
    encrypted = cipher.encrypt(full_entry.encode())
    with open(DATA_FILE, "ab") as f:
        f.write(encrypted + b"\n")
    messagebox.showinfo("Saved", "Entry saved and encrypted.")
    text_widget.delete("1.0", tk.END)

# Read diary entries
def read_entries(cipher):
    if not os.path.exists(DATA_FILE):
        messagebox.showinfo("No Entries", "No diary entries found.")
        return
    with open(DATA_FILE, "rb") as f:
        lines = f.readlines()
        decrypted_entries = []
        for line in lines:
            try:
                decrypted = cipher.decrypt(line.strip()).decode()
                decrypted_entries.append(decrypted)
            except:
                decrypted_entries.append("[Failed to decrypt entry]")
    
    view_window = tk.Toplevel()
    view_window.title("📖 Your Diary Entries")
    text_area = scrolledtext.ScrolledText(view_window, width=80, height=30)
    text_area.pack(padx=10, pady=10)
    text_area.insert(tk.END, "\n\n".join(decrypted_entries))
    text_area.config(state=tk.DISABLED)

# GUI setup
def run_gui(cipher):
    root = tk.Tk()
    root.title("🔐 Encrypted Diary")

    label = tk.Label(root, text="Write your diary entry:", font=("Arial", 12))
    label.pack(pady=5)

    text_widget = scrolledtext.ScrolledText(root, width=80, height=20)
    text_widget.pack(padx=10, pady=5)

    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=10)

    save_btn = tk.Button(btn_frame, text="Save Entry", command=lambda: write_entry(cipher, text_widget))
    save_btn.grid(row=0, column=0, padx=10)

    read_btn = tk.Button(btn_frame, text="View Entries", command=lambda: read_entries(cipher))
    read_btn.grid(row=0, column=1, padx=10)

    quit_btn = tk.Button(btn_frame, text="Quit", command=root.destroy)
    quit_btn.grid(row=0, column=2, padx=10)

    root.mainloop()

# Main flow
def main():
    if not os.path.exists(SALT_FILE) or not os.path.exists(PASS_HASH_FILE):
        messagebox.showinfo("Setup", "🔧 First-time setup required")
        password, salt = create_password()
        if not password:
            return
    else:
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
        password = validate_password(salt)
        if not password:
            return
    
    cipher = get_cipher(password, salt)
    run_gui(cipher)

if __name__ == "__main__":
    tk.Tk().withdraw()  # Hide root window until authenticated
    main()
