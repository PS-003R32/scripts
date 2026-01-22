# to generate a exe file, run: pyinstaller --noconsole --onefile main.py

import tkinter as tk
from tkinter import messagebox, ttk, simpledialog
import sqlite3
import hashlib
import os
import base64
import random
import string
import datetime
import pyperclip
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DATABASE_NAME = "my_vault.db"

class Backend:
    def __init__(self):
        self.conn = sqlite3.connect(DATABASE_NAME)
        self.cursor = self.conn.cursor()
        self.check_tables()
        self.key = None

    def check_tables(self):
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS master 
                               (id INTEGER PRIMARY KEY, password_hash TEXT, salt TEXT)''')
        
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS vault 
                               (id INTEGER PRIMARY KEY, service TEXT, username TEXT, encrypted_pass TEXT, date_saved TEXT)''')
        self.conn.commit()

    def is_new_user(self):
        self.cursor.execute("SELECT * FROM master")
        return self.cursor.fetchone() is None

    def set_master_password(self, password):
        salt = os.urandom(16)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        self.cursor.execute("INSERT INTO master (password_hash, salt) VALUES (?, ?)", 
                            (pwd_hash.hex(), salt.hex()))
        self.conn.commit()
        self.derive_key(password, salt)

    def login(self, password):
        self.cursor.execute("SELECT password_hash, salt FROM master")
        data = self.cursor.fetchone()
        if not data: return False
        
        stored_hash = data[0]
        salt = bytes.fromhex(data[1])
        input_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()
        
        if input_hash == stored_hash:
            self.derive_key(password, salt)
            return True
        return False

    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        self.key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def add_password(self, service, username, password):
        f = Fernet(self.key)
        encrypted_pass = f.encrypt(password.encode()).decode()
        date_saved = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cursor.execute("INSERT INTO vault (service, username, encrypted_pass, date_saved) VALUES (?, ?, ?, ?)",
                            (service, username, encrypted_pass, date_saved))
        self.conn.commit()

    def update_password(self, id, new_username, new_password):
        f = Fernet(self.key)
        encrypted_pass = f.encrypt(new_password.encode()).decode()
        date_updated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        self.cursor.execute("UPDATE vault SET username = ?, encrypted_pass = ?, date_saved = ? WHERE id = ?",
                            (new_username, encrypted_pass, date_updated, id))
        self.conn.commit()

    def get_passwords(self):
        self.cursor.execute("SELECT id, service, username, encrypted_pass, date_saved FROM vault")
        rows = self.cursor.fetchall()
        decrypted_rows = []
        f = Fernet(self.key)
        for row in rows:
            try:
                decrypted_pass = f.decrypt(row[3].encode()).decode()
                decrypted_rows.append((row[0], row[1], row[2], decrypted_pass, row[4]))
            except:
                decrypted_rows.append((row[0], row[1], row[2], "Error Decrypting", row[4]))
        return decrypted_rows

    def delete_entry_by_id(self, id):
        self.cursor.execute("DELETE FROM vault WHERE id = ?", (id,))
        self.conn.commit()


class PasswordManagerApp:
    def __init__(self, root):
        self.db = Backend()
        self.root = root
        self.root.title("Sentinel-V1   USB Secure Vault")
        self.root.geometry("950x600")
        
        self.show_passwords = False 
        self.is_dark_mode = False
        self.group_by_service = False
        self.cached_data = []
        
        self.setup_styles()
        
        if self.db.is_new_user():
            self.show_register_screen()
        else:
            self.show_login_screen()

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.colors = {
            "bg": "#f0f0f0",
            "fg": "black",
            "entry_bg": "white",
            "entry_fg": "black",
            "btn_bg": "#e1e1e1",
            "tree_bg": "white",
            "tree_fg": "black",
            "header_bg": "#dddddd"
        }
        self.apply_theme()

    def apply_theme(self):
        bg = self.colors["bg"]
        fg = self.colors["fg"]
        
        self.root.configure(bg=bg)
        
        self.style.configure("TFrame", background=bg)
        self.style.configure("TLabel", background=bg, foreground=fg)
        self.style.configure("TButton", background=self.colors["btn_bg"], foreground=fg)
        self.style.configure("Treeview", 
                             background=self.colors["tree_bg"], 
                             foreground=self.colors["tree_fg"], 
                             fieldbackground=self.colors["tree_bg"])
        self.style.configure("Treeview.Heading", 
                             background=self.colors["header_bg"], 
                             foreground="black", 
                             font=('Arial', 10, 'bold'))
        self.style.map("Treeview", background=[('selected', '#0078d7')], foreground=[('selected', 'white')])

        self.update_widgets_recursively(self.root)

    def update_widgets_recursively(self, widget):
        try:
            widget_type = widget.winfo_class()
            if widget_type in ('Frame', 'Label', 'Button', 'Checkbutton'):
                widget.configure(bg=self.colors["bg"], fg=self.colors["fg"])
                if widget_type == 'Button':
                    widget.configure(bg=self.colors["btn_bg"])
            elif widget_type == 'Entry':
                widget.configure(bg=self.colors["entry_bg"], fg=self.colors["entry_fg"], insertbackground=self.colors["fg"])
        except:
            pass
            
        for child in widget.winfo_children():
            self.update_widgets_recursively(child)

    def toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        
        if self.is_dark_mode:
            self.colors = {
                "bg": "#2d2d2d",
                "fg": "#ffffff",
                "entry_bg": "#404040",
                "entry_fg": "white",
                "btn_bg": "#505050",
                "tree_bg": "#333333",
                "tree_fg": "white",
                "header_bg": "#555555"
            }
            self.btn_theme.config(text="☀️ Light Mode")
        else:
            self.colors = {
                "bg": "#f0f0f0",
                "fg": "black",
                "entry_bg": "white",
                "entry_fg": "black",
                "btn_bg": "#e1e1e1",
                "tree_bg": "white",
                "tree_fg": "black",
                "header_bg": "#dddddd"
            }
            self.btn_theme.config(text="🌙 Dark Mode")
            
        self.apply_theme()

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()


    def show_register_screen(self):
        self.clear_screen()
        frame = tk.Frame(self.root)
        frame.pack(pady=50)
        
        tk.Label(frame, text="Create Master Password", font=("Arial", 16)).pack(pady=10)
        tk.Label(frame, text="This password encrypts your database. Do not forget it!", fg="red").pack()
        
        self.entry_pass = tk.Entry(frame, show="*", width=30)
        self.entry_pass.pack(pady=10)
        
        tk.Button(frame, text="Setup Vault", command=self.do_register).pack(pady=10)
        self.apply_theme()

    def show_login_screen(self):
        self.clear_screen()
        frame = tk.Frame(self.root)
        frame.pack(pady=50)

        tk.Label(frame, text="Login to Sentinel-V1", font=("Arial", 16)).pack(pady=10)
        
        self.entry_pass = tk.Entry(frame, show="*", width=30)
        self.entry_pass.pack(pady=10)
        self.entry_pass.bind('<Return>', lambda event: self.do_login())
        
        tk.Button(frame, text="Unlock", command=self.do_login).pack(pady=10)
        self.apply_theme()

    def show_dashboard(self):
        self.clear_screen()
        
        header = tk.Frame(self.root, height=50)
        header.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(header, text="Dashboard", font=("Arial", 14, "bold")).pack(side=tk.LEFT)
        
        tk.Button(header, text="Lock / Exit", command=self.root.quit, bg="#ffcccc", fg="red").pack(side=tk.RIGHT, padx=5)
        
        self.btn_theme = tk.Button(header, text="🌙 Dark Mode", command=self.toggle_theme)
        self.btn_theme.pack(side=tk.RIGHT, padx=5)

        notebook = ttk.Notebook(self.root)
        notebook.pack(expand=True, fill="both", padx=10, pady=5)

        self.frame_view = tk.Frame(notebook)
        notebook.add(self.frame_view, text="My Passwords")
        self.setup_view_tab()

        self.frame_add = tk.Frame(notebook)
        notebook.add(self.frame_add, text="Add New")
        self.setup_add_tab()

        self.frame_gen = tk.Frame(notebook)
        notebook.add(self.frame_gen, text="Generator")
        self.setup_gen_tab()
        
        if self.is_dark_mode: self.btn_theme.config(text="☀️ Light Mode")
        self.apply_theme()


    def do_register(self):
        pwd = self.entry_pass.get()
        if len(pwd) < 4:
            messagebox.showerror("Error", "Password too short!")
            return
        self.db.set_master_password(pwd)
        messagebox.showinfo("Success", "Vault setup complete!")
        self.show_dashboard()

    def do_login(self):
        pwd = self.entry_pass.get()
        if self.db.login(pwd):
            self.show_dashboard()
        else:
            messagebox.showerror("Error", "Invalid Password")


    def setup_view_tab(self):
        # Toolbar
        toolbar = tk.Frame(self.frame_view)
        toolbar.pack(fill=tk.X, padx=10, pady=5)

        self.chk_group_var = tk.BooleanVar(value=False)
        tk.Checkbutton(toolbar, text="Group by Service", variable=self.chk_group_var, command=self.refresh_list).pack(side=tk.LEFT)
        
        tk.Button(toolbar, text="Refresh", command=self.refresh_list).pack(side=tk.LEFT, padx=10)

        columns = ("Service", "Username", "Password", "Date")
        self.tree = ttk.Treeview(self.frame_view, columns=columns, show="headings", selectmode="browse")
        
        self.tree.heading("Service", text="Service / URL")
        self.tree.heading("Username", text="Username")
        self.tree.heading("Password", text="Password")
        self.tree.heading("Date", text="Date & Time Saved") 

        self.tree.column("Service", width=200)
        self.tree.column("Username", width=150)
        self.tree.column("Password", width=150)
        self.tree.column("Date", width=160) 

        scrollbar = ttk.Scrollbar(self.frame_view, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(expand=True, fill="both", padx=10, pady=5)

        btn_frame = tk.Frame(self.frame_view)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.btn_toggle = tk.Button(btn_frame, text="Show Passwords 👁️", command=self.toggle_visibility)
        self.btn_toggle.pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="Copy 📋", command=self.copy_password).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Update ✏️", command=self.open_update_window).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Delete 🗑️", command=self.delete_password, fg="red").pack(side=tk.RIGHT, padx=5)
        
        self.refresh_list()

    def setup_add_tab(self):
        form_frame = tk.Frame(self.frame_add)
        form_frame.pack(pady=20)

        tk.Label(form_frame, text="Service / Website:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.add_service = tk.Entry(form_frame, width=30)
        self.add_service.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(form_frame, text="Username:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.add_user = tk.Entry(form_frame, width=30)
        self.add_user.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(form_frame, text="Password:").grid(row=2, column=0, sticky="e", padx=5, pady=5)
        self.add_pass = tk.Entry(form_frame, width=30)
        self.add_pass.grid(row=2, column=1, padx=5, pady=5)

        tk.Button(form_frame, text="Save to Vault", command=self.save_entry, width=20).grid(row=3, column=1, pady=20)

    def setup_gen_tab(self):
        gen_frame = tk.Frame(self.frame_gen)
        gen_frame.pack(pady=40)

        self.lbl_gen = tk.Entry(gen_frame, font=("Courier", 14), width=30, justify='center')
        self.lbl_gen.pack(pady=10)
        self.lbl_gen.insert(0, "Click generate...")

        tk.Button(gen_frame, text="Generate Strong Password", command=self.generate_pass).pack(pady=5)
        tk.Button(gen_frame, text="Copy to Clipboard", command=lambda: pyperclip.copy(self.lbl_gen.get())).pack(pady=5)


    def refresh_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        self.cached_data = self.db.get_passwords()

        group_mode = self.chk_group_var.get()

        if group_mode:
            self.tree.configure(show="tree headings")
            
            sorted_data = sorted(self.cached_data, key=lambda x: x[1].lower())
            
            seen_services = {}
            
            for row in sorted_data:
                row_id, service, username, real_pass, date = row
                display_pass = real_pass if self.show_passwords else "••••••••••"
                
                if service not in seen_services:
                    parent_id = self.tree.insert("", tk.END, text=service, values=(service, "", "", ""), open=True)
                    seen_services[service] = parent_id

                self.tree.insert(seen_services[service], tk.END, values=("", username, display_pass, date), tags=(str(row_id),))

        else:
            self.tree.configure(show="headings")
            for row in self.cached_data:
                row_id, service, username, real_pass, date = row
                display_pass = real_pass if self.show_passwords else "••••••••••"
                self.tree.insert("", tk.END, values=(service, username, display_pass, date), tags=(str(row_id),))

    def get_selected_db_id(self):
        selected = self.tree.selection()
        if not selected: return None
        
        item = self.tree.item(selected[0])
        
        if not item['tags']:
            return None
            
        return int(item['tags'][0])

    def toggle_visibility(self):
        self.show_passwords = not self.show_passwords
        self.btn_toggle.config(text="Hide Passwords 🔒" if self.show_passwords else "Show Passwords 👁️")
        self.refresh_list()

    def copy_password(self):
        db_id = self.get_selected_db_id()
        if not db_id:
            messagebox.showwarning("Warning", "Please select a specific password entry.")
            return

        for row in self.cached_data:
            if row[0] == db_id:
                pyperclip.copy(row[3])
                messagebox.showinfo("Copied", "Password copied to clipboard!")
                return

    def open_update_window(self):
        db_id = self.get_selected_db_id()
        if not db_id:
            messagebox.showwarning("Warning", "Please select an entry to update.")
            return

        target_row = None
        for row in self.cached_data:
            if row[0] == db_id:
                target_row = row
                break
        
        if not target_row: return

        update_win = tk.Toplevel(self.root)
        update_win.title("Update Entry")
        update_win.geometry("350x250")
        
        bg = self.colors["bg"]
        fg = self.colors["fg"]
        update_win.configure(bg=bg)

        tk.Label(update_win, text=f"Update: {target_row[1]}", bg=bg, fg=fg, font=("Arial", 10, "bold")).pack(pady=10)

        tk.Label(update_win, text="Username:", bg=bg, fg=fg).pack()
        user_entry = tk.Entry(update_win, width=30)
        user_entry.pack(pady=5)
        user_entry.insert(0, target_row[2])

        tk.Label(update_win, text="New Password:", bg=bg, fg=fg).pack()
        pass_entry = tk.Entry(update_win, width=30)
        pass_entry.pack(pady=5)
        pass_entry.insert(0, target_row[3])

        def confirm_update():
            new_user = user_entry.get()
            new_pass = pass_entry.get()
            if new_user and new_pass:
                self.db.update_password(db_id, new_user, new_pass)
                messagebox.showinfo("Success", "Updated successfully!")
                update_win.destroy()
                self.refresh_list()
            else:
                messagebox.showerror("Error", "Fields cannot be empty.")

        tk.Button(update_win, text="Save Changes", command=confirm_update, bg="#ccffcc", fg="black").pack(pady=15)

    def delete_password(self):
        db_id = self.get_selected_db_id()
        if not db_id:
            messagebox.showwarning("Warning", "Please select an entry to delete.")
            return

        if messagebox.askyesno("Confirm", "Are you sure you want to delete this password?"):
            self.db.delete_entry_by_id(db_id)
            self.refresh_list()

    def save_entry(self):
        srv = self.add_service.get()
        usr = self.add_user.get()
        pwd = self.add_pass.get()
        if srv and pwd:
            self.db.add_password(srv, usr, pwd)
            self.add_service.delete(0, tk.END)
            self.add_user.delete(0, tk.END)
            self.add_pass.delete(0, tk.END)
            messagebox.showinfo("Saved", "Password Encrypted & Saved!")
            self.refresh_list()

    def generate_pass(self):
        special_chars = "!@#$%&*()[];+=-?."
        chars = string.ascii_letters + string.digits + special_chars
        while True:
            pwd = "".join(random.choice(chars) for _ in range(16))
            if any(c in special_chars for c in pwd):
                break
        self.lbl_gen.delete(0, tk.END)
        self.lbl_gen.insert(0, pwd)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
