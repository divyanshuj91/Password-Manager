"""
main.py — Smart Password Manager Desktop GUI (CustomTkinter).

This is the DESKTOP interface. For the WEB interface, run ``server.py``.

Both interfaces share the same modular core:
  • encryption.py — Argon2 hashing + Fernet encryption
  • database.py   — SQLAlchemy ORM (SQLite / PostgreSQL-ready)
  • totp.py       — TOTP 2FA code generation

Screens
-------
1. Login / Signup  (master password setup & verification)
2. Dashboard       (scrollable credential list with add / copy / show / delete)
"""

import string
import random
import customtkinter as ctk
from tkinter import messagebox

import encryption
import database
import totp

# ── Appearance ────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── Colour palette ────────────────────────────────────────────────────────
BG_DARK       = "#000000"
CARD_BG       = "#202124"
ACCENT        = "#303134"
HIGHLIGHT     = "#8ab4f8"
TEXT_PRIMARY  = "#e8eaed"
TEXT_SECONDARY = "#9ca3af"
ENTRY_BG      = "#202124"
BUTTON_HOVER  = "#3c4043"


class PasswordManagerApp(ctk.CTk):
    """Root application window."""

    def __init__(self):
        super().__init__()

        self.title("🔐 Smart Password Manager")
        self.geometry("900x620")
        self.minsize(780, 520)
        self.configure(fg_color=BG_DARK)

        database.init_db()

        self.encryption_key = None  # set after successful login
        self._totp_labels = {}
        self._timer_running = False

        # Container that holds all "screens"
        self.container = ctk.CTkFrame(self, fg_color=BG_DARK)
        self.container.pack(fill="both", expand=True)

        self.frames: dict[str, ctk.CTkFrame] = {}

        if database.master_exists():
            self._show_login()
        else:
            self._show_signup()

    # ─── Screen helpers ───────────────────────────────────────────────

    def _clear(self):
        for w in self.container.winfo_children():
            w.destroy()

    # ─── Signup screen ────────────────────────────────────────────────

    def _show_signup(self):
        self._clear()

        frame = ctk.CTkFrame(self.container, fg_color=CARD_BG, corner_radius=20, width=420, height=420)
        frame.place(relx=0.5, rely=0.5, anchor="center")
        frame.pack_propagate(False)

        ctk.CTkLabel(frame, text="🔐", font=ctk.CTkFont(size=48)).pack(pady=(30, 5))
        ctk.CTkLabel(frame, text="Create Master Password",
                     font=ctk.CTkFont(size=22, weight="bold"),
                     text_color=TEXT_PRIMARY).pack(pady=(0, 5))
        ctk.CTkLabel(frame, text="This password protects your entire vault.",
                     font=ctk.CTkFont(size=13), text_color=TEXT_SECONDARY).pack(pady=(0, 20))

        pw_entry = ctk.CTkEntry(frame, placeholder_text="Master Password", show="•",
                                width=300, height=42, corner_radius=10,
                                fg_color=ENTRY_BG, border_width=0,
                                text_color=TEXT_PRIMARY)
        pw_entry.pack(pady=(0, 12))

        confirm_entry = ctk.CTkEntry(frame, placeholder_text="Confirm Password", show="•",
                                     width=300, height=42, corner_radius=10,
                                     fg_color=ENTRY_BG, border_width=0,
                                     text_color=TEXT_PRIMARY)
        confirm_entry.pack(pady=(0, 20))

        def on_signup():
            pw = pw_entry.get().strip()
            cf = confirm_entry.get().strip()
            if not pw:
                messagebox.showwarning("Warning", "Password cannot be empty.")
                return
            if len(pw) < 6:
                messagebox.showwarning("Warning", "Password must be at least 6 characters.")
                return
            if pw != cf:
                messagebox.showerror("Error", "Passwords do not match.")
                return
            salt = encryption.generate_salt()
            pw_hash = encryption.hash_master_password(pw)
            database.set_master(pw_hash, salt)
            self.encryption_key = encryption.derive_key(pw, salt)
            self._show_dashboard()

        ctk.CTkButton(frame, text="Create Vault", width=300, height=44,
                      corner_radius=10, fg_color=HIGHLIGHT,
                      hover_color="#c73652",
                      font=ctk.CTkFont(size=15, weight="bold"),
                      command=on_signup).pack()

    # ─── Login screen ─────────────────────────────────────────────────

    def _show_login(self):
        self._clear()

        frame = ctk.CTkFrame(self.container, fg_color=CARD_BG, corner_radius=20, width=420, height=380)
        frame.place(relx=0.5, rely=0.5, anchor="center")
        frame.pack_propagate(False)

        ctk.CTkLabel(frame, text="🔐", font=ctk.CTkFont(size=48)).pack(pady=(30, 5))
        ctk.CTkLabel(frame, text="Unlock Your Vault",
                     font=ctk.CTkFont(size=22, weight="bold"),
                     text_color=TEXT_PRIMARY).pack(pady=(0, 5))
        ctk.CTkLabel(frame, text="Enter your master password to continue.",
                     font=ctk.CTkFont(size=13), text_color=TEXT_SECONDARY).pack(pady=(0, 20))

        pw_entry = ctk.CTkEntry(frame, placeholder_text="Master Password", show="•",
                                width=300, height=42, corner_radius=10,
                                fg_color=ENTRY_BG, border_width=0,
                                text_color=TEXT_PRIMARY)
        pw_entry.pack(pady=(0, 20))

        error_label = ctk.CTkLabel(frame, text="", text_color=HIGHLIGHT,
                                   font=ctk.CTkFont(size=12))
        error_label.pack()

        def on_login(event=None):
            pw = pw_entry.get().strip()
            master = database.get_master()
            if master is None:
                messagebox.showerror("Error", "No master password set.")
                return
            stored_hash, salt = master
            if not encryption.verify_master_password(pw, stored_hash):
                error_label.configure(text="❌ Incorrect password. Try again.")
                pw_entry.delete(0, "end")
                return
            self.encryption_key = encryption.derive_key(pw, salt)
            self._show_dashboard()

        pw_entry.bind("<Return>", on_login)

        ctk.CTkButton(frame, text="Unlock", width=300, height=44,
                      corner_radius=10, fg_color=HIGHLIGHT,
                      hover_color="#c73652",
                      font=ctk.CTkFont(size=15, weight="bold"),
                      command=on_login).pack(pady=(8, 0))

    # ─── Dashboard ────────────────────────────────────────────────────

    def _show_dashboard(self):
        self._clear()

        # ── Top bar ──
        top = ctk.CTkFrame(self.container, fg_color=BG_DARK, height=60, corner_radius=0)
        top.pack(fill="x")
        top.pack_propagate(False)

        header_frame = ctk.CTkFrame(top, fg_color="transparent")
        header_frame.pack(side="left", padx=15, pady=12)
        
        ctk.CTkLabel(header_frame, text="≡", font=ctk.CTkFont(size=24), text_color=TEXT_SECONDARY).pack(side="left", padx=(0, 15))
        ctk.CTkLabel(header_frame, text="Authenticator",
                     font=ctk.CTkFont(size=20, weight="normal"),
                     text_color=TEXT_PRIMARY).pack(side="left")

        actions_frame = ctk.CTkFrame(top, fg_color="transparent")
        actions_frame.pack(side="right", padx=15, pady=12)
        
        ctk.CTkButton(actions_frame, text="🔍", width=36, height=36, corner_radius=18,
                      fg_color="transparent", hover_color=BUTTON_HOVER, text_color=TEXT_PRIMARY, font=ctk.CTkFont(size=18)).pack(side="left", padx=5)
                      
        user_btn = ctk.CTkButton(actions_frame, text="👤", width=32, height=32, corner_radius=16,
                                 fg_color=HIGHLIGHT, hover_color="#6b9cf6", text_color=BG_DARK,
                                 font=ctk.CTkFont(size=14), command=self._lock_vault)
        user_btn.pack(side="right", padx=5)

        # ── Start live updates ──
        if not self._timer_running:
            self._timer_running = True
            self._update_timers()

        # ── Scrollable list ──
        self.scroll = ctk.CTkScrollableFrame(self.container, fg_color=BG_DARK, corner_radius=0)
        self.scroll.pack(fill="both", expand=True)

        fab_frame = ctk.CTkFrame(self.container, fg_color="transparent")
        fab_frame.place(relx=1.0, rely=1.0, x=-24, y=-24, anchor="se")
        ctk.CTkButton(fab_frame, text="＋", width=56, height=56, corner_radius=16,
                      fg_color="#202124", hover_color="#303134",
                      font=ctk.CTkFont(size=28, weight="bold"),
                      text_color="#8ab4f8", command=self._open_add_dialog).pack()

        self._refresh_entries()

    # ── Live Timers ───────────────────────────────────────────────────

    def _update_timers(self):
        if not self.encryption_key or not self._timer_running:
            self._timer_running = False
            return
            
        remaining = totp.get_time_remaining()
        
        for eid, data in self._totp_labels.items():
            try:
                secret = encryption.decrypt(data["enc_totp"], self.encryption_key)
                code = totp.get_totp_code(secret)
                data["code_label"].configure(text=f"{code[:3]} {code[3:]}")
                data["time_label"].configure(text=f"{remaining}s")
                if remaining <= 5:
                    data["time_label"].configure(text_color="#ef4444")
                elif remaining <= 10:
                    data["time_label"].configure(text_color="#f59e0b")
                else:
                    data["time_label"].configure(text_color=TEXT_PRIMARY)
            except Exception:
                pass
                
        self.after(1000, self._update_timers)

    # ── Refresh the entry list ────────────────────────────────────────

    def _refresh_entries(self):
        for w in self.scroll.winfo_children():
            w.destroy()
            
        self._totp_labels.clear()

        entries = database.get_all_entries_full()

        if not entries:
            ctk.CTkLabel(self.scroll, text="Looks like there are no codes yet.",
                         font=ctk.CTkFont(size=16), text_color=TEXT_PRIMARY).pack(pady=(120, 5))
            ctk.CTkLabel(self.scroll, text="Add a code using the + button.",
                         font=ctk.CTkFont(size=13), text_color=TEXT_SECONDARY).pack()
            return

        for idx, entry in enumerate(entries):
            eid = entry["id"]
            site = entry["website"]
            user = entry["username"]
            enc_pw = entry["encrypted_password"]
            enc_totp = entry["totp_secret"]

            row = ctk.CTkFrame(self.scroll, fg_color=BG_DARK, corner_radius=0)
            row.pack(fill="x", padx=10, pady=5)

            left_frame = ctk.CTkFrame(row, fg_color="transparent")
            left_frame.pack(side="left", padx=15, pady=10)
            
            ctk.CTkLabel(left_frame, text=f"{site} ({user})", font=ctk.CTkFont(size=14), text_color=TEXT_SECONDARY, anchor="w").pack(fill="x")
            
            right_frame = ctk.CTkFrame(row, fg_color="transparent")
            right_frame.pack(side="right", padx=15, pady=10)

            def make_open_view(e_id, e_site, e_user, e_pw, e_totp):
                def action(event=None):
                    self._open_view_dialog(e_id, e_site, e_user, e_pw, e_totp)
                return action

            view_action = make_open_view(eid, site, user, enc_pw, enc_totp)
            row.bind("<Button-1>", view_action)
            left_frame.bind("<Button-1>", view_action)
            right_frame.bind("<Button-1>", view_action)

            for child in left_frame.winfo_children() + right_frame.winfo_children():
                child.bind("<Button-1>", view_action)

            if enc_totp:
                def make_copy_totp(cipher):
                    def copy(event=None):
                        try:
                            secret = encryption.decrypt(cipher, self.encryption_key)
                            code = totp.get_totp_code(secret)
                            self.clipboard_clear()
                            self.clipboard_append(code)
                            messagebox.showinfo("Copied", "Code copied", icon="info")
                        except Exception:
                            pass
                    return copy
                
                code_lbl = ctk.CTkLabel(left_frame, text="------", font=ctk.CTkFont(size=34, family="Courier", weight="normal"), text_color=HIGHLIGHT, anchor="w", cursor="hand2")
                code_lbl.pack(fill="x", pady=(5,0))
                code_action = make_copy_totp(enc_totp)
                code_lbl.bind("<Button-1>", code_action)
                
                time_lbl = ctk.CTkLabel(right_frame, text="30", font=ctk.CTkFont(size=18, weight="bold"), text_color=TEXT_PRIMARY)
                time_lbl.pack(side="right", padx=10, pady=15)
                
                self._totp_labels[eid] = {
                    "enc_totp": enc_totp,
                    "code_label": code_lbl,
                    "time_label": time_lbl
                }
            else:
                ctk.CTkLabel(left_frame, text="Pass🔑", font=ctk.CTkFont(size=18), text_color=TEXT_SECONDARY, anchor="w").pack(fill="x", pady=(5,0))

    def _open_view_dialog(self, eid, site, user, enc_pw, enc_totp):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Account Info")
        dialog.geometry("380x360")
        dialog.configure(fg_color=BG_DARK)
        dialog.resizable(False, False)
        dialog.transient(self)
        dialog.grab_set()

        ctk.CTkLabel(dialog, text="Account Info",
                     font=ctk.CTkFont(size=20),
                     text_color=TEXT_PRIMARY).pack(pady=(20, 16))
                     
        ctk.CTkLabel(dialog, text=f"Website: {site}", text_color=TEXT_SECONDARY, anchor="w").pack(fill="x", padx=30, pady=2)
        ctk.CTkLabel(dialog, text=f"Username: {user}", text_color=TEXT_SECONDARY, anchor="w").pack(fill="x", padx=30, pady=2)

        revealed = {"state": False}
        pw_str = ctk.StringVar(value="••••••••••••••••")
        
        pw_frame = ctk.CTkFrame(dialog, fg_color=ENTRY_BG, corner_radius=8, height=40)
        pw_frame.pack(fill="x", padx=30, pady=15)
        pw_frame.pack_propagate(False)
        
        ctk.CTkLabel(pw_frame, textvariable=pw_str, font=ctk.CTkFont(family="Courier"), text_color=TEXT_PRIMARY).pack(side="left", padx=15)
        
        def toggle_pw():
            if revealed["state"]:
                pw_str.set("••••••••••••••••")
                revealed["state"] = False
            else:
                try:
                    plain = encryption.decrypt(enc_pw, self.encryption_key)
                    pw_str.set(plain)
                    revealed["state"] = True
                except Exception:
                    pass

        def copy_pw():
             try:
                 plain = encryption.decrypt(enc_pw, self.encryption_key)
                 self.clipboard_clear()
                 self.clipboard_append(plain)
                 messagebox.showinfo("Copied", "Password copied!")
             except Exception:
                 pass
                 
        ctk.CTkButton(pw_frame, text="📋", width=30, fg_color="transparent", hover_color=BUTTON_HOVER, text_color=HIGHLIGHT, command=copy_pw).pack(side="right", padx=(0, 5))
        ctk.CTkButton(pw_frame, text="👁", width=30, fg_color="transparent", hover_color=BUTTON_HOVER, text_color=HIGHLIGHT, command=toggle_pw).pack(side="right", padx=(0, 5))

        def on_delete():
            if messagebox.askyesno("Confirm", "Delete this account?"):
                database.delete_entry(eid)
                dialog.destroy()
                self._refresh_entries()

        ctk.CTkButton(dialog, text="Delete Account", width=320, height=40,
                      corner_radius=20, fg_color="transparent", border_width=1, border_color="#f28b82",
                      hover_color="#f28b82", text_color="#f28b82",
                      font=ctk.CTkFont(size=14),
                      command=on_delete).pack(pady=(20, 10))

    # ── Add-entry dialog ──────────────────────────────────────────────

    def _open_add_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Add New Credential")
        dialog.geometry("420x420")
        dialog.configure(fg_color=BG_DARK)
        dialog.resizable(False, False)
        dialog.transient(self)
        dialog.grab_set()

        ctk.CTkLabel(dialog, text="Add New Entry",
                     font=ctk.CTkFont(size=20, weight="bold"),
                     text_color=TEXT_PRIMARY).pack(pady=(24, 16))

        website_entry = ctk.CTkEntry(dialog, placeholder_text="Website / App name",
                                     width=340, height=42, corner_radius=10,
                                     fg_color=ENTRY_BG, border_width=0,
                                     text_color=TEXT_PRIMARY)
        website_entry.pack(pady=(0, 10))

        user_entry = ctk.CTkEntry(dialog, placeholder_text="Username / Email",
                                  width=340, height=42, corner_radius=10,
                                  fg_color=ENTRY_BG, border_width=0,
                                  text_color=TEXT_PRIMARY)
        user_entry.pack(pady=(0, 10))

        pw_entry = ctk.CTkEntry(dialog, placeholder_text="Password",
                                width=340, height=42, corner_radius=10,
                                fg_color=ENTRY_BG, border_width=0,
                                text_color=TEXT_PRIMARY)
        pw_entry.pack(pady=(0, 6))

        def generate_password():
            chars = string.ascii_letters + string.digits + string.punctuation
            pw = "".join(random.SystemRandom().choice(chars) for _ in range(16))
            pw_entry.delete(0, "end")
            pw_entry.insert(0, pw)

        ctk.CTkButton(dialog, text="⚡ Generate Strong Password",
                      width=340, height=36, corner_radius=10,
                      fg_color=ACCENT, hover_color="#0a2647",
                      font=ctk.CTkFont(size=13),
                      command=generate_password).pack(pady=(0, 18))

        def on_save():
            site = website_entry.get().strip()
            user = user_entry.get().strip()
            pw   = pw_entry.get().strip()
            if not site or not user or not pw:
                messagebox.showwarning("Warning", "All fields are required.")
                return
            enc = encryption.encrypt(pw, self.encryption_key)
            database.add_entry(site, user, enc)
            dialog.destroy()
            self._refresh_entries()

        ctk.CTkButton(dialog, text="💾  Save Entry", width=340, height=44,
                      corner_radius=10, fg_color=HIGHLIGHT,
                      hover_color="#c73652",
                      font=ctk.CTkFont(size=15, weight="bold"),
                      command=on_save).pack(pady=(0, 10))

    # ── Lock vault ────────────────────────────────────────────────────

    def _lock_vault(self):
        self.encryption_key = None
        self._show_login()


# ── Entry point ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()
