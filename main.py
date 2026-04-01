"""
main.py — Smart Password Manager GUI (CustomTkinter).

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

# ── Appearance ────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── Colour palette ────────────────────────────────────────────────────────
BG_DARK       = "#1a1a2e"
CARD_BG       = "#16213e"
ACCENT        = "#0f3460"
HIGHLIGHT      = "#e94560"
TEXT_PRIMARY   = "#ffffff"
TEXT_SECONDARY = "#a8a8b3"
ENTRY_BG       = "#0f3460"
BUTTON_HOVER   = "#e94560"


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
        top = ctk.CTkFrame(self.container, fg_color=CARD_BG, height=60, corner_radius=0)
        top.pack(fill="x")
        top.pack_propagate(False)

        ctk.CTkLabel(top, text="🔐 Vault Dashboard",
                     font=ctk.CTkFont(size=20, weight="bold"),
                     text_color=TEXT_PRIMARY).pack(side="left", padx=20)

        ctk.CTkButton(top, text="＋ Add New", width=130, height=36,
                      corner_radius=10, fg_color=HIGHLIGHT,
                      hover_color="#c73652",
                      font=ctk.CTkFont(size=14, weight="bold"),
                      command=self._open_add_dialog).pack(side="right", padx=(0, 10), pady=12)

        ctk.CTkButton(top, text="🔒 Lock", width=90, height=36,
                      corner_radius=10, fg_color=ACCENT,
                      hover_color="#0a2647",
                      font=ctk.CTkFont(size=13),
                      command=self._lock_vault).pack(side="right", padx=(0, 8), pady=12)

        # ── Column headers ──
        header = ctk.CTkFrame(self.container, fg_color=ACCENT, height=40, corner_radius=0)
        header.pack(fill="x")
        header.pack_propagate(False)

        for col, w in [("Website", 180), ("Username", 180), ("Password", 180), ("Actions", 250)]:
            ctk.CTkLabel(header, text=col, width=w,
                         font=ctk.CTkFont(size=13, weight="bold"),
                         text_color=TEXT_SECONDARY).pack(side="left", padx=8)

        # ── Scrollable list ──
        self.scroll = ctk.CTkScrollableFrame(self.container, fg_color=BG_DARK)
        self.scroll.pack(fill="both", expand=True, padx=0, pady=0)

        self._refresh_entries()

    # ── Refresh the entry list ────────────────────────────────────────

    def _refresh_entries(self):
        for w in self.scroll.winfo_children():
            w.destroy()

        entries = database.get_all_entries()

        if not entries:
            ctk.CTkLabel(self.scroll, text="Your vault is empty.\nClick  ＋ Add New  to save your first password.",
                         font=ctk.CTkFont(size=14), text_color=TEXT_SECONDARY).pack(pady=60)
            return

        for idx, (eid, website, username, enc_pw) in enumerate(entries):
            row_color = CARD_BG if idx % 2 == 0 else "#1b2a4a"
            row = ctk.CTkFrame(self.scroll, fg_color=row_color, height=48, corner_radius=8)
            row.pack(fill="x", padx=6, pady=3)
            row.pack_propagate(False)

            ctk.CTkLabel(row, text=website, width=180,
                         font=ctk.CTkFont(size=13), text_color=TEXT_PRIMARY,
                         anchor="w").pack(side="left", padx=8)
            ctk.CTkLabel(row, text=username, width=180,
                         font=ctk.CTkFont(size=13), text_color=TEXT_PRIMARY,
                         anchor="w").pack(side="left", padx=8)

            pw_label = ctk.CTkLabel(row, text="••••••••", width=180,
                                    font=ctk.CTkFont(size=13), text_color=TEXT_PRIMARY,
                                    anchor="w")
            pw_label.pack(side="left", padx=8)

            # State tracking for show/hide
            revealed = {"state": False}

            def make_toggle(lbl, cipher, rev):
                def toggle():
                    if rev["state"]:
                        lbl.configure(text="••••••••")
                        rev["state"] = False
                    else:
                        try:
                            plain = encryption.decrypt(cipher, self.encryption_key)
                            lbl.configure(text=plain)
                            rev["state"] = True
                        except Exception:
                            messagebox.showerror("Error", "Decryption failed.")
                return toggle

            def make_copy(cipher):
                def copy():
                    try:
                        plain = encryption.decrypt(cipher, self.encryption_key)
                        self.clipboard_clear()
                        self.clipboard_append(plain)
                        messagebox.showinfo("Copied", "Password copied to clipboard!")
                    except Exception:
                        messagebox.showerror("Error", "Decryption failed.")
                return copy

            def make_delete(entry_id):
                def delete():
                    if messagebox.askyesno("Confirm", "Delete this entry?"):
                        database.delete_entry(entry_id)
                        self._refresh_entries()
                return delete

            btn_frame = ctk.CTkFrame(row, fg_color="transparent")
            btn_frame.pack(side="right", padx=6)

            ctk.CTkButton(btn_frame, text="👁 Show", width=70, height=30,
                          corner_radius=8, fg_color=ACCENT,
                          hover_color="#0a2647", font=ctk.CTkFont(size=12),
                          command=make_toggle(pw_label, enc_pw, revealed)).pack(side="left", padx=2)

            ctk.CTkButton(btn_frame, text="📋 Copy", width=70, height=30,
                          corner_radius=8, fg_color=ACCENT,
                          hover_color="#0a2647", font=ctk.CTkFont(size=12),
                          command=make_copy(enc_pw)).pack(side="left", padx=2)

            ctk.CTkButton(btn_frame, text="🗑", width=36, height=30,
                          corner_radius=8, fg_color="#8B0000",
                          hover_color="#b91c1c", font=ctk.CTkFont(size=14),
                          command=make_delete(eid)).pack(side="left", padx=2)

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
