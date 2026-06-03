import os
import sys
import gc
import json
import base64
import sqlite3
import hmac
import hashlib
import io
import time
import qrcode
from dataclasses import dataclass
from enum import Enum

import pyotp
from PyQt6.QtGui import QPixmap, QImage
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox, QStackedWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QFileDialog, QDialog, QDialogButtonBox, QGraphicsOpacityEffect,
    QAbstractItemView, QComboBox, QToolButton, QFrame, QButtonGroup
)
from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QProcess

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


APP_DIR = os.path.join(os.path.expanduser("~"), ".offline_vault_demo")
CONFIG_PATH = os.path.join(APP_DIR, "config.json")
DB_PATH = os.path.join(APP_DIR, "vault.db")
PREFS_PATH = os.path.join(APP_DIR, "prefs.json")

DEFAULT_PREFS = {"theme": "light"}
THRESHOLD_DAYS = 90
TRASH_RETENTION_DAYS = 30


# Theme palettes. Both dicts MUST share identical keys. LIGHT_PALETTE values are
# the exact original colors so light mode is pixel-identical to the old design.
LIGHT_PALETTE = {
    "window_bg": "#f5f7fb",
    "text": "#1f2937",
    "input_bg": "white",
    "input_border": "#d1d5db",
    "input_focus": "#6366f1",
    "input_disabled_bg": "#f3f4f6",
    "input_disabled_text": "#9ca3af",
    "selection_bg": "#c7d2fe",
    "selection_text": "#1e1b4b",
    "btn_bg": "#4f46e5",
    "btn_text": "white",
    "btn_bg_hover": "#4338ca",
    "btn_bg_pressed": "#3730a3",
    "btn_disabled_bg": "#e5e7eb",
    "btn_disabled_text": "#9ca3af",
    "secondary_bg": "white",
    "secondary_text": "#4f46e5",
    "secondary_border": "#c7d2fe",
    "secondary_hover_bg": "#eef2ff",
    "secondary_hover_border": "#a5b4fc",
    "secondary_pressed_bg": "#e0e7ff",
    "danger_bg": "white",
    "danger_text": "#b91c1c",
    "danger_border": "#fecaca",
    "danger_hover_bg": "#fef2f2",
    "danger_hover_border": "#fca5a5",
    "label_text": "#374151",
    "title_text": "#0f172a",
    "subtitle_text": "#64748b",
    "card_bg": "white",
    "card_border": "#e5e7eb",
    "table_bg": "white",
    "table_alt_bg": "#f9fafb",
    "table_border": "#e5e7eb",
    "table_sel_bg": "#eef2ff",
    "table_sel_text": "#1e293b",
    "header_bg": "#f1f5f9",
    "header_text": "#475569",
    "header_border": "#e2e8f0",
    "dialog_bg": "#f5f7fb",
    "msgbox_bg": "white",
    "warning_text": "#b45309",
    "sidebar_bg": "#e9edf5",
    "sidebar_active_bg": "#dbe3ff",
    "sidebar_active_text": "#3730a3",
    "sidebar_text": "#475569",
    "sidebar_border": "#e2e8f0",
    "strength_weak": "#dc2626",
    "strength_medium": "#d97706",
    "strength_strong": "#059669",
    "strength_neutral": "#6b7280",
    "reuse_warn": "#b45309",
}

DARK_PALETTE = {
    "window_bg": "#0f172a",
    "text": "#e2e8f0",
    "input_bg": "#1e293b",
    "input_border": "#334155",
    "input_focus": "#818cf8",
    "input_disabled_bg": "#1e293b",
    "input_disabled_text": "#64748b",
    "selection_bg": "#3730a3",
    "selection_text": "#e0e7ff",
    "btn_bg": "#6366f1",
    "btn_text": "white",
    "btn_bg_hover": "#818cf8",
    "btn_bg_pressed": "#4f46e5",
    "btn_disabled_bg": "#334155",
    "btn_disabled_text": "#64748b",
    "secondary_bg": "#1e293b",
    "secondary_text": "#c7d2fe",
    "secondary_border": "#475569",
    "secondary_hover_bg": "#334155",
    "secondary_hover_border": "#64748b",
    "secondary_pressed_bg": "#475569",
    "danger_bg": "#1e293b",
    "danger_text": "#f87171",
    "danger_border": "#7f1d1d",
    "danger_hover_bg": "#422020",
    "danger_hover_border": "#b91c1c",
    "label_text": "#cbd5e1",
    "title_text": "#f1f5f9",
    "subtitle_text": "#94a3b8",
    "card_bg": "#1e293b",
    "card_border": "#334155",
    "table_bg": "#1e293b",
    "table_alt_bg": "#243044",
    "table_border": "#334155",
    "table_sel_bg": "#312e81",
    "table_sel_text": "#e0e7ff",
    "header_bg": "#243044",
    "header_text": "#cbd5e1",
    "header_border": "#334155",
    "dialog_bg": "#0f172a",
    "msgbox_bg": "#1e293b",
    "warning_text": "#fbbf24",
    "sidebar_bg": "#0b1220",
    "sidebar_active_bg": "#1e293b",
    "sidebar_active_text": "#e0e7ff",
    "sidebar_text": "#94a3b8",
    "sidebar_border": "#1e293b",
    "strength_weak": "#f87171",
    "strength_medium": "#fbbf24",
    "strength_strong": "#34d399",
    "strength_neutral": "#94a3b8",
    "reuse_warn": "#fbbf24",
}

# QSS template. Uses @@token@@ placeholders (NOT f-strings/.format) because QSS
# blocks contain literal { } braces.
STYLESHEET_TEMPLATE = """
QWidget {
    background-color: @@window_bg@@;
    color: @@text@@;
    font-family: "Segoe UI", "Inter", "SF Pro Display", sans-serif;
    font-size: 14px;
}

QLineEdit {
    background-color: @@input_bg@@;
    color: @@text@@;
    border: 1px solid @@input_border@@;
    border-radius: 8px;
    padding: 9px 12px;
    selection-background-color: @@selection_bg@@;
    selection-color: @@selection_text@@;
}

QLineEdit:focus {
    border: 1px solid @@input_focus@@;
}

QLineEdit:disabled {
    background-color: @@input_disabled_bg@@;
    color: @@input_disabled_text@@;
}

QComboBox {
    background-color: @@input_bg@@;
    color: @@text@@;
    border: 1px solid @@input_border@@;
    border-radius: 8px;
    padding: 8px 12px;
}

QComboBox:focus {
    border: 1px solid @@input_focus@@;
}

QComboBox QAbstractItemView {
    background-color: @@input_bg@@;
    color: @@text@@;
    selection-background-color: @@table_sel_bg@@;
    selection-color: @@table_sel_text@@;
}

QPushButton {
    background-color: @@btn_bg@@;
    color: @@btn_text@@;
    border: 1px solid @@btn_bg@@;
    border-radius: 8px;
    padding: 9px 18px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: @@btn_bg_hover@@;
    border-color: @@btn_bg_hover@@;
}

QPushButton:pressed {
    background-color: @@btn_bg_pressed@@;
    border-color: @@btn_bg_pressed@@;
}

QPushButton:disabled {
    background-color: @@btn_disabled_bg@@;
    border-color: @@btn_disabled_bg@@;
    color: @@btn_disabled_text@@;
}

QPushButton[variant="secondary"] {
    background-color: @@secondary_bg@@;
    color: @@secondary_text@@;
    border: 1px solid @@secondary_border@@;
}

QPushButton[variant="secondary"]:hover {
    background-color: @@secondary_hover_bg@@;
    border-color: @@secondary_hover_border@@;
}

QPushButton[variant="secondary"]:pressed {
    background-color: @@secondary_pressed_bg@@;
}

QPushButton[variant="danger"] {
    background-color: @@danger_bg@@;
    color: @@danger_text@@;
    border: 1px solid @@danger_border@@;
}

QPushButton[variant="danger"]:hover {
    background-color: @@danger_hover_bg@@;
    border-color: @@danger_hover_border@@;
}

QToolButton {
    background-color: @@secondary_bg@@;
    color: @@secondary_text@@;
    border: 1px solid @@secondary_border@@;
    border-radius: 8px;
    padding: 9px 12px;
    font-weight: 600;
}

QToolButton:hover {
    background-color: @@secondary_hover_bg@@;
    border-color: @@secondary_hover_border@@;
}

QToolButton:checked {
    background-color: @@secondary_hover_bg@@;
    border-color: @@secondary_hover_border@@;
}

QLabel {
    background: transparent;
    color: @@label_text@@;
}

QLabel[role="title"] {
    font-size: 24px;
    font-weight: 700;
    color: @@title_text@@;
    padding: 4px 0 2px 0;
}

QLabel[role="subtitle"] {
    font-size: 13px;
    color: @@subtitle_text@@;
    padding-bottom: 6px;
}

QLabel[role="warning"] {
    color: @@warning_text@@;
    font-weight: 600;
}

QFrame#card {
    background-color: @@card_bg@@;
    border: 1px solid @@card_border@@;
    border-radius: 12px;
}

QFrame#sidebar {
    background-color: @@sidebar_bg@@;
    border: none;
    border-right: 1px solid @@sidebar_border@@;
}

QPushButton[nav="true"] {
    text-align: left;
    border: none;
    background-color: transparent;
    color: @@sidebar_text@@;
    padding: 11px 16px;
    border-radius: 8px;
    font-weight: 600;
}

QPushButton[nav="true"]:hover {
    background-color: @@sidebar_active_bg@@;
    border: none;
}

QPushButton[nav="true"]:checked {
    background-color: @@sidebar_active_bg@@;
    color: @@sidebar_active_text@@;
    border: none;
    font-weight: 700;
}

QTableWidget {
    background-color: @@table_bg@@;
    alternate-background-color: @@table_alt_bg@@;
    border: 1px solid @@table_border@@;
    border-radius: 10px;
    gridline-color: transparent;
    selection-background-color: @@table_sel_bg@@;
    selection-color: @@table_sel_text@@;
    font-size: 13px;
}

QTableWidget::item {
    padding: 10px 8px;
}

QHeaderView::section {
    background-color: @@header_bg@@;
    color: @@header_text@@;
    padding: 12px 10px;
    border: none;
    border-bottom: 1px solid @@header_border@@;
    font-weight: 700;
    font-size: 12px;
}

QMessageBox {
    background-color: @@msgbox_bg@@;
}

QDialog {
    background-color: @@dialog_bg@@;
}

QDialogButtonBox QPushButton {
    min-width: 80px;
}
"""


def build_stylesheet(palette: dict) -> str:
    qss = STYLESHEET_TEMPLATE
    for key, value in palette.items():
        qss = qss.replace("@@" + key + "@@", value)
    return qss


# Active palette, updated by MainWindow.apply_theme(). Inline-styled widgets
# (strength/reuse labels) read their colors from here so they re-theme too.
CURRENT_PALETTE = dict(LIGHT_PALETTE)


def make_qr_pixmap(data: str, box_size: int = 6, border: int = 2) -> QPixmap:
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=box_size,
        border=border,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qimg = QImage.fromData(buf.getvalue(), "PNG")
    return QPixmap.fromImage(qimg)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


def ensure_app_dir():
    os.makedirs(APP_DIR, exist_ok=True)


def load_prefs() -> dict:
    """Load non-sensitive UI prefs (e.g. theme). Safe defaults on missing/corrupt."""
    try:
        with open(PREFS_PATH, "r", encoding="utf-8") as f:
            obj = json.load(f)
        if not isinstance(obj, dict):
            return dict(DEFAULT_PREFS)
        prefs = dict(DEFAULT_PREFS)
        prefs.update(obj)
        if prefs.get("theme") not in ("light", "dark"):
            prefs["theme"] = DEFAULT_PREFS["theme"]
        return prefs
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return dict(DEFAULT_PREFS)


def save_prefs(prefs: dict) -> None:
    """Best-effort persist of UI prefs; never raises out of a slot."""
    try:
        ensure_app_dir()
        with open(PREFS_PATH, "w", encoding="utf-8") as f:
            json.dump(prefs, f)
    except OSError:
        pass


def _remove_with_retry(path: str, attempts: int = 5, delay: float = 0.1) -> bool:
    """Delete a file, retrying briefly to ride out Windows file-lock timing.

    Returns True if the file is gone (or never existed) afterwards.
    """
    for _ in range(attempts):
        if not os.path.exists(path):
            return True
        try:
            os.remove(path)
            return True
        except (PermissionError, OSError):
            gc.collect()
            time.sleep(delay)
    return not os.path.exists(path)


def reset_vault_files() -> tuple[bool, str]:
    """Erase all vault data. Never raises (caller is a Qt slot).

    Deletes config + the SQLite db and its journal/WAL sidecars independently so
    one stubborn file does not leave the rest behind. prefs.json is preserved.
    """
    gc.collect()
    targets = [
        CONFIG_PATH,
        DB_PATH,
        DB_PATH + "-journal",
        DB_PATH + "-wal",
        DB_PATH + "-shm",
    ]
    failed = [p for p in targets if not _remove_with_retry(p)]
    if failed:
        names = ", ".join(os.path.basename(p) for p in failed)
        return False, f"Could not delete: {names}. Close other programs and try again."
    return True, "Vault deleted."


def relaunch_app() -> None:
    """Start a fresh instance of this app and quit the current one.

    QProcess.startDetached (args as a list) handles the spaced install path and
    venv python correctly, and quitting releases all OS/file handles cleanly.
    """
    if getattr(sys, "frozen", False):
        program, args = sys.executable, sys.argv[1:]
    else:
        program, args = sys.executable, sys.argv
    QProcess.startDetached(program, args)
    QApplication.quit()


def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(master_password.encode("utf-8"))


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def aesgcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b""):
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, aad)
    return nonce, ct


def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b""):
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, aad)


def fade_in_widget(widget, duration: int = 240):
    effect = QGraphicsOpacityEffect(widget)
    effect.setOpacity(0.0)
    widget.setGraphicsEffect(effect)

    anim = QPropertyAnimation(effect, b"opacity")
    anim.setDuration(duration)
    anim.setStartValue(0.0)
    anim.setEndValue(1.0)
    anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    def _cleanup():
        widget.setGraphicsEffect(None)
    anim.finished.connect(_cleanup)
    anim.start()
    widget._fade_anim = anim


def fade_in_window(widget, duration: int = 180):
    widget.setWindowOpacity(0.0)
    anim = QPropertyAnimation(widget, b"windowOpacity")
    anim.setDuration(duration)
    anim.setStartValue(0.0)
    anim.setEndValue(1.0)
    anim.setEasingCurve(QEasingCurve.Type.OutCubic)
    anim.start()
    widget._window_fade_anim = anim


def attach_password_toggle(line_edit: QLineEdit) -> QToolButton:
    """Return a checkable show/hide button wired to line_edit's echo mode.

    Caller places the returned button next to the field (e.g. in an HBox).
    Toggling echo is independent of read-only, so it composes with edit flows.
    """
    btn = QToolButton()
    btn.setCheckable(True)
    btn.setText("Show")
    btn.setProperty("variant", "secondary")
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    btn.setToolTip("Show or hide the password")

    def _on_toggled(checked: bool):
        if checked:
            line_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            btn.setText("Hide")
        else:
            line_edit.setEchoMode(QLineEdit.EchoMode.Password)
            btn.setText("Show")

    btn.toggled.connect(_on_toggled)
    line_edit._toggle_btn = btn  # keep a handle so callers can sync state
    return btn


def password_strength(pw: str):
    score = 0
    if len(pw) >= 12:
        score += 2
    elif len(pw) >= 8:
        score += 1
    if any(c.islower() for c in pw):
        score += 1
    if any(c.isupper() for c in pw):
        score += 1
    if any(c.isdigit() for c in pw):
        score += 1
    if any(c in "!@#$%^&*()-_=+[]{};:'\",.<>?/\\|`~" for c in pw):
        score += 1

    if score <= 2:
        return "Weak", score
    if score <= 4:
        return "Medium", score
    return "Strong", score


def format_date(ts) -> str:
    """Human-readable local date/time for a unix timestamp; 'Unknown' for 0."""
    if not ts:
        return "Unknown"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(int(ts)))


def password_age_text(modified_at) -> str:
    """Warning text based on when the password was last changed."""
    if not modified_at:
        return "Password age unknown."
    age_days = max(0, (int(time.time()) - int(modified_at)) // 86400)
    plural = "s" if age_days != 1 else ""
    text = f"This password is {age_days} day{plural} old."
    if age_days >= THRESHOLD_DAYS:
        text += " Consider changing it."
    return text


def trash_days_left(deleted_at, retention_days: int = TRASH_RETENTION_DAYS) -> int:
    """Days remaining before a trashed entry is auto-removed (>= 0)."""
    if not deleted_at:
        return retention_days
    days_in_trash = (int(time.time()) - int(deleted_at)) // 86400
    return max(0, retention_days - days_in_trash)


class VaultDB:
    def __init__(self, path: str):
        self.path = path
        # One persistent connection so the OS file handle lifetime is
        # deterministic and can be closed before deleting/overwriting the db.
        self._con = sqlite3.connect(self.path)
        self._init_db()

    def close(self):
        if self._con is not None:
            try:
                self._con.close()
            finally:
                self._con = None

    def __del__(self):
        # Safety net only; correctness relies on explicit close().
        try:
            self.close()
        except Exception:
            pass

    def _init_db(self):
        self._con.execute(
            """
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL,
                username TEXT NOT NULL,
                pw_nonce BLOB NOT NULL,
                pw_ct BLOB NOT NULL,
                pw_fingerprint BLOB NOT NULL,
                created_at INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL DEFAULT 0,
                deleted_at INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        # Migrate older/imported databases that predate these columns.
        cols = [r[1] for r in self._con.execute("PRAGMA table_info(entries)").fetchall()]
        if "created_at" not in cols:
            self._con.execute(
                "ALTER TABLE entries ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0"
            )
        if "updated_at" not in cols:
            self._con.execute(
                "ALTER TABLE entries ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0"
            )
            # Treat existing rows' last-modified time as their creation time.
            self._con.execute("UPDATE entries SET updated_at = created_at WHERE updated_at = 0")
        if "deleted_at" not in cols:
            self._con.execute(
                "ALTER TABLE entries ADD COLUMN deleted_at INTEGER NOT NULL DEFAULT 0"
            )
        self._con.commit()

    def add_entry(self, site: str, username: str, pw_nonce: bytes, pw_ct: bytes, pw_fp: bytes):
        now = int(time.time())
        self._con.execute(
            "INSERT INTO entries(site, username, pw_nonce, pw_ct, pw_fingerprint, "
            "created_at, updated_at, deleted_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
            (site, username, pw_nonce, pw_ct, pw_fp, now, now),
        )
        self._con.commit()

    def update_entry(self, entry_id: int, pw_nonce: bytes, pw_ct: bytes, pw_fp: bytes):
        # Only the modification time changes; the creation time is preserved.
        self._con.execute(
            "UPDATE entries SET pw_nonce=?, pw_ct=?, pw_fingerprint=?, updated_at=? WHERE id=?",
            (pw_nonce, pw_ct, pw_fp, int(time.time()), entry_id),
        )
        self._con.commit()

    # ---- soft delete / trash ----

    def delete_entry(self, entry_id: int):
        # Soft delete: move to trash. Auto-purged after TRASH_RETENTION_DAYS.
        self._con.execute(
            "UPDATE entries SET deleted_at=? WHERE id=?", (int(time.time()), entry_id)
        )
        self._con.commit()

    def restore_entry(self, entry_id: int):
        self._con.execute("UPDATE entries SET deleted_at=0 WHERE id=?", (entry_id,))
        self._con.commit()

    def permanently_delete_entry(self, entry_id: int):
        self._con.execute("DELETE FROM entries WHERE id=?", (entry_id,))
        self._con.commit()

    def list_trash(self):
        cur = self._con.execute(
            "SELECT id, site, username, deleted_at FROM entries WHERE deleted_at > 0 "
            "ORDER BY deleted_at DESC"
        )
        return cur.fetchall()

    def empty_trash(self):
        self._con.execute("DELETE FROM entries WHERE deleted_at > 0")
        self._con.commit()

    def purge_expired_trash(self, retention_days: int = TRASH_RETENTION_DAYS) -> int:
        cutoff = int(time.time()) - retention_days * 86400
        cur = self._con.execute(
            "DELETE FROM entries WHERE deleted_at > 0 AND deleted_at < ?", (cutoff,)
        )
        self._con.commit()
        return cur.rowcount

    # ---- queries (active entries only) ----

    def list_entries(self):
        cur = self._con.execute(
            "SELECT id, site, username FROM entries WHERE deleted_at = 0 ORDER BY id DESC"
        )
        return cur.fetchall()

    def get_all_fingerprints(self):
        cur = self._con.execute(
            "SELECT pw_fingerprint FROM entries WHERE deleted_at = 0"
        )
        return [row[0] for row in cur.fetchall()]

    def get_fingerprints_excluding(self, entry_id: int):
        cur = self._con.execute(
            "SELECT pw_fingerprint FROM entries WHERE id != ? AND deleted_at = 0",
            (entry_id,),
        )
        return [row[0] for row in cur.fetchall()]

    def get_entry_secret(self, entry_id: int):
        cur = self._con.execute(
            "SELECT pw_nonce, pw_ct FROM entries WHERE id = ?",
            (entry_id,),
        )
        return cur.fetchone()

    def get_entry_meta(self, entry_id: int):
        cur = self._con.execute(
            "SELECT pw_nonce, pw_ct, created_at, updated_at FROM entries WHERE id = ?",
            (entry_id,),
        )
        return cur.fetchone()


@dataclass
class Config:
    salt: bytes
    verifier: bytes
    totp_nonce: bytes
    totp_ct: bytes
    failed_attempts: int = 0
    locked_until: float = 0.0
    last_used_window: int = 0
    lockout_level: int = 0

    def to_json(self) -> dict:
        return {
            "salt": b64e(self.salt),
            "verifier": b64e(self.verifier),
            "totp_nonce": b64e(self.totp_nonce),
            "totp_ct": b64e(self.totp_ct),
            "failed_attempts": self.failed_attempts,
            "locked_until": self.locked_until,
            "last_used_window": self.last_used_window,
            "lockout_level": self.lockout_level,
        }

    @staticmethod
    def from_file(path: str) -> "Config":
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        return Config(
            salt=b64d(obj["salt"]),
            verifier=b64d(obj["verifier"]),
            totp_nonce=b64d(obj["totp_nonce"]),
            totp_ct=b64d(obj["totp_ct"]),
            failed_attempts=int(obj.get("failed_attempts", 0)),
            locked_until=float(obj.get("locked_until", 0.0)),
            last_used_window=int(obj.get("last_used_window", 0)),
            lockout_level=int(obj.get("lockout_level", 0)),
        )


LOCKOUT_THRESHOLD = 3
LOCKOUT_DURATIONS = [60, 180, 300]
TOTP_INTERVAL = 30


def format_lockout_duration(secs: int) -> str:
    if secs < 60:
        return f"{secs} second{'s' if secs != 1 else ''}"
    mins, remainder = divmod(secs, 60)
    if remainder == 0:
        return f"{mins} minute{'s' if mins != 1 else ''}"
    return f"{mins} min {remainder} sec"


class TotpResult(Enum):
    OK = "ok"
    LOCKED = "locked"
    EXPIRED_OR_INVALID = "bad"
    REPLAY = "replay"


def _save_config(cfg: Config) -> None:
    ensure_app_dir()
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg.to_json(), f)


def verify_totp_strict(
    cfg: Config, secret: str, code: str, persist: bool = True
) -> tuple[TotpResult, int]:
    """Strict TOTP verification with replay protection and lockout tracking.

    Returns (result, seconds_remaining). seconds_remaining is only meaningful
    for LOCKED. When persist=True, mutations to cfg are written to CONFIG_PATH;
    set persist=False for flows where the cfg lives in memory only (e.g. import).
    """
    now = time.time()

    if cfg.locked_until and now < cfg.locked_until:
        return TotpResult.LOCKED, int(cfg.locked_until - now) + 1

    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=0):
        cfg.failed_attempts += 1
        if cfg.failed_attempts >= LOCKOUT_THRESHOLD:
            duration = LOCKOUT_DURATIONS[min(cfg.lockout_level, len(LOCKOUT_DURATIONS) - 1)]
            cfg.locked_until = now + duration
            cfg.failed_attempts = 0
            cfg.lockout_level += 1
        if persist:
            _save_config(cfg)
        return TotpResult.EXPIRED_OR_INVALID, 0

    current_window = int(now // TOTP_INTERVAL)
    if cfg.last_used_window == current_window:
        return TotpResult.REPLAY, 0

    cfg.failed_attempts = 0
    cfg.locked_until = 0.0
    cfg.lockout_level = 0
    cfg.last_used_window = current_window
    if persist:
        _save_config(cfg)
    return TotpResult.OK, 0


class SetupScreen(QWidget):
    def __init__(self, on_done, on_imported):
        super().__init__()
        self.on_done = on_done
        self.on_imported = on_imported

        layout = QVBoxLayout()
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(10)

        title = QLabel("Create Your Vault")
        title.setProperty("role", "title")
        layout.addWidget(title)

        subtitle = QLabel("Set a master password and we'll generate a TOTP secret for two-factor unlock.")
        subtitle.setProperty("role", "subtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        layout.addWidget(QLabel("Master password"))
        self.pw1 = QLineEdit()
        self.pw1.setEchoMode(QLineEdit.EchoMode.Password)
        pw1_row = QHBoxLayout()
        pw1_row.addWidget(self.pw1)
        pw1_row.addWidget(attach_password_toggle(self.pw1))
        layout.addLayout(pw1_row)

        layout.addWidget(QLabel("Confirm master password"))
        self.pw2 = QLineEdit()
        self.pw2.setEchoMode(QLineEdit.EchoMode.Password)
        pw2_row = QHBoxLayout()
        pw2_row.addWidget(self.pw2)
        pw2_row.addWidget(attach_password_toggle(self.pw2))
        layout.addLayout(pw2_row)

        self.totp_label = QLabel("TOTP secret will be generated after setup.")
        self.totp_label.setWordWrap(True)
        layout.addWidget(self.totp_label)

        self.qr_label = QLabel("QR will appear here after vault creation.")
        self.qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.qr_label.setMinimumHeight(220)
        layout.addWidget(self.qr_label)

        self.secret_label = QLabel("")
        self.secret_label.setWordWrap(True)
        layout.addWidget(self.secret_label)

        self.btn = QPushButton("Create Vault")
        self.btn.clicked.connect(self.handle_setup)
        layout.addWidget(self.btn)

        self.import_btn = QPushButton("Import Encrypted Backup Instead")
        self.import_btn.setProperty("variant", "secondary")
        self.import_btn.clicked.connect(self.handle_import)
        layout.addWidget(self.import_btn)

        layout.addStretch()
        self.setLayout(layout)

    def handle_import(self):
        result = import_backup_via_dialog(self)
        if result is None:
            return
        key, secret = result
        self.on_imported(key, secret)

    def handle_setup(self):
        pw1 = self.pw1.text()
        pw2 = self.pw2.text()

        if not pw1 or pw1 != pw2:
            QMessageBox.warning(self, "Setup error", "Passwords do not match.")
            return

        strength, _ = password_strength(pw1)
        if strength == "Weak":
            QMessageBox.warning(
                self,
                "Weak password",
                "Please use a stronger master password (longer, mixed characters)."
            )
            return

        ensure_app_dir()

        # Guarantee a fresh, empty vault even if a prior reset did not fully
        # remove the old database (e.g. a Windows file lock left it behind).
        ok, msg = reset_vault_files()
        if not ok:
            QMessageBox.critical(self, "Setup error", msg)
            return

        salt = os.urandom(16)
        key = derive_key(pw1, salt)

        verifier = hmac_sha256(key, b"vault-verifier-v1")

        totp_secret = pyotp.random_base32()
        totp = pyotp.TOTP(totp_secret)
        otpauth_uri = totp.provisioning_uri(
            name="user@offline-vault",
            issuer_name="OfflineVault"
        )

        self.qr_label.setPixmap(make_qr_pixmap(otpauth_uri))
        self.secret_label.setText(f"Manual setup key (Base32): {totp_secret}")
        self.totp_label.setText("Scan the QR using an authenticator app before unlocking.")

        totp_nonce, totp_ct = aesgcm_encrypt(
            key,
            totp_secret.encode("utf-8"),
            aad=b"totp-secret-v1"
        )

        cfg = Config(
            salt=salt,
            verifier=verifier,
            totp_nonce=totp_nonce,
            totp_ct=totp_ct
        )

        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg.to_json(), f, indent=2)

        VaultDB(DB_PATH)

        QMessageBox.information(
            self,
            "Setup complete",
            "Vault created.\n\nScan the QR code, then proceed to Unlock."
        )

        self.on_done()


class UnlockScreen(QWidget):
    def __init__(self, on_unlocked, on_reset):
        super().__init__()
        self.on_unlocked = on_unlocked
        self.on_reset = on_reset

        layout = QVBoxLayout()
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(10)

        title = QLabel("Welcome Back")
        title.setProperty("role", "title")
        layout.addWidget(title)

        subtitle = QLabel("Unlock your offline vault with your master password and TOTP code.")
        subtitle.setProperty("role", "subtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        layout.addWidget(QLabel("Master password"))
        self.master_pw = QLineEdit()
        self.master_pw.setEchoMode(QLineEdit.EchoMode.Password)
        master_pw_row = QHBoxLayout()
        master_pw_row.addWidget(self.master_pw)
        master_pw_row.addWidget(attach_password_toggle(self.master_pw))
        layout.addLayout(master_pw_row)

        layout.addWidget(QLabel("TOTP code (6 digits)"))
        self.otp = QLineEdit()
        self.otp.setMaxLength(6)
        layout.addWidget(self.otp)

        self.btn = QPushButton("Unlock")
        self.btn.clicked.connect(self.handle_unlock)
        layout.addWidget(self.btn)

        self.import_btn = QPushButton("Import Encrypted Backup")
        self.import_btn.setProperty("variant", "secondary")
        self.import_btn.clicked.connect(self.handle_import)
        layout.addWidget(self.import_btn)

        self.reset_btn = QPushButton("Reset Vault (Forgot Master Password)")
        self.reset_btn.setProperty("variant", "danger")
        self.reset_btn.clicked.connect(self.handle_reset)
        layout.addWidget(self.reset_btn)

        layout.addStretch()
        self.setLayout(layout)

    def handle_import(self):
        result = import_backup_via_dialog(self)
        if result is None:
            return
        key, secret = result
        self.on_unlocked(key, secret)

    def handle_unlock(self):

        if not os.path.exists(CONFIG_PATH):
            QMessageBox.warning(self, "Not setup", "No vault found. Please run setup first.")
            return

        cfg = Config.from_file(CONFIG_PATH)
        pw = self.master_pw.text()
        code = self.otp.text().strip()

        try:
            key = derive_key(pw, cfg.salt)
        except Exception:
            QMessageBox.warning(self, "Unlock failed", "Invalid master password.")
            return

        verifier_check = hmac_sha256(key, b"vault-verifier-v1")
        if not hmac.compare_digest(verifier_check, cfg.verifier):
            QMessageBox.warning(self, "Unlock failed", "Invalid master password.")
            return

        try:
            secret = aesgcm_decrypt(
                key,
                cfg.totp_nonce,
                cfg.totp_ct,
                aad=b"totp-secret-v1"
            ).decode("utf-8")
        except Exception:
            QMessageBox.critical(self, "Unlock failed", "Could not decrypt TOTP secret.")
            return

        result, secs = verify_totp_strict(cfg, secret, code)
        if result is TotpResult.LOCKED:
            QMessageBox.warning(
                self,
                "Locked out",
                f"Too many failed attempts. Try again in {format_lockout_duration(secs)}.",
            )
            return
        if result is TotpResult.REPLAY:
            QMessageBox.warning(
                self,
                "Code already used",
                "That code has already been used. Wait for your authenticator to show a new code.",
            )
            return
        if result is TotpResult.EXPIRED_OR_INVALID:
            QMessageBox.warning(
                self,
                "Code expired",
                "Code expired or invalid. Enter the current code from your authenticator.",
            )
            return

        QMessageBox.information(
            self,
            "Unlocked",
            f"Vault unlocked.\nCurrent OTP (demo): {pyotp.TOTP(secret).now()}"
        )

        # Don't leave the master password / TOTP sitting in the widgets.
        self.clear_inputs()
        self.on_unlocked(key, secret)

    def clear_inputs(self):
        self.master_pw.clear()
        self.otp.clear()
        tb = getattr(self.master_pw, "_toggle_btn", None)
        if tb is not None and tb.isChecked():
            tb.setChecked(False)  # restores hidden echo via its toggled handler

    def handle_reset(self):
        reply = QMessageBox.question(
            self,
            "Confirm Reset",
            "This will DELETE the local vault and all stored passwords, "
            "then restart the app.\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        # The actual erase + relaunch is owned by MainWindow (it can close the
        # live db handle first). Guard so nothing escapes this slot and aborts.
        try:
            self.on_reset()
        except Exception as e:
            QMessageBox.critical(self, "Reset failed", f"Could not reset the vault:\n{e}")
        
class TOTPPromptDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Authenticate")
        self.setModal(True)
        self.setMinimumWidth(340)

        layout = QVBoxLayout()
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(10)
        layout.addWidget(QLabel("Enter current TOTP code to reveal password:"))

        self.otp = QLineEdit()
        self.otp.setMaxLength(6)
        self.otp.setPlaceholderText("6-digit code")
        layout.addWidget(self.otp)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def showEvent(self, event):
        super().showEvent(event)
        fade_in_window(self)

    def code(self) -> str:
        return self.otp.text().strip()


class RevealPasswordDialog(QDialog):
    def __init__(self, site, username, password, entry_id, key, db,
                 created_at, updated_at, parent=None):
        super().__init__(parent)
        self.entry_id = entry_id
        self.key = key
        self.db = db
        self.username = username
        self._original_pw = password

        self.setWindowTitle(f"Password — {site}")
        self.setModal(True)
        self.setMinimumWidth(400)

        layout = QVBoxLayout()
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(10)
        layout.addWidget(QLabel(f"Site: {site}"))
        layout.addWidget(QLabel(f"Username: {username}"))

        self.created_label = QLabel(f"Created: {format_date(created_at)}")
        self.created_label.setProperty("role", "subtitle")
        layout.addWidget(self.created_label)

        self.modified_label = QLabel(f"Last modified: {format_date(updated_at)}")
        self.modified_label.setProperty("role", "subtitle")
        layout.addWidget(self.modified_label)

        self.age_label = QLabel(password_age_text(updated_at))
        self.age_label.setWordWrap(True)
        self.age_label.setProperty("role", "warning")
        layout.addWidget(self.age_label)

        pw_row = QHBoxLayout()
        self.pw_field = QLineEdit(password)
        self.pw_field.setReadOnly(True)
        self.pw_field.setEchoMode(QLineEdit.EchoMode.Password)
        pw_row.addWidget(self.pw_field)
        pw_row.addWidget(attach_password_toggle(self.pw_field))
        layout.addLayout(pw_row)

        row = QHBoxLayout()
        copy_pw_btn = QPushButton("Copy Password")
        copy_pw_btn.clicked.connect(
            lambda: QApplication.clipboard().setText(self.pw_field.text())
        )

        copy_user_btn = QPushButton("Copy Username")
        copy_user_btn.setProperty("variant", "secondary")
        copy_user_btn.clicked.connect(
            lambda: QApplication.clipboard().setText(self.username)
        )

        self.edit_btn = QPushButton("Edit")
        self.edit_btn.setProperty("variant", "secondary")
        self.edit_btn.clicked.connect(self.enter_edit)

        self.save_btn = QPushButton("Save")
        self.save_btn.setEnabled(False)
        self.save_btn.clicked.connect(self.do_save)

        close_btn = QPushButton("Close")
        close_btn.setProperty("variant", "secondary")
        close_btn.clicked.connect(self.accept)

        row.addWidget(copy_pw_btn)
        row.addWidget(copy_user_btn)
        row.addWidget(self.edit_btn)
        row.addWidget(self.save_btn)
        row.addWidget(close_btn)
        layout.addLayout(row)

        self.setLayout(layout)

    def enter_edit(self):
        self.pw_field.setReadOnly(False)
        self.pw_field.setEchoMode(QLineEdit.EchoMode.Normal)
        tb = getattr(self.pw_field, "_toggle_btn", None)
        if tb is not None and not tb.isChecked():
            tb.setChecked(True)  # the value is now visible — reflect it on the toggle
        self.pw_field.setFocus()
        self.edit_btn.setEnabled(False)
        self.save_btn.setEnabled(True)

    def do_save(self):
        new_pw = self.pw_field.text()
        if not new_pw:
            QMessageBox.warning(self, "Empty password", "Password cannot be empty.")
            return

        strength, _ = password_strength(new_pw)
        if strength == "Weak":
            QMessageBox.warning(self, "Weak password", "Password is too weak. Use a stronger one.")
            return

        # Reuse check excludes this entry's own fingerprint so re-saving the same
        # value is allowed, but matching a different entry is blocked.
        fp = hmac_sha256(self.key, new_pw.encode("utf-8"))
        others = self.db.get_fingerprints_excluding(self.entry_id)
        if any(hmac.compare_digest(fp, e) for e in others):
            QMessageBox.warning(self, "Password reuse", "This password is already used by another entry.")
            return

        nonce, ct = aesgcm_encrypt(self.key, new_pw.encode("utf-8"), aad=b"vault-entry-v1")
        self.db.update_entry(self.entry_id, nonce, ct, fp)
        self._original_pw = new_pw

        # Reflect the new modification time / age immediately.
        now = int(time.time())
        self.modified_label.setText(f"Last modified: {format_date(now)}")
        self.age_label.setText(password_age_text(now))

        self.pw_field.setReadOnly(True)
        self.edit_btn.setEnabled(True)
        self.save_btn.setEnabled(False)
        QMessageBox.information(self, "Saved", "Password updated.")

    def showEvent(self, event):
        super().showEvent(event)
        fade_in_window(self)


class ImportDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Import Encrypted Backup")
        self.setModal(True)
        self.setMinimumWidth(380)

        layout = QVBoxLayout()
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(10)

        info = QLabel("Enter the master password and a current TOTP code from your authenticator app to restore this backup.")
        info.setWordWrap(True)
        layout.addWidget(info)

        layout.addWidget(QLabel("Master password"))
        self.pw_field = QLineEdit()
        self.pw_field.setEchoMode(QLineEdit.EchoMode.Password)
        pw_row = QHBoxLayout()
        pw_row.addWidget(self.pw_field)
        pw_row.addWidget(attach_password_toggle(self.pw_field))
        layout.addLayout(pw_row)

        layout.addWidget(QLabel("TOTP code (6 digits)"))
        self.otp_field = QLineEdit()
        self.otp_field.setMaxLength(6)
        layout.addWidget(self.otp_field)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def showEvent(self, event):
        super().showEvent(event)
        fade_in_window(self)

    def password(self) -> str:
        return self.pw_field.text()

    def code(self) -> str:
        return self.otp_field.text().strip()


def import_backup_via_dialog(parent):
    path, _ = QFileDialog.getOpenFileName(
        parent, "Import Encrypted Backup", "", "Encrypted Backup (*.enc)"
    )
    if not path:
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        if "salt" not in payload:
            QMessageBox.critical(
                parent, "Import failed",
                "Backup is missing salt (older format). Re-export it from the original device."
            )
            return None
        salt = b64d(payload["salt"])
        nonce = b64d(payload["nonce"])
        ct = b64d(payload["ct"])
    except Exception as e:
        QMessageBox.critical(parent, "Import failed", f"Could not read backup file:\n{e}")
        return None

    dlg = ImportDialog(parent)
    if dlg.exec() != QDialog.DialogCode.Accepted:
        return None

    pw = dlg.password()
    code = dlg.code()
    if not pw or not code:
        QMessageBox.warning(parent, "Import failed", "Master password and TOTP code are required.")
        return None

    try:
        key = derive_key(pw, salt)
        bundle = aesgcm_decrypt(key, nonce, ct, aad=b"backup-v1")
    except Exception:
        QMessageBox.warning(parent, "Import failed", "Invalid master password or corrupted backup.")
        return None

    try:
        parts = bundle.split(b"\n")
        if len(parts) != 3 or parts[0] != b"VAULTBACKUPv1":
            raise ValueError("Unrecognized backup version")
        cfg_bytes = b64d(parts[1].decode("utf-8"))
        db_bytes = b64d(parts[2].decode("utf-8"))
    except Exception as e:
        QMessageBox.critical(parent, "Import failed", f"Backup contents are invalid:\n{e}")
        return None

    try:
        cfg_obj = json.loads(cfg_bytes.decode("utf-8"))
        totp_nonce = b64d(cfg_obj["totp_nonce"])
        totp_ct = b64d(cfg_obj["totp_ct"])
        secret = aesgcm_decrypt(
            key, totp_nonce, totp_ct, aad=b"totp-secret-v1"
        ).decode("utf-8")
    except Exception:
        QMessageBox.critical(parent, "Import failed", "Could not decrypt TOTP secret from backup.")
        return None

    tracking_cfg: Config
    tracking_persist: bool
    if os.path.exists(CONFIG_PATH):
        try:
            tracking_cfg = Config.from_file(CONFIG_PATH)
            tracking_persist = True
        except Exception:
            tracking_cfg = Config(
                salt=b64d(cfg_obj["salt"]),
                verifier=b64d(cfg_obj["verifier"]),
                totp_nonce=b64d(cfg_obj["totp_nonce"]),
                totp_ct=b64d(cfg_obj["totp_ct"]),
            )
            tracking_persist = False
    else:
        tracking_cfg = Config(
            salt=b64d(cfg_obj["salt"]),
            verifier=b64d(cfg_obj["verifier"]),
            totp_nonce=b64d(cfg_obj["totp_nonce"]),
            totp_ct=b64d(cfg_obj["totp_ct"]),
        )
        tracking_persist = False

    result, secs = verify_totp_strict(tracking_cfg, secret, code, persist=tracking_persist)
    if result is TotpResult.LOCKED:
        QMessageBox.warning(
            parent,
            "Locked out",
            f"Too many failed attempts. Try again in {format_lockout_duration(secs)}.",
        )
        return None
    if result is TotpResult.REPLAY:
        QMessageBox.warning(
            parent,
            "Code already used",
            "That code has already been used. Wait for your authenticator to show a new code.",
        )
        return None
    if result is TotpResult.EXPIRED_OR_INVALID:
        QMessageBox.warning(
            parent,
            "Code expired",
            "Code expired or invalid. Enter the current code from your authenticator.",
        )
        return None

    if os.path.exists(CONFIG_PATH) or os.path.exists(DB_PATH):
        reply = QMessageBox.question(
            parent,
            "Replace local vault?",
            "A vault already exists on this device. Importing will replace it.\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return None

    imported_cfg = Config(
        salt=b64d(cfg_obj["salt"]),
        verifier=b64d(cfg_obj["verifier"]),
        totp_nonce=b64d(cfg_obj["totp_nonce"]),
        totp_ct=b64d(cfg_obj["totp_ct"]),
        failed_attempts=0,
        locked_until=0.0,
        last_used_window=int(time.time() // TOTP_INTERVAL),
    )
    cfg_bytes = json.dumps(imported_cfg.to_json()).encode("utf-8")

    ensure_app_dir()
    with open(CONFIG_PATH, "wb") as f:
        f.write(cfg_bytes)
    with open(DB_PATH, "wb") as f:
        f.write(db_bytes)

    QMessageBox.information(parent, "Import complete", "Backup restored successfully.")
    return key, secret


class VaultScreen(QWidget):
    def __init__(self, on_logout=None, on_toggle_theme=None, on_reset=None, theme="light"):
        super().__init__()
        self.key = None
        self.totp_secret = None
        self.db = None
        self.on_logout = on_logout
        self.on_toggle_theme = on_toggle_theme
        self.on_reset = on_reset
        self._all_rows = []

        root = QHBoxLayout()
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_sidebar())

        self.content = QStackedWidget()
        self.passwords_page = self._build_passwords_page()
        self.backup_page = self._build_backup_page()
        self.trash_page = self._build_trash_page()
        self.settings_page = self._build_settings_page()
        self.content.addWidget(self.passwords_page)
        self.content.addWidget(self.backup_page)
        self.content.addWidget(self.trash_page)
        self.content.addWidget(self.settings_page)
        root.addWidget(self.content, 1)

        self.setLayout(root)

        self.nav_passwords.setChecked(True)
        self.update_theme_button(theme)

    # ---- sidebar ----

    def _build_sidebar(self):
        self.sidebar = QFrame()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(190)

        col = QVBoxLayout()
        col.setContentsMargins(14, 22, 14, 18)
        col.setSpacing(6)

        brand = QLabel("🔒 Vault")
        brand.setProperty("role", "title")
        col.addWidget(brand)
        col.addSpacing(8)

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)

        self.nav_passwords = self._make_nav_button("Passwords")
        self.nav_backup = self._make_nav_button("Backup")
        self.nav_trash = self._make_nav_button("Trash")
        self.nav_settings = self._make_nav_button("Settings")

        self.nav_passwords.toggled.connect(
            lambda on: self._show_page(self.passwords_page) if on else None
        )
        self.nav_backup.toggled.connect(
            lambda on: self._show_page(self.backup_page) if on else None
        )
        self.nav_trash.toggled.connect(self._on_trash_nav)
        self.nav_settings.toggled.connect(
            lambda on: self._show_page(self.settings_page) if on else None
        )

        col.addWidget(self.nav_passwords)
        col.addWidget(self.nav_backup)
        col.addWidget(self.nav_trash)
        col.addWidget(self.nav_settings)
        col.addStretch()

        self.logout_btn = QPushButton("Logout")
        self.logout_btn.setProperty("variant", "secondary")
        self.logout_btn.clicked.connect(self.handle_logout)
        col.addWidget(self.logout_btn)

        self.sidebar.setLayout(col)
        return self.sidebar

    def _make_nav_button(self, text):
        btn = QPushButton(text)
        btn.setCheckable(True)
        btn.setProperty("nav", "true")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.nav_group.addButton(btn)
        return btn

    def _show_page(self, page):
        self.content.setCurrentWidget(page)
        fade_in_widget(page)

    def _on_trash_nav(self, on):
        if not on:
            return
        # Drop anything past its retention window, then show what's left.
        if self.db is not None:
            self.db.purge_expired_trash()
        self.refresh_trash()
        self._show_page(self.trash_page)

    # ---- pages ----

    def _build_passwords_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(12)

        title = QLabel("Passwords")
        title.setProperty("role", "title")
        layout.addWidget(title)

        subtitle = QLabel("Add credentials, search your vault, and select a row to reveal, edit, or delete. Revealing always asks for your TOTP code.")
        subtitle.setProperty("role", "subtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        # Search row
        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("Search by"))
        self.search_by = QComboBox()
        self.search_by.addItems(["Website", "Username"])
        self.search_by.currentIndexChanged.connect(self.apply_filter)
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search...")
        self.search_box.textChanged.connect(self.apply_filter)
        search_row.addWidget(self.search_by)
        search_row.addWidget(self.search_box, 1)
        layout.addLayout(search_row)

        # Add-entry form
        form = QHBoxLayout()
        self.site = QLineEdit()
        self.site.setPlaceholderText("Site")
        self.user = QLineEdit()
        self.user.setPlaceholderText("Username")
        self.pw = QLineEdit()
        self.pw.setPlaceholderText("Password")
        self.pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw.textChanged.connect(self.on_pw_changed)

        self.add_btn = QPushButton("Add Entry")
        self.add_btn.clicked.connect(self.add_entry)
        self.add_btn.setEnabled(False)
        self.add_btn.setToolTip("Enter a password to add an entry.")

        form.addWidget(self.site)
        form.addWidget(self.user)
        form.addWidget(self.pw)
        form.addWidget(attach_password_toggle(self.pw))
        form.addWidget(self.add_btn)
        layout.addLayout(form)

        # Strength / reuse row
        self.str_label = QLabel("Strength: -")
        self.str_label.setStyleSheet(
            f"color: {CURRENT_PALETTE['strength_neutral']}; font-weight: 600;"
        )
        self.reuse_label = QLabel("")
        self.reuse_label.setStyleSheet(
            f"color: {CURRENT_PALETTE['reuse_warn']}; font-weight: 600;"
        )
        info = QHBoxLayout()
        info.addWidget(self.str_label)
        info.addWidget(self.reuse_label)
        info.addStretch()
        layout.addLayout(info)

        # Table
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["ID", "Site", "Username"])
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setDefaultSectionSize(42)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        self.table.itemDoubleClicked.connect(lambda _it: self.reveal_selected())
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

        # Action row
        action_row = QHBoxLayout()
        self.reveal_btn = QPushButton("Reveal Password")
        self.reveal_btn.setEnabled(False)
        self.reveal_btn.setToolTip("Select an entry first")
        self.reveal_btn.setMinimumWidth(160)
        self.reveal_btn.clicked.connect(self.reveal_selected)
        action_row.addWidget(self.reveal_btn)

        self.delete_btn = QPushButton("Delete")
        self.delete_btn.setProperty("variant", "danger")
        self.delete_btn.setEnabled(False)
        self.delete_btn.setToolTip("Select an entry first")
        self.delete_btn.clicked.connect(self.delete_selected)
        action_row.addWidget(self.delete_btn)
        action_row.addStretch()
        layout.addLayout(action_row)

        page.setLayout(layout)
        return page

    def _build_backup_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(12)

        title = QLabel("Backup")
        title.setProperty("role", "title")
        layout.addWidget(title)

        desc = QLabel("Export an encrypted backup of your vault, or restore one. Importing replaces the current vault and signs you back in.")
        desc.setProperty("role", "subtitle")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        self.backup_btn = QPushButton("Export Encrypted Backup")
        self.backup_btn.clicked.connect(self.export_backup)
        layout.addWidget(self.backup_btn)

        self.import_btn = QPushButton("Import Encrypted Backup")
        self.import_btn.setProperty("variant", "secondary")
        self.import_btn.clicked.connect(self.handle_import_backup)
        layout.addWidget(self.import_btn)

        layout.addStretch()
        page.setLayout(layout)
        return page

    def _build_trash_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(12)

        title = QLabel("Trash")
        title.setProperty("role", "title")
        layout.addWidget(title)

        subtitle = QLabel(
            f"Deleted entries are kept here for {TRASH_RETENTION_DAYS} days, then removed "
            "automatically. Restore an entry to return it to your vault, or delete it permanently."
        )
        subtitle.setProperty("role", "subtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        self.trash_table = QTableWidget(0, 4)
        self.trash_table.setHorizontalHeaderLabels(["ID", "Site", "Username", "Auto-removes in"])
        self.trash_table.verticalHeader().setVisible(False)
        self.trash_table.setAlternatingRowColors(True)
        self.trash_table.setShowGrid(False)
        self.trash_table.verticalHeader().setDefaultSectionSize(42)
        self.trash_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.trash_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.trash_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.trash_table.itemSelectionChanged.connect(self.on_trash_selection_changed)
        t_header = self.trash_table.horizontalHeader()
        t_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        t_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        t_header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        t_header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.trash_table)

        action_row = QHBoxLayout()
        self.restore_btn = QPushButton("Restore")
        self.restore_btn.setEnabled(False)
        self.restore_btn.setToolTip("Select a trashed entry first")
        self.restore_btn.clicked.connect(self.restore_selected)
        action_row.addWidget(self.restore_btn)

        self.perm_delete_btn = QPushButton("Permanently Delete")
        self.perm_delete_btn.setProperty("variant", "danger")
        self.perm_delete_btn.setEnabled(False)
        self.perm_delete_btn.setToolTip("Select a trashed entry first")
        self.perm_delete_btn.clicked.connect(self.permanently_delete_selected)
        action_row.addWidget(self.perm_delete_btn)

        action_row.addStretch()

        self.empty_trash_btn = QPushButton("Empty Trash")
        self.empty_trash_btn.setProperty("variant", "danger")
        self.empty_trash_btn.clicked.connect(self.empty_trash)
        action_row.addWidget(self.empty_trash_btn)
        layout.addLayout(action_row)

        page.setLayout(layout)
        return page

    def _build_settings_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(12)

        title = QLabel("Settings")
        title.setProperty("role", "title")
        layout.addWidget(title)

        appearance = QLabel("Appearance")
        appearance.setProperty("role", "subtitle")
        layout.addWidget(appearance)
        self.theme_btn = QPushButton("Switch to Dark Mode")
        self.theme_btn.setProperty("variant", "secondary")
        self.theme_btn.clicked.connect(self._toggle_theme_clicked)
        layout.addWidget(self.theme_btn)

        layout.addSpacing(10)

        security = QLabel("Security")
        security.setProperty("role", "subtitle")
        layout.addWidget(security)
        self.remind_btn = QPushButton("Show Security Reminders")
        self.remind_btn.setProperty("variant", "secondary")
        self.remind_btn.clicked.connect(self.show_reminders)
        layout.addWidget(self.remind_btn)

        layout.addSpacing(10)

        danger = QLabel("Danger zone")
        danger.setProperty("role", "subtitle")
        layout.addWidget(danger)
        reset_desc = QLabel("Resetting erases ALL stored passwords on this device, then restarts the app.")
        reset_desc.setWordWrap(True)
        layout.addWidget(reset_desc)
        self.reset_btn = QPushButton("Reset Vault")
        self.reset_btn.setProperty("variant", "danger")
        self.reset_btn.clicked.connect(self.handle_reset)
        layout.addWidget(self.reset_btn)

        layout.addStretch()
        page.setLayout(layout)
        return page

    # ---- theme helpers ----

    def _toggle_theme_clicked(self):
        if self.on_toggle_theme:
            self.on_toggle_theme()

    def update_theme_button(self, theme):
        if hasattr(self, "theme_btn"):
            self.theme_btn.setText(
                "Switch to Light Mode" if theme == "dark" else "Switch to Dark Mode"
            )

    def refresh_dynamic_colors(self):
        # Inline-styled labels don't cascade on theme change; re-derive them.
        self.on_pw_changed()

    # ---- reset (Settings page) ----

    def handle_reset(self):
        reply = QMessageBox.question(
            self,
            "Confirm Reset",
            "This will DELETE the local vault and all stored passwords, "
            "then restart the app.\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            if self.on_reset:
                self.on_reset()
        except Exception as e:
            QMessageBox.critical(self, "Reset failed", f"Could not reset the vault:\n{e}")

    # ---- session / table ----

    def handle_logout(self):
        if self.db is not None:
            self.db.close()
        self.key = None
        self.totp_secret = None
        self.db = None
        self._all_rows = []
        self.table.setRowCount(0)
        self.trash_table.setRowCount(0)
        self.site.clear()
        self.user.clear()
        self.pw.clear()
        self.search_box.clear()
        if self.on_logout:
            self.on_logout()

    def set_session(self, key: bytes, totp_secret: str):
        if self.db is not None:
            self.db.close()
        self.key = key
        self.totp_secret = totp_secret
        self.db = VaultDB(DB_PATH)
        self.db.purge_expired_trash()  # drop anything past its retention window
        self.nav_passwords.setChecked(True)
        self.search_box.clear()
        self.refresh_table()
        self.refresh_trash()

    def refresh_table(self):
        self._all_rows = self.db.list_entries()
        self.apply_filter()

    def apply_filter(self):
        if not hasattr(self, "table"):
            return
        q = self.search_box.text().strip().lower()
        idx = 1 if self.search_by.currentText() == "Website" else 2
        sel = self._current_entry_id()
        rows = [r for r in self._all_rows if not q or q in str(r[idx]).lower()]
        self._render_rows(rows, reselect_id=sel)

    def _render_rows(self, rows, reselect_id=None):
        self.table.blockSignals(True)
        self.table.setRowCount(0)
        for r in rows:
            entry_id, site, username = r
            row_idx = self.table.rowCount()
            self.table.insertRow(row_idx)

            id_item = QTableWidgetItem(f"{entry_id:04d}")
            id_item.setFlags(id_item.flags() ^ Qt.ItemFlag.ItemIsEditable)
            id_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            id_item.setData(Qt.ItemDataRole.UserRole, entry_id)
            self.table.setItem(row_idx, 0, id_item)

            for c, val in enumerate((site, username), start=1):
                item = QTableWidgetItem(str(val))
                item.setFlags(item.flags() ^ Qt.ItemFlag.ItemIsEditable)
                item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
                self.table.setItem(row_idx, c, item)

            if reselect_id is not None and entry_id == reselect_id:
                self.table.selectRow(row_idx)

        self.table.blockSignals(False)
        self.on_selection_changed()

    def _current_entry_id(self):
        row = self.table.currentRow()
        if row < 0:
            return None
        item = self.table.item(row, 0)
        if item is None:
            return None
        return item.data(Qt.ItemDataRole.UserRole)

    def on_selection_changed(self):
        has_selection = self.table.currentRow() >= 0 and bool(self.table.selectedItems())
        self.reveal_btn.setEnabled(has_selection)
        self.reveal_btn.setToolTip("" if has_selection else "Select an entry first")
        self.delete_btn.setEnabled(has_selection)
        self.delete_btn.setToolTip("" if has_selection else "Select an entry first")

    def delete_selected(self):
        entry_id = self._current_entry_id()
        if entry_id is None:
            return
        row = self.table.currentRow()
        site_item = self.table.item(row, 1)
        site = site_item.text() if site_item else ""
        reply = QMessageBox.question(
            self,
            "Move to Trash",
            f'Move the entry for "{site}" to Trash?\n\n'
            f"It will be kept for {TRASH_RETENTION_DAYS} days, then removed automatically. "
            "You can restore it from the Trash before then.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        self.db.delete_entry(entry_id)
        self.refresh_table()
        if hasattr(self, "trash_table"):
            self.refresh_trash()

    # ---- trash ----

    def refresh_trash(self):
        if self.db is None:
            self.trash_table.setRowCount(0)
            self.on_trash_selection_changed()
            return
        rows = self.db.list_trash()
        self.trash_table.blockSignals(True)
        self.trash_table.setRowCount(0)
        for entry_id, site, username, deleted_at in rows:
            row_idx = self.trash_table.rowCount()
            self.trash_table.insertRow(row_idx)

            id_item = QTableWidgetItem(f"{entry_id:04d}")
            id_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            id_item.setData(Qt.ItemDataRole.UserRole, entry_id)
            self.trash_table.setItem(row_idx, 0, id_item)

            for c, val in enumerate((site, username), start=1):
                item = QTableWidgetItem(str(val))
                item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
                self.trash_table.setItem(row_idx, c, item)

            days_left = trash_days_left(deleted_at)
            left_text = "Today" if days_left == 0 else f"{days_left} day{'s' if days_left != 1 else ''}"
            left_item = QTableWidgetItem(left_text)
            left_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.trash_table.setItem(row_idx, 3, left_item)

        self.trash_table.blockSignals(False)
        self.on_trash_selection_changed()

    def _current_trash_id(self):
        row = self.trash_table.currentRow()
        if row < 0:
            return None
        item = self.trash_table.item(row, 0)
        if item is None:
            return None
        return item.data(Qt.ItemDataRole.UserRole)

    def on_trash_selection_changed(self):
        has_selection = (
            self.trash_table.currentRow() >= 0 and bool(self.trash_table.selectedItems())
        )
        self.restore_btn.setEnabled(has_selection)
        self.perm_delete_btn.setEnabled(has_selection)
        self.empty_trash_btn.setEnabled(self.trash_table.rowCount() > 0)

    def restore_selected(self):
        entry_id = self._current_trash_id()
        if entry_id is None or self.db is None:
            return
        self.db.restore_entry(entry_id)
        self.refresh_trash()
        self.refresh_table()

    def permanently_delete_selected(self):
        entry_id = self._current_trash_id()
        if entry_id is None or self.db is None:
            return
        row = self.trash_table.currentRow()
        site_item = self.trash_table.item(row, 1)
        site = site_item.text() if site_item else ""
        reply = QMessageBox.question(
            self,
            "Permanently delete",
            f'Permanently delete the entry for "{site}"? This cannot be undone.',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        self.db.permanently_delete_entry(entry_id)
        self.refresh_trash()

    def empty_trash(self):
        if self.db is None or self.trash_table.rowCount() == 0:
            return
        reply = QMessageBox.question(
            self,
            "Empty Trash",
            "Permanently delete ALL entries in the Trash? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        self.db.empty_trash()
        self.refresh_trash()

    def handle_import_backup(self):
        # Close our handle first so the import can overwrite vault.db on Windows.
        if self.db is not None:
            self.db.close()
            self.db = None
        result = import_backup_via_dialog(self)
        if result is None:
            # Nothing was written on cancel/failure; reopen the existing session.
            if self.key is not None:
                self.db = VaultDB(DB_PATH)
                self.refresh_table()
            return
        key, secret = result
        self.set_session(key, secret)

    def reveal_selected(self):
        row = self.table.currentRow()
        if row < 0:
            return
        id_item = self.table.item(row, 0)
        if id_item is None:
            return
        entry_id = id_item.data(Qt.ItemDataRole.UserRole)
        site = self.table.item(row, 1).text()
        username = self.table.item(row, 2).text()
        self.reveal_password(entry_id, site, username)

    def reveal_password(self, entry_id: int, site: str, username: str):
        if not self.totp_secret or not self.key:
            QMessageBox.warning(self, "Locked", "Vault session is not active.")
            return

        dlg = TOTPPromptDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        code = dlg.code()
        if not code:
            QMessageBox.warning(self, "TOTP required", "Please enter your TOTP code.")
            return

        try:
            cfg = Config.from_file(CONFIG_PATH)
        except Exception:
            QMessageBox.critical(self, "Access denied", "Could not load vault config.")
            return

        result, secs = verify_totp_strict(cfg, self.totp_secret, code)
        if result is TotpResult.LOCKED:
            QMessageBox.warning(
                self,
                "Locked out",
                f"Too many failed attempts. Try again in {format_lockout_duration(secs)}.",
            )
            return
        if result is TotpResult.REPLAY:
            QMessageBox.warning(
                self,
                "Code already used",
                "That code has already been used. Wait for your authenticator to show a new code.",
            )
            return
        if result is TotpResult.EXPIRED_OR_INVALID:
            QMessageBox.warning(
                self,
                "Code expired",
                "Code expired or invalid. Enter the current code from your authenticator.",
            )
            return

        meta = self.db.get_entry_meta(entry_id)
        if not meta:
            QMessageBox.warning(self, "Not found", "Entry no longer exists.")
            return

        pw_nonce, pw_ct, created_at, updated_at = meta
        try:
            password = aesgcm_decrypt(
                self.key, pw_nonce, pw_ct, aad=b"vault-entry-v1"
            ).decode("utf-8")
        except Exception:
            QMessageBox.critical(self, "Decrypt failed", "Could not decrypt password.")
            return

        RevealPasswordDialog(
            site, username, password, entry_id, self.key, self.db,
            created_at, updated_at, self
        ).exec()
        # A Save inside the dialog changes the stored password; refresh so the
        # reuse check and next reveal see the new value/age.
        self.refresh_table()

    def on_pw_changed(self):
        pw = self.pw.text()
        if not pw:
            self.str_label.setText("Strength: -")
            self.str_label.setStyleSheet(
                f"color: {CURRENT_PALETTE['strength_neutral']}; font-weight: 600;"
            )
            self.reuse_label.setText("")
            self.add_btn.setEnabled(False)
            self.add_btn.setToolTip("Enter a password to add an entry.")
            return

        strength, _ = password_strength(pw)
        strength_colors = {
            "Weak": CURRENT_PALETTE["strength_weak"],
            "Medium": CURRENT_PALETTE["strength_medium"],
            "Strong": CURRENT_PALETTE["strength_strong"],
        }
        self.str_label.setText(f"Strength: {strength}")
        self.str_label.setStyleSheet(
            f"color: {strength_colors[strength]}; font-weight: 600;"
        )

        is_reuse = False
        if self.key and self.db:
            fp = hmac_sha256(self.key, pw.encode("utf-8"))
            existing = self.db.get_all_fingerprints()
            is_reuse = any(hmac.compare_digest(fp, e) for e in existing)

        if is_reuse:
            self.reuse_label.setText("Warning: password reuse detected")
            self.reuse_label.setStyleSheet(
                f"color: {CURRENT_PALETTE['reuse_warn']}; font-weight: 600;"
            )
        else:
            self.reuse_label.setText("")

        is_weak = strength == "Weak"
        self.add_btn.setEnabled(not is_weak and not is_reuse)
        if is_weak and is_reuse:
            self.add_btn.setToolTip("Password is too weak and already in use.")
        elif is_weak:
            self.add_btn.setToolTip("Password is too weak.")
        elif is_reuse:
            self.add_btn.setToolTip("Password is already used by another entry.")
        else:
            self.add_btn.setToolTip("")

    def add_entry(self):
        site = self.site.text().strip()
        user = self.user.text().strip()
        pw = self.pw.text()

        if not site or not user or not pw:
            QMessageBox.warning(self, "Missing fields", "Please fill in site, username, and password.")
            return

        strength, _ = password_strength(pw)
        if strength == "Weak":
            QMessageBox.warning(self, "Weak password", "Password is too weak. Use a stronger one.")
            return

        fp = hmac_sha256(self.key, pw.encode("utf-8"))
        if any(hmac.compare_digest(fp, e) for e in self.db.get_all_fingerprints()):
            QMessageBox.warning(self, "Password reuse", "This password is already used by another entry.")
            return

        nonce, ct = aesgcm_encrypt(self.key, pw.encode("utf-8"), aad=b"vault-entry-v1")

        self.db.add_entry(site, user, nonce, ct, fp)
        self.site.clear()
        self.user.clear()
        self.pw.clear()
        self.refresh_table()

    def show_reminders(self):
        msg = (
            "Security reminders:\n"
            "1) Use a strong master password.\n"
            "2) Do not reuse passwords across sites.\n"
            "3) Keep your recovery information safe.\n"
            "4) Export an encrypted backup after major changes."
        )
        QMessageBox.information(self, "Reminders", msg)

    def export_backup(self):
        if not os.path.exists(CONFIG_PATH) or not os.path.exists(DB_PATH):
            QMessageBox.warning(self, "Backup error", "Missing config or database.")
            return

        out_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save backup",
            "vault-backup.enc",
            "Encrypted Backup (*.enc)"
        )
        if not out_path:
            return

        cfg = Config.from_file(CONFIG_PATH)

        with open(CONFIG_PATH, "rb") as f:
            cfg_bytes = f.read()
        with open(DB_PATH, "rb") as f:
            db_bytes = f.read()

        bundle = (
            b"VAULTBACKUPv1\n"
            + b64e(cfg_bytes).encode("utf-8")
            + b"\n"
            + b64e(db_bytes).encode("utf-8")
        )

        nonce, ct = aesgcm_encrypt(self.key, bundle, aad=b"backup-v1")

        payload = {
            "salt": b64e(cfg.salt),
            "nonce": b64e(nonce),
            "ct": b64e(ct),
        }

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)

        QMessageBox.information(
            self,
            "Backup created",
            f"Encrypted backup saved:\n{out_path}"
        )


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Offline Password Vault")

        prefs = load_prefs()
        self.current_theme = prefs.get("theme", "light")

        self.stack = QStackedWidget()

        self.setup_screen = SetupScreen(
            on_done=self.goto_unlock,
            on_imported=self.goto_vault,
        )
        self.unlock_screen = UnlockScreen(
            on_unlocked=self.goto_vault,
            on_reset=self.handle_reset_and_relaunch,
        )
        self.vault_screen = VaultScreen(
            on_logout=self.goto_unlock,
            on_toggle_theme=self.toggle_theme,
            on_reset=self.handle_reset_and_relaunch,
            theme=self.current_theme,
        )

        self.stack.addWidget(self.setup_screen)
        self.stack.addWidget(self.unlock_screen)
        self.stack.addWidget(self.vault_screen)

        layout = QVBoxLayout()
        layout.addWidget(self.stack)
        self.setLayout(layout)

        self.apply_theme(self.current_theme)

        if os.path.exists(CONFIG_PATH):
            self.goto_unlock()
        else:
            self.goto_setup()

    def apply_theme(self, theme):
        global CURRENT_PALETTE
        CURRENT_PALETTE = DARK_PALETTE if theme == "dark" else LIGHT_PALETTE
        self.current_theme = theme
        self.setStyleSheet(build_stylesheet(CURRENT_PALETTE))
        # Inline-styled labels don't cascade; re-derive them from the new palette.
        self.vault_screen.refresh_dynamic_colors()
        self.vault_screen.update_theme_button(theme)

    def toggle_theme(self):
        new_theme = "light" if self.current_theme == "dark" else "dark"
        self.apply_theme(new_theme)
        prefs = load_prefs()
        prefs["theme"] = new_theme
        save_prefs(prefs)

    def close_vault_db(self):
        try:
            if self.vault_screen.db is not None:
                self.vault_screen.db.close()
                self.vault_screen.db = None
        except Exception:
            pass

    def handle_reset_and_relaunch(self):
        # Release any live db handle so the files can actually be deleted on
        # Windows, erase everything, then relaunch a clean instance.
        self.close_vault_db()
        ok, msg = reset_vault_files()
        if not ok:
            QMessageBox.critical(self, "Reset failed", msg)
            return
        QMessageBox.information(self, "Vault reset", "Vault deleted. Restarting the app...")
        relaunch_app()

    def goto_unlock(self):
        self.unlock_screen.clear_inputs()
        self.stack.setCurrentWidget(self.unlock_screen)
        fade_in_widget(self.unlock_screen)

    def goto_setup(self):
        self.stack.setCurrentWidget(self.setup_screen)
        fade_in_widget(self.setup_screen)

    def goto_vault(self, key: bytes, totp_secret: str):
        self.vault_screen.set_session(key, totp_secret)
        self.stack.setCurrentWidget(self.vault_screen)
        fade_in_widget(self.vault_screen)

def demo_insecure_hash():
    password = "MyPassword123"
    return hashlib.md5(password.encode()).hexdigest()

def main():
    app = QApplication([])
    w = MainWindow()
    w.resize(1000, 560)
    w.setWindowOpacity(0.0)
    w.show()
    fade_in_window(w, duration=320)
    app.exec()


if __name__ == "__main__":
    main()
