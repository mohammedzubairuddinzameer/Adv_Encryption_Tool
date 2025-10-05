# Features:
# - Streamlit-based Login / Signup (local JSON user store, passwords hashed)
# - Encrypt / Decrypt files using AES-256 (CBC) with PBKDF2-derived key
# - Keeps encrypted filename as <original_name>.enc and decrypted as <original_name>.dec
# - Simple UX with logo, file-type icon, operation history
# - Safe handling of uploaded files using a temp folder

import streamlit as st
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import os
import json
import hashlib
import tempfile
from pathlib import Path
import base64

# --- Config ---
USERS_FILE = "users.json"
CHUNK_SIZE = 64 * 1024
SALT_SIZE = 16
KEY_SIZE = 32  # AES-256
IV_SIZE = 16
PBKDF2_ITERATIONS = 100000

# Ensure users file exists
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, "w") as f:
        json.dump({}, f)

# --- Utilities for user management ---
def hash_password(password: str, salt: bytes = None):
    if salt is None:
        salt = get_random_bytes(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200000)
    return salt.hex() + ":" + hashed.hex()

def verify_password(stored: str, provided_password: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split(":")
        salt = bytes.fromhex(salt_hex)
        check = hashlib.pbkdf2_hmac("sha256", provided_password.encode(), salt, 200000).hex()
        return check == hash_hex
    except Exception:
        return False

def load_users():
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

# --- Key derivation and AES helpers ---
def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)

def encrypt_bytes(data_bytes: bytes, password: str) -> bytes:
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # pad to block size
    pad_len = (AES.block_size - len(data_bytes) % AES.block_size) or AES.block_size
    data_bytes_padded = data_bytes + bytes([pad_len]) * pad_len

    ciphertext = cipher.encrypt(data_bytes_padded)
    return salt + iv + ciphertext

def decrypt_bytes(enc_bytes: bytes, password: str) -> bytes:
    salt = enc_bytes[:SALT_SIZE]
    iv = enc_bytes[SALT_SIZE:SALT_SIZE+IV_SIZE]
    ciphertext = enc_bytes[SALT_SIZE+IV_SIZE:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    pad_len = decrypted_padded[-1]
    if pad_len < 1 or pad_len > AES.block_size:
        # invalid padding
        raise ValueError("Invalid password or corrupted file (bad padding).")
    return decrypted_padded[:-pad_len]

# --- Small helper to map extension to emoji/icon ---
EXT_ICON = {
    ".pdf": "📄 PDF",
    ".ppt": "📊 PPT",
    ".pptx": "📊 PPTX",
    ".doc": "📄 DOC",
    ".docx": "📄 DOCX",
    ".xls": "📈 XLS",
    ".xlsx": "📈 XLSX",
    ".txt": "📄 TXT",
    ".py": "🐍 PY",
    ".zip": "🗜️ ZIP",
}

def file_icon_for_name(name: str) -> str:
    ext = Path(name).suffix.lower()
    return EXT_ICON.get(ext, "📁 File")

# --- Session state defaults ---
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = None
if "history" not in st.session_state:
    st.session_state.history = []

# --- Authentication UI ---
st.set_page_config(page_title="Advanced Encryption Tool", layout="centered")

# Top logo (you can place a local image named 'logo.png' next to this script)
st.markdown(
    """
    <div style="text-align: center;">
        <img src="https://raw.githubusercontent.com/mohammedzubairuddinzameer/Adv_Encryption_Tool/main/logo.png" width="150">
        <h2>🔐 Advanced Encryption Tool</h2>
    </div>
    """,
    unsafe_allow_html=True
)



with st.expander("Login / Signup", expanded=not st.session_state.logged_in):
    cols = st.columns(2)
    with cols[0]:
        st.subheader("Login")
        login_username = st.text_input("Username", key="login_user")
        login_password = st.text_input("Password", type="password", key="login_pass")
        if st.button("Login"):
            users = load_users()
            if login_username in users and verify_password(users[login_username]["password"], login_password):
                st.success("Logged in successfully")
                st.session_state.logged_in = True
                st.session_state.username = login_username
            else:
                st.error("Invalid username or password")
    with cols[1]:
        st.subheader("Sign Up")
        signup_username = st.text_input("Choose a username", key="signup_user")
        signup_password = st.text_input("Choose a password", type="password", key="signup_pass")
        signup_fullname = st.text_input("Full name (optional)", key="signup_full")
        if st.button("Sign Up"):
            users = load_users()
            if not signup_username:
                st.error("Enter a username")
            elif signup_username in users:
                st.error("Username already exists")
            elif not signup_password or len(signup_password) < 6:
                st.error("Choose a password at least 6 characters long")
            else:
                users[signup_username] = {"password": hash_password(signup_password), "full_name": signup_fullname}
                save_users(users)
                st.success("User registered — you can now log in")

# If not logged in, don't show the rest
if not st.session_state.logged_in:
    st.info("Please log in or sign up to use the encryption tool")
    st.stop()

# Main app UI after login
if st.sidebar.button("Logout"):
    st.session_state.logged_in = False
    st.session_state.username = None
    st.rerun()


st.header("File Encrypt / Decrypt")
mode = st.radio("Mode", ["Encrypt", "Decrypt"]) 
password = st.text_input("Enter password (for key derivation)", type="password")
uploaded_file = st.file_uploader("Upload a file", type=None)

if uploaded_file is not None:
    st.write(f"**File:** {uploaded_file.name} — {file_icon_for_name(uploaded_file.name)}")

col1, col2 = st.columns([1,3])
with col1:
    if st.button("Run"):
    if not uploaded_file:
        st.error("Please upload a file first")
    elif not password:
        st.error("Enter the password for encryption/decryption")
    else:
        # Save uploaded to a temp file to avoid memory issues
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(uploaded_file.read())
            tmp_path = tmp.name

        original_name = uploaded_file.name
        try:
            if mode == "Encrypt":
                # Read file and encrypt
                with open(tmp_path, "rb") as f:
                    data = f.read()
                enc_bytes = encrypt_bytes(data, password)

                # Encrypted filename keeps original name + .enc
                out_name = original_name + ".enc"
                with open(out_name, "wb") as f_out:
                    f_out.write(enc_bytes)

                st.success(f"Encrypted: {out_name}")

                # Download button with correct MIME type
                with open(out_name, "rb") as f_out:
                    st.download_button(
                        "Download Encrypted File",
                        data=f_out,
                        file_name=out_name,
                        mime="application/octet-stream"
                    )

                st.session_state.history.append({"action": "Encrypt", "file": original_name})

            else:  # Decrypt
                with open(tmp_path, "rb") as f:
                    enc_bytes = f.read()
                try:
                    dec_bytes = decrypt_bytes(enc_bytes, password)
                except Exception as e:
                    st.error(f"Decryption failed: {e}")
                    os.unlink(tmp_path)
                    st.stop()

                # Restore original extension
                if original_name.lower().endswith(".enc"):
                    base = original_name[:-4]  # remove .enc
                else:
                    base = original_name

                # Create mobile-friendly decrypted filename
                name_part = Path(base).stem
                ext_part = Path(base).suffix
                out_name = f"{name_part}_decrypted{ext_part}"

                with open(out_name, "wb") as f_out:
                    f_out.write(dec_bytes)

                st.success(f"Decrypted: {out_name}")

                # Set MIME type for mobile compatibility
                mime_type = "application/octet-stream"
                ext = ext_part.lower()
                if ext == ".pdf":
                    mime_type = "application/pdf"
                elif ext in [".txt", ".log"]:
                    mime_type = "text/plain"
                elif ext in [".jpg", ".jpeg"]:
                    mime_type = "image/jpeg"
                elif ext == ".png":
                    mime_type = "image/png"
                elif ext in [".mp4", ".mov"]:
                    mime_type = "video/mp4"

                with open(out_name, "rb") as f_out:
                    st.download_button(
                        "Download Decrypted File",
                        data=f_out,
                        file_name=out_name,
                        mime=mime_type
                    )

                st.session_state.history.append({"action": "Decrypt", "file": original_name})

        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

with col2:
    st.markdown("**Notes**")
    st.write("- Encrypted files are saved as <original_filename>.enc")
    st.write("- Decrypted output files are saved as <original_filename>.dec")
    st.write("- Keep your password safe. We derive keys with PBKDF2 and AES-256 CBC mode.")

# Operation history
if st.session_state.history:
    st.subheader("Operation history")
    for i, h in enumerate(reversed(st.session_state.history[-20:]), start=1):
        st.write(f"{i}. **{h['action']}** - {h['file']}")

# Footer / credits
st.markdown("---")
st.caption("Built with Streamlit. For production use, replace local JSON auth with a secure backend (Supabase, Firebase, or OAuth)."), "w") as f:
        json.dump({}, f)

# --- Utilities for user management ---
def hash_password(password: str, salt: bytes = None):
    if salt is None:
        salt = get_random_bytes(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200000)
    return salt.hex() + ":" + hashed.hex()

def verify_password(stored: str, provided_password: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split(":")
        salt = bytes.fromhex(salt_hex)
        check = hashlib.pbkdf2_hmac("sha256", provided_password.encode(), salt, 200000).hex()
        return check == hash_hex
    except Exception:
        return False

def load_users():
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

# --- Key derivation and AES helpers ---
def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)

def encrypt_bytes(data_bytes: bytes, password: str) -> bytes:
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # pad to block size
    pad_len = (AES.block_size - len(data_bytes) % AES.block_size) or AES.block_size
    data_bytes_padded = data_bytes + bytes([pad_len]) * pad_len

    ciphertext = cipher.encrypt(data_bytes_padded)
    return salt + iv + ciphertext

def decrypt_bytes(enc_bytes: bytes, password: str) -> bytes:
    salt = enc_bytes[:SALT_SIZE]
    iv = enc_bytes[SALT_SIZE:SALT_SIZE+IV_SIZE]
    ciphertext = enc_bytes[SALT_SIZE+IV_SIZE:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    pad_len = decrypted_padded[-1]
    if pad_len < 1 or pad_len > AES.block_size:
        # invalid padding
        raise ValueError("Invalid password or corrupted file (bad padding).")
    return decrypted_padded[:-pad_len]

# --- Small helper to map extension to emoji/icon ---
EXT_ICON = {
    ".pdf": "📄 PDF",
    ".ppt": "📊 PPT",
    ".pptx": "📊 PPTX",
    ".doc": "📄 DOC",
    ".docx": "📄 DOCX",
    ".xls": "📈 XLS",
    ".xlsx": "📈 XLSX",
    ".txt": "📄 TXT",
    ".py": "🐍 PY",
    ".zip": "🗜️ ZIP",
}

def file_icon_for_name(name: str) -> str:
    ext = Path(name).suffix.lower()
    return EXT_ICON.get(ext, "📁 File")

# --- Session state defaults ---
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = None
if "history" not in st.session_state:
    st.session_state.history = []

# --- Authentication UI ---
st.set_page_config(page_title="Advanced Encryption Tool", layout="centered")

# Top logo (you can place a local image named 'logo.png' next to this script)
st.markdown(
    """
    <div style="text-align: center;">
        <img src="https://raw.githubusercontent.com/mohammedzubairuddinzameer/Adv_Encryption_Tool/main/logo.png" width="150">
        <h2>🔐 Advanced Encryption Tool</h2>
    </div>
    """,
    unsafe_allow_html=True
)



with st.expander("Login / Signup", expanded=not st.session_state.logged_in):
    cols = st.columns(2)
    with cols[0]:
        st.subheader("Login")
        login_username = st.text_input("Username", key="login_user")
        login_password = st.text_input("Password", type="password", key="login_pass")
        if st.button("Login"):
            users = load_users()
            if login_username in users and verify_password(users[login_username]["password"], login_password):
                st.success("Logged in successfully")
                st.session_state.logged_in = True
                st.session_state.username = login_username
            else:
                st.error("Invalid username or password")
    with cols[1]:
        st.subheader("Sign Up")
        signup_username = st.text_input("Choose a username", key="signup_user")
        signup_password = st.text_input("Choose a password", type="password", key="signup_pass")
        signup_fullname = st.text_input("Full name (optional)", key="signup_full")
        if st.button("Sign Up"):
            users = load_users()
            if not signup_username:
                st.error("Enter a username")
            elif signup_username in users:
                st.error("Username already exists")
            elif not signup_password or len(signup_password) < 6:
                st.error("Choose a password at least 6 characters long")
            else:
                users[signup_username] = {"password": hash_password(signup_password), "full_name": signup_fullname}
                save_users(users)
                st.success("User registered — you can now log in")

# If not logged in, don't show the rest
if not st.session_state.logged_in:
    st.info("Please log in or sign up to use the encryption tool")
    st.stop()

# Main app UI after login
if st.sidebar.button("Logout"):
    st.session_state.logged_in = False
    st.session_state.username = None
    st.rerun()


st.header("File Encrypt / Decrypt")
mode = st.radio("Mode", ["Encrypt", "Decrypt"]) 
password = st.text_input("Enter password (for key derivation)", type="password")
uploaded_file = st.file_uploader("Upload a file", type=None)

if uploaded_file is not None:
    st.write(f"**File:** {uploaded_file.name} — {file_icon_for_name(uploaded_file.name)}")

col1, col2 = st.columns([1,3])
with col1:
    if st.button("Run"):
        if not uploaded_file:
            st.error("Please upload a file first")
        elif not password:
            st.error("Enter the password for encryption/decryption")
        else:
            # Save uploaded to a temp file to avoid memory issues
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(uploaded_file.read())
                tmp_path = tmp.name

            original_name = uploaded_file.name
            try:
                if mode == "Encrypt":
                    with open(tmp_path, "rb") as f:
                        data = f.read()
                    enc_bytes = encrypt_bytes(data, password)
                    out_name = original_name + ".enc"
                    with open(out_name, "wb") as f_out:
                        f_out.write(enc_bytes)
                    st.success(f"Encrypted: {out_name}")
                    with open(out_name, "rb") as f_out:
                        st.download_button("Download Encrypted File", f_out, file_name=out_name)
                    st.session_state.history.append({"action":"Encrypt","file":original_name})
                else:  # Decrypt
                    with open(tmp_path, "rb") as f:
                        enc_bytes = f.read()
                    try:
                        dec_bytes = decrypt_bytes(enc_bytes, password)
                    except Exception as e:
                        st.error(f"Decryption failed: {e}")
                        os.unlink(tmp_path)
                        st.stop()
                    # produce .dec filename
                    if original_name.lower().endswith(".enc"):
                        base = original_name[:-4]
                    else:
                        base = original_name
                    out_name = base + ".dec"
                    with open(out_name, "wb") as f_out:
                        f_out.write(dec_bytes)
                    st.success(f"Decrypted: {out_name}")
                    with open(out_name, "rb") as f_out:
                        st.download_button("Download Decrypted File", f_out, file_name=out_name)
                    st.session_state.history.append({"action":"Decrypt","file":original_name})
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
with col2:
    st.markdown("**Notes**")
    st.write("- Encrypted files are saved as <original_filename>.enc")
    st.write("- Decrypted output files are saved as <original_filename>.dec")
    st.write("- Keep your password safe. We derive keys with PBKDF2 and AES-256 CBC mode.")

# Operation history
if st.session_state.history:
    st.subheader("Operation history")
    for i, h in enumerate(reversed(st.session_state.history[-20:]), start=1):
        st.write(f"{i}. **{h['action']}** - {h['file']}")

# Footer / credits
st.markdown("---")
st.caption("Built with Streamlit. For production use, replace local JSON auth with a secure backend (Supabase, Firebase, or OAuth).")
