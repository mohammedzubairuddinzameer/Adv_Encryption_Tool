# AES-256 Encryption Web App using Streamlit (1GB Support + History)
import streamlit as st
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import os
import json
import datetime

# Constants
KEY_LEN = 32
SALT_LEN = 16
IV_LEN = 16
ITERATIONS = 100000
HISTORY_FILE = "history.json"
CHUNK_SIZE = 1024 * 1024 * 10  # 10MB chunks for large files

# --- Utility Functions ---
def load_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    return []

def save_history(history):
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=4)

def add_to_history(action, filename, size):
    history = load_history()
    history.append({
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "filename": filename,
        "size_MB": round(size / (1024 * 1024), 2)
    })
    save_history(history)

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=KEY_LEN, count=ITERATIONS)

def encrypt_file(file_path, password, output_path):
    salt = get_random_bytes(SALT_LEN)
    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CFB)
    with open(file_path, "rb") as f_in, open(output_path, "wb") as f_out:
        f_out.write(salt + cipher.iv)  # Store salt + IV at start
        while chunk := f_in.read(CHUNK_SIZE):
            f_out.write(cipher.encrypt(chunk))

def decrypt_file(file_path, password, output_path):
    with open(file_path, "rb") as f_in:
        salt = f_in.read(SALT_LEN)
        iv = f_in.read(IV_LEN)
        key = derive_key(password.encode(), salt)
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        with open(output_path, "wb") as f_out:
            while chunk := f_in.read(CHUNK_SIZE):
                f_out.write(cipher.decrypt(chunk))

# --- Streamlit UI ---
st.set_page_config(page_title="🔐 AES-256 File Encryption Tool", layout="centered")
st.title("🔐 AES-256 File Encryption Tool (1GB Support + History)")

option = st.radio("Choose an operation:", ["Encrypt", "Decrypt"])
password = st.text_input("Enter a password:", type="password")
uploaded_file = st.file_uploader("Upload a file (max 1GB)", type=None)

if uploaded_file and password:
    temp_input_path = os.path.join("temp_input_" + uploaded_file.name)
    with open(temp_input_path, "wb") as f:
        f.write(uploaded_file.read())

    temp_output_path = "output_" + uploaded_file.name
    file_size = os.path.getsize(temp_input_path)

    if option == "Encrypt":
        encrypt_file(temp_input_path, password, temp_output_path)
        st.success("✅ File encrypted successfully!")
        with open(temp_output_path, "rb") as f:
            st.download_button("Download Encrypted File", data=f, file_name=uploaded_file.name + ".enc")
        add_to_history("Encrypt", uploaded_file.name, file_size)

    elif option == "Decrypt":
        try:
            decrypt_file(temp_input_path, password, temp_output_path)
            st.success("✅ File decrypted successfully!")
            with open(temp_output_path, "rb") as f:
                st.download_button("Download Decrypted File", data=f, file_name="decrypted_" + uploaded_file.name)
            add_to_history("Decrypt", uploaded_file.name, file_size)
        except Exception as e:
            st.error(f"❌ Decryption failed: {str(e)}")

# --- Show History ---
st.markdown("### 📜 Operation History")
history = load_history()
if history:
    st.table(history)
else:
    st.info("No history found yet.")

# Cleanup temp files
for file in [temp_input_path, temp_output_path]:
    if os.path.exists(file):
        os.remove(file)
