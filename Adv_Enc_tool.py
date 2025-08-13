import os
import streamlit as st
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64

# Constants
CHUNK_SIZE = 64 * 1024  # 64KB chunks
SALT_SIZE = 16
KEY_SIZE = 32  # AES-256
IV_SIZE = 16
PBKDF2_ITERATIONS = 100000

# Session state for history
if "history" not in st.session_state:
    st.session_state.history = []

def derive_key(password, salt):
    """Generate AES key from password using PBKDF2"""
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)

def encrypt_file(input_file, password):
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    output_file = input_file.name + ".enc"
    with open(output_file, "wb") as f_out:
        f_out.write(salt)
        f_out.write(iv)

        while chunk := input_file.read(CHUNK_SIZE):
            if len(chunk) % AES.block_size != 0:
                chunk += b' ' * (AES.block_size - len(chunk) % AES.block_size)
            encrypted_chunk = cipher.encrypt(chunk)
            f_out.write(encrypted_chunk)

    return output_file

def decrypt_file(input_file, password):
    salt = input_file.read(SALT_SIZE)
    iv = input_file.read(IV_SIZE)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    output_file = input_file.name.replace(".enc", "") + "_decrypted"
    with open(output_file, "wb") as f_out:
        while chunk := input_file.read(CHUNK_SIZE):
            decrypted_chunk = cipher.decrypt(chunk)
            f_out.write(decrypted_chunk.rstrip(b' '))

    return output_file

# Streamlit UI
st.title("🔐 Advanced AES-256 Encryption Tool")
st.write("Securely encrypt and decrypt large files with AES-256 and salted keys.")

mode = st.radio("Choose Mode", ["Encrypt", "Decrypt"])
password = st.text_input("Enter Password", type="password")
uploaded_file = st.file_uploader("Upload File", type=None)

if st.button("Run") and uploaded_file and password:
    with open("temp_input", "wb") as f:
        f.write(uploaded_file.read())

    with open("temp_input", "rb") as f:
        if mode == "Encrypt":
            output_path = encrypt_file(f, password)
            st.success(f"File encrypted: {output_path}")
            with open(output_path, "rb") as f_out:
                st.download_button("Download Encrypted File", f_out, file_name=os.path.basename(output_path))
            st.session_state.history.append({"action": "Encrypt", "file": uploaded_file.name})
        else:
            output_path = decrypt_file(f, password)
            st.success(f"File decrypted: {output_path}")
            with open(output_path, "rb") as f_out:
                st.download_button("Download Decrypted File", f_out, file_name=os.path.basename(output_path))
            st.session_state.history.append({"action": "Decrypt", "file": uploaded_file.name})

# Show History
if st.session_state.history:
    st.subheader("📜 Operation History")
    for item in st.session_state.history:
        st.write(f"**{item['action']}** - {item['file']}")
