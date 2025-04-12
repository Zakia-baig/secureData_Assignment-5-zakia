import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json
import os
from datetime import datetime, timedelta

# Initialize session state
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = {}
if 'locked_out' not in st.session_state:
    st.session_state.locked_out = {}
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'auth_page' not in st.session_state:
    st.session_state.auth_page = False

# Generate or load encryption key
def get_encryption_key():
    if 'encryption_key' not in st.session_state:
        # In a real application, this should be stored securely
        st.session_state.encryption_key = Fernet.generate_key()
    return st.session_state.encryption_key

# Hash function using SHA-256
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt data
def encrypt_data(data, passkey):
    cipher_suite = Fernet(get_encryption_key())
    encrypted_data = cipher_suite.encrypt(data.encode())
    return encrypted_data

# Decrypt data
def decrypt_data(encrypted_data, passkey):
    cipher_suite = Fernet(get_encryption_key())
    decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
    return decrypted_data

# Check if user is locked out
def is_locked_out(username):
    if username in st.session_state.locked_out:
        lock_time = st.session_state.locked_out[username]
        if datetime.now() < lock_time:
            return True
        else:
            del st.session_state.locked_out[username]
            st.session_state.failed_attempts[username] = 0
    return False

# Authentication page
def auth_page():
    st.title("🔒 Reauthorization Required")
    st.warning("Too many failed attempts. Please authenticate to continue.")
    
    username = st.text_input("Enter your username")
    auth_passkey = st.text_input("Enter your authentication passkey", type="password")
    
    if st.button("Authenticate"):
        if username in st.session_state.stored_data:
            hashed_auth = hash_passkey(auth_passkey)
            stored_hash = st.session_state.stored_data[username]["passkey"]
            
            if hashed_auth == stored_hash:
                st.session_state.failed_attempts[username] = 0
                st.session_state.auth_page = False
                st.session_state.current_user = username
                st.rerun()
            else:
                st.error("Authentication failed. Please try again.")
        else:
            st.error("Username not found.")

# Store data page
def store_data_page():
    st.title("💾 Store New Data")
    
    username = st.text_input("Choose a username")
    data = st.text_area("Enter data to store securely")
    passkey = st.text_input("Create a passkey", type="password")
    confirm_passkey = st.text_input("Confirm passkey", type="password")
    
    if st.button("Store Data Securely"):
        if not username or not data or not passkey:
            st.error("All fields are required!")
        elif passkey != confirm_passkey:
            st.error("Passkeys do not match!")
        elif username in st.session_state.stored_data:
            st.error("Username already exists. Choose a different one.")
        else:
            # Hash the passkey
            hashed_passkey = hash_passkey(passkey)
            
            # Encrypt the data
            encrypted_data = encrypt_data(data, passkey)
            
            # Store in memory
            st.session_state.stored_data[username] = {
                "encrypted_text": encrypted_data,
                "passkey": hashed_passkey
            }
            
            st.success("Data stored securely! You can now retrieve it with your passkey.")

# Retrieve data page
def retrieve_data_page():
    st.title("🔍 Retrieve Stored Data")
    
    username = st.text_input("Enter your username")
    
    if username:
        if username not in st.session_state.stored_data:
            st.error("Username not found.")
            return
        
        if is_locked_out(username):
            lock_time = st.session_state.locked_out[username]
            remaining_time = (lock_time - datetime.now()).seconds
            st.error(f"Account locked due to too many failed attempts. Please try again in {remaining_time} seconds.")
            st.session_state.auth_page = True
            st.rerun()
            return
        
        passkey = st.text_input("Enter your passkey", type="password")
        
        if st.button("Retrieve Data"):
            stored_data = st.session_state.stored_data[username]
            hashed_input = hash_passkey(passkey)
            
            if hashed_input == stored_data["passkey"]:
                # Reset failed attempts on success
                if username in st.session_state.failed_attempts:
                    del st.session_state.failed_attempts[username]
                
                # Decrypt and display data
                decrypted_data = decrypt_data(stored_data["encrypted_text"], passkey)
                st.success("Data retrieved successfully!")
                st.text_area("Your secure data", value=decrypted_data, height=200)
            else:
                # Increment failed attempts
                if username not in st.session_state.failed_attempts:
                    st.session_state.failed_attempts[username] = 0
                st.session_state.failed_attempts[username] += 1
                
                remaining_attempts = 3 - st.session_state.failed_attempts[username]
                
                if remaining_attempts > 0:
                    st.error(f"Incorrect passkey! {remaining_attempts} attempts remaining.")
                else:
                    # Lock the account for 5 minutes
                    st.session_state.locked_out[username] = datetime.now() + timedelta(minutes=5)
                    st.error("Too many failed attempts. Account locked for 5 minutes.")
                    st.session_state.auth_page = True
                    st.rerun()

# Main app
def main():
    st.sidebar.title("Secure Data Encryption System")
    
    if st.session_state.auth_page:
        auth_page()
        return
    
    if st.session_state.current_user:
        st.sidebar.success(f"Logged in as: {st.session_state.current_user}")
        if st.sidebar.button("Logout"):
            st.session_state.current_user = None
            st.rerun()
    
    menu_options = ["Home", "Store Data", "Retrieve Data"]
    choice = st.sidebar.selectbox("Menu", menu_options)
    
    if choice == "Home":
        st.title("🏠 Secure Data Encryption System")
        st.write("""
        Welcome to the Secure Data Encryption System!
        
        ### Features:
        - Store sensitive data securely with encryption
        - Retrieve data only with the correct passkey
        - Protection against brute force attacks
        - No external database - everything stays in memory
        
        ### How to use:
        1. **Store Data**: Choose a username, enter your data, and set a passkey
        2. **Retrieve Data**: Provide your username and passkey to access your data
        """)
        
        if st.session_state.stored_data:
            st.info(f"System currently storing data for {len(st.session_state.stored_data)} user(s)")
        
    elif choice == "Store Data":
        if not st.session_state.current_user:
            store_data_page()
        else:
            st.warning("You are already logged in. Logout to store data as a different user.")
    
    elif choice == "Retrieve Data":
        if not st.session_state.current_user:
            retrieve_data_page()
        else:
            # If already logged in, show the data directly
            stored_data = st.session_state.stored_data[st.session_state.current_user]
            passkey = st.text_input("Enter your passkey", type="password")
            
            if st.button("Retrieve Data"):
                hashed_input = hash_passkey(passkey)
                
                if hashed_input == stored_data["passkey"]:
                    decrypted_data = decrypt_data(stored_data["encrypted_text"], passkey)
                    st.success("Data retrieved successfully!")
                    st.text_area("Your secure data", value=decrypted_data, height=200)
                else:
                    st.error("Incorrect passkey!")

if __name__ == "__main__":
    main()