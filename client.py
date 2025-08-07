import socket
import threading
import json
import base64
import os
import time
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
from tkinter import ttk # Import ttk for themed widgets

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- Cryptographic Functions (copied from previous demo, with deserialize_private_key added) ---
def generate_rsa_key_pair():
    """Generates an RSA public and private key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048, # 2048-bit key size
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_rsa_keys(private_key, public_key):
    """Serializes RSA keys to PEM format (for storage/exchange)."""
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() # For demonstration, no encryption
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def deserialize_public_key(public_pem):
    """Deserializes RSA public key from PEM format."""
    return serialization.load_pem_public_key(
        public_pem,
        backend=default_backend()
    )

def deserialize_private_key(private_pem):
    """Deserializes RSA private key from PEM format."""
    return serialization.load_pem_private_key(
        private_pem,
        password=None,
        backend=default_backend()
    )

def rsa_encrypt(public_key, plaintext):
    """Encrypts data using RSA public key (OAEP padding)."""
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(private_key, ciphertext):
    """Decrypts data using RSA private key (OAEP padding)."""
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def generate_aes_key():
    """Generates a random AES-256 key."""
    return os.urandom(32) # 32 bytes = 256 bits

def aes_encrypt(key, plaintext):
    """Encrypts data using AES-256 in GCM mode."""
    iv = os.urandom(12) # GCM recommends 12-byte IV
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag # Authentication tag for GCM
    return iv, ciphertext, tag

def aes_decrypt(key, iv, ciphertext, tag):
    """Decrypts data using AES-256 in GCM mode."""
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

# --- Client Logic ---
HOST = '13.127.182.89'  # <--- THIS MUST BE YOUR SERVER'S PUBLIC IP ADDRESS
PORT = 65432        # The same port the server is listening on

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
username = ""
private_key = None
public_key = None
private_pem = None
public_pem = None
is_connected = False

# Store other users' public keys and shared AES keys
other_users_public_keys = {} # {username: public_key_object}
chat_aes_keys = {} # {target_username: aes_key_object}

# GUI Elements (global references for updating from threads)
root = None
chat_history_text = None
message_entry = None
recipient_entry = None
status_label = None
send_button = None
list_users_button = None

def update_chat_history(message):
    """Safely updates the chat history text widget from any thread."""
    if chat_history_text:
        chat_history_text.config(state='normal')
        chat_history_text.insert(tk.END, message + '\n')
        chat_history_text.config(state='disabled')
        chat_history_text.yview(tk.END) # Scroll to bottom

def update_status_label(message, color):
    """Safely updates the status label text and color."""
    if status_label:
        status_label.config(text=message, foreground=color)
        root.update_idletasks() # Force a GUI refresh

def set_connection_status(connected):
    """Updates the connection status and enables/disables widgets."""
    global is_connected
    is_connected = connected
    if connected:
        update_status_label("Connected", '#98c379')
        send_button.config(state='normal')
        list_users_button.config(state='normal')
        message_entry.config(state='normal')
        recipient_entry.config(state='normal')
    else:
        update_status_label("Disconnected", '#e06c75')
        send_button.config(state='disabled')
        list_users_button.config(state='disabled')
        message_entry.config(state='disabled')
        recipient_entry.config(state='disabled')

def send_message_to_server(recipient, message_text, is_key_exchange=False):
    """Sends a message payload to the server."""
    if not is_connected:
        update_chat_history("Error: Not connected to the server.")
        return

    if not recipient or not message_text:
        update_chat_history("Error: Recipient and message cannot be empty.")
        return

    if recipient not in other_users_public_keys and not is_key_exchange:
        update_chat_history(f"Error: Public key for '{recipient}' not available. Cannot establish secure chat.")
        return

    if is_key_exchange:
        encrypted_data = base64.b64decode(message_text)
        iv = b'' # IV not applicable for RSA key exchange
        tag = b'' # Tag not applicable for RSA key exchange
    else:
        if recipient not in chat_aes_keys:
            update_chat_history(f"Error: AES key not established with '{recipient}'. Initiating key exchange...")
            initiate_key_exchange(recipient)
            # Give a moment for key exchange to process, this is a simplification
            time.sleep(1)
            if recipient not in chat_aes_keys:
                update_chat_history("Key exchange failed. Cannot send message.")
                return

        aes_key = chat_aes_keys[recipient]
        try:
            iv, ciphertext, tag = aes_encrypt(aes_key, message_text.encode('utf-8'))
            encrypted_data = ciphertext
        except Exception as e:
            update_chat_history(f"Encryption failed: {e}")
            return

    message_payload = {
        "sender": username,
        "recipient": recipient,
        "encrypted_message": base64.b64encode(encrypted_data).decode('utf-8'),
        "iv": base64.b64encode(iv).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
        "is_key_exchange": is_key_exchange
    }
    try:
        client_socket.sendall(json.dumps(message_payload).encode('utf-8'))
        if not is_key_exchange:
            update_chat_history(f"[You to {recipient}]: {message_text}")
    except Exception as e:
        update_chat_history(f"Failed to send message: {e}")

def initiate_key_exchange(target_username):
    """Generates an AES key and encrypts it with the target's RSA public key."""
    if target_username not in other_users_public_keys:
        update_chat_history(f"Error: Cannot initiate key exchange. Public key for '{target_username}' not known.")
        return

    new_aes_key = generate_aes_key()
    chat_aes_keys[target_username] = new_aes_key
    update_chat_history(f"[SECURE] Generated new AES key for chat with {target_username}.")

    target_public_key = other_users_public_keys[target_username]
    encrypted_aes_key = rsa_encrypt(target_public_key, new_aes_key)

    update_chat_history(f"Sending encrypted AES key to {target_username}...")
    send_message_to_server(target_username, base64.b64encode(encrypted_aes_key).decode('utf-8'), is_key_exchange=True)

def receive_messages():
    global private_key # Ensure private_key is accessible
    while True:
        try:
            data_json = client_socket.recv(4096).decode('utf-8')
            if not data_json:
                update_chat_history("Server disconnected.")
                set_connection_status(False)
                break

            message_obj = json.loads(data_json)

            if message_obj.get("type") == "user_list":
                users_info = message_obj['users']
                active_users_str = "\n--- Active Users ---\n"
                if not users_info:
                    active_users_str += "No other users found.\n"
                else:
                    for user_info in users_info:
                        uname = user_info['username']
                        if uname != username:
                            active_users_str += f"- {uname}\n"
                            other_users_public_keys[uname] = deserialize_public_key(user_info['public_key_pem'].encode('utf-8'))
                active_users_str += "--------------------"
                update_chat_history(active_users_str)
            elif message_obj.get("status") == "error":
                update_chat_history(f"Server Error: {message_obj['message']}")
            else:
                sender = message_obj['sender']
                encrypted_message_b64 = message_obj['encrypted_message']
                iv_b64 = message_obj['iv']
                tag_b64 = message_obj['tag']
                is_key_exchange = message_obj.get('is_key_exchange', False)

                if is_key_exchange:
                    encrypted_aes_key_bytes = base64.b64decode(encrypted_message_b64)
                    try:
                        decrypted_aes_key = rsa_decrypt(private_key, encrypted_aes_key_bytes)
                        chat_aes_keys[sender] = decrypted_aes_key
                        update_chat_history(f"[SECURE] AES key established with {sender}.")
                    except Exception as e:
                        update_chat_history(f"[ERROR] Failed to decrypt AES key from {sender}: {e}")
                else:
                    if sender not in chat_aes_keys:
                        update_chat_history(f"[ERROR] No AES key for chat with {sender}. Cannot decrypt message.")
                        update_chat_history(f"[{sender}]: [Encrypted Message - Key Missing]")
                        continue

                    aes_key = chat_aes_keys[sender]
                    iv = base64.b64decode(iv_b64)
                    ciphertext = base64.b64decode(encrypted_message_b64)
                    tag = base64.b64decode(tag_b64)

                    try:
                        decrypted_text = aes_decrypt(aes_key, iv, ciphertext, tag).decode('utf-8')
                        update_chat_history(f"[{sender}]: {decrypted_text}")
                    except Exception as e:
                        update_chat_history(f"[ERROR] Decryption failed for message from {sender}: {e}")
                        update_chat_history(f"[{sender}]: [Encrypted Message - Decryption Failed]")

        except json.JSONDecodeError:
            update_chat_history("Received invalid JSON from server.")
        except ConnectionResetError:
            update_chat_history("Server closed the connection.")
            set_connection_status(False)
            break
        except Exception as e:
            update_chat_history(f"An error occurred while receiving: {e}")
            set_connection_status(False)
            break

def send_message_gui():
    """Called when the send button is pressed."""
    recipient = recipient_entry.get().strip()
    message_text = message_entry.get().strip()
    if message_text:
        send_message_to_server(recipient, message_text)
        message_entry.delete(0, tk.END) # Clear the message entry field
    else:
        messagebox.showwarning("Empty Message", "Message cannot be empty.")

def list_users_gui():
    """Displays known active users in the chat history."""
    update_chat_history("\n--- Known Users ---")
    if not other_users_public_keys:
        update_chat_history("No other users known yet.")
    else:
        for uname in other_users_public_keys:
            update_chat_history(f"- {uname}")
    update_chat_history("--------------------")

def on_closing():
    """Handles closing the GUI window."""
    try:
        if client_socket:
            client_socket.close()
    except Exception as e:
        print(f"Error closing socket: {e}")
    root.destroy()

def start_client_gui():
    global root, chat_history_text, message_entry, recipient_entry, username, private_key, public_key, private_pem, public_pem, status_label, send_button, list_users_button

    # Initialize root and ask for username first
    root = tk.Tk()
    root.withdraw() # Hide main window while dialog is open

    username = simpledialog.askstring("Username", "Enter your username:", parent=root)
    if not username:
        messagebox.showerror("Error", "Username is required to start the chat.")
        root.destroy()
        return

    # Generate RSA keys after getting the username
    private_key, public_key = generate_rsa_key_pair()
    private_pem, public_pem = serialize_rsa_keys(private_key, public_key)

    # Now that we have the username, set up the main window
    root.deiconify() # Show the main window
    root.title(f"Secure Chat Client - {username}")
    root.geometry("600x500")
    root.protocol("WM_DELETE_WINDOW", on_closing) # Handle window close event

    # Apply a dark theme
    style = ttk.Style()
    style.theme_use('clam') # 'clam', 'alt', 'default', 'classic'
    style.configure('.', background='#282c34', foreground='#abb2bf', font=('Segoe UI', 10))
    style.configure('TFrame', background='#282c34')
    style.configure('TLabel', background='#282c34', foreground='#61afef')
    style.configure('TEntry', fieldbackground='#3e4451', foreground='#abb2bf', borderwidth=1, relief='flat')
    style.map('TEntry', fieldbackground=[('focus', '#4a505c')]) # Change background on focus

    style.configure('TButton',
        background='#61afef', # Blue for main buttons
        foreground='white',
        font=('Segoe UI', 10, 'bold'),
        borderwidth=0,
        relief='flat',
        padding=(10, 5)
    )
    style.map('TButton',
        background=[('active', '#529dff')], # Darker blue on hover
        foreground=[('active', 'white')]
    )

    # Specific style for the Send button
    style.configure('Send.TButton',
        background='#98c379', # Green
        foreground='white',
        font=('Segoe UI', 10, 'bold')
    )
    style.map('Send.TButton',
        background=[('active', '#82b365')]
    )

    # Specific style for the List Users button
    style.configure('List.TButton',
        background='#e5c07b', # Yellow/Orange
        foreground='white',
        font=('Segoe UI', 10, 'bold')
    )
    style.map('List.TButton',
        background=[('active', '#d1a65d')]
    )

    # Status Label
    status_label = ttk.Label(root, text="Connecting...", font=('Segoe UI', 10, 'bold'), anchor='w')
    status_label.pack(padx=10, pady=(5, 0), fill=tk.X)
    update_status_label("Connecting...", '#e5c07b') # Initial status

    # Chat History Display
    chat_history_text = scrolledtext.ScrolledText(root, state='disabled', wrap='word', bg='#21252b', fg='#abb2bf', font=('Consolas', 10), relief='flat', borderwidth=0)
    chat_history_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    # Recipient Entry
    recipient_frame = ttk.Frame(root) # Use ttk.Frame for themed background
    recipient_frame.pack(padx=10, pady=(0, 5), fill=tk.X)
    ttk.Label(recipient_frame, text="Recipient:").pack(side=tk.LEFT, padx=(0, 5))
    recipient_entry = ttk.Entry(recipient_frame, width=20)
    recipient_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

    # Message Entry and Send Button
    message_frame = ttk.Frame(root) # Use ttk.Frame
    message_frame.pack(padx=10, pady=(0, 10), fill=tk.X)

    message_entry = ttk.Entry(message_frame)
    message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
    message_entry.bind("<Return>", lambda event=None: send_message_gui()) # Bind Enter key

    send_button = ttk.Button(message_frame, text="Send", command=send_message_gui, style='Send.TButton')
    send_button.pack(side=tk.RIGHT)

    # List Users Button
    list_users_button = ttk.Button(root, text="List Active Users", command=list_users_gui, style='List.TButton')
    list_users_button.pack(padx=10, pady=(0, 10), fill=tk.X)

    # Disable input fields until connected
    set_connection_status(False)

    # Connection and receive logic
    def connect_and_receive():
        try:
            client_socket.connect((HOST, PORT))
            update_chat_history(f"Connected to server at {HOST}:{PORT}")
            set_connection_status(True)

            initial_payload = {
                "username": username,
                "public_key_pem": public_pem.decode('utf-8')
            }
            client_socket.sendall(json.dumps(initial_payload).encode('utf-8'))

            receive_thread = threading.Thread(target=receive_messages)
            receive_thread.daemon = True
            receive_thread.start()

        except ConnectionRefusedError:
            update_chat_history("Connection Error: Connection refused. Make sure the server is running and port 65432 is open.")
            set_connection_status(False)
        except Exception as e:
            update_chat_history(f"An error occurred during connection: {e}")
            set_connection_status(False)
    
    # Start connection attempt in a separate thread to prevent GUI freeze
    connection_thread = threading.Thread(target=connect_and_receive)
    connection_thread.daemon = True
    connection_thread.start()

    # This ensures the GUI event loop always starts regardless of connection status
    root.mainloop()

if __name__ == "__main__":
    start_client_gui()
