import socket
import threading
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# --- Cryptographic Functions (from client code, only using the ones needed for server) ---
def serialize_public_key(public_key):
    """Serializes RSA public key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_pem):
    """Deserializes RSA public key from PEM format."""
    return serialization.load_pem_public_key(
        public_pem,
        backend=default_backend()
    )

# --- Server Logic ---
HOST = '0.0.0.0'  # Listen on all available network interfaces
PORT = 65432      # The same port the clients will connect to

clients = {} # {username: (socket_object, public_key_object)}
clients_lock = threading.Lock() # Lock to ensure thread-safe access to the 'clients' dictionary

def handle_client(conn, addr):
    """Handles all communication with a single client connection."""
    print(f"Connected by {addr}")
    username = None
    try:
        # Step 1: Receive username and public key from client
        data = conn.recv(4096).decode('utf-8')
        initial_data = json.loads(data)
        username = initial_data['username']
        public_key_pem = initial_data['public_key_pem'].encode('utf-8')
        client_public_key = deserialize_public_key(public_key_pem)

        with clients_lock:
            # Check for duplicate username
            if username in clients:
                conn.sendall(json.dumps({"status": "error", "message": "Username already taken."}).encode('utf-8'))
                conn.close()
                return
            clients[username] = (conn, client_public_key)
            print(f"User '{username}' registered with public key.")

        # Step 2: Send the list of other active users to the new client
        send_active_users()

        # Step 3: Continuously receive and relay messages from this client
        while True:
            message_data_json = conn.recv(4096).decode('utf-8')
            if not message_data_json:
                break # Client disconnected

            message_data = json.loads(message_data_json)
            recipient_username = message_data['recipient']
            
            with clients_lock:
                if recipient_username in clients:
                    recipient_conn, _ = clients[recipient_username]
                    # The server does not decrypt the message, it simply relays the encrypted payload
                    recipient_conn.sendall(message_data_json.encode('utf-8'))
                    print(f"Relayed message from {username} to {recipient_username}.")
                else:
                    print(f"Recipient '{recipient_username}' not found.")
                    conn.sendall(json.dumps({"status": "error", "message": "Recipient not found"}).encode('utf-8'))

    except json.JSONDecodeError:
        print(f"Invalid JSON received from {addr}")
    except ConnectionResetError:
        print(f"Client {addr} ({username}) disconnected unexpectedly.")
    except Exception as e:
        print(f"Error handling client {addr} ({username}): {e}")
    finally:
        # Clean up client connection when the loop breaks
        if username:
            with clients_lock:
                if username in clients:
                    del clients[username]
                    print(f"User '{username}' disconnected.")
            # Notify all other clients that a user has left
            notify_user_list_change()
        conn.close()

def send_active_users():
    """Sends the current list of active users and their public keys to all clients."""
    with clients_lock:
        user_list = []
        for uname, (_, pub_key_obj) in clients.items():
            user_list.append({
                'username': uname,
                'public_key_pem': serialize_public_key(pub_key_obj).decode('utf-8')
            })
        
        # Send the user list to all currently connected clients
        for uname, (conn, _) in clients.items():
            try:
                # Exclude the client's own info from the list sent to them
                filtered_user_list = [user for user in user_list if user['username'] != uname]
                conn.sendall(json.dumps({"type": "user_list", "users": filtered_user_list}).encode('utf-8'))
            except Exception as e:
                print(f"Error sending user list to {uname}: {e}")

def notify_user_list_change():
    """Notifies all clients that the user list has changed by resending the list."""
    send_active_users()

def start_server():
    """Initializes and runs the chat server."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allows reuse of the address
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"Server listening on {HOST}:{PORT}")

    while True:
        conn, addr = server_socket.accept()
        # Start a new thread for each new client to handle their communication
        client_thread = threading.Thread(target=handle_client, args=(conn, addr))
        client_thread.start()

if __name__ == "__main__":
    start_server()
