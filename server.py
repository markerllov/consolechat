import socket
import threading
import json
import os
import uuid
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad
import base64


class ChatServer:
    def __init__(self):
        self.host = '0.0.0.0'
        self.port = 5555
        self.users_file = 'users.json'
        self.setup_files()
        self.server_socket = None
        self.online_users = {}  # Format: {device_id: (username, client_socket)}
        self.running = True
        self.shared_secret = b'secure_secret_key_32bytes_256bits!'

    def setup_files(self):
        if not os.path.exists(self.users_file):
            with open(self.users_file, 'w') as f:
                json.dump({}, f)

    def load_users(self):
        try:
            with open(self.users_file, 'r') as f:
                return json.load(f)
        except:
            return {}

    def save_users(self, users):
        with open(self.users_file, 'w') as f:
            json.dump(users, f, indent=4)

    def encrypt_message(self, message):
        try:
            iv = get_random_bytes(16)
            cipher = AES.new(self.shared_secret, AES.MODE_CBC, iv)
            padded_msg = pad(message.encode('utf-8'), AES.block_size)
            encrypted = cipher.encrypt(padded_msg)
            hmac = HMAC.new(self.shared_secret, iv + encrypted, digestmod=SHA256)
            mac = hmac.digest()
            return base64.b64encode(iv + mac + encrypted).decode('utf-8')
        except Exception as e:
            print(f"Encryption error: {e}")
            return None

    def decrypt_message(self, encrypted_msg):
        try:
            raw = base64.b64decode(encrypted_msg)
            iv, mac, encrypted = raw[:16], raw[16:48], raw[48:]

            # Проверка целостности
            hmac = HMAC.new(self.shared_secret, iv + encrypted, digestmod=SHA256)
            hmac.verify(mac)

            cipher = AES.new(self.shared_secret, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
            return decrypted.decode('utf-8')
        except (ValueError, KeyError, Exception) as e:
            print(f"Decryption failed: {e}")
            return None

    def handle_client(self, client, address):
        print(f"New connection from {address}")
        current_user = None
        device_id = None

        try:
            while self.running:
                try:
                    data = client.recv(1024).decode('utf-8').strip()
                    if not data:
                        break

                    parts = data.split('|')
                    if len(parts) < 1:
                        continue

                    command = parts[0]
                    users = self.load_users()

                    if command == 'register':
                        if len(parts) < 3:
                            continue
                        username = parts[1]
                        password = parts[2]

                        if username in users:
                            response = "ERROR|Username already exists"
                        else:
                            device_id = str(uuid.uuid4())[:3]
                            users[username] = {
                                'password': password,
                                'device_id': device_id,
                                'created_at': str(datetime.now())
                            }
                            self.save_users(users)
                            response = f"SUCCESS|Registered|{device_id}"

                    elif command == 'login':
                        if len(parts) < 3:
                            continue
                        username = parts[1]
                        password = parts[2]

                        if username in users and users[username]['password'] == password:
                            current_user = username
                            device_id = users[username]['device_id']
                            self.online_users[device_id] = (username, client)
                            response = f"SUCCESS|Logged in|{device_id}"
                        else:
                            response = "ERROR|Invalid credentials"

                    elif command == 'list':
                        online_list = {did: username for did, (username, _) in self.online_users.items()}
                        response = "ONLINE|" + json.dumps(online_list)

                    elif command == 'profile':
                        print(f'Name: {username}\nID: {device_id}')
                        response = "PROFILE|" + json.dumps(users)



                    elif command == 'send':

                        if len(parts) < 3:
                            continue

                        target_id = parts[1]

                        encrypted_msg = parts[2]

                        # Расшифровываем для проверки перед пересылкой

                        decrypted = self.decrypt_message(encrypted_msg)

                        if decrypted is None:

                            response = "ERROR|Invalid message"

                        elif target_id in self.online_users:

                            recipient = self.online_users[target_id][1]

                            try:

                                recipient.sendall(f"MESSAGE|{current_user}|{encrypted_msg}\n".encode('utf-8'))

                                response = "SUCCESS|Message sent"

                            except:

                                response = "ERROR|Failed to send message"

                        else:

                            response = "ERROR|User not online"

                    elif command == 'logout':
                        if device_id in self.online_users:
                            del self.online_users[device_id]
                        response = "SUCCESS|Logged out"
                        client.sendall((response + "\n").encode('utf-8'))
                        break

                    else:
                        response = "ERROR|Unknown command"

                    client.sendall((response + "\n").encode('utf-8'))

                except Exception as e:
                    print(f"Error with {address}: {str(e)}")
                    break

        finally:
            if device_id in self.online_users:
                del self.online_users[device_id]
            client.close()
            print(f"Connection closed: {address}")

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen()
            print(f"Server started on {self.host}:{self.port}")

            while self.running:
                try:
                    client, address = self.server_socket.accept()
                    threading.Thread(
                        target=self.handle_client,
                        args=(client, address),
                        daemon=True
                    ).start()
                except:
                    break

        except Exception as e:
            print(f"Server error: {str(e)}")
        finally:
            self.stop()

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        print("Server stopped")


if __name__ == "__main__":
    server = ChatServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()