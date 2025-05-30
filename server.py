import socket
import threading
import json
import os
from security import SimpleCipher
import datetime


class ChatServer:
    def __init__(self):
        self.host = '0.0.0.0'
        self.port = 5555
        self.users_file = 'users.json'
        self.messages_file = 'messages.json'
        self.online_users = {}  # {device_id: (username, client_socket)}
        self.server_socket = None
        self.cipher = SimpleCipher()
        self.encryption_key = "secret_chat_key_123"  # Общий ключ шифрования

        self.setup_files()

    def setup_files(self):
        if not os.path.exists(self.users_file):
            with open(self.users_file, 'w') as f:
                json.dump({}, f)
        if not os.path.exists(self.messages_file):
            with open(self.messages_file, 'w') as f:
                json.dump([], f)

    def load_users(self):
        try:
            with open(self.users_file, 'r') as f:
                return json.load(f)
        except:
            return {}

    def save_users(self, users):
        with open(self.users_file, 'w') as f:
            json.dump(users, f, indent=4)

    def load_messages(self):
        try:
            with open(self.messages_file, 'r') as f:
                return json.load(f)
        except:
            return []

    def save_message(self, sender, recipient, message):
        messages = self.load_messages()
        messages.append({
            'sender': sender,
            'recipient': recipient,
            'message': message,
            'timestamp': str(datetime.datetime.now())
        })
        with open(self.messages_file, 'w') as f:
            json.dump(messages, f, indent=4)

    def handle_client(self, client, address):
        print(f"New connection from {address}")
        current_user = None
        device_id = None

        try:
            while True:
                encrypted_data = client.recv(1024).decode('utf-8')
                if not encrypted_data:
                    break

                # Дешифруем полученные данные
                data = self.cipher.decrypt(encrypted_data, self.encryption_key)
                parts = data.split('|')
                command = parts[0]

                if command == 'register':
                    username = parts[1]
                    password = parts[2]
                    users = self.load_users()

                    if username in users:
                        response = "ERROR|Username already exists"
                    else:
                        device_id = str(len(users) + 1)  # Простой ID
                        users[username] = {
                            'password': password,
                            'device_id': device_id
                        }
                        self.save_users(users)
                        response = f"SUCCESS|Registered|{device_id}"

                elif command == 'login':
                    username = parts[1]
                    password = parts[2]
                    users = self.load_users()

                    if username in users and users[username]['password'] == password:
                        current_user = username
                        device_id = users[username]['device_id']
                        self.online_users[device_id] = (username, client)
                        response = f"SUCCESS|Logged in|{device_id}"
                    else:
                        response = "ERROR|Invalid username or password"

                elif command == 'list':
                    online_list = {did: info[0] for did, info in self.online_users.items()}
                    response = "ONLINE|" + json.dumps(online_list)

                elif command == 'send':
                    if len(parts) < 3:
                        continue
                    target_id = parts[1]
                    message = parts[2]

                    if target_id in self.online_users:
                        recipient = self.online_users[target_id][1]
                        response = f"MESSAGE|{current_user}|{message}"
                        # Шифруем перед отправкой
                        encrypted_response = self.cipher.encrypt(response, self.encryption_key)
                        recipient.send(encrypted_response.encode('utf-8'))
                        response = "SUCCESS|Message sent"
                    else:
                        response = "ERROR|User not online"

                elif command == 'get_history':
                    target_user = parts[1] if len(parts) > 1 else None
                    messages = self.load_messages()
                    user_messages = [
                        msg for msg in messages
                        if msg['sender'] == current_user or msg['recipient'] == current_user
                    ]
                    if target_user:
                        user_messages = [
                            msg for msg in user_messages
                            if msg['sender'] == target_user or msg['recipient'] == target_user
                        ]
                    response = "HISTORY|" + json.dumps(user_messages)

                elif command == 'logout':
                    if device_id in self.online_users:
                        del self.online_users[device_id]
                    response = "SUCCESS|Logged out"
                    # Шифруем ответ перед отправкой
                    encrypted_response = self.cipher.encrypt(response, self.encryption_key)
                    client.send(encrypted_response.encode('utf-8'))
                    break

                else:
                    response = "ERROR|Unknown command"

                # Шифруем ответ перед отправкой
                encrypted_response = self.cipher.encrypt(response, self.encryption_key)
                client.send(encrypted_response.encode('utf-8'))

        except Exception as e:
            print(f"Error with {address}: {str(e)}")
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

            while True:
                client, address = self.server_socket.accept()
                threading.Thread(
                    target=self.handle_client,
                    args=(client, address),
                    daemon=True
                ).start()

        except KeyboardInterrupt:
            print("\nServer shutting down...")
        finally:
            self.stop()

    def stop(self):
        if self.server_socket:
            self.server_socket.close()
        print("Server stopped")


if __name__ == "__main__":
    server = ChatServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()