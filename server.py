import socket
import threading
import json
import os
import uuid
from datetime import datetime
from security import SimpleCipher


class ChatServer:
    def __init__(self):
        self.host = '0.0.0.0'
        self.port = 5555
        self.file_port = 5556
        self.users_file = 'users.json'
        self.setup_files()
        self.server_socket = None
        self.file_socket = None
        self.online_users = {}  # {device_id: (username, client_socket)}
        self.running = True
        self.chiper = SimpleCipher()
        self.encryption_key = "secret_key"
        self.file_transfers = {}  # Для отслеживания передач файлов

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

    def start_file_server(self):
        """Запуск сервера для передачи файлов"""
        self.file_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.file_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.file_socket.bind((self.host, self.file_port))
        self.file_socket.listen(5)

        print(f"File transfer server started on {self.host}:{self.file_port}")

        while self.running:
            try:
                conn, addr = self.file_socket.accept()
                threading.Thread(
                    target=self.handle_file_transfer,
                    args=(conn, addr),
                    daemon=True
                ).start()
            except:
                break

    def handle_file_transfer(self, conn, addr):
        """Обработка передачи файла"""
        try:
            # Получаем метаданные о передаче
            metadata = conn.recv(1024).decode('utf-8').strip()
            if not metadata:
                return

            parts = metadata.split('|')
            if len(parts) < 4:
                return

            transfer_type = parts[0]
            sender_id = parts[1]
            recipient_id = parts[2]
            filename = parts[3]

            if transfer_type == 'REQUEST':
                # Уведомляем получателя о запросе на передачу файла
                if recipient_id in self.online_users:
                    recipient_socket = self.online_users[recipient_id][1]
                    recipient_socket.sendall(
                        f"FILE_REQUEST|{sender_id}|{filename}\n".encode('utf-8')
                    )

            elif transfer_type == 'DATA':
                # Пересылаем файл получателю
                if recipient_id in self.online_users:
                    recipient_socket = self.online_users[recipient_id][1]

                    # Отправляем получателю подтверждение
                    recipient_socket.sendall(
                        f"FILE_START|{filename}\n".encode('utf-8')
                    )

                    # Пересылаем данные файла
                    while True:
                        data = conn.recv(4096)
                        if not data:
                            break
                        recipient_socket.sendall(data)

                    recipient_socket.sendall(
                        f"FILE_END|{filename}\n".encode('utf-8')
                    )

        except Exception as e:
            print(f"File transfer error: {str(e)}")
        finally:
            conn.close()

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

                    decrypted_data = self.chiper.decrypt(data, self.encryption_key)

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
                            device_id = str(uuid.uuid4())[:8]
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

                    elif command == 'send':
                        if len(parts) < 3:
                            continue
                        target_id = parts[1]
                        message = parts[2]

                        if target_id in self.online_users:
                            recipient = self.online_users[target_id][1]
                            try:
                                encrypted_response = self.chiper.encrypt(response, self.encryption_key)
                                recipient.sendall(f"MESSAGE|{current_user}|{message}\n".encode('utf-8'))
                                response = "SUCCESS|Message sent"
                            except:
                                response = "ERROR|Failed to send message"
                        else:
                            response = "ERROR|User not online"

                    elif command == 'sendfile':
                        if len(parts) < 3:
                            continue
                        target_id = parts[1]
                        filename = parts[2]

                        if not os.path.exists(filename):
                            response = "ERROR|File not found"
                        elif target_id not in self.online_users:
                            response = "ERROR|User not online"
                        else:
                            filesize = os.path.getsize(filename)
                            response = f"FILE_INIT|{filename}|{filesize}"
                            self.file_transfers[(device_id, target_id)] = filename

                    elif command == 'acceptfile':
                        if len(parts) < 2:
                            continue
                        sender_id = parts[1]

                        if (sender_id, device_id) in self.file_transfers:
                            filename = self.file_transfers[(sender_id, device_id)]
                            response = f"FILE_ACCEPT|{filename}"
                        else:
                            response = "ERROR|No file transfer request"

                    elif command == 'logout':
                        if device_id in self.online_users:
                            del self.online_users[device_id]
                        response = "SUCCESS|Logged out"
                        encrypted_response = self.chiper.encrypt(response, self.encryption_key)
                        client.sendall((encrypted_response + "\n").encode('utf-8'))
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

        # Запускаем сервер для файлов в отдельном потоке
        threading.Thread(
            target=self.start_file_server,
            daemon=True
        ).start()

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen()
            print(f"Chat server started on {self.host}:{self.port}")

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
        if self.file_socket:
            self.file_socket.close()
        print("Server stopped")


if __name__ == "__main__":
    server = ChatServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
