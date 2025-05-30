import socket
import threading
import json
from security import SimpleCipher


class ChatClient:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.current_user = None
        self.device_id = None
        self.running = True
        self.cipher = SimpleCipher()
        self.encryption_key = "secret_chat_key_123"  # Должен совпадать с серверным

    def connect(self, host, port):
        try:
            self.socket.connect((host, port))
            threading.Thread(target=self.receive_messages, daemon=True).start()
            return True
        except Exception as e:
            print(f"Connection error: {e}")
            return False

    def receive_messages(self):
        while self.running:
            try:
                encrypted_data = self.socket.recv(1024).decode('utf-8')
                if not encrypted_data:
                    print("\nServer closed the connection")
                    self.running = False
                    break

                # Дешифруем сообщение
                message = self.cipher.decrypt(encrypted_data, self.encryption_key)
                self.handle_server_message(message)

            except ConnectionResetError:
                print("\nConnection lost with server")
                self.running = False
                break
            except Exception as e:
                print(f"\nReceive error: {e}")
                self.running = False
                break

    def handle_server_message(self, message):
        parts = message.split('|', 2)
        status = parts[0]

        if status == "ERROR":
            print(f"\nError: {parts[1]}")
        elif status == "SUCCESS":
            print(f"\nSuccess: {parts[1]}")
            if "Registered" in parts[1] or "Logged in" in parts[1]:
                self.device_id = parts[2] if len(parts) > 2 else None
                if "Logged in" in parts[1]:
                    self.current_user = True
        elif status == "ONLINE":
            try:
                users = json.loads(parts[1])
                print("\nOnline users:")
                for device_id, username in users.items():
                    print(f"{username} (ID: {device_id})")
            except:
                print("\nFailed to load online users")
        elif status == "MESSAGE":
            sender = parts[1]
            msg = parts[2] if len(parts) > 2 else ""
            print(f"\nNew message from {sender}: {msg}")
        elif status == "HISTORY":
            try:
                history = json.loads(parts[1])
                print("\nMessage history:")
                for msg in history:
                    direction = "to" if msg['sender'] == self.current_user else "from"
                    other_user = msg['recipient'] if direction == "to" else msg['sender']
                    print(f"[{msg['timestamp']}] {direction} {other_user}: {msg['message']}")
            except:
                print("\nFailed to load history")

        self.show_menu()

    def send_command(self, command, username=None, password=None):
        try:
            if username and password:
                message = f"{command}|{username}|{password}"
            else:
                message = command

            # Шифруем команду перед отправкой
            encrypted = self.cipher.encrypt(message, self.encryption_key)
            self.socket.sendall(encrypted.encode('utf-8'))
        except Exception as e:
            print(f"Send error: {e}")
            self.running = False

    def show_menu(self):
        if not self.current_user:
            print("\n1. Register\n2. Login\n3. Exit")
        else:
            print("\n1. Send message\n2. List users\n3. View history\n4. Logout")
        print("> ", end="", flush=True)

    def run(self):
        host = input("Enter server IP: ").strip() or "localhost"
        if not self.connect(host, 5555):
            return

        self.show_menu()

        while self.running:
            try:
                choice = input().strip()

                if not self.current_user:
                    if choice == '1':
                        user = input("Username: ").strip()
                        pwd = input("Password: ").strip()
                        self.send_command("register", user, pwd)
                    elif choice == '2':
                        user = input("Username: ").strip()
                        pwd = input("Password: ").strip()
                        self.send_command("login", user, pwd)
                    elif choice == '3':
                        self.running = False
                        self.send_command("exit")
                    else:
                        print("Invalid choice")
                else:
                    if choice == '1':
                        target = input("Recipient ID: ").strip()
                        msg = input("Message: ").strip()
                        self.send_command(f"send|{target}|{msg}")
                    elif choice == '2':
                        self.send_command("list")
                    elif choice == '3':
                        target = input("Filter by user ID (leave empty for all): ").strip()
                        self.send_command(f"get_history|{target}" if target else "get_history")
                    elif choice == '4':
                        self.current_user = None
                        self.send_command("logout")
                    else:
                        print("Invalid choice")

                if self.running:
                    self.show_menu()

            except KeyboardInterrupt:
                print("\nClosing connection...")
                self.running = False
                self.send_command("exit")
            except Exception as e:
                print(f"\nError: {e}")
                self.running = False

        self.socket.close()
        print("Goodbye!")


if __name__ == "__main__":
    client = ChatClient()
    client.run()