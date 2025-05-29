import socket
import threading
import json
import sys
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad
import base64

class ChatClient:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.current_user = None
        self.device_id = None
        self.running = True
        self.shared_secret = b'secure_secret_key_32bytes_256bits!'

    def connect(self, host, port):
        try:
            self.socket.connect((host, port))
            threading.Thread(target=self.receive_messages, daemon=True).start()
            return True
        except Exception as e:
            print(f"Connection error: {e}")
            return False

    def receive_messages(self):
        buffer = ""
        while self.running:
            try:
                data = self.socket.recv(1024).decode('utf-8')
                if not data:
                    print("\nServer closed the connection")
                    self.running = False
                    break

                buffer += data
                while "\n" in buffer:
                    message, buffer = buffer.split("\n", 1)
                    self.handle_server_message(message.strip())

            except ConnectionResetError:
                print("\nConnection lost with server")
                self.running = False
                break
            except Exception as e:
                print(f"\nReceive error: {e}")
                self.running = False
                break

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

    def handle_server_message(self, message):
        if not message:
            return

        parts = message.split('|', 2)
        if len(parts) < 2:
            return

        status = parts[0]
        content = parts[1]

        if status == "ERROR":
            print(f"\nError: {content}")
        elif status == "SUCCESS":
            print(f"\nSuccess: {content}")
            if "Registered" in content or "Logged in" in content:
                self.device_id = parts[2] if len(parts) > 2 else None
                if "Logged in" in content:
                    self.current_user = True
        elif status == "ONLINE":
            try:
                users = json.loads(content)
                print("\nOnline users:")
                for device_id, username in users.items():
                    print(f"{username} (ID: {device_id})")
            except:
                print("\nFailed to load online users")

        elif status == "MESSAGE":
            sender = content
            encrypted_msg = parts[2] if len(parts) > 2 else ""
            decrypted = self.decrypt_message(encrypted_msg)
            if decrypted:
                print(f"\nNew message from {sender}: {decrypted}")
            else:
                print("\nReceived corrupted message")

        self.show_menu()

    def send_command(self, command, username=None, password=None):
        try:
            if username and password:
                message = f"{command}|{username}|{password}\n"
            else:
                message = f"{command}\n"
            self.socket.sendall(message.encode('utf-8'))
        except Exception as e:
            print(f"Send error: {e}")
            self.running = False

    def show_menu(self):
        if not self.current_user:
            print("\n1. Register\n2. Login\n3. Exit")
        else:
            print("\n1. Send message\n2. List users\n3. Profile\n4. Logout")
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
                        target = input("Recipient ID: ").strip()
                        msg = input("Message: ").strip()
                        encrypted_msg = self.encrypt_message(msg)
                        self.send_command(f"send|{target}|{encrypted_msg}")
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
                        self.send_command("profile")
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