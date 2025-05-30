import socket
import threading
import json
import os
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
from datetime import datetime
from security import SimpleCipher


class ChatClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Чат-мессенджер")
        self.root.geometry("800x600")

        # Сетевые параметры
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.file_socket = None
        self.current_user = None
        self.device_id = None
        self.running = True
        self.server_host = "localhost"
        self.receiving_file = None
        self.receiving_filename = None
        self.chiper = SimpleCipher()
        self.encryption_key = "secret_key"

        # Создаем интерфейс
        self.create_login_frame()
        self.create_chat_frame()
        self.show_login_frame()

        # Настройка тегов для сообщений
        self.setup_tags()

        # Запускаем обработчик закрытия окна
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_tags(self):
        """Настройка стилей для сообщений"""
        self.chat_area.tag_config("outgoing", foreground="blue")
        self.chat_area.tag_config("incoming", foreground="green")
        self.chat_area.tag_config("system", foreground="gray")

    def create_login_frame(self):
        """Создаем фрейм для входа/регистрации"""
        self.login_frame = ttk.Frame(self.root)

        ttk.Label(self.login_frame, text="Адрес сервера:").grid(row=0, column=0, padx=5, pady=5)
        self.server_entry = ttk.Entry(self.login_frame)
        self.server_entry.insert(0, "localhost")
        self.server_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self.login_frame, text="Имя пользователя:").grid(row=1, column=0, padx=5, pady=5)
        self.username_entry = ttk.Entry(self.login_frame)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(self.login_frame, text="Пароль:").grid(row=2, column=0, padx=5, pady=5)
        self.password_entry = ttk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)

        self.login_button = ttk.Button(self.login_frame, text="Войти", command=self.login)
        self.login_button.grid(row=3, column=0, padx=5, pady=5)

        self.register_button = ttk.Button(self.login_frame, text="Зарегистрироваться", command=self.register)
        self.register_button.grid(row=3, column=1, padx=5, pady=5)

        self.status_label = ttk.Label(self.login_frame, text="", foreground="red")
        self.status_label.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

    def create_chat_frame(self):
        """Создаем фрейм для чата"""
        self.chat_frame = ttk.Frame(self.root)

        # Список пользователей
        self.users_frame = ttk.LabelFrame(self.chat_frame, text="Онлайн пользователи")
        self.users_frame.pack(fill=tk.Y, side=tk.LEFT, padx=5, pady=5)

        # Фрейм для кнопки обновления
        self.users_control_frame = ttk.Frame(self.users_frame)
        self.users_control_frame.pack(fill=tk.X, padx=5, pady=(0, 5))

        # Кнопка обновления списка пользователей
        self.refresh_button = ttk.Button(
            self.users_control_frame,
            text="Обновить",
            command=self.refresh_users_list
        )
        self.refresh_button.pack(fill=tk.X, expand=True)

        self.users_tree = ttk.Treeview(self.users_frame, columns=("id", "name"), show="headings")
        self.users_tree.heading("id", text="ID")
        self.users_tree.column("id", width=50, anchor=tk.CENTER)
        self.users_tree.heading("name", text="Имя")
        self.users_tree.column("name", width=150)
        self.users_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Чат
        self.chat_area = scrolledtext.ScrolledText(self.chat_frame, state='disabled')
        self.chat_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Панель сообщений
        self.message_frame = ttk.Frame(self.chat_frame)
        self.message_frame.pack(fill=tk.X, padx=5, pady=5)

        self.message_entry = ttk.Entry(self.message_frame)
        self.message_entry.pack(fill=tk.X, expand=True, side=tk.LEFT, padx=5)
        self.message_entry.bind("<Return>", lambda e: self.send_message())

        self.send_button = ttk.Button(self.message_frame, text="Отправить", command=self.send_message)
        self.send_button.pack(side=tk.LEFT, padx=5)

        # Панель файлов
        self.file_frame = ttk.Frame(self.chat_frame)
        self.file_frame.pack(fill=tk.X, padx=5, pady=5)

        self.file_button = ttk.Button(self.file_frame, text="Отправить файл", command=self.send_file_dialog)
        self.file_button.pack(side=tk.LEFT, padx=5)

        self.logout_button = ttk.Button(self.chat_frame, text="Выйти", command=self.logout)
        self.logout_button.pack(side=tk.BOTTOM, padx=5, pady=5)

    def refresh_users_list(self):
        """Обновить список пользователей"""
        if self.current_user:
            self.send_command("list")
            self.display_message("Система", "Обновление списка пользователей...", system=True)

    def show_login_frame(self):
        """Показываем фрейм входа"""
        self.chat_frame.pack_forget()
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        self.username_entry.focus_set()

    def show_chat_frame(self):
        """Показываем фрейм чата"""
        self.login_frame.pack_forget()
        self.chat_frame.pack(fill=tk.BOTH, expand=True)
        self.message_entry.focus_set()
        # Запрашиваем список пользователей при входе в чат
        self.send_command("list")

    def connect(self, host, port):
        """Подключаемся к серверу"""
        try:
            self.server_host = host
            self.socket.connect((host, port))
            threading.Thread(target=self.receive_messages, daemon=True).start()
            return True
        except Exception as e:
            self.show_error(f"Ошибка подключения: {e}")
            return False

    def receive_messages(self):
        """Получаем сообщения от сервера"""
        buffer = ""
        while self.running:
            try:
                data = self.socket.recv(1024).decode('utf-8')
                if not data:
                    self.show_error("Сервер закрыл соединение")
                    self.running = False
                    break

                message = self.chiper.decrypt(data, self.encryption_key)

            except ConnectionResetError:
                self.show_error("Соединение с сервером потеряно")
                self.running = False
                break
            except Exception as e:
                self.show_error(f"Ошибка получения: {e}")
                self.running = False
                break

    def handle_server_message(self, message):
        """Обрабатываем сообщения от сервера"""
        if not message:
            return

        parts = message.split('|', 2)
        if len(parts) < 2:
            return

        status = parts[0]
        content = parts[1]

        if status == "ERROR":
            self.show_error(content)
        elif status == "SUCCESS":
            self.show_info(content)
            if "Registered" in content or "Logged in" in content:
                self.device_id = parts[2] if len(parts) > 2 else None
                if "Logged in" in content:
                    self.current_user = self.username_entry.get()
                    self.root.title(f"Чат-мессенджер - {self.current_user}")
                    self.show_chat_frame()
        elif status == "ONLINE":
            try:
                users = json.loads(content)
                self.update_users_list(users)
            except Exception as e:
                self.show_error(f"Ошибка загрузки списка пользователей: {e}")
        elif status == "MESSAGE":
            sender = content
            message = parts[2] if len(parts) > 2 else ""
            self.display_message(sender, message)
        elif status == "FILE_REQUEST":
            sender_id = content
            filename = parts[2] if len(parts) > 2 else ""
            self.handle_file_request(sender_id, filename)
        elif status == "FILE_START":
            filename = content
            self.start_receiving_file(filename)
        elif status == "FILE_END":
            self.finish_receiving_file()
        elif status == "FILE_INIT":
            filename = content
            filesize = parts[2] if len(parts) > 2 else 0
            self.init_file_transfer(filename, filesize)

    def update_users_list(self, users):
        """Обновление списка пользователей"""
        # Очищаем текущий список
        for item in self.users_tree.get_children():
            self.users_tree.delete(item)

        # Добавляем новых пользователей
        for device_id, username in users.items():
            if device_id != self.device_id:  # Не показываем себя в списке
                self.users_tree.insert("", tk.END, values=(device_id, username))

    def send_command(self, command, username=None, password=None):
        """Отправляем команду на сервер"""
        try:
            if username and password:
                message = f"{command}|{username}|{password}\n"
            else:
                message = command

            encrypted = self.chiper.encrypt(message, self.encryption_key)
            self.socket.sendall(encrypted.encode('utf-8'))
        except Exception as e:
            self.show_error(f"Ошибка отправки: {e}")
            self.running = False

    def login(self):
        """Вход пользователя"""
        host = self.server_entry.get().strip() or "localhost"
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            self.show_error("Введите имя пользователя и пароль")
            return

        if not self.connect(host, 5555):
            return

        self.send_command("login", username, password)

    def register(self):
        """Регистрация пользователя"""
        host = self.server_entry.get().strip() or "localhost"
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            self.show_error("Введите имя пользователя и пароль")
            return

        if not self.connect(host, 5555):
            return

        self.send_command("register", username, password)

    def logout(self):
        """Выход пользователя"""
        self.send_command("logout")
        self.current_user = None
        self.device_id = None
        self.show_login_frame()
        self.socket.close()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True

    def send_message(self):
        """Отправка сообщения"""
        message = self.message_entry.get().strip()
        if not message:
            return

        selected = self.users_tree.selection()
        if not selected:
            self.show_error("Выберите получателя")
            return

        recipient_id = self.users_tree.item(selected[0])['values'][0]
        self.send_command(f"send|{recipient_id}|{message}")
        self.display_message("Вы", message, outgoing=True)
        self.message_entry.delete(0, tk.END)

    def send_file_dialog(self):
        """Диалог выбора файла для отправки"""
        selected = self.users_tree.selection()
        if not selected:
            self.show_error("Выберите получателя")
            return

        recipient_id = self.users_tree.item(selected[0])['values'][0]
        filename = filedialog.askopenfilename(title="Выберите файл для отправки")

        if filename:
            self.send_command(f"sendfile|{recipient_id}|{filename}")

    def send_file(self, filename):
        """Отправка файла"""
        try:
            # Устанавливаем соединение для передачи файла
            self.file_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.file_socket.connect((self.server_host, 5556))

            # Отправляем метаданные
            metadata = f"DATA|{self.device_id}|{self.device_id}|{os.path.basename(filename)}"
            self.file_socket.sendall(metadata.encode('utf-8'))

            # Отправляем файл
            with open(filename, 'rb') as f:
                while True:
                    data = f.read(4096)
                    if not data:
                        break
                    self.file_socket.sendall(data)

            self.show_info(f"Файл {os.path.basename(filename)} отправлен успешно!")

        except Exception as e:
            self.show_error(f"Ошибка отправки файла: {e}")
        finally:
            if self.file_socket:
                self.file_socket.close()

    def handle_file_request(self, sender_id, filename):
        """Обработка запроса на передачу файла"""
        answer = messagebox.askyesno(
            "Запрос на передачу файла",
            f"Пользователь {sender_id} хочет отправить вам файл: {filename}\nПринять файл?"
        )

        if answer:
            self.send_command(f"acceptfile|{sender_id}")
        else:
            self.send_command(f"rejectfile|{sender_id}")

    def start_receiving_file(self, filename):
        """Начало приема файла"""
        self.receiving_filename = filename
        try:
            self.receiving_file = open(filename, 'wb')
            self.display_message("Система", f"Начало приема файла: {filename}", system=True)
        except Exception as e:
            self.show_error(f"Ошибка создания файла: {e}")
            self.receiving_filename = None

    def finish_receiving_file(self):
        """Завершение приема файла"""
        if self.receiving_file:
            self.receiving_file.close()
            self.receiving_file = None
            self.display_message("Система", f"Файл {self.receiving_filename} получен успешно!", system=True)
            self.receiving_filename = None

    def init_file_transfer(self, filename, filesize):
        """Инициализация передачи файла"""
        self.send_file(filename)

    def display_message(self, sender, message, outgoing=False, system=False):
        """Отображение сообщения в чате"""
        self.chat_area.config(state='normal')
        timestamp = datetime.now().strftime("%H:%M:%S")

        if system:
            self.chat_area.insert(tk.END, f"[{timestamp}] {sender}: {message}\n", "system")
        elif outgoing:
            self.chat_area.insert(tk.END, f"[{timestamp}] Вы: {message}\n", "outgoing")
        else:
            self.chat_area.insert(tk.END, f"[{timestamp}] {sender}: {message}\n", "incoming")

        self.chat_area.config(state='disabled')
        self.chat_area.see(tk.END)

    def show_error(self, message):
        """Показываем сообщение об ошибке"""
        self.status_label.config(text=message, foreground="red")
        self.display_message("Система", message, system=True)

    def show_info(self, message):
        """Показываем информационное сообщение"""
        self.status_label.config(text=message, foreground="green")
        self.display_message("Система", message, system=True)

    def on_closing(self):
        """Обработчик закрытия окна"""
        if messagebox.askokcancel("Выход", "Вы действительно хотите выйти?"):
            if self.current_user:
                self.logout()
            self.running = False
            self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()

    # Настраиваем стили
    style = ttk.Style()
    style.configure("TButton", padding=5)
    style.configure("TEntry", padding=5)

    app = ChatClientGUI(root)
    root.mainloop()