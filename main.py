from captcha.image import ImageCaptcha
from PIL import ImageTk, Image
import random
import string
import json
import os
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import re
import hashlib
from datetime import datetime

USER_FILE = 'users.json'
REGISTER_LOG = 'register_log.txt'
OPERATION_LOG = 'operation_log.txt'
MAX_ATTEMPTS = 3
MIN_PASSWORD_LENGTH = 8
CAPTCHA_TEXT = ""

def random_text(length=6):
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choice(letters_and_digits) for i in range(length))

def generate_captcha():
    global CAPTCHA_TEXT
    CAPTCHA_TEXT = random_text()
    image_captcha = ImageCaptcha(width=280, height=90)
    captcha_image = image_captcha.generate_image(CAPTCHA_TEXT)
    captcha_image.save('captcha.png')
    return 'captcha.png'

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def validate_password(password):
    if len(password) < MIN_PASSWORD_LENGTH:
        return False
    has_latin = re.search(r'[A-Za-z]', password)
    has_cyrillic = re.search(r'[А-Яа-яІіЇїЄєҐґ]', password)
    has_punctuation = re.search(r'[.,!?;:]', password)
    return has_latin and has_cyrillic and has_punctuation

def load_users():
    if not os.path.exists(USER_FILE):
        with open(USER_FILE, 'w', encoding='utf-8') as f:
            json.dump({
                "ADMIN": {
                    "password_hash": "",
                    "is_locked": False,
                    "password_restrictions": False
                }
            }, f, ensure_ascii=False, indent=4)
    with open(USER_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_users(users):
    with open(USER_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=4)

def log_register_action(username, action):
    with open(REGISTER_LOG, 'a', encoding='utf-8') as log:
        log.write(f"{datetime.now()}: {username} {action}\n")

def log_operation_action(username, action):
    with open(OPERATION_LOG, 'a', encoding='utf-8') as log:
        log.write(f"{datetime.now()}: {username} {action}\n")

class LoginApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Система аутентифікації")
        self.master.geometry("400x300")
        self.users = load_users()
        self.attempts = 0
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.master, text="Ім'я користувача:").grid(row=0, column=0, padx=10, pady=10, sticky='e')
        self.username_entry = tk.Entry(self.master)
        self.username_entry.grid(row=0, column=1, padx=10, pady=10, sticky='w')

        tk.Label(self.master, text="Пароль:").grid(row=1, column=0, padx=10, pady=10, sticky='e')
        self.password_entry = tk.Entry(self.master, show="*")
        self.password_entry.grid(row=1, column=1, padx=10, pady=10, sticky='w')

        captcha_image = generate_captcha()
        self.captcha_img = ImageTk.PhotoImage(Image.open(captcha_image))
        self.captcha_label = tk.Label(self.master, image=self.captcha_img)
        self.captcha_label.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

        tk.Label(self.master, text="Введіть CAPTCHA:").grid(row=3, column=0, padx=10, pady=10, sticky='e')
        self.captcha_entry = tk.Entry(self.master)
        self.captcha_entry.grid(row=3, column=1, padx=10, pady=10, sticky='w')

        tk.Button(self.master, text="Вхід", command=self.login, width=20).grid(row=4, column=0, columnspan=2, pady=20)

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        captcha_input = self.captcha_entry.get().strip()

        if captcha_input.lower() != CAPTCHA_TEXT.lower():
            messagebox.showerror("Помилка", "Неправильна CAPTCHA.")
            return

        if username not in self.users:
            messagebox.showerror("Помилка", "Користувач не знайдений.")
            return

        user = self.users[username]

        if user["is_locked"]:
            messagebox.showerror("Заблоковано", "Ваш обліковий запис заблоковано.")
            return

        if user["password_hash"] == "":
            self.master.withdraw()
            self.set_initial_password(username)
            self.master.deiconify()
            return

        if user["password_hash"] != hash_password(password):
            self.attempts += 1
            remaining = MAX_ATTEMPTS - self.attempts
            if remaining > 0:
                messagebox.showerror("Помилка", f"Неправильний пароль. Залишилось спроб: {remaining}")
            else:
                user["is_locked"] = True
                save_users(self.users)
                log_register_action(username, "заблоковано за перевищення кількості спроб")
                messagebox.showerror("Заблоковано", "Превищено кількість спроб. Обліковий запис заблоковано.")
                self.master.destroy()
            return
        else:
            self.attempts = 0

        log_register_action(username, "успішний вхід")

        if username.upper() == "ADMIN":
            self.master.withdraw()
            admin_window = tk.Toplevel(self.master)
            AdminApp(admin_window, username, self.users, save_users)
        else:
            self.master.withdraw()
            user_window = tk.Toplevel(self.master)
            UserApp(user_window, username, self.users, save_users)

    def set_initial_password(self, username):
        messagebox.showinfo("Первинний вхід", "Необхідно встановити пароль.")
        while True:
            new_password = simpledialog.askstring("Встановити пароль", "Введіть новий пароль:", show="*")
            if new_password is None:
                messagebox.showinfo("Вихід", "Необхідно встановити пароль для входу.")
                self.master.destroy()
                return
            confirm_password = simpledialog.askstring("Підтвердження пароля", "Підтвердіть новий пароль:", show="*")
            if new_password != confirm_password:
                messagebox.showerror("Помилка", "Паролі не співпадають. Спробуйте ще раз.")
                continue
            if self.users[username]["password_restrictions"]:
                if not validate_password(new_password):
                    messagebox.showerror("Помилка", "Пароль повинен містити латинські літери, кириличні символи та розділові знаки.")
                    continue
            self.users[username]["password_hash"] = hash_password(new_password)
            save_users(self.users)
            log_register_action(username, "встановив новий пароль")
            messagebox.showinfo("Успіх", "Пароль успішно встановлено.")
            break

class AdminApp:
    def __init__(self, master, username, users, save_func):
        self.master = master
        self.master.title("Адміністратор")
        self.master.geometry("600x400")
        self.username = username
        self.users = users
        self.save_func = save_func
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.master, text=f"Ласкаво просимо, {self.username}!", font=("Arial", 16)).pack(pady=20)
        tk.Button(self.master, text="Вийти", command=self.logout).pack()

    def logout(self):
        log_register_action(self.username, "вийшов з системи")
        self.master.destroy()
        root.deiconify()

class UserApp:
    def __init__(self, master, username, users, save_func):
        self.master = master
        self.master.title(f"Користувач: {username}")
        self.master.geometry("400x200")
        self.username = username
        self.users = users
        self.save_func = save_func
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.master, text=f"Ласкаво просимо, {self.username}!", font=("Arial", 14)).pack(padx=20, pady=20)
        tk.Button(self.master, text="Вийти", command=self.logout).pack(pady=10)

    def logout(self):
        log_register_action(self.username, "вийшов з системи")
        self.master.destroy()
        root.deiconify()

if __name__ == "__main__":
    root = tk.Tk()
    app = LoginApp(root)
    root.mainloop()
