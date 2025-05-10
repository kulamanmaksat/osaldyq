# SQL Injection Examples
def unsafe_sql_query(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id  # Уязвимо к SQL инъекции
    cursor.execute(query)

def safe_sql_query(user_id):
    query = "SELECT * FROM users WHERE id = ?"  # Безопасно, использует параметризованный запрос
    cursor.execute(query, (user_id,))

# XSS Vulnerability Examples
def unsafe_xss(user_input):
    html = "<div>" + user_input + "</div>"  # Уязвимо к XSS
    document.write(html)

def safe_xss(user_input):
    html = "<div>" + escape(user_input) + "</div>"  # Безопасно, экранирует специальные символы
    element.textContent = html

# Command Injection Examples
def unsafe_command(filename):
    os.system("cat " + filename)  # Уязвимо к инъекции команд
    subprocess.call("echo " + filename, shell=True)

def safe_command(filename):
    subprocess.run(["cat", filename])  # Безопасно, использует список аргументов

# File Operation Examples
def unsafe_file(user_input):
    f = open("data/" + user_input)  # Уязвимо к path traversal
    return f.read()

def safe_file(user_input):
    safe_path = os.path.join(safe_dir, os.path.basename(user_input))  # Безопасно
    return open(safe_path).read()

# Hard-coded Credentials Examples
def unsafe_auth():
    password = "super_secret_123"  # Уязвимо - захардкоженный пароль
    api_key = "1234567890abcdef"  # Уязвимо - захардкоженный ключ API

def safe_auth():
    password = os.environ.get("DB_PASSWORD")  # Безопасно - берёт из переменных окружения
    api_key = config.get("api_key")  # Безопасно - берёт из конфига

# Небезопасная десериализация
import pickle
import yaml
import json

def unsafe_deserialization(data):
    # Уязвимо к атакам через pickle
    return pickle.loads(data)

def unsafe_yaml_load(data):
    # Уязвимо к YAML-бомбам и выполнению кода
    return yaml.load(data)

def safe_deserialization(data):
    # Безопасно - использует json
    return json.loads(data)

# Уязвимости криптографии
from Crypto.Cipher import DES  # Устаревший алгоритм
import hashlib

def unsafe_encryption():
    # Уязвимо - использует устаревший DES
    cipher = DES.new('12345678', DES.MODE_ECB)
    return cipher.encrypt(b"Secret message")

def unsafe_hashing(password):
    # Уязвимо - использует MD5
    return hashlib.md5(password.encode()).hexdigest()

def safe_hashing(password):
    # Безопасно - использует современные методы
    salt = os.urandom(32)
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

# Race Conditions
def unsafe_transaction(user_id, amount):
    balance = get_balance(user_id)
    if balance >= amount:
        # Уязвимо к race condition
        new_balance = balance - amount
        update_balance(user_id, new_balance)
        process_withdrawal(amount)

def safe_transaction(user_id, amount):
    # Безопасно - использует транзакции
    with transaction.atomic():
        balance = get_balance(user_id)
        if balance >= amount:
            new_balance = balance - amount
            update_balance(user_id, new_balance)
            process_withdrawal(amount)

# Buffer Overflow (в Python менее актуально, но важно знать)
def unsafe_buffer():
    # Потенциально уязвимо при использовании с C-расширениями
    buffer = create_string_buffer(10)
    buffer.value = b"A" * 100  # Переполнение буфера

def safe_buffer():
    # Безопасно - проверяем размер
    max_size = 10
    data = b"A" * 100
    if len(data) <= max_size:
        buffer = create_string_buffer(max_size)
        buffer.value = data 