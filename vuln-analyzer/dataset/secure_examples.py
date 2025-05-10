# Безопасные примеры работы с базой данных
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import text

def safe_db_query(user_id):
    # Используем ORM и параметризованные запросы
    session = Session()
    result = session.query(User).filter(User.id == user_id).first()
    return result

# Безопасная обработка пользовательского ввода
from html import escape
import bleach

def safe_html_handler(user_input):
    # Экранируем HTML и разрешаем только безопасные теги
    clean_html = bleach.clean(user_input, 
                            tags=['p', 'b', 'i', 'u'],
                            attributes={})
    return clean_html

# Безопасная работа с файлами
import os
from pathlib import Path

def safe_file_operations(filename):
    # Используем pathlib для безопасной работы с путями
    safe_base_dir = Path("/safe/directory")
    safe_path = safe_base_dir / Path(filename).name
    
    if safe_path.exists() and safe_path.is_file():
        return safe_path.read_text()
    return None

# Безопасная конфигурация
from configparser import ConfigParser
import os

def safe_config():
    config = ConfigParser()
    # Загружаем конфигурацию из файла
    config.read('config.ini')
    
    # Используем переменные окружения для чувствительных данных
    db_password = os.environ.get('DB_PASSWORD')
    api_key = os.environ.get('API_KEY')
    
    return {
        'db_password': db_password,
        'api_key': api_key,
        'debug_mode': config.getboolean('app', 'debug', fallback=False)
    }

# Безопасная обработка команд
import subprocess

def safe_command_execution(command_args):
    # Используем список аргументов вместо shell=True
    try:
        result = subprocess.run(
            command_args,
            capture_output=True,
            text=True,
            timeout=30,
            shell=False
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Command timed out"
    except subprocess.SubprocessError:
        return "Command failed"

# Безопасная сериализация и десериализация
import json
from marshmallow import Schema, fields

class UserSchema(Schema):
    id = fields.Int(required=True)
    name = fields.Str(required=True)
    email = fields.Email(required=True)

def safe_serialization(data):
    # Используем схему для валидации и сериализации
    schema = UserSchema()
    return schema.dumps(data)

def safe_deserialization(json_data):
    # Используем схему для валидации и десериализации
    schema = UserSchema()
    return schema.loads(json_data)

# Безопасная криптография
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def safe_encryption(message):
    # Используем современные методы шифрования
    key = Fernet.generate_key()
    f = Fernet(key)
    return f.encrypt(message.encode())

def safe_password_hashing(password):
    # Используем современные методы хеширования с солью
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    return {'key': key, 'salt': salt}

# Безопасная работа с многопоточностью
import threading
from threading import Lock

class SafeCounter:
    def __init__(self):
        self._counter = 0
        self._lock = Lock()
    
    def increment(self):
        with self._lock:
            self._counter += 1
            return self._counter

# Безопасная валидация входных данных
from typing import Optional
from pydantic import BaseModel, EmailStr, constr

class UserInput(BaseModel):
    username: constr(min_length=3, max_length=50)
    email: EmailStr
    age: Optional[int] = None

def safe_input_validation(data: dict):
    # Используем Pydantic для валидации
    try:
        user = UserInput(**data)
        return user
    except ValueError as e:
        return {'error': str(e)} 