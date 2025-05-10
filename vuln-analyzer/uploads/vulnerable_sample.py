import os
import sqlite3

# Хардкод паролі (уязвимость)
DB_PASSWORD = "admin123"

def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # SQL-инъекция
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    user = cursor.fetchone()
    
    conn.close()
    return user

def run_ping(ip):
    # Command injection
    os.system("ping " + ip)

def evaluate_expression(expr):
    # eval қолдану — өте қауіпті
    return eval(expr)

# Қолдану мысалы
user = get_user("admin' OR '1'='1")
run_ping("8.8.8.8 && rm -rf /")  # Пайдаланушы енгізген IP арқылы шабуыл
evaluate_expression("__import__('os').system('ls')")
