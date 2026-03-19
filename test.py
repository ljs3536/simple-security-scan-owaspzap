import subprocess
import sqlite3
import hashlib
import pickle

# [취약점 1] 하드코딩된 비밀번호 (Hardcoded Credentials)
# 규칙: 변수명에 'key', 'password' 등이 들어가고 문자열이 직접 대입되는 경우 탐지
SECRET_API_KEY = "super_secret_key_12345"
DB_PASSWORD = "admin_password!"

def execute_system_ping(ip_address):
    # [취약점 2] OS 명령어 삽입 (OS Command Injection)
    # 규칙: subprocess 계열 함수 사용 시 'shell=True' 옵션이 켜져 있는지 탐지
    command = f"ping -c 1 {ip_address}"
    subprocess.call(command, shell=True)

def get_user_data(username):
    # [취약점 3] SQL 인젝션 (SQL Injection)
    # 규칙: SQL 쿼리문에 변수를 문자열 포매팅(f-string, % 등)으로 직접 집어넣는지 탐지
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()

def hash_data(data):
    # [취약점 4] 취약한 암호화 알고리즘 (Weak Cryptography)
    # 규칙: hashlib 모듈에서 이미 뚫린 구형 알고리즘(md5, sha1 등)을 호출하는지 탐지
    return hashlib.md5(data.encode()).hexdigest()

def load_user_session(serialized_data):
    # [취약점 5] 안전하지 않은 역직렬화 (Insecure Deserialization)
    # 규칙: 파이썬의 pickle 모듈은 임의의 코드를 실행할 수 있어 사용 자체를 위험으로 탐지
    return pickle.loads(serialized_data)