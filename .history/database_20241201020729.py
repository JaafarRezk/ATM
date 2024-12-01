import sqlite3
import csv
from encryption import hash_password

def setup_database():
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            balance REAL NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            amount REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (username) REFERENCES users (username)
        )
    ''')

    conn.commit()
    conn.close()

def verify_login(username, password):
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()

    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    conn.close()
    if result:
        stored_password_hash = result[0]
        return stored_password_hash == hash_password(password) 
    return False


def get_balance(username):
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()

    cursor.execute("SELECT balance FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    conn.close()
    return result[0] if result else None

def update_balance(username, new_balance):
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()

    cursor.execute("UPDATE users SET balance = ? WHERE username = ?", (new_balance, username))
    conn.commit()
    conn.close()

def update_password(username, new_password):
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()

    cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hash_password(new_password), username))
    conn.commit()
    conn.close()

def log_transaction(username, action, amount):
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()

    cursor.execute("INSERT INTO transactions (username, action, amount) VALUES (?, ?, ?)", (username, action, amount))
    conn.commit()
    conn.close()

def get_transactions(username):
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()

    cursor.execute("SELECT action, amount, timestamp FROM transactions WHERE username = ? ORDER BY timestamp DESC", (username,))
    transactions = cursor.fetchall()

    conn.close()
    return transactions

def seed_data_from_csv(file_path):
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()

    try:
        with open(file_path, mode='r', encoding='utf-8') as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                username = row['username']
                password = hash_password(row['password'])
                balance = float(row['balance'])
                
                try:
                    cursor.execute("INSERT INTO users (username, password, balance) VALUES (?, ?, ?)", (username, password, balance))
                except sqlite3.IntegrityError:
                    pass 
    except FileNotFoundError:
        print(f"Error: The file {file_path} does not exist.")
    except KeyError as e:
        print(f"Error: Missing column in CSV file: {e}")

    conn.commit()
    conn.close()
