import socket
import threading
from database import setup_database, seed_data_from_csv ,verify_login, get_balance, update_balance, update_password, get_transactions, log_transaction
from encryption import load_rsa_keys, decrypt_rsa, encrypt_rsa

def handle_client(client_socket, private_key, public_key):
    logged_in_clients = {}

    try:
        while True:
            command = client_socket.recv(1024).decode()
            if not command:
                break

            # LOGIN Command
            if command == "LOGIN":
                username = client_socket.recv(1024).decode()
                encrypted_password = client_socket.recv(1024)
                try:
                    password = decrypt_rsa(private_key, encrypted_password)
                except Exception:
                    client_socket.send(b"FAIL")
                    continue

                if verify_login(username, password):
                    logged_in_clients[client_socket] = username
                    client_socket.send(b"SUCCESS")
                else:
                    client_socket.send(b"FAIL")

            # Operations requiring login
            elif command in ["BALANCE", "DEPOSIT", "WITHDRAW", "CHANGE_PASSWORD", "TRANSFER", "TRANSACTIONS"]:
                username = logged_in_clients.get(client_socket)
                if not username:
                    client_socket.send(b"LOGIN_REQUIRED")
                    continue

                if command == "BALANCE":
                    balance = get_balance(username)
                    encrypted_balance = encrypt_rsa(public_key, str(balance))
                    client_socket.send(encrypted_balance)

                elif command == "DEPOSIT":
                    amount = float(client_socket.recv(1024).decode())
                    balance = float(get_balance(username))
                    update_balance(username, balance + amount)
                    log_transaction(username, "DEPOSIT", amount)
                    client_socket.send(b"SUCCESS")

                elif command == "WITHDRAW":
                    amount = float(client_socket.recv(1024).decode())
                    balance = float(get_balance(username))
                    if balance >= amount:
                        update_balance(username, balance - amount)
                        log_transaction(username, "WITHDRAW", amount)
                        client_socket.send(b"SUCCESS")
                    else:
                        client_socket.send(b"INSUFFICIENT_FUNDS")

                elif command == "CHANGE_PASSWORD":
                    old_password_encrypted = client_socket.recv(1024)
                    new_password_encrypted = client_socket.recv(1024)

                    old_password = decrypt_rsa(private_key, old_password_encrypted)
                    new_password = decrypt_rsa(private_key, new_password_encrypted)

                    if verify_login(username, old_password):
                        update_password(username, new_password)
                        client_socket.send(b"SUCCESS")
                    else:
                        client_socket.send(b"INVALID_OLD_PASSWORD")

                elif command == "TRANSFER":
                    recipient = client_socket.recv(1024).decode()
                    amount = float(client_socket.recv(1024).decode())

                    sender_balance = float(get_balance(username))
                    recipient_balance = float(get_balance(recipient))

                    if sender_balance >= amount:
                        update_balance(username, sender_balance - amount)
                        update_balance(recipient, recipient_balance + amount)
                        log_transaction(username, "TRANSFER", amount)
                        client_socket.send(b"SUCCESS")
                    else:
                        client_socket.send(b"INSUFFICIENT_FUNDS")

                elif command == "TRANSACTIONS":
                    transactions = get_transactions(username)
                    client_socket.send(str(transactions).encode())

            elif command == "EXIT":
                logged_in_clients.pop(client_socket, None)
                client_socket.send(b"GOODBYE")
                break

    finally:
        client_socket.close()

def start_server():
    private_key, public_key = load_rsa_keys()
    setup_database()
    seed_data_from_csv("users.csv")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 3000))
    server_socket.listen(5)

    print("Server is running on port 3000...")

    while True:
        client_socket, _ = server_socket.accept()
        threading.Thread(target=handle_client, args=(client_socket, private_key, public_key)).start()

if __name__ == "__main__":
    start_server()