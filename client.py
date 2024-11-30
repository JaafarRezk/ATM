import socket
from encryption import load_rsa_keys, decrypt_rsa, encrypt_rsa

def print_menu():
    print("\nATM Simulation")
    print("1. Login")
    print("2. Check Balance")
    print("3. Deposit")
    print("4. Withdraw")
    print("5. Change Password")
    print("6. Transfer")
    print("7. View Transactions")
    print("8. Exit")

def main():
    private_key, public_key = load_rsa_keys()

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 3000)) 
    print("Connected to the server!")

    logged_in = False
    while True:
        print_menu()
        choice = input("Enter your choice: ")

        if choice == "1":
            client_socket.send(b"LOGIN")
            username = input("Enter username: ")
            password = input("Enter password: ")
            encrypted_password = encrypt_rsa(public_key, password)  
            client_socket.send(username.encode()) 
            client_socket.send(encrypted_password) 

            response = client_socket.recv(1024).decode()
            if response == "SUCCESS":
                logged_in = True
                print("Login successful!")
            else:
                print("Login failed!")

        elif logged_in: 
            if choice == "2":
                client_socket.send(b"BALANCE")
                encrypted_balance = client_socket.recv(1024)
                balance = decrypt_rsa(private_key, encrypted_balance) 
                print(f"Your balance is: {balance}")

            elif choice == "3":  
                client_socket.send(b"DEPOSIT")
                amount = input("Enter deposit amount: ")
                client_socket.send(amount.encode())
                print(client_socket.recv(1024).decode())

            elif choice == "4": 
                client_socket.send(b"WITHDRAW")
                amount = input("Enter withdrawal amount: ")
                client_socket.send(amount.encode()) 
                print(client_socket.recv(1024).decode())

            elif choice == "5": 
                client_socket.send(b"CHANGE_PASSWORD")
                old_password = input("Enter old password: ")
                new_password = input("Enter new password: ")
                encrypted_old = encrypt_rsa(public_key, old_password) 
                encrypted_new = encrypt_rsa(public_key, new_password)  
                client_socket.send(encrypted_old)
                client_socket.send(encrypted_new)
                print(client_socket.recv(1024).decode())

            elif choice == "6":
                client_socket.send(b"TRANSFER")
                recipient = input("Enter recipient username: ")
                amount = input("Enter transfer amount: ")
                client_socket.send(recipient.encode())  
                client_socket.send(amount.encode()) 
                print(client_socket.recv(1024).decode())

            elif choice == "7": 
                client_socket.send(b"TRANSACTIONS")
                transactions = client_socket.recv(1024).decode()
                print("Transactions:")
                print(transactions)

            elif choice == "8": 
                client_socket.send(b"EXIT")
                print("Goodbye!")
                break

        else:
            print("Please login first!")

    client_socket.close()

if __name__ == "__main__":
    main()
