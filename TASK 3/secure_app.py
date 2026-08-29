import sqlite3
import hashlib
import os
import getpass

DATABASE = "secure_users.db"


# Database connection
def get_connection():
    return sqlite3.connect(DATABASE)


# Create database table
def initialize_database():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()


# Secure password hashing using PBKDF2
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        100000
    )

    return password_hash.hex(), salt.hex()


# Password verification
def verify_password(password, stored_hash, stored_salt):
    salt = bytes.fromhex(stored_salt)

    password_hash, _ = hash_password(password, salt)

    return password_hash == stored_hash


# Password policy
def valid_password(password):
    return len(password) >= 8


# Register user
def register(username, password):

    username = username.strip()

    if not username:
        print("Username cannot be empty.")
        return

    if not valid_password(password):
        print("Password must contain at least 8 characters.")
        return

    password_hash, salt = hash_password(password)

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO users
            (username, password_hash, salt)
            VALUES (?, ?, ?)
            """,
            (username, password_hash, salt)
        )

        conn.commit()
        print("User registered successfully.")

    except sqlite3.IntegrityError:
        print("Username already exists.")

    finally:
        conn.close()


# Login user
def login(username, password):

    username = username.strip()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT password_hash, salt
        FROM users
        WHERE username = ?
        """,
        (username,)
    )

    user = cursor.fetchone()
    conn.close()

    if user:
        stored_hash, stored_salt = user

        if verify_password(password, stored_hash, stored_salt):
            print("Login successful.")
            return

    print("Invalid username or password.")


# Main program
initialize_database()

print("\n===== Secure User Authentication =====")
print("1. Register")
print("2. Login")

choice = input("Enter choice: ")

if choice == "1":

    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    register(username, password)

elif choice == "2":

    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    login(username, password)

else:
    print("Invalid choice.")