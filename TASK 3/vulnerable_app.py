import sqlite3
import hashlib

# Database connection
conn = sqlite3.connect("users.db")
cursor = conn.cursor()

# Create users table
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT
)
""")

conn.commit()


# Register user
def register(username, password):
    # Vulnerability: weak SHA-256 password hashing
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    cursor.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, password_hash)
    )

    conn.commit()
    print("User registered successfully.")


# Login user
def login(username, password):
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    cursor.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password_hash)
    )

    user = cursor.fetchone()

    if user:
        print("Login successful.")
    else:
        print("Invalid username or password.")


# Main program
print("1. Register")
print("2. Login")

choice = input("Enter choice: ")

if choice == "1":
    username = input("Enter username: ")
    password = input("Enter password: ")
    register(username, password)

elif choice == "2":
    username = input("Enter username: ")
    password = input("Enter password: ")
    login(username, password)

else:
    print("Invalid choice.")

conn.close()