import sqlite3
import hashlib

con = sqlite3.connect('oxcy_auth.db')
cur = con.cursor()

username = "admin"
password = hashlib.sha256("admin123".encode()).hexdigest()

try:
    cur.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
        (username, password, 1)
    )
    con.commit()
    print(f"✓ User created: {username}")
    print(f"  Password: admin123")
except sqlite3.IntegrityError:
    print(f"✗ User already exists: {username}")

con.close()
