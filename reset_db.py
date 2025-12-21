import sqlite3
import hashlib
import os

db_file = 'oxcy_auth.db'

# Delete old database
if os.path.exists(db_file):
    os.remove(db_file)
    print(f"[OK] Deleted {db_file}")

# Create new database
con = sqlite3.connect(db_file)
cur = con.cursor()

# Create users table
cur.execute("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        hwid TEXT,
        ip TEXT,
        last_login TEXT,
        blocked INTEGER DEFAULT 0,
        app_name TEXT,
        owner_id TEXT,
        secret TEXT,
        is_admin INTEGER DEFAULT 0,
        hwid_locked INTEGER DEFAULT 0,
        hwid_reset_requested INTEGER DEFAULT 0,
        force_logout INTEGER DEFAULT 0,
        version TEXT DEFAULT '1.1'
    )
""")

cur.execute("""
    CREATE TABLE licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        hwid TEXT,
        expires TEXT,
        owner_id TEXT
    )
""")

cur.execute("""
    CREATE TABLE banned_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        hwid TEXT,
        reason TEXT,
        date TEXT
    )
""")

con.commit()
print("[OK] Created tables")

# Create admin user
username = "1"
password = hashlib.sha256("1".encode()).hexdigest()
app_name = "OxcyShop"

cur.execute(
    "INSERT INTO users (username, password, app_name, is_admin) VALUES (?, ?, ?, ?)",
    (username, password, app_name, 1)
)
con.commit()
print(f"[OK] Created user: 1 / 1 (is_admin=1, app_name={app_name})")

# Verify
cur.execute("SELECT id, username, app_name, is_admin FROM users WHERE username=?", (username,))
user = cur.fetchone()
print(f"[OK] Verified: ID={user[0]}, Username={user[1]}, app_name={user[2]}, is_admin={user[3]}")

con.close()
