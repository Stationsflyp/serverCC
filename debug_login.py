import sqlite3
import hashlib

def sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()

con = sqlite3.connect('oxcy_auth.db')
cur = con.cursor()

# Check if user exists
cur.execute("SELECT id, username, password, is_admin FROM users WHERE username=?", ("admin",))
user = cur.fetchone()

if user:
    print(f"✓ User found:")
    print(f"  ID: {user[0]}")
    print(f"  Username: {user[1]}")
    print(f"  is_admin: {user[3]}")
    print(f"  Stored password hash: {user[2]}")
    
    # Check password
    test_pass = "admin123"
    calc_hash = sha256(test_pass)
    print(f"\n✓ Calculated hash for 'admin123': {calc_hash}")
    
    if user[2] == calc_hash:
        print(f"✓ PASSWORD MATCHES!")
    else:
        print(f"✗ PASSWORD DOES NOT MATCH")
        print(f"  Stored:     {user[2]}")
        print(f"  Calculated: {calc_hash}")
else:
    print("✗ User 'admin' not found")
    print("\nAll users in database:")
    cur.execute("SELECT id, username, is_admin FROM users")
    for row in cur.fetchall():
        print(f"  ID={row[0]}, Username={row[1]}, is_admin={row[2]}")

con.close()
