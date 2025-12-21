import sqlite3

con = sqlite3.connect('oxcy_auth.db')
cur = con.cursor()

print("=== USUARIOS EN LA BASE DE DATOS ===\n")
cur.execute("SELECT id, username, owner_id, secret, app_name, is_admin FROM users")
for row in cur.fetchall():
    print(f"ID: {row[0]}")
    print(f"Username: {row[1]}")
    print(f"Owner ID: |{row[2]}|")
    print(f"Secret: |{row[3]}|")
    print(f"App Name: |{row[4]}|")
    print(f"Is Admin: {row[5]}")
    print()

con.close()
