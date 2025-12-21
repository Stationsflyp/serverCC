import sqlite3
con = sqlite3.connect('oxcy_auth.db')
cur = con.cursor()
cur.execute('SELECT id, username FROM users')
rows = cur.fetchall()
if rows:
    for row in rows:
        print(f"ID: {row[0]}, Username: {row[1]}")
else:
    print("No users found")
con.close()
