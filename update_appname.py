import sqlite3

con = sqlite3.connect('oxcy_auth.db')
cur = con.cursor()

# Actualizar app_name para el usuario admin
cur.execute(
    "UPDATE users SET app_name=? WHERE username=?",
    ("OxcyShop", "1")
)
con.commit()

# Verificar
cur.execute("SELECT owner_id, secret, app_name FROM users WHERE username=?", ("1",))
user = cur.fetchone()
print("✓ Usuario actualizado:")
print(f"  Owner ID: {user[0]}")
print(f"  Secret: {user[1]}")
print(f"  App Name: {user[2]}")

con.close()
