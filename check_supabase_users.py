# check_supabase_users.py
from sqlalchemy import create_engine, text
from dotenv import load_dotenv
import os

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("❌ No se encontró DATABASE_URL en el archivo .env")

# Crear conexión (igual que en app.py)
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    connect_args={"sslmode": "require"},  # Requerido por Supabase
)

print("Conectando a Supabase...\n")

with engine.connect() as conn:
    # Verificar usuarios
    result = conn.execute(text("SELECT id, username, email, role FROM users ORDER BY id;"))
    rows = result.fetchall()

    if not rows:
        print("⚠️  No hay usuarios registrados en la tabla 'users'.")
    else:
        print("🧑‍💻 Usuarios encontrados:\n")
        for r in rows:
            print(f" - ID {r.id}: {r.username} | {r.email} | Rol: {r.role}")

print("\n✅ Conexión cerrada correctamente.")
