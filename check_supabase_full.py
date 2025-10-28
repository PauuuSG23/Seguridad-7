# check_supabase_full.py
from sqlalchemy import create_engine, text
from dotenv import load_dotenv
import os

# === 1️⃣ Cargar variables del entorno ===
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("❌ No se encontró DATABASE_URL en el archivo .env")

# === 2️⃣ Conexión a Supabase ===
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    connect_args={"sslmode": "require"},  # 🔒 Supabase exige SSL
)

print("\n🌐 Conectando a Supabase...\n")

# === 3️⃣ Ejecutar consultas ===
with engine.connect() as conn:
    # Obtener lista de tablas
    tables = [
        "users",
        "auth_throttle",
        "user_audit",
        "user_deletions",
    ]

    for table in tables:
        try:
            count = conn.execute(text(f"SELECT COUNT(*) FROM {table};")).scalar()
            print(f"📊 Tabla '{table}': {count} registros")

            if table == "users" and count > 0:
                print("   👥 Usuarios:")
                result = conn.execute(text("SELECT id, username, email, role FROM users ORDER BY id;"))
                for r in result.fetchall():
                    print(f"     - ID {r.id}: {r.username} | {r.email} | Rol: {r.role}")

            elif table == "auth_throttle" and count > 0:
                print("   🔐 Registros de intentos fallidos (Auth Throttle):")
                result = conn.execute(text("SELECT username, fail_count, locked_until FROM auth_throttle ORDER BY id DESC LIMIT 5;"))
                for r in result.fetchall():
                    print(f"     - {r.username}: {r.fail_count} fallos | bloqueado hasta {r.locked_until}")

            elif table == "user_audit" and count > 0:
                print("   🕵️‍♂️ Registros de auditoría recientes:")
                result = conn.execute(text("SELECT id, user_id, action, ip FROM user_audit ORDER BY id DESC LIMIT 5;"))
                for r in result.fetchall():
                    print(f"     - Audit {r.id}: user_id={r.user_id}, acción={r.action}, IP={r.ip}")

            elif table == "user_deletions" and count > 0:
                print("   🗑️ Registros de usuarios eliminados:")
                result = conn.execute(text("SELECT username, role, actor_user_id FROM user_deletions ORDER BY id DESC LIMIT 5;"))
                for r in result.fetchall():
                    print(f"     - {r.username} ({r.role}) eliminado por {r.actor_user_id}")

            print("")  # salto entre tablas

        except Exception as e:
            print(f"⚠️ No se pudo acceder a la tabla '{table}': {e}")
            continue

print("✅ Conexión cerrada correctamente.\n")
