from dotenv import load_dotenv
import os
import psycopg

load_dotenv()

dsn = os.getenv("PSYCOPG_DSN") or "postgresql://postgres:usTa202510.@db.jfqrpfgjnquepxdwovbg.supabase.co:5432/postgres"

try:
    with psycopg.connect(dsn, sslmode="require") as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT current_database(), current_user, NOW();")
            print("✅ Conectado:", cur.fetchone())
    print("🔒 Conexión cerrada correctamente.")
except Exception as e:
    print("❌ Error:", e)
