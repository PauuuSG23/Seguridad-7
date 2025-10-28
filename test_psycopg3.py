from dotenv import load_dotenv
import os
import psycopg

load_dotenv()

dsn = os.getenv("PSYCOPG_DSN")
assert dsn, "Falta PSYCOPG_DSN en .env" # Data Source Name es el string de conexión

try:
    with psycopg.connect(dsn, sslmode="require") as conn:
        with conn.cursor() as cur:
            cur.execute("select current_database(), current_user, now();")
            print("✅ Conectado:", cur.fetchone())
    print("🔒 Conexión cerrada correctamente.")
except Exception as e:
    print("❌ Error:", e)
