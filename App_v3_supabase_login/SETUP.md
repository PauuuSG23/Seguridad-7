# Setup rápido (PowerShell)

1) Crear y activar entorno virtual

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2) Actualizar pip e instalar dependencias

```powershell
python.exe -m pip install --upgrade pip
pip install -r ..\requirements.txt
```

3) Copiar la plantilla `.env.template` a `.env` y rellenar los valores (especialmente la contraseña y host de Supabase)

```powershell
copy .env.template .env
# luego editar .env con Notepad o VSCode
code .\.env
```

4) Crear proyecto en Supabase (manual)
- Ir a https://app.supabase.com → crear nuevo proyecto.
- En "Database" → Settings → Ver/Reset DB password; copiar host (ej. db.xxxxx.supabase.co), puerto (5432), user (postgres), password y dbname.
- Construir la `PSYCOPG_DSN` y `DATABASE_URL` en `.env` con los datos fornidos.

5) Probar conexión (opcional)

```powershell
# desde la raíz del repo
python .\connect_supabase.py
```

Notas:
- Supabase requiere SSL: las conexiones suelen usar `sslmode=require`.
- No subir el archivo `.env` a repositorios públicos. Use secretos en CI/CD.
