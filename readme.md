# Crear entorno y acceder

python -m venv .venv

.venv\Scripts\Activate.ps1   

# Copiar requirements.txt

# Instalar dependencias
pip install -r requirements.txt

# Actualizar el pip install*
python.exe -m pip install --upgrade pip

# Copiar las carpetas con los archivos de la estructura base del proyecto

# ---------------- Truncar las tablas
TRUNCATE TABLE user_audit, user_deletions, auth_throttle, users RESTART IDENTITY CASCADE;

## Variables de entorno (.env) — cómo crear y probar

1) Copiar la plantilla a un archivo local `.env` (no subirlo al repo):

```powershell
copy .\.env.template .\.env
code .\.env
```

2) Rellena las variables con los valores de tu proyecto Supabase:

- `DATABASE_URL`: postgresql+psycopg://postgres:TU_PASSWORD@db.<hash>.supabase.co:5432/postgres
- `PSYCOPG_DSN`: postgresql://postgres:TU_PASSWORD@db.<hash>.supabase.co:5432/postgres

3) Probar la conexión sin guardar la contraseña en disco (temporal en la sesión de PowerShell):

```powershell
$env:PSYCOPG_DSN = "postgresql://postgres:TU_PASSWORD@db.<hash>.supabase.co:5432/postgres"
python .\connect_supabase.py
Remove-Item Env:\PSYCOPG_DSN
```

4) Si la conexión falla, revisa:
- Contraseña correcta
- Host correcto (db.<hash>.supabase.co)
- Conexión a Internet y reglas de red

5) Seguridad:
- No subas `.env` a repositorios públicos. Usa `.env.template` en el repo y guarda valores reales localmente o en secretos de CI.
- Si crees que la contraseña se expuso, rota la contraseña desde Supabase: Settings → Database → Reset DB password.
