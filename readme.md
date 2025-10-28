# Crear entorno y acceder

- crear el entorno
python -m venv .venv

- acceder al entorno
.venv\Scripts\Activate.ps1   

# Copiar requirements.txt

# Instalar dependencias
pip install -r requirements.txt

# Actualizar el pip install*
python.exe -m pip install --upgrade pip

# Copiar las carpetas con los archivos de la estructura base del proyecto

# ---------------- Truncar las tablas
TRUNCATE TABLE user_audit, user_deletions, auth_throttle, users RESTART IDENTITY CASCADE;
