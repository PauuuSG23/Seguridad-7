# Estructura del proytecto

project/
├─ app.py
├─ forms.py                  # manejo del formulario de entrada con CSRF
├─ requirements.txt          # instalaciones
├─ .env                      # claves reCAPTCHA (pública/privada)
├─ templates/
│  ├─ base.html
│  └─ index.html             # usa form.csrf_token y form.recaptcha
└─ static/
   └─ css/custom.css




# Pasos para correr el proyecto

- 1. Crear y activar entorno virtual:
python -m venv .venv
.\.venv\Scripts\Activate.ps1

- 2. Instalar dependencias:
pip install -r requirements.txt

-------------------------------------------------- DB LOGIN ------------------------------------------------------------------------

# App_login version

0. ) crear la base de datos mysql:
CREATE DATABASE flask_login_demo CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;

1. ) activar el entornor virtual
.\.venv\Scripts\Activate.ps1  


2. ) actualizar el gestor de paquetes oficial pip e Instalar requirements
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
