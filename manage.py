# manage.py, para crear el usuario inicial admin
import os
import getpass
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, User

def main():
    load_dotenv()
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL no definido en .env")

    engine = create_engine(database_url, pool_pre_ping=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    db = Session()

    try:
        print("=== Crear usuario inicial ===")
        username = input("Usuario (e.g., admin): ").strip().lower()
        email = input("Correo (e.g., admin@usta.edu.co): ").strip()

        # pedir contraseña 2 veces
        while True:
            pwd1 = getpass.getpass("Contraseña: ")
            pwd2 = getpass.getpass("Confirmar contraseña: ")
            if pwd1 != pwd2:
                print("Las contraseñas no coinciden. Intenta de nuevo.")
            elif len(pwd1) < 6:
                print("Usa al menos 6 caracteres. Intenta de nuevo.")
            else:
                break

        # ¿ya existe?
        exists = db.query(User).filter((User.username == username) | (User.email == email)).first()
        if exists:
            print("Ya existe un usuario con ese username o email.")
            return

        # crear
        user = User(username=username, email=email, role="admin")
        user.set_password(pwd1)
        db.add(user)
        db.commit()
        print(f"Usuario creado: {username} ({email}) con rol admin.")
    finally:
        db.close()

if __name__ == "__main__":
    main()
