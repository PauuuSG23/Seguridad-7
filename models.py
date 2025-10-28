# models.py
from flask_login import UserMixin
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Integer, Enum
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import Integer, String, DateTime, func
from datetime import datetime
from sqlalchemy import Text, ForeignKey
from sqlalchemy.orm import relationship

class Base(DeclarativeBase):  # para heredar en los modelos, es decir para hacer el mapeo ORM
    pass # pass es para indicar que no hay nada más que hacer aquí, es un marcador de posición.

class User(Base, UserMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(120), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(Enum("admin","usuario", name="role_enum"), default="usuario", nullable=False)

    # helpers
    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class AuthThrottle(Base):
    __tablename__ = "auth_throttle"  # “limitador de autenticación” o “control de intentos de login”. 

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    fail_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_fail_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), server_default=func.now(), onupdate=func.now(), nullable=False)

class UserAudit(Base):
    __tablename__ = "user_audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    actor_user_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True)
    action: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # ej: 'profile_update', 'login_success'
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)              # JSON/Texto breve
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)            # IPv4/IPv6 (45 chars)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), server_default=func.now(), nullable=False)

    user = relationship("User", foreign_keys=[user_id])
    actor = relationship("User", foreign_keys=[actor_user_id])



class UserDeletion(Base):
    __tablename__ = "user_deletions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Identidad del eliminado (snapshot)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)  # id que tenía
    username: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    # Actor (quien eliminó)
    actor_user_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"), index=True)
    actor = relationship("User", foreign_keys=[actor_user_id])
    # Metadatos
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    deleted_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), server_default=func.now(), nullable=False)
    #  vínculo al evento de auditoría
    audit_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("user_audit.id", ondelete="SET NULL"), nullable=True)
