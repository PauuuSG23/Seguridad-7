from flask import Flask, render_template, flash, redirect, url_for, session, request
from dotenv import load_dotenv
from flask_wtf import CSRFProtect
import os
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Dict
import json

from flask_login import LoginManager, login_user, logout_user, login_required, current_user

from markupsafe import Markup, escape
from sqlalchemy import create_engine, or_
from sqlalchemy.orm import sessionmaker, scoped_session, joinedload

# Modelos y formularios
import models  # para models.UserAudit en queries con joinedload
from models import Base, User, UserAudit  # uso directo en la app
from forms import LoginForm, UserCreateForm, UserEditForm, UserSelfEditForm

from werkzeug.exceptions import NotFound

from sqlalchemy.orm import joinedload, aliased
from sqlalchemy import or_

# ===  constantes de throttling y helper === thorttle significa aceleración controlada de un proceso
MAX_FAILS = 2                # Intentos permitidos antes de bloquear
FAIL_WINDOW_SECONDS = 60     # Ventana para contar fallos (1 minuto)
LOCK_SECONDS = 60            # Bloqueo 1 minuto

def normalize_username(u: str) -> str:
    return (u or "").strip().lower()
# ===============================================


load_dotenv()

app = Flask(__name__)
# Configuración base
app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET_KEY", "dev_secret_change_me"),
    WTF_CSRF_SECRET_KEY=os.getenv("WTF_CSRF_SECRET_KEY", "dev_csrf_change_me"),
    RECAPTCHA_PUBLIC_KEY=os.getenv("RECAPTCHA_SITE_KEY"),
    RECAPTCHA_PRIVATE_KEY=os.getenv("RECAPTCHA_SECRET_KEY"),
    RECAPTCHA_PARAMETERS={"hl": "es"},
    # Cookies (ajustar SECURE=True solo si sirves por HTTPS)
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False  # cambiar a True en producción con HTTPS
)

csrf = CSRFProtect(app)

# ---------- SQLAlchemy mysql----------
"""DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("Falta DATABASE_URL en .env (ej: mysql+pymysql://root:@localhost/flask_login_demo)")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False))
Base.metadata.create_all(engine)"""


# ---------- SQLAlchemy postgresql----------
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "Falta DATABASE_URL en .env (ej: postgresql+psycopg://usuario:pass@host:5432/dbname)"
    )

# Supabase exige SSL
engine = create_engine( # crear motor con SSL, es decir, cifrado en la conexión. SSL es Secure Sockets Layer
    DATABASE_URL,
    pool_pre_ping=True,
    connect_args={"sslmode": "require"},
)

SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False))
Base.metadata.create_all(engine)




# ---------- Flask-Login ----------
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Inicia sesión para continuar."
login_manager.login_message_category = "warning"

@login_manager.user_loader
def load_user(user_id):
    db = SessionLocal()
    try:
        return db.get(User, int(user_id))
    finally:
        db.close()

@login_manager.unauthorized_handler
def unauthorized():
    flash("Inicia sesión para continuar.", "warning")
    return redirect(url_for("login", next=request.path))

@app.teardown_appcontext
def remove_session(exception=None):
    SessionLocal.remove()

# ---------- Rutas ----------
@app.route("/")
def index():
    # Landing informativa
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    # Si ya está autenticado, respeta ?next= o lleva a dashboard
    if current_user.is_authenticated:
        dest = request.args.get("next") or url_for("dashboard")
        return redirect(dest)

    form = LoginForm()
    if form.validate_on_submit():
        now = datetime.utcnow()
        input_username = normalize_username(form.username.data)
        db = SessionLocal()
        try:
            # --- 1) Verificar si está bloqueado ---
            from models import AuthThrottle, User  # evita imports circulares en runtime
            throttle = db.query(AuthThrottle).filter(AuthThrottle.username == input_username).first()
            if throttle and throttle.locked_until and now < throttle.locked_until:
                remaining = int((throttle.locked_until - now).total_seconds())
                flash(f"Usuario bloqueado. Inténtalo en {remaining} s.", "danger")
                #  aquí mandamos lock_remaining al template para el banner + countdown
                return render_template("login.html", form=form, lock_remaining=remaining)

            # --- 2) Intentar autenticar ---
            user = db.query(User).filter(User.username == input_username).first()
            is_valid = bool(user and user.check_password(form.password.data))

            if is_valid:
                # éxito → reset de throttle y login
                if throttle:
                    throttle.fail_count = 0
                    throttle.first_fail_at = None
                    throttle.locked_until = None
                    db.add(throttle)
                    db.commit()

                login_user(user)
                flash("¡Bienvenido!", "success")
                next_url = request.args.get("next")
                return redirect(next_url or url_for("dashboard"))

            # --- 3) Fallo: actualizar contadores/lock sin filtrar info ---
            if not throttle:
                throttle = AuthThrottle(
                    username=input_username,
                    fail_count=1,
                    first_fail_at=now,
                    locked_until=None
                )
                db.add(throttle)
                db.commit()
            else:
                # Si ventana venció, reinicia contador
                if not throttle.first_fail_at or (now - throttle.first_fail_at).total_seconds() > FAIL_WINDOW_SECONDS:
                    throttle.fail_count = 1
                    throttle.first_fail_at = now
                    throttle.locked_until = None
                else:
                    throttle.fail_count += 1
                    # ¿se alcanza umbral?
                    if throttle.fail_count >= MAX_FAILS:
                        throttle.fail_count = 0
                        throttle.first_fail_at = None
                        throttle.locked_until = now + timedelta(seconds=LOCK_SECONDS)

                db.add(throttle)
                db.commit()

            # Mensaje genérico (sin filtrar si el usuario existe o no)
            flash("Usuario o contraseña inválidos.", "danger")

        finally:
            db.close()

    elif form.is_submitted():
        for field, errors in form.errors.items():
            for err in errors:
                flash(f"{getattr(form, field).label.text}: {err}", "danger")
        flash("Revisa el formulario.", "warning")

    # Render normal (sin bloqueo)
    return render_template("login.html", form=form)



@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    session.clear()
    flash("Sesión cerrada.", "info")
    return redirect(url_for("login"))

# Páginas protegidas
@app.route("/dashboard")
@login_required
def dashboard():
    data = {"nombre": current_user.username, "correo": current_user.email}
    return render_template("dashboard.html", data=data)

@app.route("/perfil")
@login_required
def perfil():
    data = {"nombre": current_user.username, "correo": current_user.email}
    return render_template("perfil.html", data=data)

@app.route("/reportes")
@login_required
def reportes():
    data = {"nombre": current_user.username, "correo": current_user.email}
    return render_template("reportes.html", data=data)


# --- Ruta: solo admin ---
def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if getattr(current_user, "role", None) != "admin":
            flash("No tienes permisos para esta sección.", "danger")
            return redirect(url_for("dashboard"))
        return view_func(*args, **kwargs)
    return wrapper

# ------------------ Gestión de usuarios (CRUD) ------------------

@app.route("/usuarios")
@login_required
@admin_required
def users_index():
    q = (request.args.get("q") or "").strip()
    db = SessionLocal()
    try:
        query = db.query(User)
        if q:
            like = f"%{q.lower()}%"
            query = query.filter(or_(User.username.ilike(like), User.email.ilike(like)))
        users = query.order_by(User.id.desc()).all()
        return render_template("users_index.html", users=users, q=q)
    finally:
        db.close()


@app.route("/usuarios/crear", methods=["GET", "POST"])
@login_required
@admin_required
def users_create():
    form = UserCreateForm()
    if form.validate_on_submit():
        db = SessionLocal()
        try:
            exists = db.query(User).filter(or_(User.username == form.username.data.lower(),
                                               User.email == form.email.data.lower())).first()
            if exists:
                flash("Ya existe un usuario con ese username o correo.", "danger")
                return render_template("users_form.html", form=form, is_edit=False)

            u = User(
                username=form.username.data.strip().lower(),
                email=form.email.data.strip().lower(),
                role=form.role.data
            )
            u.set_password(form.password.data)
            db.add(u)
            db.commit()

            # Auditoría
            log_audit(
                db,
                user_id=u.id,
                action="admin_user_create",
                detail={"created": {"username": u.username, "email": u.email, "role": u.role}},
                actor_user_id=current_user.id
            )

            flash("Usuario creado correctamente.", "success")
            return redirect(url_for("users_index"))
        finally:
            db.close()
    elif form.is_submitted():
        flash("Revisa el formulario.", "warning")

    return render_template("users_form.html", form=form, is_edit=False)



@app.route("/usuarios/<int:user_id>/editar", methods=["GET", "POST"])
@login_required
@admin_required
def users_edit(user_id: int):
    db = SessionLocal()
    try:
        u = db.get(User, user_id)
        if not u:
            raise NotFound()

        form = UserEditForm(obj=u)
        if form.validate_on_submit():
            # Chequear colisiones...
            clash = db.query(User).filter(
                or_(User.username == form.username.data.strip().lower(),
                    User.email == form.email.data.strip().lower())
            ).filter(User.id != u.id).first()
            if clash:
                flash("Otro usuario ya tiene ese username o correo.", "danger")
                return render_template("users_form.html", form=form, is_edit=True, user=u)

            # === DIFF para auditoría ===
            old_username = u.username
            old_email    = u.email
            old_role     = u.role

            u.username = form.username.data.strip().lower()
            u.email = form.email.data.strip().lower()
            u.role = form.role.data

            pwd_changed = False
            if form.password.data:
                u.set_password(form.password.data)
                pwd_changed = True

            db.add(u)
            db.commit()

            # === AUDITORÍA ===
            changes = {}
            if u.username != old_username:
                changes["username"] = {"old": old_username, "new": u.username}
            if u.email != old_email:
                changes["email"] = {"old": old_email, "new": u.email}
            if u.role != old_role:
                changes["role"] = {"old": old_role, "new": u.role}
            if pwd_changed:
                changes["password"] = "updated"

            if changes:
                log_audit(
                    db,
                    user_id=u.id,                   # usuario afectado
                    action="admin_user_update",
                    detail={"changes": changes, "reason": "admin_edit"},
                    actor_user_id=current_user.id    # quién hizo la acción (admin)
                )

            flash("Usuario actualizado.", "success")
            return redirect(url_for("users_index"))
        elif request.method == "GET":
            form.role.data = u.role

        return render_template("users_form.html", form=form, is_edit=True, user=u)
    finally:
        db.close()



@app.route("/usuarios/<int:user_id>/eliminar", methods=["POST"])
@login_required
@admin_required
def users_delete(user_id: int):
    if user_id == current_user.id:
        flash("No puedes eliminar tu propio usuario mientras estás logueado.", "warning")
        return redirect(url_for("users_index"))

    db = SessionLocal()
    try:
        u = db.get(User, user_id)
        if not u:
            raise NotFound()

        # 1) Auditoría (antes de borrar)
        audit = log_audit(
            db,
            user_id=u.id,
            action="admin_user_delete",
            detail={"deleted": {"username": u.username, "email": u.email, "role": u.role}},
            actor_user_id=current_user.id
        )

        # 2) Snapshot en tabla de eliminados
        record_user_deletion(db, u, actor_id=current_user.id, audit_row=audit)

        # 3) Borrado real
        db.delete(u)
        db.commit()
        flash("Usuario eliminado.", "info")
        return redirect(url_for("users_index"))
    finally:
        db.close()



# --- Ruta: edición de perfil por el propio usuario (sin permitir cambiar el rol) ---

@app.route("/mi-perfil/editar", methods=["GET", "POST"])
@login_required
def self_edit_profile():
    db = SessionLocal()
    try:
        u = db.get(User, current_user.id)
        if not u:
            flash("Usuario no encontrado.", "danger")
            return redirect(url_for("perfil"))

        form = UserSelfEditForm(obj=u)

        if form.validate_on_submit():
            new_username = (form.username.data or "").strip().lower()
            new_email    = (form.email.data or "").strip().lower()
            new_pwd      = (form.new_password.data or "").strip()

            # 1) Colisiones de username/email con otros usuarios
            clash = db.query(User).filter(
                or_(User.username == new_username, User.email == new_email)
            ).filter(User.id != u.id).first()
            if clash:
                flash("Otro usuario ya tiene ese username o correo.", "danger")
                return render_template("perfil_edit.html", form=form)

            # 2) Detectar cambios sensibles
            changing_email    = (new_email != u.email)
            changing_password = bool(new_pwd)

            if changing_email or changing_password:
                # Requiere contraseña actual correcta
                if not form.current_password.data or not u.check_password(form.current_password.data):
                    flash("Debes confirmar tu contraseña actual para cambiar correo o contraseña.", "danger")
                    return render_template("perfil_edit.html", form=form)

            # ================== AUDITORÍA DE CAMBIOS ==================
            # Estado original (por claridad/depuración futura)
            original = {"username": u.username, "email": u.email}

            # Calcula diferencias
            changes = {}
            if new_username != u.username:
                changes["username"] = {"old": u.username, "new": new_username}
            if new_email != u.email:
                changes["email"] = {"old": u.email, "new": new_email}
            if changing_password:
                changes["password"] = "updated"  # Nunca guardes hashes/valores reales
            # ==========================================================

            # 3) Aplicar cambios permitidos
            u.username = new_username
            u.email = new_email
            if changing_password:
                u.set_password(new_pwd)

            db.add(u)
            db.commit()

            # 4) Registrar auditoría si hubo cambios
            if changes:
                log_audit(
                  db,
                  user_id=u.id,  # usuario afectado
                  action="profile_update",
                  detail={
                    "changes": changes,
                    "reason": "self_edit",
                  },
                  actor_user_id=current_user.id  # quien realizó la acción
                )

            flash("Perfil actualizado correctamente.", "success")
            return redirect(url_for("perfil"))

        # GET o errores de validación
        return render_template("perfil_edit.html", form=form)

    finally:
        db.close()



# --- Auditoría de acciones para usuarios, es para obtener IP y User-Agent ---
def _client_ip(req) -> str | None:
    # Respeta proxy/reverse-proxy (Render/NGINX)
    hdr = (req.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    return hdr or req.remote_addr

# --- Auditoría de acciones para usuarios, en esta User-Agent es para obtener el navegador ---
def _ua(req) -> str | None:
    return (req.headers.get("User-Agent") or "")[:255]

# --- Auditoría de acciones para usuarios, en esta función se registra la auditoría ---
def log_audit(db, user_id: int, action: str, detail: dict | None = None, actor_user_id: int | None = None):
    entry = UserAudit(
        user_id=user_id,
        actor_user_id=actor_user_id,
        action=action,
        detail=json.dumps(detail, ensure_ascii=False) if detail else None,
        ip=_client_ip(request),
        user_agent=_ua(request),
    )
    db.add(entry)
    db.commit()
    return entry  



# --- Vista de auditoría personal ---
@app.route("/mi-perfil/auditoria")
@login_required
def my_audit():
    db = SessionLocal()
    try:
        page = max(1, int(request.args.get("page", 1)))
        size = min(50, max(5, int(request.args.get("size", 10))))
        q = db.query(models.UserAudit).filter(models.UserAudit.user_id == current_user.id)\
                                      .order_by(models.UserAudit.id.desc())
        total = q.count()
        audits = q.offset((page-1)*size).limit(size).all()
        return render_template("audit_my.html", audits=audits, page=page, size=size, total=total)
    finally:
        db.close()

# --- Vista de auditoría para admin (todos los usuarios) ---
# app.py


@app.route("/admin/auditoria")
@login_required
@admin_required
def audit_admin():
    db = SessionLocal()
    try:
        q_text = (request.args.get("q") or "").strip().lower()
        page = max(1, int(request.args.get("page", 1)))
        size = min(100, max(10, int(request.args.get("size", 20))))

        # alias para poder filtrar por usuario afectado y actor
        UserAffected = aliased(models.User)
        UserActor    = aliased(models.User)

        qry = (db.query(models.UserAudit)
                .outerjoin(UserAffected, models.UserAudit.user)   # relación "user"
                .outerjoin(UserActor,    models.UserAudit.actor)  # relación "actor"
                .options(
                    joinedload(models.UserAudit.user),
                    joinedload(models.UserAudit.actor),
                )
                .order_by(models.UserAudit.id.desc()))

        if q_text:
            like = f"%{q_text}%"
            qry = qry.filter(or_(
                models.UserAudit.action.ilike(like),
                models.UserAudit.detail.ilike(like),
                models.UserAudit.ip.ilike(like),
                models.UserAudit.user_agent.ilike(like),
                UserAffected.username.ilike(like),   # ← usuario afectado
                UserActor.username.ilike(like),      # ← actor
            ))

        total = qry.count()
        audits = qry.offset((page-1)*size).limit(size).all()

        return render_template("audit_admin.html",
                               audits=audits, page=page, size=size, total=total, q=q_text)
    finally:
        db.close()


@app.template_filter("prettyjson")  # ################################ solo si queremos la vista de cambios en formato json
def prettyjson_filter(value):
    import json
    from markupsafe import Markup, escape
    try:
        if isinstance(value, str):
            data = json.loads(value)
        else:
            data = value
        pretty = json.dumps(data, ensure_ascii=False, indent=2)
        return Markup("<pre class='m-0 small bg-light border rounded p-2'>") + escape(pretty) + Markup("</pre>")
    except Exception:
        return Markup("<pre class='m-0 small bg-light border rounded p-2'>") + escape(value or "") + Markup("</pre>")



@app.route("/admin/mis-acciones")
@login_required
@admin_required
def audit_admin_mine():
    db = SessionLocal()
    try:
        q_text = (request.args.get("q") or "").strip().lower()
        page = max(1, int(request.args.get("page", 1)))
        size = min(100, max(10, int(request.args.get("size", 20))))

        UserAffected = aliased(models.User)

        qry = (db.query(models.UserAudit)
                .filter(models.UserAudit.actor_user_id == current_user.id)
                .outerjoin(UserAffected, models.UserAudit.user)
                .options(
                    joinedload(models.UserAudit.user),
                    joinedload(models.UserAudit.actor),
                )
                .order_by(models.UserAudit.id.desc()))

        if q_text:
            like = f"%{q_text}%"
            qry = qry.filter(or_(
                models.UserAudit.action.ilike(like),
                models.UserAudit.detail.ilike(like),
                models.UserAudit.ip.ilike(like),
                models.UserAudit.user_agent.ilike(like),
                UserAffected.username.ilike(like),   # ← usuario afectado
            ))

        total = qry.count()
        audits = qry.offset((page-1)*size).limit(size).all()

        return render_template("audit_admin_mine.html",
                               audits=audits, page=page, size=size, total=total, q=q_text)
    finally:
        db.close()


@app.template_filter("render_audit_detail")
def render_audit_detail(value):
    """
    Renderiza el campo 'detail' (JSON o dict) en HTML legible:
    - 'changes': lista de cambios old → new; password = 'actualizada'
    - 'created' / 'deleted': ficha con campos
    - 'reason': nota al pie
    """
    # 1) Parsea a dict
    try:
        data = json.loads(value) if isinstance(value, str) else (value or {})
        if not isinstance(data, dict):
            data = {}
    except Exception:
        # Si no es JSON válido, lo mostramos plano
        return Markup("<span class='text-muted small'>") + escape(value or "") + Markup("</span>")

    parts = []

    # 2) Cambios
    changes = data.get("changes")
    if isinstance(changes, dict) and changes:
        rows = []
        for key, val in changes.items():
            if key == "password" and (val == "updated" or (isinstance(val, str) and "updated" in val)):
                rows.append(
                    f"<li class='mb-1'><strong>{escape(key)}</strong>: "
                    f"<span class='badge text-bg-warning'>actualizada</span></li>"
                )
            elif isinstance(val, dict) and "old" in val and "new" in val:
                old = escape(val.get("old", ""))
                new = escape(val.get("new", ""))
                rows.append(
                    "<li class='mb-1'><strong>{k}</strong>: "
                    "<span class='text-danger'>{o}</span> &rarr; "
                    "<span class='text-success'>{n}</span></li>"
                    .format(k=escape(key), o=old, n=new)
                )
            else:
                rows.append(
                    "<li class='mb-1'><strong>{k}</strong>: {v}</li>"
                    .format(k=escape(key), v=escape(str(val)))
                )
        parts.append(
            "<div class='mb-2'>"
            "<div class='fw-semibold mb-1'>Cambios</div>"
            "<ul class='mb-0 small ps-3'>"
            + "".join(rows) +
            "</ul></div>"
        )

    # 3) Creado / Eliminado
    def _render_kv_block(label, obj):
        items = "".join(
            "<dt class='col-sm-4 text-muted'>{k}</dt><dd class='col-sm-8'>{v}</dd>"
            .format(k=escape(k), v=escape(v))
            for k, v in obj.items()
        )
        return (
            "<div class='mb-2'>"
            f"<span class='badge text-bg-secondary'>{label}</span>"
            "<dl class='row small mb-0 mt-2'>" + items + "</dl>"
            "</div>"
        )

    created = data.get("created")
    if isinstance(created, dict) and created:
        parts.append(_render_kv_block("Creado", created))

    deleted = data.get("deleted")
    if isinstance(deleted, dict) and deleted:
        parts.append(_render_kv_block("Eliminado", deleted))

    # 4) reason
    reason = data.get("reason")
    if reason:
        parts.append("<div class='small text-muted mt-1'>Motivo: {}</div>".format(escape(reason)))

    if not parts:
        parts.append("<span class='text-muted'>—</span>")

    return Markup("".join(parts))


def record_user_deletion(db, u: User, actor_id: int | None, audit_row: UserAudit | None = None):
    from models import UserDeletion
    row = UserDeletion(
        user_id=u.id,
        username=u.username,
        email=u.email,
        role=u.role,
        actor_user_id=actor_id,
        ip=_client_ip(request),
        user_agent=_ua(request),
        audit_id=(audit_row.id if audit_row else None),
    )
    db.add(row)
    db.commit()
    return row



@app.route("/admin/eliminados")
@login_required
@admin_required
def audit_deleted():
    db = SessionLocal()
    try:
        q = (request.args.get("q") or "").strip()
        page = max(1, int(request.args.get("page", 1)))
        size = min(100, max(10, int(request.args.get("size", 20))))

        Actor = aliased(models.User)

        qry = (db.query(models.UserDeletion)
               .outerjoin(Actor, models.UserDeletion.actor)
               .options(joinedload(models.UserDeletion.actor))
               .order_by(models.UserDeletion.id.desc()))

        if q:
            like = f"%{q.lower()}%"
            qry = qry.filter(or_(
                models.UserDeletion.username.ilike(like),
                models.UserDeletion.email.ilike(like),
                models.UserDeletion.role.ilike(like),
                Actor.username.ilike(like),
                models.UserDeletion.ip.ilike(like),
                models.UserDeletion.user_agent.ilike(like),
            ))

        total = qry.count()
        rows = qry.offset((page-1)*size).limit(size).all()
        return render_template("audit_deleted.html", rows=rows, page=page, size=size, total=total, q=q)
    finally:
        db.close()




if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8095)
