# forms.py
# forms.py
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, Email, Optional,EqualTo

class LoginForm(FlaskForm):
    username = StringField(
        "Usuario",
        validators=[DataRequired("El usuario es obligatorio."), Length(min=3, max=50)]
    )
    password = PasswordField(
        "Contraseña",
        validators=[DataRequired("La contraseña es obligatoria.")]
    )
    recaptcha = RecaptchaField()
    submit = SubmitField("Ingresar")


class UserCreateForm(FlaskForm):
    username = StringField("Usuario", validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField("Correo", validators=[DataRequired(), Email(), Length(max=120)])
    role = SelectField("Rol", choices=[("admin", "admin"), ("usuario", "usuario")], validators=[DataRequired()])
    password = PasswordField("Contraseña", validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Crear")


class UserEditForm(FlaskForm):
    username = StringField("Usuario", validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField("Correo", validators=[DataRequired(), Email(), Length(max=120)])
    role = SelectField("Rol", choices=[("admin", "admin"), ("usuario", "usuario")], validators=[DataRequired()])
    # Password opcional al editar; si lo dejas vacío no cambia
    password = PasswordField("Nueva contraseña (opcional)", validators=[Optional(), Length(min=6)])
    submit = SubmitField("Guardar cambios")

class UserSelfEditForm(FlaskForm):
    """Edición de perfil por el propio usuario (sin permitir el cambio de rol)."""
    username = StringField("Usuario", validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField("Correo", validators=[DataRequired(), Email(), Length(max=120)])

    # Cambios sensibles
    current_password = PasswordField("Contraseña actual (requerida si cambias correo o contraseña)", validators=[Optional()])
    new_password = PasswordField("Nueva contraseña (opcional)", validators=[Optional(), Length(min=6, message="Mínimo 6 caracteres.")])
    confirm_new_password = PasswordField("Confirmar nueva contraseña",validators=[Optional(), EqualTo("new_password", message="Las contraseñas no coinciden.")])
    submit = SubmitField("Guardar cambios")