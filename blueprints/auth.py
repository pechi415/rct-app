from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, session, g, flash
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_conn

auth_bp = Blueprint("auth", __name__)

# ---------------------------------------------------------
# [AUTH] Cargar usuario logueado en cada request
# ---------------------------------------------------------
@auth_bp.before_app_request
def load_logged_in_user():
    user_id = session.get("user_id")
    g.user = None
    g.user_minas = []  # SIEMPRE definido

    if not user_id:
        return

    with get_conn() as conn:
        try:
            u = conn.execute(
                """
                    SELECT id, username, rol, is_active, debe_cambiar_pass
                    FROM users
                    WHERE id = ?
                    LIMIT 1
                """,
                (user_id,)
            ).fetchone()

            # Cargar minas del usuario
            rows = conn.execute(
                """
                    SELECT mina
                    FROM user_minas
                    WHERE user_id = ?
                    ORDER BY mina
                """,
                (user_id,)
            ).fetchall()
            g.user_minas = [r["mina"] for r in rows]

        except Exception:
            u = None
            g.user_minas = []

    if u is None:
        session.clear()
        g.user = None
        g.user_minas = []
        return

    if u["is_active"] != 1:
        session.clear()
        g.user = None
        g.user_minas = []
        return

    g.user = dict(u) if u else None

    # Bloqueo para Cambio de Contraseña Obligatorio
    if g.user and g.user.get("debe_cambiar_pass") == 1:
        if request.endpoint not in ["auth.cambiar_password", "auth.logout", "static"]:
            flash("Por seguridad, debes cambiar la contraseña temporal asignada.", "warning")
            return redirect(url_for("auth.cambiar_password"))


# ---------------------------------------------------------
# [DECORATORS] Permisos y Roles
# ---------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))
        if g.user["rol"] != "ADMIN":
            return ("No autorizado", 403)
        return view(*args, **kwargs)
    return wrapped

def roles_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("auth.login"))
            if g.user["rol"] not in roles:
                return ("No autorizado", 403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


# ---------------------------------------------------------
# [RUTAS] Login / Logout / Password
# ---------------------------------------------------------
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        with get_conn() as conn:
            user = conn.execute(
                """
                    SELECT id, username, password_hash, rol, is_active, debe_cambiar_pass
                    FROM users
                    WHERE LOWER(username) = ?
                    LIMIT 1
                """,
                (username,)
            ).fetchone()

        if user is None:
            error = "Usuario o contraseña incorrectos."
        elif user["is_active"] != 1:
            error = "Usuario inactivo."
        elif not check_password_hash(user["password_hash"], password):
            error = "Usuario o contraseña incorrectos."
        else:
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("reportes.ver_reportes"))

    return render_template("login.html", error=error)


@auth_bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))


@auth_bp.route("/mi-cuenta/password", methods=["GET", "POST"])
@login_required
def cambiar_password():
    error = None
    ok = session.pop("flash_ok", None)

    if request.method == "POST":
        actual = request.form.get("actual", "")
        nueva = request.form.get("nueva", "")
        confirmar = request.form.get("confirmar", "")

        if not actual or not nueva or not confirmar:
            error = "Debes completar todos los campos."
        elif nueva != confirmar:
            error = "La nueva contraseña y la confirmación no coinciden."
        elif len(nueva) < 6:
            error = "La nueva contraseña debe tener al menos 6 caracteres."
        else:
            with get_conn() as conn:
                u = conn.execute("""
                    SELECT id, password_hash, is_active
                    FROM users
                    WHERE id = ?
                    LIMIT 1
                """, (g.user["id"],)).fetchone()

                if (not u) or (u["is_active"] != 1):
                    session.clear()
                    return redirect(url_for("auth.login"))

                if not check_password_hash(u["password_hash"], actual):
                    error = "La contraseña actual no es correcta."
                else:
                    era_obligatorio = (g.user.get("debe_cambiar_pass") == 1)

                    conn.execute("""
                        UPDATE users
                        SET password_hash = ?, debe_cambiar_pass = 0
                        WHERE id = ?
                    """, (generate_password_hash(nueva), g.user["id"]))
                    conn.commit()

                    g.user["debe_cambiar_pass"] = 0
                    session["flash_ok"] = "Contraseña actualizada correctamente."
                    
                    if request.endpoint == "auth.cambiar_password" and era_obligatorio:
                        return redirect(url_for("reportes.ver_reportes"))

                    return redirect(url_for("auth.cambiar_password"))

    return render_template("cambiar_password.html", error=error, ok=ok)
