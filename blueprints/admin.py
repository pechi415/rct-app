from flask import Blueprint, render_template, request, redirect, url_for, g, flash, abort
from werkzeug.security import generate_password_hash
from database import get_conn
from config import ROLES, MINAS
from blueprints.auth import admin_required

admin_bp = Blueprint("admin", __name__)

# =========================================================
# [ADMIN] Usuarios (solo ADMIN)
# =========================================================

@admin_bp.route("/admin/usuarios")
@admin_required
def admin_usuarios():
    with get_conn() as conn:
        users = conn.execute("""
            SELECT id, username, rol, is_active, created_at
            FROM users
            ORDER BY id DESC
        """).fetchall()

        minas_por_user = conn.execute("""
            SELECT user_id, mina
            FROM user_minas
            ORDER BY user_id
        """).fetchall()

    # Agrupar minas por usuario
    mp = {}
    for r in minas_por_user:
        mp.setdefault(r["user_id"], []).append(r["mina"])

    return render_template("admin_usuarios.html", users=users, minas_por_user=mp)


# =========================================================
# [ADMIN] Crear usuarios nuevos
# =========================================================
@admin_bp.route("/admin/usuarios/nuevo", methods=["GET", "POST"])
@admin_required
def admin_usuario_nuevo():
    if request.method == "GET":
        return render_template(
            "admin_usuario_nuevo.html",
            roles=ROLES,
            minas=MINAS
        )

    username = (request.form.get("username") or "").strip().lower()
    password = request.form.get("password") or ""
    rol = (request.form.get("rol") or "").strip().upper()
    is_active = 1 if request.form.get("is_active") in ("1", "on", "true", "True") else 0
    minas_sel = request.form.getlist("minas")

    if not username or not password:
        flash("Faltan datos obligatorios.", "warning")
        return redirect(url_for("admin.admin_usuario_nuevo"))

    if rol not in ROLES:
        flash("Rol inválido.", "warning")
        return redirect(url_for("admin.admin_usuario_nuevo"))

    # ✅ Regla de negocio: si no tiene minas, forzar INACTIVO (antes del INSERT)
    if not minas_sel:
        is_active = 0

    password_hash = generate_password_hash(password)

    with get_conn() as conn:
        # ✅ Check duplicado usando la misma conexión
        if conn.execute(
            "SELECT 1 FROM users WHERE username = ?",
            (username,)
        ).fetchone():
            flash("El usuario ya existe.", "warning")
            return redirect(url_for("admin.admin_usuario_nuevo"))

        # ✅ Crear user (solo columnas reales)
        if getattr(conn, "_is_pg", False):
            row = conn.execute("""
                INSERT INTO users (username, password_hash, rol, is_active, debe_cambiar_pass)
                VALUES (?, ?, ?, ?, 1)
                RETURNING id
            """, (username, password_hash, rol, int(is_active))).fetchone()
            user_id = row["id"] if row else None
        else:
            cur = conn.execute("""
                INSERT INTO users (username, password_hash, rol, is_active, debe_cambiar_pass)
                VALUES (?, ?, ?, ?, 1)
            """, (username, password_hash, rol, int(is_active)))
            user_id = cur.lastrowid

        # ✅ Guardar minas (solo si seleccionó)
        for m in minas_sel:
            m = (m or "").strip().upper()
            if not m:
                continue

            if getattr(conn, "_is_pg", False):
                conn.execute("""
                    INSERT INTO user_minas (user_id, mina)
                    VALUES (?, ?)
                    ON CONFLICT (user_id, mina) DO NOTHING
                """, (user_id, m))
            else:
                conn.execute("""
                    INSERT OR IGNORE INTO user_minas (user_id, mina)
                    VALUES (?, ?)
                """, (user_id, m))

        # ✅ Doble seguro: si no hay minas, dejarlo INACTIVO en BD sí o sí
        if not minas_sel:
            conn.execute(
                "UPDATE users SET is_active = 0 WHERE id = ?",
                (user_id,)
            )

        conn.commit()

    # ✅ Mensaje final coherente
    if not minas_sel:
        flash("Usuario creado como INACTIVO porque no tiene minas asignadas.", "warning")
    else:
        estado_txt = "ACTIVO" if int(is_active) == 1 else "INACTIVO"
        minas_txt = ", ".join(minas_sel)
        flash(f"Usuario creado: {username} ({rol}) — {estado_txt}. Minas: {minas_txt}", "success")

    return redirect(url_for("admin.admin_usuarios"))



@admin_bp.route("/admin/usuarios/<int:user_id>/editar", methods=["GET", "POST"])
@admin_required
def admin_usuario_editar(user_id):
    with get_conn() as conn:
        u = conn.execute(
            "SELECT id, username, rol, is_active FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

        if not u:
            flash("Usuario no encontrado.", "warning")
            return redirect(url_for("admin.admin_usuarios"))

        if request.method == "GET":
            rows = conn.execute(
                "SELECT mina FROM user_minas WHERE user_id = ? ORDER BY mina",
                (user_id,)
            ).fetchall()
            user_minas_set = {r["mina"] for r in rows}

            return render_template(
                "admin_usuario_editar.html",
                u=u,
                roles=ROLES,
                minas=MINAS,
                user_minas_set=user_minas_set
            )

        # POST
        rol = (request.form.get("rol") or "").strip().upper()
        is_active = 1 if request.form.get("is_active") in ("1", "on", "true", "True") else 0
        minas_sel = request.form.getlist("minas")
        new_password = request.form.get("new_password", "").strip()

        if rol not in ROLES:
            flash("Rol inválido.", "warning")
            return redirect(url_for("admin.admin_usuario_editar", user_id=user_id))

        # Validar nueva contraseña si se proporciona
        if new_password and len(new_password) < 6:
            flash("La contraseña debe tener al menos 6 caracteres.", "warning")
            return redirect(url_for("admin.admin_usuario_editar", user_id=user_id))

        # Preparar valores a actualizar
        if new_password:
            password_hash = generate_password_hash(new_password)
            conn.execute("""
                UPDATE users
                SET rol = ?, is_active = ?, password_hash = ?, debe_cambiar_pass = 1
                WHERE id = ?
            """, (rol, int(is_active), password_hash, user_id))
        else:
            conn.execute("""
                UPDATE users
                SET rol = ?, is_active = ?
                WHERE id = ?
            """, (rol, int(is_active), user_id))

        # Reset minas
        conn.execute("DELETE FROM user_minas WHERE user_id = ?", (user_id,))

        for m in minas_sel:
            m = (m or "").strip().upper()
            if not m:
                continue

            if getattr(conn, "_is_pg", False):
                conn.execute("""
                    INSERT INTO user_minas (user_id, mina)
                    VALUES (?, ?)
                    ON CONFLICT (user_id, mina) DO NOTHING
                """, (user_id, m))
            else:
                conn.execute("""
                    INSERT OR IGNORE INTO user_minas (user_id, mina)
                    VALUES (?, ?)
                """, (user_id, m))

        conn.commit()

    flash("Usuario actualizado correctamente.", "success")
    return redirect(url_for("admin.admin_usuarios"))



@admin_bp.post("/admin/usuarios/<int:user_id>/eliminar")
@admin_required
def admin_usuario_eliminar(user_id):
    # No permitir eliminarse a sí mismo
    if user_id == g.user["id"]:
        return ("No puedes eliminar tu propio usuario.", 400)

    with get_conn() as conn:
        u = conn.execute(
            "SELECT id FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

        if not u:
            abort(404)

        # Eliminar relaciones primero
        conn.execute("DELETE FROM user_minas WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))

    return redirect(url_for("admin.admin_usuarios"))
