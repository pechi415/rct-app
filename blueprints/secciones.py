
import os
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, g, flash, abort
from database import get_conn, insert_and_get_id
from utils import norm_text
from blueprints.auth import roles_required
from blueprints.reportes import fetch_reporte, reporte_mina_required

secciones_bp = Blueprint("secciones", __name__)

# ---------------------------------------------------------
# [RUTA] GESTIÓN
# ---------------------------------------------------------
@secciones_bp.route("/reportes/<int:reporte_id>/gestion", methods=["GET", "POST"])
@reporte_mina_required
def gestion_areas(reporte_id):
    error = None

    with get_conn() as conn:
        reporte = fetch_reporte(conn, reporte_id)

        if request.method == "POST":
            if g.user is None:
                return redirect(url_for("auth.login"))

            if g.user["rol"] == "LECTOR":
                error = "No tienes permisos para registrar información."
            elif reporte["estado"] == "CERRADO":
                error = "Este reporte está cerrado. No se puede editar."
            else:
                hora = request.form.get("hora", "").strip()
                hallazgo = request.form.get("hallazgo", "").strip()
                accion = request.form.get("accion", "").strip()
                responsable = request.form.get("responsable", "").strip()
                corregido = request.form.get("corregido", "0").strip()

                if hora == "" or not re.match(r'^([01]\d|2[0-3]):[0-5]\d$', hora):
                    error = "La hora debe estar en formato militar HH:MM (00:00 a 23:59)."

                if hora == "" or hallazgo == "" or accion == "" or responsable == "":
                    error = "Todos los campos son obligatorios."
                else:
                    corregido_val = 1 if corregido == "1" else 0
                    conn.execute("""
                        INSERT INTO gestion_areas (reporte_id, hora, hallazgo, accion, corregido, responsable)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (reporte_id, hora, hallazgo, accion, corregido_val, responsable))
                    return redirect(url_for("secciones.gestion_areas", reporte_id=reporte_id))

        items = conn.execute(
            "SELECT * FROM gestion_areas WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()

    return render_template("gestion.html", reporte=reporte, r=reporte, items=items, error=error)


@secciones_bp.route("/reportes/<int:reporte_id>/gestion/<int:item_id>/editar", methods=["GET", "POST"])
@reporte_mina_required
def editar_item_gestion(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)

        if r["estado"] == "CERRADO":
            items = conn.execute(
                "SELECT * FROM gestion_areas WHERE reporte_id = ? ORDER BY id DESC",
                (reporte_id,)
            ).fetchall()
            return render_template(
                "gestion.html",
                r=r, reporte=r, items=items,
                error="Este reporte está CERRADO. No se puede editar."
            )

        item = conn.execute(
            "SELECT * FROM gestion_areas WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        ).fetchone()
        if item is None:
            abort(404)

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                return ("No autorizado", 403)

            hora = request.form.get("hora", "").strip()
            hallazgo = request.form.get("hallazgo", "").strip()
            accion = request.form.get("accion", "").strip()
            responsable = request.form.get("responsable", "").strip()
            corregido = request.form.get("corregido", "0").strip()
            corregido_val = 1 if corregido == "1" else 0

            if hora == "" or not re.match(r'^([01]\d|2[0-3]):[0-5]\d$', hora):
                error = "La hora debe estar en formato militar HH:MM (00:00 a 23:59)."

            if not hora or not hallazgo or not accion or not responsable:
                item_dict = dict(item)
                item_dict.update({
                    "hora": hora,
                    "hallazgo": hallazgo,
                    "accion": accion,
                    "responsable": responsable,
                    "corregido": corregido_val
                })
                return render_template(
                    "gestion_editar.html",
                    r=r, reporte=r, item=item_dict,
                    error="Todos los campos son obligatorios."
                )

            conn.execute("""
                UPDATE gestion_areas
                SET hora = ?, hallazgo = ?, accion = ?, responsable = ?, corregido = ?
                WHERE id = ? AND reporte_id = ?
            """, (hora, hallazgo, accion, responsable, corregido_val, item_id, reporte_id))

            return redirect(url_for("secciones.gestion_areas", reporte_id=reporte_id))

        return render_template("gestion_editar.html", r=r, reporte=r, item=item, error=None)


@secciones_bp.route("/reportes/<int:reporte_id>/gestion/eliminar/<int:item_id>", methods=["POST"])
@reporte_mina_required
def eliminar_item_gestion(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)

        if r["estado"] == "CERRADO":
            items = conn.execute(
                "SELECT * FROM gestion_areas WHERE reporte_id = ? ORDER BY id DESC",
                (reporte_id,)
            ).fetchall()
            return render_template(
                "gestion.html",
                r=r, reporte=r, items=items,
                error="Este reporte está CERRADO. No se puede eliminar."
            )

        if g.user["rol"] == "LECTOR":
            return ("No autorizado", 403)

        conn.execute(
            "DELETE FROM gestion_areas WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        )

    return redirect(url_for("secciones.gestion_areas", reporte_id=reporte_id))


# ---------------------------------------------------------
# [RUTA] BUSES
# ---------------------------------------------------------
@secciones_bp.route("/reportes/<int:reporte_id>/buses", methods=["GET", "POST"])
@reporte_mina_required
def buses_bahias(reporte_id):
    with get_conn() as conn:
        reporte = fetch_reporte(conn, reporte_id)
        error = None

        # ✅ Bahías según mina del reporte
        bahias_base = BAHIAS_POR_MINA.get(reporte["mina"], [])

        items = conn.execute(
            "SELECT * FROM buses_bahias WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()

        usadas = {it["bahia"] for it in items}
        bahias_disponibles = [b for b in bahias_base if b not in usadas]

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                error = "No tienes permisos para registrar información."
            elif reporte["estado"] == "CERRADO":
                error = "Este reporte está cerrado. No se puede editar."
            else:
                bahia = request.form.get("bahia", "").strip()
                hora = request.form.get("hora", "").strip()

                # 🔒 Observación deshabilitada: ignorar cualquier valor enviado
                observacion = ""

                if bahia == "" or hora == "":
                    error = "Bahía y Hora son obligatorios."
                elif not re.match(r'^([01]\d|2[0-3]):[0-5]\d$', hora):
                    error = "La hora debe estar en formato militar HH:MM (00:00 a 23:59)."
                elif bahia not in bahias_base:
                    error = "Debes seleccionar una bahía válida para esta mina."
                elif bahia in usadas:
                    error = f"La bahía {bahia} ya fue registrada en este reporte."
                else:
                    conn.execute("""
                        INSERT INTO buses_bahias (reporte_id, bahia, hora, observacion)
                        VALUES (?, ?, ?, ?)
                    """, (reporte_id, bahia, hora, observacion))
                    return redirect(url_for("buses_bahias", reporte_id=reporte_id))

        # refrescar
        items = conn.execute(
            "SELECT * FROM buses_bahias WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()
        usadas = {it["bahia"] for it in items}
        bahias_disponibles = [b for b in bahias_base if b not in usadas]

    return render_template(
        "buses.html",
        reporte=reporte, r=reporte,
        items=items,
        error=error,
        bahias=bahias_disponibles
    )


@secciones_bp.route("/reportes/<int:reporte_id>/buses/<int:item_id>/editar", methods=["GET", "POST"])
@reporte_mina_required
def editar_item_buses(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)

        # ✅ Bahías según mina del reporte
        bahias_base = BAHIAS_POR_MINA.get(r["mina"], [])

        if r["estado"] == "CERRADO":
            return redirect(url_for("buses_bahias", reporte_id=reporte_id))

        item = conn.execute(
            "SELECT * FROM buses_bahias WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        ).fetchone()
        if item is None:
            abort(404)

        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                return ("No autorizado", 403)

            bahia = request.form.get("bahia", "").strip()
            hora = request.form.get("hora", "").strip()

            # 🔒 Observación deshabilitada: no se edita ni se guarda (se conserva)
            observacion = item["observacion"] or ""

            if bahia == "" or hora == "":
                error = "Bahía y Hora llegada son obligatorios."
            elif not re.match(r'^([01]\d|2[0-3]):[0-5]\d$', hora):
                    error = "La hora debe estar en formato militar HH:MM (00:00 a 23:59)."
            elif bahia not in bahias_base:
                error = "Debes seleccionar una bahía válida para esta mina."
            else:
                conn.execute("""
                    UPDATE buses_bahias
                    SET bahia = ?, hora = ?, observacion = ?
                    WHERE id = ? AND reporte_id = ?
                """, (bahia, hora, observacion, item_id, reporte_id))
                return redirect(url_for("buses_bahias", reporte_id=reporte_id))

        return render_template(
            "buses_editar.html",
            r=r, reporte=r,
            item=item,
            bahias=bahias_base,
            error=error
        )



@secciones_bp.route("/reportes/<int:reporte_id>/buses/eliminar/<int:item_id>", methods=["POST"])
@reporte_mina_required
def eliminar_item_buses(reporte_id, item_id):
    with get_conn() as conn:
        rep = conn.execute(
            "SELECT estado FROM reportes WHERE id = ?",
            (reporte_id,)
        ).fetchone()
        if rep is None:
            abort(404)

        if rep["estado"] == "CERRADO":
            return redirect(url_for("buses_bahias", reporte_id=reporte_id))

        if g.user["rol"] == "LECTOR":
            return ("No autorizado", 403)

        conn.execute(
            "DELETE FROM buses_bahias WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        )

    return redirect(url_for("buses_bahias", reporte_id=reporte_id))


# ---------------------------------------------------------
# [RUTA] VARADOS
# ---------------------------------------------------------
@secciones_bp.route("/reportes/<int:reporte_id>/varados", methods=["GET", "POST"])
@reporte_mina_required
def equipos_varados(reporte_id):
    with get_conn() as conn:
        reporte = fetch_reporte(conn, reporte_id)
        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                error = "No tienes permisos para registrar información."
            elif reporte["estado"] == "CERRADO":
                error = "Este reporte está cerrado. No se puede editar."
            else:
                equipo_raw = request.form.get("equipo", "").strip()
                ubicacion = request.form.get("ubicacion", "").strip()
                motivo = request.form.get("motivo", "").strip()

                if equipo_raw == "" or ubicacion == "" or motivo == "":
                    error = "Todos los campos son obligatorios."
                elif not equipo_raw.isdigit():
                    error = "El equipo debe ser un número entero."
                else:
                    equipo = int(equipo_raw)

                    # ✅ hora ya no aplica
                    hora = None

                    conn.execute("""
                        INSERT INTO equipos_varados (reporte_id, equipo, ubicacion, motivo)
                        VALUES (?, ?, ?, ?)
                    """, (reporte_id, equipo, ubicacion, motivo))

                    return redirect(url_for("equipos_varados", reporte_id=reporte_id))

        items = conn.execute(
            "SELECT * FROM equipos_varados WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()

    return render_template("varados.html", reporte=reporte, r=reporte, items=items, error=error)


@secciones_bp.route("/reportes/<int:reporte_id>/varados/<int:item_id>/editar", methods=["GET", "POST"])
@reporte_mina_required
def editar_item_varados(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)

        if r["estado"] == "CERRADO":
            return redirect(url_for("equipos_varados", reporte_id=reporte_id))

        it = conn.execute(
            "SELECT * FROM equipos_varados WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        ).fetchone()
        if it is None:
            abort(404)

        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                return ("No autorizado", 403)

            equipo_raw = request.form.get("equipo", "").strip()
            ubicacion = request.form.get("ubicacion", "").strip()
            motivo = request.form.get("motivo", "").strip()

            if equipo_raw == "" or ubicacion == "" or motivo == "":
                error = "Todos los campos son obligatorios."
            elif not equipo_raw.isdigit():
                error = "El equipo debe ser un número entero."
            else:
                equipo = int(equipo_raw)

                conn.execute("""
                    UPDATE equipos_varados
                    SET equipo = ?, ubicacion = ?, motivo = ?
                    WHERE id = ? AND reporte_id = ?
                """, (equipo, ubicacion, motivo, item_id, reporte_id))

                return redirect(url_for("equipos_varados", reporte_id=reporte_id))

    return render_template("varados_editar.html", r=r, reporte=r, it=it, error=error)

@secciones_bp.route("/reportes/<int:reporte_id>/varados/<int:item_id>/eliminar", methods=["POST"])
@reporte_mina_required
def eliminar_item_varados(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)

        # Permisos
        if g.user["rol"] == "LECTOR":
            return ("No autorizado", 403)

        # No permitir eliminar si está cerrado
        if r["estado"] == "CERRADO":
            return redirect(url_for("equipos_varados", reporte_id=reporte_id))

        # Validar que exista el item dentro del reporte
        it = conn.execute(
            "SELECT id FROM equipos_varados WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        ).fetchone()

        if it is None:
            abort(404)

        # Eliminar
        conn.execute(
            "DELETE FROM equipos_varados WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        )

    return redirect(url_for("equipos_varados", reporte_id=reporte_id))


# =========================================================
# Bloque 7: Ausentismo + Bombas + Distribución de camiones (CRUD)
# =========================================================

# ---------------------------------------------------------
# [RUTA] Ausentismo
# ---------------------------------------------------------
@secciones_bp.route("/reportes/<int:reporte_id>/ausentismo", methods=["GET", "POST"])
@reporte_mina_required
def ausentismo(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                error = "No tienes permisos para registrar información."
            elif r["estado"] == "CERRADO":
                error = "El reporte está cerrado."
            else:
                nombre = request.form.get("nombre", "").strip()
                motivo = request.form.get("motivo", "").strip()

                if nombre == "" or motivo == "":
                    error = "Debe ingresar el nombre y el motivo."
                else:
                    conn.execute(
                        "INSERT INTO ausentismo (reporte_id, nombre, motivo) VALUES (?, ?, ?)",
                        (reporte_id, nombre, motivo)
                    )
                    return redirect(url_for("ausentismo", reporte_id=reporte_id))

        items = conn.execute(
            "SELECT * FROM ausentismo WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()

    return render_template("ausentismo.html", reporte=r, r=r, items=items, error=error)


@secciones_bp.route("/reportes/<int:reporte_id>/ausentismo/<int:item_id>/editar", methods=["GET", "POST"])
@reporte_mina_required
def editar_item_ausentismo(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        if r["estado"] == "CERRADO":
            return redirect(url_for("ausentismo", reporte_id=reporte_id))

        it = conn.execute(
            "SELECT * FROM ausentismo WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        ).fetchone()
        if it is None:
            abort(404)

        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                return ("No autorizado", 403)

            nombre = request.form.get("nombre", "").strip()
            motivo = request.form.get("motivo", "").strip()

            if nombre == "" or motivo == "":
                error = "Nombre y motivo son obligatorios."
            else:
                conn.execute("""
                    UPDATE ausentismo
                    SET nombre = ?, motivo = ?
                    WHERE id = ? AND reporte_id = ?
                """, (nombre, motivo, item_id, reporte_id))
                return redirect(url_for("ausentismo", reporte_id=reporte_id))

    return render_template("ausentismo_editar.html", r=r, reporte=r, it=it, error=error)


@secciones_bp.route("/reportes/<int:reporte_id>/ausentismo/eliminar/<int:item_id>", methods=["POST"])
@reporte_mina_required
def eliminar_item_ausentismo(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)

        if r["estado"] == "CERRADO":
            return redirect(url_for("ausentismo", reporte_id=reporte_id))

        if g.user["rol"] == "LECTOR":
            return ("No autorizado", 403)

        conn.execute(
            "DELETE FROM ausentismo WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        )

    return redirect(url_for("ausentismo", reporte_id=reporte_id))


# ---------------------------------------------------------
# [RUTA] Bombas
# ---------------------------------------------------------
@secciones_bp.route("/reportes/<int:reporte_id>/bombas", methods=["GET", "POST"])
@reporte_mina_required
def bombas(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                error = "No tienes permisos para registrar información."
            elif r["estado"] == "CERRADO":
                error = "Este reporte está cerrado. No se puede editar."
            else:
                numero = request.form.get("numero", "").strip()
                estado_bomba = request.form.get("estado_bomba", "").strip()
                ubicacion = request.form.get("ubicacion", "").strip()

                if numero == "" or estado_bomba == "" or ubicacion == "":
                    error = "Todos los campos son obligatorios."
                else:
                    conn.execute("""
                        INSERT INTO bombas (reporte_id, numero, estado, ubicacion)
                        VALUES (?, ?, ?, ?)
                    """, (reporte_id, numero, estado_bomba, ubicacion))
                    return redirect(url_for("bombas", reporte_id=reporte_id))

        items = conn.execute(
            "SELECT * FROM bombas WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()

    return render_template("bombas.html", reporte=r, r=r, items=items, error=error)


@secciones_bp.route("/reportes/<int:reporte_id>/bombas/<int:item_id>/editar", methods=["GET", "POST"])
@reporte_mina_required
def editar_bomba(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        if r["estado"] == "CERRADO":
            return redirect(url_for("bombas", reporte_id=reporte_id))

        it = conn.execute(
            "SELECT * FROM bombas WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        ).fetchone()
        if it is None:
            abort(404)

        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                return ("No autorizado", 403)

            numero = request.form.get("numero", "").strip()
            estado_bomba = request.form.get("estado_bomba", "").strip()
            ubicacion = request.form.get("ubicacion", "").strip()

            if numero == "" or estado_bomba == "" or ubicacion == "":
                error = "Todos los campos son obligatorios."
            else:
                conn.execute("""
                    UPDATE bombas
                    SET numero = ?, estado = ?, ubicacion = ?
                    WHERE id = ? AND reporte_id = ?
                """, (numero, estado_bomba, ubicacion, item_id, reporte_id))
                return redirect(url_for("bombas", reporte_id=reporte_id))

    return render_template("bombas_editar.html", r=r, reporte=r, it=it, error=error)


@secciones_bp.route("/reportes/<int:reporte_id>/bombas/eliminar/<int:item_id>", methods=["POST"])
@reporte_mina_required
def eliminar_bomba(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        if r["estado"] == "CERRADO":
            return redirect(url_for("bombas", reporte_id=reporte_id))

        if g.user["rol"] == "LECTOR":
            return ("No autorizado", 403)

        conn.execute(
            "DELETE FROM bombas WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        )

    return redirect(url_for("bombas", reporte_id=reporte_id))


# ---------------------------------------------------------
# [RUTA] Distribución de camiones
# ---------------------------------------------------------
@secciones_bp.route("/reportes/<int:reporte_id>/dist_camiones", methods=["GET", "POST"])
@reporte_mina_required
def dist_camiones(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                error = "No tienes permisos para registrar información."
            elif r["estado"] == "CERRADO":
                error = "Este reporte está cerrado. No se puede editar."
            else:
                tipo = request.form.get("tipo", "").strip()
                cantidad_txt = request.form.get("cantidad", "").strip().replace(",", ".")

                if tipo == "" or tipo not in TIPOS_DISTRIBUCION_CAMIONES:
                    error = "Selecciona un tipo válido."
                else:
                    try:
                        cantidad = float(cantidad_txt)
                    except ValueError:
                        error = "La cantidad debe ser un número (puede llevar decimales)."
                    else:
                        conn.execute("""
                            INSERT INTO distribucion_camiones (reporte_id, tipo, cantidad)
                            VALUES (?, ?, ?)
                        """, (reporte_id, tipo, cantidad))
                        return redirect(url_for("dist_camiones", reporte_id=reporte_id))

        items = conn.execute("""
            SELECT id, tipo, cantidad
            FROM distribucion_camiones
            WHERE reporte_id = ?
            ORDER BY id DESC
        """, (reporte_id,)).fetchall()

        row = conn.execute("""
            SELECT SUM(cantidad)
            FROM distribucion_camiones
            WHERE reporte_id = ?
        """, (reporte_id,)).fetchone()

        total_float = row[0] if row and row[0] is not None else 0
        total_entero = int(round(total_float))

    return render_template(
        "dist_camiones.html",
        r=r, reporte=r,
        tipos=TIPOS_DISTRIBUCION_CAMIONES,
        items=items,
        total=total_entero,
        error=error
    )


@secciones_bp.route("/reportes/<int:reporte_id>/dist_camiones/<int:item_id>/editar", methods=["GET", "POST"])
@reporte_mina_required
def editar_dist_camiones(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        if r["estado"] == "CERRADO":
            return redirect(url_for("dist_camiones", reporte_id=reporte_id))

        item = conn.execute("""
            SELECT id, tipo, cantidad
            FROM distribucion_camiones
            WHERE id = ? AND reporte_id = ?
        """, (item_id, reporte_id)).fetchone()
        if item is None:
            abort(404)

        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                return ("No autorizado", 403)

            tipo = request.form.get("tipo", "").strip()
            cantidad_txt = request.form.get("cantidad", "").strip().replace(",", ".")

            if tipo == "" or tipo not in TIPOS_DISTRIBUCION_CAMIONES:
                error = "Selecciona un tipo válido."
            else:
                try:
                    cantidad = float(cantidad_txt)
                except ValueError:
                    error = "La cantidad debe ser un número."
                else:
                    conn.execute("""
                        UPDATE distribucion_camiones
                        SET tipo = ?, cantidad = ?
                        WHERE id = ? AND reporte_id = ?
                    """, (tipo, cantidad, item_id, reporte_id))
                    return redirect(url_for("dist_camiones", reporte_id=reporte_id))

    return render_template(
        "dist_camiones_editar.html",
        r=r, reporte=r,
        item=item,
        tipos=TIPOS_DISTRIBUCION_CAMIONES,
        error=error
    )


@secciones_bp.route("/reportes/<int:reporte_id>/dist_camiones/<int:item_id>/eliminar", methods=["POST"])
@reporte_mina_required
def eliminar_dist_camiones(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        if r["estado"] == "CERRADO":
            return redirect(url_for("dist_camiones", reporte_id=reporte_id))

        if g.user["rol"] == "LECTOR":
            return ("No autorizado", 403)

        conn.execute(
            "DELETE FROM distribucion_camiones WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        )

    return redirect(url_for("dist_camiones", reporte_id=reporte_id))


# =========================================================
# Bloque 8: Equipo liviano + Personal + Otras áreas + Entrenamiento (CRUD)
# =========================================================

# ---------------------------------------------------------
# [RUTA] Equipo liviano
# ---------------------------------------------------------
@secciones_bp.route("/reportes/<int:reporte_id>/equipo_liviano", methods=["GET", "POST"])
@reporte_mina_required
def equipo_liviano(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)

        mina = r["mina"]
        camionetas = CAMIONETAS_POR_MINA.get(mina, [])
        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                error = "No tienes permisos para registrar información."
            elif r["estado"] == "CERRADO":
                error = "Este reporte está cerrado. No se puede editar."
            else:
                camioneta_sel = request.form.get("camioneta", "").strip()
                camioneta_manual = request.form.get("camioneta_manual", "").strip()

                estado_l = request.form.get("estado_liviano", "OK").strip().upper()
                comentario = request.form.get("comentario", "").strip()

                # 1) Resolver número de camioneta (fija o manual)
                if camioneta_sel == "__OTRA__":
                    if camioneta_manual == "":
                        error = "Debes ingresar el número de la camioneta manual."
                    elif not camioneta_manual.isdigit():
                        error = "La camioneta manual debe ser un número válido."
                    else:
                        camioneta_num = int(camioneta_manual)
                else:
                    if camioneta_sel == "":
                        error = "Debe seleccionar una camioneta."
                    elif (not camioneta_sel.isdigit()) or (int(camioneta_sel) not in [int(x) for x in camionetas]):
                        error = "Debe seleccionar una camioneta válida."
                    else:
                        camioneta_num = int(camioneta_sel)

                # 2) Validar estado
                if error is None and estado_l not in ESTADOS_LIVIANO:
                    error = "Estado inválido."

                # 3) No duplicar dentro del reporte
                if error is None:
                    existe = conn.execute("""
                        SELECT 1
                        FROM equipo_liviano
                        WHERE reporte_id = ? AND camioneta = ?
                        LIMIT 1
                    """, (reporte_id, camioneta_num)).fetchone()

                    if existe:
                        error = f"La camioneta {camioneta_num} ya fue registrada en este reporte."
                    else:
                        conn.execute("""
                            INSERT INTO equipo_liviano (reporte_id, camioneta, estado, comentario)
                            VALUES (?, ?, ?, ?)
                        """, (reporte_id, camioneta_num, estado_l, comentario))
                        return redirect(url_for("equipo_liviano", reporte_id=reporte_id))


        items = conn.execute("""
            SELECT *
            FROM equipo_liviano
            WHERE reporte_id = ?
            ORDER BY id DESC
        """, (reporte_id,)).fetchall()

        ya = conn.execute("""
            SELECT camioneta
            FROM equipo_liviano
            WHERE reporte_id = ?
        """, (reporte_id,)).fetchall()
        ya_set = {row["camioneta"] for row in ya}
        camionetas_disponibles = [str(c) for c in camionetas if int(c) not in ya_set]

    camionetas_base = [str(x) for x in CAMIONETAS_POR_MINA.get(mina, [])]

    return render_template(
        "equipo_liviano.html",
        r=r, reporte=r,
        camionetas=camionetas_disponibles,
        camionetas_base=camionetas_base,
        estados=ESTADOS_LIVIANO,
        items=items,
        error=error
    )


@secciones_bp.route("/reportes/<int:reporte_id>/equipo_liviano/<int:item_id>/editar", methods=["GET", "POST"])
@reporte_mina_required
def editar_equipo_liviano(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        if r["estado"] == "CERRADO":
            return redirect(url_for("equipo_liviano", reporte_id=reporte_id))

        it = conn.execute(
            "SELECT * FROM equipo_liviano WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        ).fetchone()
        if it is None:
            abort(404)

        camionetas = [str(x) for x in CAMIONETAS_POR_MINA.get(r["mina"], [])]
        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                return ("No autorizado", 403)

            camioneta_sel = request.form.get("camioneta", "").strip()
            camioneta_manual = request.form.get("camioneta_manual", "").strip()
            estado = request.form.get("estado", "OK").strip().upper()
            comentario = request.form.get("comentario", "").strip()

            # -------------------------
            # Resolver camioneta (fija o manual)
            # -------------------------
            if camioneta_sel == "__OTRA__":
                if camioneta_manual == "":
                    error = "Debes ingresar el número de la camioneta manual."
                elif not camioneta_manual.isdigit():
                    error = "La camioneta manual debe ser un número válido."
                else:
                    camioneta_num = int(camioneta_manual)
            else:
                if camioneta_sel == "":
                    error = "Debes seleccionar una camioneta."
                elif camioneta_sel not in camionetas:
                    error = "Debes seleccionar una camioneta válida para esta mina."
                else:
                    camioneta_num = int(camioneta_sel)

            # -------------------------
            # Validar estado
            # -------------------------
            if error is None and estado not in ESTADOS_LIVIANO:
                error = "Estado inválido."

            # -------------------------
            # Evitar duplicados en el reporte
            # -------------------------
            if error is None:
                dup = conn.execute("""
                    SELECT 1
                    FROM equipo_liviano
                    WHERE reporte_id = ? AND camioneta = ? AND id <> ?
                """, (reporte_id, camioneta_num, item_id)).fetchone()

                if dup:
                    error = f"La camioneta {camioneta_num} ya está registrada en este reporte."
                else:
                    conn.execute("""
                        UPDATE equipo_liviano
                        SET camioneta = ?, estado = ?, comentario = ?
                        WHERE id = ? AND reporte_id = ?
                    """, (camioneta_num, estado, comentario, item_id, reporte_id))
                    return redirect(url_for("equipo_liviano", reporte_id=reporte_id))

    camionetas_base = [str(x) for x in CAMIONETAS_POR_MINA.get(r["mina"], [])]

    return render_template(
        "equipo_liviano_editar.html",
        r=r, reporte=r,
        it=it,
        camionetas=camionetas,
        camionetas_base=camionetas_base,
        error=error
    )



@secciones_bp.route("/reportes/<int:reporte_id>/equipo_liviano/eliminar/<int:item_id>", methods=["POST"])
@reporte_mina_required
def eliminar_equipo_liviano(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        if r["estado"] == "CERRADO":
            return redirect(url_for("equipo_liviano", reporte_id=reporte_id))

        if g.user["rol"] == "LECTOR":
            return ("No autorizado", 403)

        conn.execute(
            "DELETE FROM equipo_liviano WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        )

    return redirect(url_for("equipo_liviano", reporte_id=reporte_id))


@secciones_bp.route("/reportes/<int:reporte_id>/equipo_liviano/todas_ok", methods=["POST"])
@reporte_mina_required
def equipo_liviano_todas_ok(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        if r["estado"] == "CERRADO":
            return redirect(url_for("equipo_liviano", reporte_id=reporte_id))

        if g.user["rol"] == "LECTOR":
            return ("No autorizado", 403)

        camionetas = CAMIONETAS_POR_MINA.get(r["mina"], [])
        camionetas_int = [int(c) for c in camionetas]

        ya = conn.execute("""
            SELECT camioneta
            FROM equipo_liviano
            WHERE reporte_id = ?
        """, (reporte_id,)).fetchall()
        ya_set = {row["camioneta"] for row in ya}

        faltantes = [c for c in camionetas_int if c not in ya_set]

        for c in faltantes:
            conn.execute("""
                INSERT INTO equipo_liviano (reporte_id, camioneta, estado, comentario)
                VALUES (?, ?, 'OK', '')
            """, (reporte_id, c))

    return redirect(url_for("equipo_liviano", reporte_id=reporte_id))


# ---------------------------------------------------------
# [RUTA] Distribución del personal
# ---------------------------------------------------------
@secciones_bp.route("/reportes/<int:reporte_id>/personal", methods=["GET", "POST"])
@reporte_mina_required
def distribucion_personal(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        error = None

        items = conn.execute("""
            SELECT id, categoria, cantidad
            FROM distribucion_personal
            WHERE reporte_id = ?
            ORDER BY
                CASE
                    WHEN categoria = 'ROSTER' THEN 0
                    WHEN categoria = 'Personal solo día' THEN 1
                    ELSE 2
                END,
                id DESC
        """, (reporte_id,)).fetchall()


        usadas = {it["categoria"] for it in items}
        categorias_disponibles = [c for c in CATEGORIAS_PERSONAL if c not in usadas]
        roster, disponible = calc_disponible_personal(items)

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                error = "No tienes permisos para registrar información."
            elif r["estado"] == "CERRADO":
                error = "Este reporte está cerrado. No se puede editar."
            else:
                categoria = request.form.get("categoria", "").strip()
                cantidad_raw = request.form.get("cantidad", "").strip()

                if categoria == "" or categoria not in CATEGORIAS_PERSONAL:
                    error = "Debe seleccionar una categoría válida."
                elif categoria in usadas:
                    error = "Esta categoría ya fue registrada. Edítala en Acciones."
                elif not cantidad_raw.isdigit():
                    error = "La cantidad debe ser un número entero (0 o mayor)."
                else:
                    cantidad = int(cantidad_raw)
                    try:
                        conn.execute("""
                            INSERT INTO distribucion_personal (reporte_id, categoria, cantidad)
                            VALUES (?, ?, ?)
                        """, (reporte_id, categoria, cantidad))
                        return redirect(url_for("distribucion_personal", reporte_id=reporte_id))
                    except sqlite3.IntegrityError:
                        error = "Esta categoría ya fue registrada. Edítala en Acciones."

        # refrescar
        items = conn.execute("""
            SELECT id, categoria, cantidad
            FROM distribucion_personal
            WHERE reporte_id = ?
            ORDER BY
                CASE
                    WHEN categoria = 'ROSTER' THEN 0
                    WHEN categoria = 'Personal solo día' THEN 1
                    ELSE 2
                END,
                id DESC
        """, (reporte_id,)).fetchall()


        roster, disponible = calc_disponible_personal(items)
        usadas = {it["categoria"] for it in items}
        categorias_disponibles = [c for c in CATEGORIAS_PERSONAL if c not in usadas]

    return render_template(
        "personal.html",
        r=r, reporte=r,
        items=items,
        categorias=categorias_disponibles,
        roster=roster,
        disponible=disponible,
        error=error
    )


@secciones_bp.route("/reportes/<int:reporte_id>/personal/<int:item_id>/editar", methods=["GET", "POST"])
@reporte_mina_required
def editar_personal(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        if r["estado"] == "CERRADO":
            return redirect(url_for("distribucion_personal", reporte_id=reporte_id))

        it = conn.execute("""
            SELECT id, categoria, cantidad
            FROM distribucion_personal
            WHERE id = ? AND reporte_id = ?
        """, (item_id, reporte_id)).fetchone()
        if it is None:
            abort(404)

        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                return ("No autorizado", 403)

            cantidad_raw = request.form.get("cantidad", "").strip()
            if not cantidad_raw.isdigit():
                error = "La cantidad debe ser un número entero (0 o mayor)."
            else:
                cantidad = int(cantidad_raw)
                conn.execute("""
                    UPDATE distribucion_personal
                    SET cantidad = ?
                    WHERE id = ? AND reporte_id = ?
                """, (cantidad, item_id, reporte_id))
                return redirect(url_for("distribucion_personal", reporte_id=reporte_id))

    return render_template("personal_editar.html", r=r, reporte=r, it=it, error=error)


@secciones_bp.route("/reportes/<int:reporte_id>/personal/eliminar/<int:item_id>", methods=["POST"])
@reporte_mina_required
def eliminar_personal(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        if r["estado"] == "CERRADO":
            return redirect(url_for("distribucion_personal", reporte_id=reporte_id))

        if g.user["rol"] == "LECTOR":
            return ("No autorizado", 403)

        conn.execute(
            "DELETE FROM distribucion_personal WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        )

    return redirect(url_for("distribucion_personal", reporte_id=reporte_id))


# ---------------------------------------------------------
# [RUTA] Operadores prestados a otras áreas
# ---------------------------------------------------------
@secciones_bp.route("/reportes/<int:reporte_id>/otras_areas", methods=["GET", "POST"])
@reporte_mina_required
def otras_areas(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                error = "No tienes permisos para registrar información."
            elif r["estado"] == "CERRADO":
                error = "Este reporte está cerrado. No se puede editar."
            else:
                nombre = request.form.get("nombre", "").strip()
                area = request.form.get("area", "").strip()

                if nombre == "" or area == "":
                    error = "Nombre y área son obligatorios."
                elif area not in AREAS_OTRAS:
                    error = "Debe seleccionar un área válida."
                else:
                    conn.execute("""
                        INSERT INTO operadores_otras_areas (reporte_id, nombre, area)
                        VALUES (?, ?, ?)
                    """, (reporte_id, nombre, area))
                    return redirect(url_for("otras_areas", reporte_id=reporte_id))

        items = conn.execute("""
            SELECT *
            FROM operadores_otras_areas
            WHERE reporte_id = ?
            ORDER BY id DESC
        """, (reporte_id,)).fetchall()

    return render_template(
        "otras_areas.html",
        r=r, reporte=r,
        items=items,
        areas=AREAS_OTRAS,
        error=error
    )


@secciones_bp.route("/reportes/<int:reporte_id>/otras_areas/<int:item_id>/editar", methods=["GET", "POST"])
@reporte_mina_required
def editar_otras_areas(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        if r["estado"] == "CERRADO":
            return redirect(url_for("otras_areas", reporte_id=reporte_id))

        it = conn.execute(
            "SELECT * FROM operadores_otras_areas WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        ).fetchone()
        if it is None:
            abort(404)

        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                return ("No autorizado", 403)

            nombre = request.form.get("nombre", "").strip()
            area = request.form.get("area", "").strip()

            if nombre == "" or area == "":
                error = "Nombre y área son obligatorios."
            elif area not in AREAS_OTRAS:
                error = "Debe seleccionar un área válida."
            else:
                conn.execute("""
                    UPDATE operadores_otras_areas
                    SET nombre = ?, area = ?
                    WHERE id = ? AND reporte_id = ?
                """, (nombre, area, item_id, reporte_id))
                return redirect(url_for("otras_areas", reporte_id=reporte_id))

    return render_template(
        "otras_areas_editar.html",
        r=r, reporte=r,
        it=it,
        areas=AREAS_OTRAS,
        error=error
    )


@secciones_bp.route("/reportes/<int:reporte_id>/otras_areas/eliminar/<int:item_id>", methods=["POST"])
@reporte_mina_required
def eliminar_otras_areas(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        if r["estado"] == "CERRADO":
            return redirect(url_for("otras_areas", reporte_id=reporte_id))

        if g.user["rol"] == "LECTOR":
            return ("No autorizado", 403)

        conn.execute(
            "DELETE FROM operadores_otras_areas WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        )

    return redirect(url_for("otras_areas", reporte_id=reporte_id))


# ---------------------------------------------------------
# [RUTA] Personal en entrenamiento
# ---------------------------------------------------------
@secciones_bp.route("/reportes/<int:reporte_id>/entrenamiento", methods=["GET", "POST"])
@reporte_mina_required
def entrenamiento_personal(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        error = None

        items = conn.execute("""
            SELECT id, entrenamiento, cantidad
            FROM entrenamiento_personal
            WHERE reporte_id = ?
            ORDER BY id DESC
        """, (reporte_id,)).fetchall()

        usados = {it["entrenamiento"] for it in items}
        entrenamientos_disponibles = [e for e in ENTRENAMIENTOS_PERSONAL if e not in usados]

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                error = "No tienes permisos para registrar información."
            elif r["estado"] == "CERRADO":
                error = "Este reporte está cerrado. No se puede editar."
            else:
                entrenamiento = request.form.get("entrenamiento", "").strip()
                cantidad_raw = request.form.get("cantidad", "").strip()

                if entrenamiento == "" or entrenamiento not in ENTRENAMIENTOS_PERSONAL:
                    error = "Debe seleccionar un entrenamiento válido."
                elif entrenamiento in usados:
                    error = "Este entrenamiento ya fue registrado. Edítalo en Acciones."
                elif not cantidad_raw.isdigit():
                    error = "La cantidad debe ser un número entero (0 o mayor)."
                else:
                    cantidad = int(cantidad_raw)
                    try:
                        conn.execute("""
                            INSERT INTO entrenamiento_personal (reporte_id, entrenamiento, cantidad)
                            VALUES (?, ?, ?)
                        """, (reporte_id, entrenamiento, cantidad))
                        return redirect(url_for("entrenamiento_personal", reporte_id=reporte_id))
                    except sqlite3.IntegrityError:
                        error = "Este entrenamiento ya fue registrado. Edítalo en Acciones."

        # refrescar
        items = conn.execute("""
            SELECT id, entrenamiento, cantidad
            FROM entrenamiento_personal
            WHERE reporte_id = ?
            ORDER BY id DESC
        """, (reporte_id,)).fetchall()

        usados = {it["entrenamiento"] for it in items}
        entrenamientos_disponibles = [e for e in ENTRENAMIENTOS_PERSONAL if e not in usados]

    return render_template(
        "entrenamiento.html",
        r=r, reporte=r,
        items=items,
        entrenamientos=entrenamientos_disponibles,
        error=error
    )


@secciones_bp.route("/reportes/<int:reporte_id>/entrenamiento/<int:item_id>/editar", methods=["GET", "POST"])
@reporte_mina_required
def editar_entrenamiento_personal(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        if r["estado"] == "CERRADO":
            return redirect(url_for("entrenamiento_personal", reporte_id=reporte_id))

        it = conn.execute("""
            SELECT id, entrenamiento, cantidad
            FROM entrenamiento_personal
            WHERE id = ? AND reporte_id = ?
        """, (item_id, reporte_id)).fetchone()
        if it is None:
            abort(404)

        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                return ("No autorizado", 403)

            cantidad_raw = request.form.get("cantidad", "").strip()
            if not cantidad_raw.isdigit():
                error = "La cantidad debe ser un número entero (0 o mayor)."
            else:
                cantidad = int(cantidad_raw)
                conn.execute("""
                    UPDATE entrenamiento_personal
                    SET cantidad = ?
                    WHERE id = ? AND reporte_id = ?
                """, (cantidad, item_id, reporte_id))
                return redirect(url_for("entrenamiento_personal", reporte_id=reporte_id))

    return render_template(
        "entrenamiento_editar.html",
        r=r, reporte=r,
        it=it,
        error=error
    )


@secciones_bp.route("/reportes/<int:reporte_id>/entrenamiento/eliminar/<int:item_id>", methods=["POST"])
@reporte_mina_required
def eliminar_entrenamiento_personal(reporte_id, item_id):
    with get_conn() as conn:
        rep = conn.execute("SELECT estado FROM reportes WHERE id = ?", (reporte_id,)).fetchone()
        if rep is None:
            abort(404)

        if rep["estado"] == "CERRADO":
            return redirect(url_for("entrenamiento_personal", reporte_id=reporte_id))

        if g.user["rol"] == "LECTOR":
            return ("No autorizado", 403)

        conn.execute(
            "DELETE FROM entrenamiento_personal WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        )

    return redirect(url_for("entrenamiento_personal", reporte_id=reporte_id))


# =========================================================
# Bloque 9: Luminarias + Contactos + Seguridad (CRUD)
# =========================================================

# ---------------------------------------------------------
# [RUTA] Luminarias
# ---------------------------------------------------------
@secciones_bp.route("/reportes/<int:reporte_id>/luminarias", methods=["GET", "POST"])
@reporte_mina_required
def luminarias(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                error = "No tienes permisos para registrar información."
            elif r["estado"] == "CERRADO":
                error = "Este reporte está cerrado. No se puede editar."
            else:
                numero_raw = request.form.get("numero", "").strip()
                ubicacion = request.form.get("ubicacion", "").strip()

                if numero_raw == "":
                    error = "El número de luminaria es obligatorio."
                elif ubicacion == "":
                    error = "La ubicación es obligatoria."
                else:
                    numero = numero_raw.upper()
                    try:
                        conn.execute("""
                            INSERT INTO luminarias (reporte_id, numero, ubicacion)
                            VALUES (?, ?, ?)
                        """, (reporte_id, numero, ubicacion))
                        return redirect(url_for("luminarias", reporte_id=reporte_id))
                    except sqlite3.IntegrityError:
                        error = f"La luminaria {numero} ya fue registrada en este reporte."

        items = conn.execute("""
            SELECT *
            FROM luminarias
            WHERE reporte_id = ?
            ORDER BY id DESC
        """, (reporte_id,)).fetchall()

    return render_template("luminarias.html", r=r, reporte=r, items=items, error=error)


@secciones_bp.route("/reportes/<int:reporte_id>/luminarias/<int:item_id>/editar", methods=["GET", "POST"])
@reporte_mina_required
def editar_luminaria(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        if r["estado"] == "CERRADO":
            return redirect(url_for("luminarias", reporte_id=reporte_id))

        it = conn.execute(
            "SELECT * FROM luminarias WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        ).fetchone()
        if it is None:
            abort(404)

        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                return ("No autorizado", 403)

            numero_raw = request.form.get("numero", "").strip()
            ubicacion = request.form.get("ubicacion", "").strip()

            if numero_raw == "":
                error = "El número de luminaria es obligatorio."
            elif ubicacion == "":
                error = "La ubicación es obligatoria."
            else:
                numero = numero_raw.upper()

                dup = conn.execute("""
                    SELECT 1
                    FROM luminarias
                    WHERE reporte_id = ? AND numero = ? AND id <> ?
                    LIMIT 1
                """, (reporte_id, numero, item_id)).fetchone()

                if dup:
                    error = f"La luminaria {numero} ya fue registrada en este reporte."
                else:
                    conn.execute("""
                        UPDATE luminarias
                        SET numero = ?, ubicacion = ?
                        WHERE id = ? AND reporte_id = ?
                    """, (numero, ubicacion, item_id, reporte_id))
                    return redirect(url_for("luminarias", reporte_id=reporte_id))

    return render_template("luminarias_editar.html", r=r, reporte=r, it=it, error=error)


@secciones_bp.route("/reportes/<int:reporte_id>/luminarias/eliminar/<int:item_id>", methods=["POST"])
@reporte_mina_required
def eliminar_luminaria(reporte_id, item_id):
    with get_conn() as conn:
        rep = conn.execute("SELECT estado FROM reportes WHERE id = ?", (reporte_id,)).fetchone()
        if rep is None:
            abort(404)

        if rep["estado"] == "CERRADO":
            return redirect(url_for("luminarias", reporte_id=reporte_id))

        if g.user["rol"] == "LECTOR":
            return ("No autorizado", 403)

        conn.execute(
            "DELETE FROM luminarias WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        )

    return redirect(url_for("luminarias", reporte_id=reporte_id))


# ---------------------------------------------------------
# [RUTA] Contactos con Operadores
# ---------------------------------------------------------
@secciones_bp.route("/reportes/<int:reporte_id>/contactos", methods=["GET", "POST"])
@reporte_mina_required
def contactos_operadores(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                error = "No tienes permisos para registrar información."
            elif r["estado"] == "CERRADO":
                error = "Este reporte está cerrado. No se puede editar."
            else:
                tipo = request.form.get("tipo", "").strip()
                operador = request.form.get("operador", "").strip()

                if tipo == "" or operador == "":
                    error = "Tipo de contacto y operador son obligatorios."
                elif tipo not in TIPOS_CONTACTO:
                    error = "Debe seleccionar un tipo de contacto válido."
                else:
                    conn.execute("""
                        INSERT INTO contactos_operadores (reporte_id, tipo, operador)
                        VALUES (?, ?, ?)
                    """, (reporte_id, tipo, operador))
                    return redirect(url_for("contactos_operadores", reporte_id=reporte_id))

        items = conn.execute("""
            SELECT *
            FROM contactos_operadores
            WHERE reporte_id = ?
            ORDER BY id DESC
        """, (reporte_id,)).fetchall()

    return render_template(
        "contactos.html",
        r=r, reporte=r,
        items=items,
        tipos=TIPOS_CONTACTO,
        error=error
    )


@secciones_bp.route("/reportes/<int:reporte_id>/contactos/<int:item_id>/editar", methods=["GET", "POST"])
@reporte_mina_required
def editar_contacto_operador(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        if r["estado"] == "CERRADO":
            return redirect(url_for("contactos_operadores", reporte_id=reporte_id))

        it = conn.execute(
            "SELECT * FROM contactos_operadores WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        ).fetchone()
        if it is None:
            abort(404)

        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                return ("No autorizado", 403)

            tipo = request.form.get("tipo", "").strip()
            operador = request.form.get("operador", "").strip()

            if tipo == "" or operador == "":
                error = "Tipo de contacto y operador son obligatorios."
            elif tipo not in TIPOS_CONTACTO:
                error = "Debe seleccionar un tipo de contacto válido."
            else:
                conn.execute("""
                    UPDATE contactos_operadores
                    SET tipo = ?, operador = ?
                    WHERE id = ? AND reporte_id = ?
                """, (tipo, operador, item_id, reporte_id))
                return redirect(url_for("contactos_operadores", reporte_id=reporte_id))

    return render_template(
        "contactos_editar.html",
        r=r, reporte=r,
        it=it,
        tipos=TIPOS_CONTACTO,
        error=error
    )


@secciones_bp.route("/reportes/<int:reporte_id>/contactos/eliminar/<int:item_id>", methods=["POST"])
@reporte_mina_required
def eliminar_contacto_operador(reporte_id, item_id):
    with get_conn() as conn:
        rep = conn.execute("SELECT estado FROM reportes WHERE id = ?", (reporte_id,)).fetchone()
        if rep is None:
            abort(404)

        if rep["estado"] == "CERRADO":
            return redirect(url_for("contactos_operadores", reporte_id=reporte_id))

        if g.user["rol"] == "LECTOR":
            return ("No autorizado", 403)

        conn.execute(
            "DELETE FROM contactos_operadores WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        )

    return redirect(url_for("contactos_operadores", reporte_id=reporte_id))


# ---------------------------------------------------------
# [RUTA] Seguridad (Observación + Charla)
# ---------------------------------------------------------
TIPOS_DIVULGADA = [("1", "Sí"), ("0", "No")]

@secciones_bp.route("/reportes/<int:reporte_id>/seguridad", methods=["GET", "POST"])
@reporte_mina_required
def seguridad(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)

        error_obs = None
        error_charla = None

        if request.method == "POST":
            form_type = request.form.get("form_type", "").strip()

            if g.user is None:
                return redirect(url_for("auth.login"))

            if g.user["rol"] == "LECTOR":
                msg = "No tienes permisos para registrar información."
                error_obs = msg
                error_charla = msg

            elif r["estado"] == "CERRADO":
                msg = "Este reporte está cerrado. No se puede editar."
                error_obs = msg
                error_charla = msg

            else:
                if form_type == "obs":
                    lugar = request.form.get("lugar", "").strip()
                    hallazgos_raw = request.form.get("hallazgos", "").strip()
                    divulgada_raw = request.form.get("divulgada", "").strip()

                    if lugar == "" or hallazgos_raw == "" or divulgada_raw == "":
                        error_obs = "Lugar, # Hallazgos y Divulgada son obligatorios."
                    else:
                        try:
                            hallazgos = int(hallazgos_raw)
                        except ValueError:
                            error_obs = "El número de hallazgos debe ser un entero."
                        else:
                            if hallazgos < 0:
                                error_obs = "El número de hallazgos no puede ser negativo."
                            elif divulgada_raw not in ("0", "1"):
                                error_obs = "Valor inválido para 'Divulgada'."
                            else:
                                divulgada = 1 if divulgada_raw == "1" else 0
                                lugar_norm = norm_text(lugar)
                                try:
                                    conn.execute("""
                                        INSERT INTO seguridad_observaciones
                                        (reporte_id, lugar, lugar_norm, hallazgos, divulgada)
                                        VALUES (?, ?, ?, ?, ?)
                                    """, (reporte_id, lugar, lugar_norm, hallazgos, divulgada))
                                    return redirect(url_for("seguridad", reporte_id=reporte_id))
                                except sqlite3.IntegrityError:
                                    error_obs = "Este registro ya existe (duplicado)."

                elif form_type == "charla":
                    tema = request.form.get("tema", "").strip()
                    personas_raw = request.form.get("personas", "").strip()
                    lugar = request.form.get("lugar", "").strip()

                    if tema == "" or personas_raw == "" or lugar == "":
                        error_charla = "Tema, # Personas y Lugar son obligatorios."
                    else:
                        try:
                            personas = int(personas_raw)
                        except ValueError:
                            error_charla = "El número de personas debe ser un entero."
                        else:
                            if personas < 1:
                                error_charla = "El número de personas debe ser 1 o mayor."
                            else:
                                tema_norm = norm_text(tema)
                                lugar_norm = norm_text(lugar)
                                try:
                                    conn.execute("""
                                        INSERT INTO seguridad_charlas
                                        (reporte_id, tema, tema_norm, personas, lugar, lugar_norm)
                                        VALUES (?, ?, ?, ?, ?, ?)
                                    """, (reporte_id, tema, tema_norm, personas, lugar, lugar_norm))
                                    return redirect(url_for("seguridad", reporte_id=reporte_id))
                                except sqlite3.IntegrityError:
                                    error_charla = "Este registro ya existe (duplicado)."
                else:
                    msg = "Formulario inválido."
                    error_obs = msg
                    error_charla = msg

        obs_items = conn.execute("""
            SELECT id, lugar, hallazgos, divulgada
            FROM seguridad_observaciones
            WHERE reporte_id = ?
            ORDER BY id DESC
        """, (reporte_id,)).fetchall()

        charla_items = conn.execute("""
            SELECT id, tema, personas, lugar
            FROM seguridad_charlas
            WHERE reporte_id = ?
            ORDER BY id DESC
        """, (reporte_id,)).fetchall()

    return render_template(
        "seguridad.html",
        r=r, reporte=r,
        obs_items=obs_items,
        charla_items=charla_items,
        error_obs=error_obs,
        error_charla=error_charla,
        tipos_divulgada=TIPOS_DIVULGADA
    )


@secciones_bp.route("/reportes/<int:reporte_id>/seguridad/obs/<int:item_id>/editar", methods=["GET", "POST"])
@reporte_mina_required
def seguridad_obs_editar(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        if r["estado"] == "CERRADO":
            return redirect(url_for("seguridad", reporte_id=reporte_id))

        it = conn.execute("""
            SELECT id, lugar, hallazgos, divulgada
            FROM seguridad_observaciones
            WHERE id = ? AND reporte_id = ?
        """, (item_id, reporte_id)).fetchone()
        if it is None:
            abort(404)

        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                return ("No autorizado", 403)

            lugar = request.form.get("lugar", "").strip()
            hallazgos_raw = request.form.get("hallazgos", "").strip()
            divulgada_raw = request.form.get("divulgada", "").strip()

            if lugar == "" or hallazgos_raw == "" or divulgada_raw == "":
                error = "Todos los campos son obligatorios."
            else:
                try:
                    hallazgos = int(hallazgos_raw)
                except ValueError:
                    error = "El número de hallazgos debe ser un entero."
                else:
                    if hallazgos < 0:
                        error = "El número de hallazgos no puede ser negativo."
                    elif divulgada_raw not in ("0", "1"):
                        error = "Valor inválido para 'Divulgada'."
                    else:
                        divulgada = 1 if divulgada_raw == "1" else 0
                        lugar_norm = norm_text(lugar)
                        try:
                            conn.execute("""
                                UPDATE seguridad_observaciones
                                SET lugar = ?, lugar_norm = ?, hallazgos = ?, divulgada = ?
                                WHERE id = ? AND reporte_id = ?
                            """, (lugar, lugar_norm, hallazgos, divulgada, item_id, reporte_id))
                            return redirect(url_for("seguridad", reporte_id=reporte_id))
                        except sqlite3.IntegrityError:
                            error = "Este registro ya existe (duplicado)."

    return render_template(
        "seguridad_obs_editar.html",
        r=r, reporte=r,
        it=it,
        error=error,
        tipos_divulgada=TIPOS_DIVULGADA
    )


@secciones_bp.route("/reportes/<int:reporte_id>/seguridad/obs/<int:item_id>/eliminar", methods=["POST"])
@reporte_mina_required
def seguridad_obs_eliminar(reporte_id, item_id):
    with get_conn() as conn:
        rep = conn.execute("SELECT estado FROM reportes WHERE id = ?", (reporte_id,)).fetchone()
        if rep is None:
            abort(404)

        if rep["estado"] == "CERRADO":
            return redirect(url_for("seguridad", reporte_id=reporte_id))

        if g.user["rol"] == "LECTOR":
            return ("No autorizado", 403)

        conn.execute(
            "DELETE FROM seguridad_observaciones WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        )

    return redirect(url_for("seguridad", reporte_id=reporte_id))


@secciones_bp.route("/reportes/<int:reporte_id>/seguridad/charla/<int:item_id>/editar", methods=["GET", "POST"])
@reporte_mina_required
def seguridad_charla_editar(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        if r["estado"] == "CERRADO":
            return redirect(url_for("seguridad", reporte_id=reporte_id))

        it = conn.execute("""
            SELECT id, tema, personas, lugar
            FROM seguridad_charlas
            WHERE id = ? AND reporte_id = ?
        """, (item_id, reporte_id)).fetchone()
        if it is None:
            abort(404)

        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                return ("No autorizado", 403)

            tema = request.form.get("tema", "").strip()
            personas_raw = request.form.get("personas", "").strip()
            lugar = request.form.get("lugar", "").strip()

            if tema == "" or personas_raw == "" or lugar == "":
                error = "Todos los campos son obligatorios."
            else:
                try:
                    personas = int(personas_raw)
                except ValueError:
                    error = "El número de personas debe ser un entero."
                else:
                    if personas < 1:
                        error = "El número de personas debe ser 1 o mayor."
                    else:
                        tema_norm = norm_text(tema)
                        lugar_norm = norm_text(lugar)
                        try:
                            conn.execute("""
                                UPDATE seguridad_charlas
                                SET tema = ?, tema_norm = ?, personas = ?, lugar = ?, lugar_norm = ?
                                WHERE id = ? AND reporte_id = ?
                            """, (tema, tema_norm, personas, lugar, lugar_norm, item_id, reporte_id))
                            return redirect(url_for("seguridad", reporte_id=reporte_id))
                        except sqlite3.IntegrityError:
                            error = "Este registro ya existe (duplicado)."

    return render_template(
        "seguridad_charla_editar.html",
        r=r, reporte=r,
        it=it,
        error=error
    )


@secciones_bp.route("/reportes/<int:reporte_id>/seguridad/charla/<int:item_id>/eliminar", methods=["POST"])
@reporte_mina_required
def seguridad_charla_eliminar(reporte_id, item_id):
    with get_conn() as conn:
        rep = conn.execute("SELECT estado FROM reportes WHERE id = ?", (reporte_id,)).fetchone()
        if rep is None:
            abort(404)

        if rep["estado"] == "CERRADO":
            return redirect(url_for("seguridad", reporte_id=reporte_id))

        if g.user["rol"] == "LECTOR":
            return ("No autorizado", 403)

        conn.execute(
            "DELETE FROM seguridad_charlas WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        )

    return redirect(url_for("seguridad", reporte_id=reporte_id))


# =========================================================
# Bloque 10: First/Last + PTS + Comentarios + Supervisores (CRUD)
# =========================================================

# ---------------------------------------------------------
# [RUTA] FIRST - LAST (ÚNICO)  ✅ sin validación HH:MM
# ---------------------------------------------------------
@secciones_bp.route("/reportes/<int:reporte_id>/first_last", methods=["GET", "POST"])
@reporte_mina_required
def first_last(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)

        item = conn.execute(
            "SELECT * FROM first_last WHERE reporte_id = ?",
            (reporte_id,)
        ).fetchone()

        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                error = "No tienes permisos para registrar información."
            elif r["estado"] == "CERRADO":
                error = "Este reporte está cerrado. No se puede editar."
            else:
                if item is not None:
                    error = "Este registro ya existe. Use Editar."
                else:
                    # ✅ AHORA TODO ES OPCIONAL (puede quedar vacío)
                    inicio_pit2 = request.form.get("inicio_pit2", "").strip()
                    inicio_pit5 = request.form.get("inicio_pit5", "").strip()
                    final_pit2 = request.form.get("final_pit2", "").strip()
                    final_pit5 = request.form.get("final_pit5", "").strip()

                    # ✅ validar hora militar HH:MM (solo si viene algo)
                    pat_hora = r'^([01]\d|2[0-3]):[0-5]\d$'

                    for label, val in [
                        ("Inicio " + ("Pit 2" if r["mina"] == "ED" else "Pribbenow"), inicio_pit2),
                        ("Inicio " + ("Pit 5" if r["mina"] == "ED" else "El Corozo"), inicio_pit5),
                        ("Final " + ("Pit 2" if r["mina"] == "ED" else "Pribbenow"), final_pit2),
                        ("Final " + ("Pit 5" if r["mina"] == "ED" else "El Corozo"), final_pit5),
                    ]:
                        if val != "" and not re.match(pat_hora, val):
                            error = f"{label}: hora inválida. Use formato militar HH:MM (00:00 a 23:59)."
                            break

                    camiones_raw = request.form.get("camiones_por_operador", "").strip()
                    razon = request.form.get("razon", "").strip() or ""  # ✅ NOT NULL safe

                    # ✅ camiones: vacío => 0 (para no violar NOT NULL)
                    if camiones_raw == "":
                        camiones = 0
                    elif not camiones_raw.isdigit():
                        error = "La cantidad de camiones debe ser un número entero (0 o mayor)."
                        camiones = 0
                    else:
                        camiones = int(camiones_raw)

                    # ✅ si camiones > 0 => razón obligatoria
                    if error is None and camiones > 0 and razon == "":
                        error = "Si camiones por operador es mayor que 0, la razón es obligatoria."

                    if error is None:
                        conn.execute("""
                            INSERT INTO first_last
                            (reporte_id, inicio_pit2, inicio_pit5, final_pit2, final_pit5, camiones_por_operador, razon)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, (
                            reporte_id,
                            inicio_pit2, inicio_pit5,
                            final_pit2, final_pit5,
                            camiones, razon
                        ))
                        return redirect(url_for("first_last", reporte_id=reporte_id))

        # refrescar
        item = conn.execute(
            "SELECT * FROM first_last WHERE reporte_id = ?",
            (reporte_id,)
        ).fetchone()

    return render_template("first_last.html", r=r, reporte=r, item=item, error=error)


@secciones_bp.route("/reportes/<int:reporte_id>/first_last/editar", methods=["GET", "POST"])
@reporte_mina_required
def editar_first_last(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        if r["estado"] == "CERRADO":
            return redirect(url_for("first_last", reporte_id=reporte_id))

        it = conn.execute(
            "SELECT * FROM first_last WHERE reporte_id = ?",
            (reporte_id,)
        ).fetchone()
        if it is None:
            return redirect(url_for("first_last", reporte_id=reporte_id))

        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                return ("No autorizado", 403)

            # ✅ AHORA TODO ES OPCIONAL (puede quedar vacío)
            inicio_pit2 = request.form.get("inicio_pit2", "").strip()
            inicio_pit5 = request.form.get("inicio_pit5", "").strip()
            final_pit2 = request.form.get("final_pit2", "").strip()
            final_pit5 = request.form.get("final_pit5", "").strip()

            # ✅ validar hora militar HH:MM (solo si viene algo)
            pat_hora = r'^([01]\d|2[0-3]):[0-5]\d$'

            for label, val in [
                ("Inicio " + ("Pit 2" if r["mina"] == "ED" else "Pribbenow"), inicio_pit2),
                ("Inicio " + ("Pit 5" if r["mina"] == "ED" else "El Corozo"), inicio_pit5),
                ("Final " + ("Pit 2" if r["mina"] == "ED" else "Pribbenow"), final_pit2),
                ("Final " + ("Pit 5" if r["mina"] == "ED" else "El Corozo"), final_pit5),
            ]:
                if val != "" and not re.match(pat_hora, val):
                    error = f"{label}: hora inválida. Use formato militar HH:MM (00:00 a 23:59)."
                    break

            camiones_raw = request.form.get("camiones_por_operador", "").strip()
            razon = request.form.get("razon", "").strip() or ""  # ✅ NOT NULL safe

            # ✅ camiones: vacío => 0 (para no violar NOT NULL)
            if camiones_raw == "":
                camiones = 0
            elif not camiones_raw.isdigit():
                error = "La cantidad de camiones debe ser un número entero (0 o mayor)."
                camiones = 0
            else:
                camiones = int(camiones_raw)

            # ✅ si camiones > 0 => razón obligatoria
            if error is None and camiones > 0 and razon == "":
                error = "Si camiones por operador es mayor que 0, la razón es obligatoria."

            if error is None:
                conn.execute("""
                    UPDATE first_last
                    SET inicio_pit2 = ?,
                        inicio_pit5 = ?,
                        final_pit2 = ?,
                        final_pit5 = ?,
                        camiones_por_operador = ?,
                        razon = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE reporte_id = ?
                """, (
                    inicio_pit2, inicio_pit5,
                    final_pit2, final_pit5,
                    camiones, razon,
                    reporte_id
                ))
                return redirect(url_for("first_last", reporte_id=reporte_id))

        # ✅ IMPORTANTE: siempre retornar respuesta (evita el error de "did not return a valid response")
        return render_template("first_last_editar.html", r=r, reporte=r, it=it, error=error)


@secciones_bp.route("/reportes/<int:reporte_id>/first_last/eliminar", methods=["POST"])
@reporte_mina_required
def eliminar_first_last(reporte_id):
    with get_conn() as conn:
        rep = conn.execute("SELECT estado FROM reportes WHERE id = ?", (reporte_id,)).fetchone()
        if rep is None:
            abort(404)

        if rep["estado"] == "CERRADO":
            return redirect(url_for("first_last", reporte_id=reporte_id))

        if g.user["rol"] == "LECTOR":
            return ("No autorizado", 403)

        conn.execute("DELETE FROM first_last WHERE reporte_id = ?", (reporte_id,))

    return redirect(url_for("first_last", reporte_id=reporte_id))


# ---------------------------------------------------------
# [RUTA] Divulgación PTS (ÚNICO)
# ---------------------------------------------------------
@secciones_bp.route("/reportes/<int:reporte_id>/pts", methods=["GET", "POST"])
@reporte_mina_required
def pts_divulgacion(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        error = None

        item = conn.execute(
            "SELECT * FROM pts_divulgacion WHERE reporte_id = ?",
            (reporte_id,)
        ).fetchone()

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                error = "No tienes permisos para registrar información."
            elif r["estado"] == "CERRADO":
                error = "Este reporte está cerrado. No se puede editar."
            else:
                if item is not None:
                    error = "Ya existe la divulgación del PTS. Usa Editar o Eliminar."
                else:
                    texto = request.form.get("texto", "").strip()
                    if texto == "":
                        error = "El texto de divulgación del PTS es obligatorio."
                    else:
                        conn.execute(
                            "INSERT INTO pts_divulgacion (reporte_id, texto) VALUES (?, ?)",
                            (reporte_id, texto)
                        )
                        return redirect(url_for("pts_divulgacion", reporte_id=reporte_id))

        item = conn.execute(
            "SELECT * FROM pts_divulgacion WHERE reporte_id = ?",
            (reporte_id,)
        ).fetchone()

    return render_template("pts.html", r=r, reporte=r, item=item, error=error)


@secciones_bp.route("/reportes/<int:reporte_id>/pts/editar", methods=["GET", "POST"])
@reporte_mina_required
def pts_editar(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        if r["estado"] == "CERRADO":
            return redirect(url_for("pts_divulgacion", reporte_id=reporte_id))

        item = conn.execute(
            "SELECT * FROM pts_divulgacion WHERE reporte_id = ?",
            (reporte_id,)
        ).fetchone()
        if item is None:
            return redirect(url_for("pts_divulgacion", reporte_id=reporte_id))

        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                return ("No autorizado", 403)

            texto = request.form.get("texto", "").strip()
            if texto == "":
                error = "El texto es obligatorio."
            else:
                conn.execute(
                    "UPDATE pts_divulgacion SET texto = ? WHERE reporte_id = ?",
                    (texto, reporte_id)
                )
                return redirect(url_for("pts_divulgacion", reporte_id=reporte_id))

    return render_template("pts_editar.html", r=r, reporte=r, item=item, error=error)


@secciones_bp.route("/reportes/<int:reporte_id>/pts/eliminar", methods=["POST"])
@reporte_mina_required
def pts_eliminar(reporte_id):
    with get_conn() as conn:
        rep = conn.execute("SELECT estado FROM reportes WHERE id = ?", (reporte_id,)).fetchone()
        if rep is None:
            abort(404)

        if rep["estado"] == "CERRADO":
            return redirect(url_for("pts_divulgacion", reporte_id=reporte_id))

        if g.user["rol"] == "LECTOR":
            return ("No autorizado", 403)

        conn.execute("DELETE FROM pts_divulgacion WHERE reporte_id = ?", (reporte_id,))

    return redirect(url_for("pts_divulgacion", reporte_id=reporte_id))


# ---------------------------------------------------------
# [RUTA] Comentarios del turno (MÚLTIPLES)
# ---------------------------------------------------------
@secciones_bp.route("/reportes/<int:reporte_id>/comentarios", methods=["GET", "POST"])
@reporte_mina_required
def comentarios_turno(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                error = "No tienes permisos para registrar información."
            elif r["estado"] == "CERRADO":
                error = "Este reporte está cerrado. No se puede editar."
            else:
                comentario = request.form.get("comentario", "").strip()
                if comentario == "":
                    error = "El comentario es obligatorio."
                else:
                    conn.execute(
                        "INSERT INTO comentarios_turno (reporte_id, comentario) VALUES (?, ?)",
                        (reporte_id, comentario)
                    )
                    return redirect(url_for("comentarios_turno", reporte_id=reporte_id))

        items = conn.execute(
            "SELECT * FROM comentarios_turno WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()

    return render_template("comentarios.html", r=r, reporte=r, items=items, error=error)


@secciones_bp.route("/reportes/<int:reporte_id>/comentarios/<int:item_id>/editar", methods=["GET", "POST"])
@reporte_mina_required
def comentarios_editar(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        if r["estado"] == "CERRADO":
            return redirect(url_for("comentarios_turno", reporte_id=reporte_id))

        item = conn.execute(
            "SELECT * FROM comentarios_turno WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        ).fetchone()
        if item is None:
            abort(404)

        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                return ("No autorizado", 403)

            comentario = request.form.get("comentario", "").strip()
            if comentario == "":
                error = "El comentario es obligatorio."
            else:
                conn.execute(
                    "UPDATE comentarios_turno SET comentario = ? WHERE id = ? AND reporte_id = ?",
                    (comentario, item_id, reporte_id)
                )
                return redirect(url_for("comentarios_turno", reporte_id=reporte_id))

    return render_template("comentarios_editar.html", r=r, reporte=r, item=item, error=error)


@secciones_bp.route("/reportes/<int:reporte_id>/comentarios/eliminar/<int:item_id>", methods=["POST"])
@reporte_mina_required
def comentarios_eliminar(reporte_id, item_id):
    with get_conn() as conn:
        rep = conn.execute("SELECT estado FROM reportes WHERE id = ?", (reporte_id,)).fetchone()
        if rep is None:
            abort(404)

        if rep["estado"] == "CERRADO":
            return redirect(url_for("comentarios_turno", reporte_id=reporte_id))

        if g.user["rol"] == "LECTOR":
            return ("No autorizado", 403)

        conn.execute(
            "DELETE FROM comentarios_turno WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        )

    return redirect(url_for("comentarios_turno", reporte_id=reporte_id))


# ---------------------------------------------------------
# [RUTA] Supervisores del turno
# ---------------------------------------------------------
@secciones_bp.route("/reportes/<int:reporte_id>/supervisores", methods=["GET", "POST"])
@reporte_mina_required
def supervisores_turno(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        error = None

        # ✅ Supervisores según mina del reporte
        sup_mina = SUPERVISORES_POR_MINA.get(r["mina"], {})

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                error = "No tienes permisos para registrar información."
            elif r["estado"] == "CERRADO":
                error = "Este reporte está cerrado. No se puede editar."
            else:
                grupo = request.form.get("grupo", "").strip()
                accion = request.form.get("accion", "seleccionados").strip()
                seleccionados = request.form.getlist("supervisores")

                if grupo not in GRUPOS_SUP:
                    error = "Debes seleccionar un grupo válido (G1, G2 o G3)."
                else:
                    # ✅ válidos solo de ESTA mina y ESTE grupo
                    validos = set(sup_mina.get(grupo, []))

                    if accion == "todos":
                        a_insertar = list(validos)
                    else:
                        a_insertar = [s for s in seleccionados if s in validos]

                    if not a_insertar:
                        error = "Debes seleccionar al menos un supervisor (o usar 'Seleccionar todos')."
                    else:
                        for sup in a_insertar:
                            try:
                                conn.execute("""
                                    INSERT INTO supervisores_turno (reporte_id, grupo, supervisor)
                                    VALUES (?, ?, ?)
                                """, (reporte_id, grupo, sup))
                            except sqlite3.IntegrityError:
                                pass

                        return redirect(url_for("supervisores_turno", reporte_id=reporte_id))

        items = conn.execute("""
            SELECT *
            FROM supervisores_turno
            WHERE reporte_id = ?
            ORDER BY
                CASE grupo WHEN 'G1' THEN 1 WHEN 'G2' THEN 2 WHEN 'G3' THEN 3 ELSE 99 END,
                supervisor ASC
        """, (reporte_id,)).fetchall()

    return render_template(
        "supervisores.html",
        r=r, reporte=r,
        items=items,
        error=error,
        grupos=GRUPOS_SUP,
        sup_por_grupo=sup_mina
    )



@secciones_bp.route("/reportes/<int:reporte_id>/supervisores/<int:item_id>/editar", methods=["GET", "POST"])
@reporte_mina_required
def editar_supervisor_turno(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)

        # ✅ Supervisores según mina del reporte
        sup_mina = SUPERVISORES_POR_MINA.get(r["mina"], {})

        if r["estado"] == "CERRADO":
            return redirect(url_for("supervisores_turno", reporte_id=reporte_id))

        it = conn.execute("""
            SELECT *
            FROM supervisores_turno
            WHERE id = ? AND reporte_id = ?
        """, (item_id, reporte_id)).fetchone()
        if it is None:
            abort(404)

        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                return ("No autorizado", 403)

            grupo = request.form.get("grupo", "").strip()
            supervisor = request.form.get("supervisor", "").strip()

            if grupo not in GRUPOS_SUP:
                error = "Grupo inválido."
            else:
                validos = set(sup_mina.get(grupo, []))
                if supervisor not in validos:
                    error = "Supervisor inválido para el grupo seleccionado en esta mina."
                else:
                    dup = conn.execute("""
                        SELECT 1
                        FROM supervisores_turno
                        WHERE reporte_id = ? AND grupo = ? AND supervisor = ? AND id <> ?
                        LIMIT 1
                    """, (reporte_id, grupo, supervisor, item_id)).fetchone()

                    if dup:
                        error = "Ese supervisor ya está registrado en ese grupo para este reporte."
                    else:
                        conn.execute("""
                            UPDATE supervisores_turno
                            SET grupo = ?, supervisor = ?
                            WHERE id = ? AND reporte_id = ?
                        """, (grupo, supervisor, item_id, reporte_id))

                        return redirect(url_for("supervisores_turno", reporte_id=reporte_id))

    return render_template(
        "supervisores_editar.html",
        r=r, reporte=r,
        it=it,
        error=error,
        grupos=GRUPOS_SUP,
        sup_por_grupo=sup_mina
    )



@secciones_bp.route("/reportes/<int:reporte_id>/supervisores/eliminar/<int:item_id>", methods=["POST"])
@reporte_mina_required
def eliminar_supervisor_turno(reporte_id, item_id):
    with get_conn() as conn:
        rep = conn.execute("SELECT estado FROM reportes WHERE id = ?", (reporte_id,)).fetchone()
        if rep is None:
            abort(404)

        if rep["estado"] == "CERRADO":
            return redirect(url_for("supervisores_turno", reporte_id=reporte_id))

        if g.user["rol"] == "LECTOR":
            return ("No autorizado", 403)

        conn.execute("""
            DELETE FROM supervisores_turno
            WHERE id = ? AND reporte_id = ?
        """, (item_id, reporte_id))

    return redirect(url_for("supervisores_turno", reporte_id=reporte_id))


# ---------------------------------------------------------
# [RUTA] Fatiga y Pausas
# ---------------------------------------------------------
@secciones_bp.route("/reportes/<int:reporte_id>/fatiga", methods=["GET", "POST"])
@reporte_mina_required
def fatiga(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                error = "No tienes permisos para registrar información."
            elif r["estado"] == "CERRADO":
                error = "El reporte está cerrado."
            else:
                try:
                    reportes_sueno = int(request.form.get("reportes_sueno", 0))
                    pausas_activas = int(request.form.get("pausas_activas", 0))

                    if reportes_sueno < 0 or pausas_activas < 0:
                        error = "Los valores no pueden ser negativos."
                    else:
                        conn.execute("""
                            INSERT INTO fatiga_pausas (reporte_id, reportes_sueno, pausas_activas)
                            VALUES (?, ?, ?)
                        """, (reporte_id, reportes_sueno, pausas_activas))
                        return redirect(url_for("secciones.fatiga", reporte_id=reporte_id))
                except ValueError:
                    error = "Los valores deben ser enteros válidos."

        items = conn.execute(
            "SELECT * FROM fatiga_pausas WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()

    return render_template("fatiga.html", r=r, items=items, error=error)


@secciones_bp.route("/reportes/<int:reporte_id>/fatiga/<int:item_id>/editar", methods=["GET", "POST"])
@reporte_mina_required
def editar_item_fatiga(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        if r["estado"] == "CERRADO":
            return redirect(url_for("secciones.fatiga", reporte_id=reporte_id))

        it = conn.execute(
            "SELECT * FROM fatiga_pausas WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        ).fetchone()
        if it is None:
            abort(404)

        error = None

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                return ("No autorizado", 403)

            try:
                reportes_sueno = int(request.form.get("reportes_sueno", 0))
                pausas_activas = int(request.form.get("pausas_activas", 0))

                if reportes_sueno < 0 or pausas_activas < 0:
                    error = "Los valores no pueden ser negativos."
                else:
                    conn.execute("""
                        UPDATE fatiga_pausas
                        SET reportes_sueno = ?, pausas_activas = ?
                        WHERE id = ? AND reporte_id = ?
                    """, (reportes_sueno, pausas_activas, item_id, reporte_id))
                    return redirect(url_for("secciones.fatiga", reporte_id=reporte_id))
            except ValueError:
                error = "Los valores deben ser enteros válidos."

    return render_template("fatiga_editar.html", r=r, item=it, error=error)


@secciones_bp.route("/reportes/<int:reporte_id>/fatiga/eliminar/<int:item_id>", methods=["POST"])
@reporte_mina_required
def eliminar_item_fatiga(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        if r["estado"] == "CERRADO":
            return redirect(url_for("secciones.fatiga", reporte_id=reporte_id))

        if g.user["rol"] == "LECTOR":
            return ("No autorizado", 403)

        conn.execute(
            "DELETE FROM fatiga_pausas WHERE id = ? AND reporte_id = ?",
            (item_id, reporte_id)
        )

    return redirect(url_for("secciones.fatiga", reporte_id=reporte_id))

