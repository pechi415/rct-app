
import os
import gc
from datetime import date, datetime
from flask import Blueprint, render_template, request, redirect, url_for, g, flash, abort, make_response
from weasyprint import HTML
from database import get_conn, get_db_connection
from config import MINAS, CAMIONETAS_POR_MINA
from utils import mina_label, calc_disponible_personal, get_personal_label
from blueprints.auth import roles_required

reportes_bp = Blueprint("reportes", __name__)

# Necesitamos traer fetch_reporte para que funcione aquí.
def fetch_reporte(conn, reporte_id: int):
    r = conn.execute(
        "SELECT id, fecha, turno, mina, estado FROM reportes WHERE id = ?",
        (reporte_id,)
    ).fetchone()
    if r is None:
        abort(404)
    return r

from functools import wraps
def reporte_mina_required(view):
    @wraps(view)
    def wrapped(reporte_id, *args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))
        # ADMIN bypass total
        if g.user["rol"] == "ADMIN":
            return view(reporte_id, *args, **kwargs)
        with get_conn() as conn:
            r = fetch_reporte(conn, reporte_id)
        if r["mina"] not in (g.user_minas or set()):
            return ("No autorizado para esta mina", 403)
        return view(reporte_id, *args, **kwargs)
    return wrapped



# =========================================================
# Bloque 4: Contexto del reporte (para resumen/PDF) + PDF
# =========================================================

def build_reporte_context(conn, reporte_id: int) -> dict:
    """
    Construye un diccionario con toda la data del reporte para:
      - resumen.html
      - pdf/reporte_pdf.html
    """
    r = fetch_reporte(conn, reporte_id)

    camionetas_base = [str(x) for x in CAMIONETAS_POR_MINA.get(r["mina"], [])]


    # -------------------------
    # Gestión / Buses / Varados
    # -------------------------
    gestion = conn.execute(
        "SELECT * FROM gestion_areas WHERE reporte_id = ? ORDER BY id DESC",
        (reporte_id,)
    ).fetchall()

    buses = conn.execute(
        "SELECT * FROM buses_bahias WHERE reporte_id = ? ORDER BY id DESC",
        (reporte_id,)
    ).fetchall()

    equipos = conn.execute(
        "SELECT * FROM equipos_varados WHERE reporte_id = ? ORDER BY id DESC",
        (reporte_id,)
    ).fetchall()

    # -------------------------
    # Ausentismo / Bombas
    # -------------------------
    ausentismo_items = conn.execute(
        "SELECT * FROM ausentismo WHERE reporte_id = ? ORDER BY id DESC",
        (reporte_id,)
    ).fetchall()

    bombas_items = conn.execute(
        "SELECT * FROM bombas WHERE reporte_id = ? ORDER BY id DESC",
        (reporte_id,)
    ).fetchall()

    # -------------------------
    # Distribución camiones (agrupada)
    # -------------------------
    dist_camiones = conn.execute("""
        SELECT tipo, ROUND(SUM(cantidad)::numeric, 2) AS cantidad
        FROM distribucion_camiones
        WHERE reporte_id = ?
        GROUP BY tipo
        ORDER BY
            CASE tipo
                WHEN 'Operativos' THEN 1
                WHEN 'Down' THEN 2
                WHEN 'Stand By con Operador' THEN 3
                WHEN 'Stand By sin Operador' THEN 4
                WHEN 'Carbon' THEN 5
                WHEN 'Stand By no programado' THEN 6
                ELSE 99
            END
    """, (reporte_id,)).fetchall()

    total_camiones = conn.execute(
        "SELECT COALESCE(SUM(cantidad), 0) FROM distribucion_camiones WHERE reporte_id = ?",
        (reporte_id,)
    ).fetchone()[0]
    total_camiones = int(round(total_camiones))

    camiones_disponibles = 0
    for d in dist_camiones:
        if d["tipo"] == "Operativos":
            camiones_disponibles = int(round(d["cantidad"]))
            break

    # -------------------------
    # Equipo liviano
    # -------------------------
    equipo_liviano_items = conn.execute(
        "SELECT camioneta, estado, comentario FROM equipo_liviano WHERE reporte_id = ? ORDER BY id DESC",
        (reporte_id,)
    ).fetchall()

    # -------------------------
    # Personal
    # -------------------------
    personal_items = conn.execute("""
        SELECT categoria, cantidad
        FROM distribucion_personal
        WHERE reporte_id = ?
        ORDER BY
            CASE categoria WHEN 'ROSTER' THEN 0 ELSE 1 END,
            id DESC
    """, (reporte_id,)).fetchall()

    # Condición: En turno NOCHE no aparece 'Personal solo día'
    if r["turno"] == "NOCHE":
        personal_items = [p for p in personal_items if p["categoria"] != "Personal solo día"]

    roster_p, disponible_p = calc_disponible_personal(personal_items)

    otras_areas_items = conn.execute(
        "SELECT * FROM operadores_otras_areas WHERE reporte_id = ? ORDER BY id DESC",
        (reporte_id,)
    ).fetchall()

    entrenamiento_items = conn.execute("""
        SELECT entrenamiento, cantidad
        FROM entrenamiento_personal
        WHERE reporte_id = ? AND cantidad > 0
        ORDER BY
            CASE entrenamiento
                WHEN 'Regular' THEN 1
                WHEN 'Brigada' THEN 2
                WHEN 'Equipos' THEN 3
                WHEN 'Especial' THEN 4
                ELSE 99
            END
    """, (reporte_id,)).fetchall()

    # -------------------------
    # Luminarias / Contactos
    # -------------------------
    luminarias = conn.execute(
        "SELECT * FROM luminarias WHERE reporte_id = ? ORDER BY id DESC",
        (reporte_id,)
    ).fetchall()

    contactos = conn.execute(
        "SELECT * FROM contactos_operadores WHERE reporte_id = ? ORDER BY id DESC",
        (reporte_id,)
    ).fetchall()

    # -------------------------
    # Seguridad
    # -------------------------
    seguridad_obs = conn.execute(
        "SELECT lugar, hallazgos, divulgada FROM seguridad_observaciones WHERE reporte_id = ? ORDER BY id DESC",
        (reporte_id,)
    ).fetchall()

    seguridad_charlas = conn.execute(
        "SELECT tema, personas, lugar FROM seguridad_charlas WHERE reporte_id = ? ORDER BY id DESC",
        (reporte_id,)
    ).fetchall()

    # -------------------------
    # First/Last (Operación Punto 1)
    # -------------------------
    first_last = conn.execute(
        "SELECT * FROM first_last WHERE reporte_id = ?",
        (reporte_id,)
    ).fetchone()

    operacion = {
        "inicio_pit2": None,
        "inicio_pit5": None,
        "final_pit2": None,
        "final_pit5": None,
        "camiones_por_operador": 0,
        "razon": "",
    }

    if first_last:
        operacion["inicio_pit2"] = first_last["inicio_pit2"]
        operacion["inicio_pit5"] = first_last["inicio_pit5"]
        operacion["final_pit2"] = first_last["final_pit2"]
        operacion["final_pit5"] = first_last["final_pit5"]
        operacion["camiones_por_operador"] = first_last["camiones_por_operador"]
        operacion["razon"] = first_last["razon"]

    # -------------------------
    # Bahías: normalización de keys para PDF
    # (tu tabla buses_bahias trae bahia/hora/observacion)
    # -------------------------
    bahias = []
    for x in buses:
        bahias.append({
            "nombre": x["bahia"],
            "hora_arribo": x["hora"],
            "condicion": None,
            "detalle": x["observacion"],
        })

    bahias_nota = ""

    # -------------------------
    # PTS / Comentarios / Supervisores
    # -------------------------
    pts = conn.execute(
        "SELECT texto FROM pts_divulgacion WHERE reporte_id = ?",
        (reporte_id,)
    ).fetchone()

    comentarios = conn.execute(
        "SELECT comentario FROM comentarios_turno WHERE reporte_id = ? ORDER BY id DESC",
        (reporte_id,)
    ).fetchall()

    supervisores = conn.execute("""
        SELECT grupo, supervisor
        FROM supervisores_turno
        WHERE reporte_id = ?
        ORDER BY
            CASE grupo WHEN 'G1' THEN 1 WHEN 'G2' THEN 2 WHEN 'G3' THEN 3 ELSE 99 END,
            supervisor ASC
    """, (reporte_id,)).fetchall()

    # -------------------------
    # Fatiga y Pausas Activas
    # -------------------------
    fatiga_items = conn.execute(
        "SELECT reportes_sueno, pausas_activas FROM fatiga_pausas WHERE reporte_id = ?",
        (reporte_id,)
    ).fetchall()
    
    total_sueno = sum(it["reportes_sueno"] for it in fatiga_items)
    total_pausas = sum(it["pausas_activas"] for it in fatiga_items)

    return dict(
        r=r,
        gestion=gestion,
        buses=buses,
        equipos=equipos,
        dist_camiones=dist_camiones,
        total_camiones=total_camiones,
        camiones_disponibles=camiones_disponibles,
        ausentismo=ausentismo_items,
        bombas=bombas_items,
        equipo_liviano=equipo_liviano_items,
        personal=personal_items,
        roster_p=roster_p,
        disponible_p=disponible_p,
        otras_areas=otras_areas_items,
        entrenamiento=entrenamiento_items,
        luminarias=luminarias,
        contactos=contactos,
        seguridad_obs=seguridad_obs,
        seguridad_charlas=seguridad_charlas,
        operacion=operacion,
        pts=pts,
        bahias=bahias,
        bahias_nota=bahias_nota,
        comentarios=comentarios,
        supervisores=supervisores,
        fatiga_total_sueno=total_sueno,
        fatiga_total_pausas=total_pausas,
    )



# ---------------------------------------------------------
# [RUTA] Reporte PDF
# ---------------------------------------------------------
@reportes_bp.route("/reportes/<int:reporte_id>/pdf")
@reporte_mina_required
def reporte_pdf(reporte_id: int):
    with get_conn() as conn:
        ctx = build_reporte_context(conn, reporte_id)

    ctx["generado_en"] = datetime.now().strftime("%Y-%m-%d %H:%M")

    ctx.setdefault("operacion", {
        "inicio_turno": None,
        "fin_p2": None,
        "fin_p5": None,
        "condicion_general": "Normal",
        "observacion_corta": None,
        "alertas": []
    })
    ctx.setdefault("bahias", [])
    ctx.setdefault("bahias_nota", "")


    variant = request.args.get("v", "A").strip().upper()  # uso interno

    template_map = {
        "A": "pdf/reporte_pdf.html",
        "B": "pdf/reporte_B.html",  
        "C": "pdf/reporte_C.html",   # NUEVO (1 hoja)
        # "D": "pdf/reporte_D.html",
    }

    tpl = template_map.get(variant, template_map["A"])
    html = render_template(tpl, **ctx)

    from flask import current_app
    import subprocess
    import tempfile
    import os

    base_dir = current_app.root_path
    
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f_in, \
         tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f_out:
        f_in.write(html.encode("utf-8"))
        in_name = f_in.name
        out_name = f_out.name

    try:
        subprocess.run(
            ["python", "-m", "weasyprint", in_name, out_name, "--base-url", str(base_dir)],
            check=True,
            timeout=55
        )
        with open(out_name, "rb") as f:
            pdf_bytes = f.read()
    except subprocess.TimeoutExpired:
        abort(504, "El servidor tardó demasiado en generar el PDF (Timeout).")
    except subprocess.CalledProcessError:
        abort(500, "Error interno al renderizar el archivo PDF.")
    finally:
        if os.path.exists(in_name): os.remove(in_name)
        if os.path.exists(out_name): os.remove(out_name)
        gc.collect()

    resp = make_response(pdf_bytes)
    resp.headers["Content-Type"] = "application/pdf"
    resp.headers["Content-Disposition"] = f'inline; filename="RCT_{reporte_id}.pdf"'
    return resp

# =========================================================
# Bloque 5: Home, listado, creación y estado del reporte
# =========================================================

# ---------------------------------------------------------
# [RUTA] Home
# ---------------------------------------------------------
@reportes_bp.route("/")
def home():
    return redirect(url_for("reportes.ver_reportes"))


# ---------------------------------------------------------
# [RUTA] Ver reportes (filtrado por mina)
# ---------------------------------------------------------
@reportes_bp.route("/reportes")
def ver_reportes():
    if g.user is None:
        return redirect(url_for("auth.login"))

    # -------------------------
    # Filtros (GET)
    # -------------------------
    mina = (request.args.get("mina") or "").strip()
    estado = (request.args.get("estado") or "").strip()
    turno = (request.args.get("turno") or "").strip()
    desde = (request.args.get("desde") or "").strip()
    hasta = (request.args.get("hasta") or "").strip()

    with get_conn() as conn:
        sql = """
            SELECT id, fecha, turno, estado, mina
            FROM reportes
            WHERE 1=1
        """
        params = []

        # -------------------------
        # Restricción por minas (no ADMIN)
        # -------------------------
        if g.user["rol"] != "ADMIN":
            if not g.user_minas:
                return render_template("reportes.html", reportes=[])
            placeholders = ",".join(["?"] * len(g.user_minas))
            sql += f" AND mina IN ({placeholders})"
            params.extend(list(g.user_minas))

        # -------------------------
        # Filtros exactos
        # -------------------------
        if mina in ("ED", "PB"):
            sql += " AND mina = ?"
            params.append(mina)

        if estado in ("ABIERTO", "CERRADO"):
            sql += " AND estado = ?"
            params.append(estado)

        if turno in ("DIA", "NOCHE"):
            sql += " AND turno = ?"
            params.append(turno)

        # -------------------------
        # Rango de fechas
        # -------------------------
        if desde:
            sql += " AND fecha >= ?"
            params.append(desde)

        if hasta:
            sql += " AND fecha <= ?"
            params.append(hasta)

        # Orden final
        sql += " ORDER BY fecha DESC, id DESC"

        reportes = conn.execute(sql, params).fetchall()

    return render_template("reportes.html", reportes=reportes)



# ---------------------------------------------------------
# [RUTA] Nuevo reporte
#   - ADMIN: puede crear en ED/PB
#   - SUPERVISOR: solo en sus minas (g.user_minas)
#   - DIGITADOR/LECTOR: bloqueado
# ---------------------------------------------------------
@reportes_bp.route("/reportes/nuevo", methods=["GET", "POST"])
def nuevo_reporte():
    if g.user is None:
        return redirect(url_for("auth.login"))

    # 🚫 DIGITADOR y LECTOR no pueden crear reportes
    if g.user["rol"] not in ("ADMIN", "SUPERVISOR"):
        return ("No tienes permisos para crear reportes.", 403)

    # ✅ Minas permitidas según rol
    if g.user["rol"] == "ADMIN":
        minas_permitidas = [m[0] for m in MINAS]  # ["ED","PB"]
    else:
        # SUPERVISOR: solo sus minas asignadas
        minas_permitidas = sorted(list(g.user_minas))

    # Si no tiene minas asignadas -> bloquear
    if not minas_permitidas:
        return ("No tienes minas asignadas. Contacta al administrador.", 403)

    if request.method == "GET":
        mina_sel = minas_permitidas[0]
        minas_ui = [(code, mina_label(code)) for code in minas_permitidas]

        return render_template(
            "reporte_nuevo.html",
            hoy=date.today().isoformat(),
            error=None,
            minas=minas_ui,
            mina_sel=mina_sel,
            mina_locked=(len(minas_permitidas) == 1)
        )

    # POST
    fecha = request.form.get("fecha", "").strip()
    turno = request.form.get("turno", "").strip().upper()
    mina = request.form.get("mina", "").strip().upper()

    # ✅ Validar mina contra permitidas
    if mina not in minas_permitidas:
        return ("No autorizado para crear reportes en esta mina.", 403)

    if fecha == "" or turno not in ("DIA", "NOCHE"):
        minas_ui = [(code, mina_label(code)) for code in minas_permitidas]
        return render_template(
            "reporte_nuevo.html",
            hoy=date.today().isoformat(),
            error="Debes ingresar fecha y seleccionar turno (DIA o NOCHE).",
            minas=minas_ui,
            mina_sel=mina if mina in minas_permitidas else minas_permitidas[0],
            mina_locked=(len(minas_permitidas) == 1)
        )

    # ✅ Insert + RETURNING id (Postgres) y lectura blindada del row
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO reportes (fecha, turno, estado, mina) "
            "VALUES (?, ?, 'ABIERTO', ?) RETURNING id",
            (fecha, turno, mina)
        )
        row = cur.fetchone()

        # row puede venir como tupla (id,) o como dict-like {'id': id}
        if row is None:
            reporte_id = None
        elif isinstance(row, (tuple, list)):
            reporte_id = row[0]
        else:
            # dict / RowMapping
            try:
                reporte_id = row["id"]
            except Exception:
                # último fallback
                reporte_id = getattr(row, "id", None)

    if not reporte_id or int(reporte_id) <= 0:
        return redirect(url_for("reportes.ver_reportes"))

    return redirect(url_for("reportes.reporte_inicio", reporte_id=reporte_id))




# ---------------------------------------------------------
# [RUTA] Inicio del reporte
# ---------------------------------------------------------
@reportes_bp.route("/reportes/<int:reporte_id>")
@reporte_mina_required
def reporte_inicio(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
    return render_template("reporte_inicio.html", r=r)


# ---------------------------------------------------------
# [RUTA] Cerrar reporte
# (nota: aquí también conviene validar mina con @reporte_mina_required)
# ---------------------------------------------------------
@reportes_bp.route("/reportes/<int:reporte_id>/cerrar", methods=["POST"])
@reporte_mina_required
@roles_required("ADMIN", "SUPERVISOR")
def cerrar_reporte(reporte_id):
    with get_conn() as conn:
        conn.execute(
            "UPDATE reportes SET estado = 'CERRADO' WHERE id = ?",
            (reporte_id,)
        )
    return redirect(url_for("reportes.ver_reportes"))


# ---------------------------------------------------------
# [RUTA] Reabrir reporte
# ---------------------------------------------------------
@reportes_bp.route("/reportes/<int:reporte_id>/reabrir", methods=["POST"])
@reporte_mina_required
@roles_required("ADMIN", "SUPERVISOR")
def reabrir_reporte(reporte_id):
    with get_conn() as conn:
        conn.execute(
            "UPDATE reportes SET estado = 'ABIERTO' WHERE id = ?",
            (reporte_id,)
        )
    return redirect(url_for("reportes.ver_reportes"))


# ---------------------------------------------------------
# [RUTA] Editar fecha del reporte (ADMIN y SUPERVISOR)
# ---------------------------------------------------------
@reportes_bp.route("/reportes/<int:reporte_id>/editar-fecha", methods=["GET", "POST"])
@reporte_mina_required
@roles_required("ADMIN", "SUPERVISOR")
def editar_fecha_reporte(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
    
    if request.method == "GET":
        return render_template(
            "reporte_editar_fecha.html",
            r=r,
            error=None
        )
    
    # POST
    nueva_fecha = request.form.get("fecha", "").strip()
    
    if nueva_fecha == "":
        return render_template(
            "reporte_editar_fecha.html",
            r=r,
            error="Debes ingresar una fecha válida."
        )
    
    # Actualizar la fecha en la base de datos
    with get_conn() as conn:
        conn.execute(
            "UPDATE reportes SET fecha = ? WHERE id = ?",
            (nueva_fecha, reporte_id)
        )
    
    return redirect(url_for("reportes.reporte_inicio", reporte_id=reporte_id))




# ---------------------------------------------------------
@reportes_bp.route("/reportes/<int:reporte_id>/resumen")
@reporte_mina_required
def resumen(reporte_id):
    from flask import current_app
    current_app.logger.error("MARCADOR_RESUMEN_V2: usando fetchval + total AS alias")

    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)

        gestion = conn.execute(
            "SELECT * FROM gestion_areas WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()

        buses = conn.execute(
            "SELECT * FROM buses_bahias WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()

        equipos = conn.execute(
            "SELECT * FROM equipos_varados WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()

        ausentismo_items = conn.execute(
            "SELECT * FROM ausentismo WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()

        bombas_items = conn.execute(
            "SELECT * FROM bombas WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()

        # ✅ FIX POSTGRES: ROUND(double precision, int) no existe -> castear a numeric
        dist_camiones = conn.execute("""
            SELECT
                tipo,
                ROUND(SUM(cantidad)::numeric, 2) AS cantidad
            FROM distribucion_camiones
            WHERE reporte_id = ?
            GROUP BY tipo
            ORDER BY
            CASE tipo
                WHEN 'Operativos' THEN 1
                WHEN 'Down' THEN 2
                WHEN 'Stand By con Operador' THEN 3
                WHEN 'Stand By sin Operador' THEN 4
                WHEN 'Carbon' THEN 5
                WHEN 'Stand By no programado' THEN 6
                ELSE 99
            END
        """, (reporte_id,)).fetchall()

        camiones_disponibles = 0
        for d in dist_camiones:
            if d["tipo"] == "Operativos":
                camiones_disponibles = int(round(d["cantidad"]))
                break

        row_total = conn.execute(
            "SELECT COALESCE(SUM(cantidad), 0) AS total FROM distribucion_camiones WHERE reporte_id = ?",
            (reporte_id,)
        ).fetchone()

        total_camiones = conn.fetchval(
            "SELECT COALESCE(SUM(cantidad), 0) FROM distribucion_camiones WHERE reporte_id = ?",
            (reporte_id,),
            default=0
        )
        total_camiones = int(round(total_camiones))


        equipo_liviano_items = conn.execute(
            "SELECT camioneta, estado, comentario FROM equipo_liviano WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()

        personal_items = conn.execute("""
            SELECT categoria, cantidad
            FROM distribucion_personal
            WHERE reporte_id = ?
            ORDER BY
                CASE categoria WHEN 'ROSTER' THEN 0 ELSE 1 END,
                id DESC
        """, (reporte_id,)).fetchall()

        # Condición: En turno NOCHE no aparece 'Personal solo día'
        if r["turno"] == "NOCHE":
            personal_items = [p for p in personal_items if p["categoria"] != "Personal solo día"]

        roster_p, disponible_p = calc_disponible_personal(personal_items)

        otras_areas_items = conn.execute(
            "SELECT * FROM operadores_otras_areas WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()

        entrenamiento_items = conn.execute("""
            SELECT entrenamiento, cantidad
            FROM entrenamiento_personal
            WHERE reporte_id = ? AND cantidad > 0
            ORDER BY
                CASE entrenamiento
                    WHEN 'Regular' THEN 1
                    WHEN 'Brigada' THEN 2
                    WHEN 'Equipos' THEN 3
                    WHEN 'Especial' THEN 4
                    ELSE 99
                END
        """, (reporte_id,)).fetchall()

        luminarias = conn.execute(
            "SELECT * FROM luminarias WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()

        contactos = conn.execute(
            "SELECT * FROM contactos_operadores WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()

        seguridad_obs = conn.execute(
            "SELECT lugar, hallazgos, divulgada FROM seguridad_observaciones WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()

        seguridad_charlas = conn.execute(
            "SELECT tema, personas, lugar FROM seguridad_charlas WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()

        first_last = conn.execute(
            "SELECT * FROM first_last WHERE reporte_id = ?",
            (reporte_id,)
        ).fetchone()

        pts = conn.execute(
            "SELECT texto FROM pts_divulgacion WHERE reporte_id = ?",
            (reporte_id,)
        ).fetchone()

        comentarios = conn.execute(
            "SELECT comentario FROM comentarios_turno WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()

        supervisores = conn.execute("""
            SELECT grupo, supervisor
            FROM supervisores_turno
            WHERE reporte_id = ?
            ORDER BY
                CASE grupo WHEN 'G1' THEN 1 WHEN 'G2' THEN 2 WHEN 'G3' THEN 3 ELSE 99 END,
                supervisor ASC
        """, (reporte_id,)).fetchall()

    return render_template(
        "resumen.html",
        r=r,
        gestion=gestion,
        buses=buses,
        equipos=equipos,
        ausentismo=ausentismo_items,
        bombas=bombas_items,
        dist_camiones=dist_camiones,
        total_camiones=total_camiones,
        camiones_disponibles=camiones_disponibles,
        equipo_liviano=equipo_liviano_items,
        personal_items=personal_items,
        roster_p=roster_p,
        disponible_p=disponible_p,
        otras_areas=otras_areas_items,
        entrenamiento_items=entrenamiento_items,
        luminarias=luminarias,
        contactos=contactos,
        seguridad_obs=seguridad_obs,
        seguridad_charlas=seguridad_charlas,
        first_last=first_last,
        pts=pts,
        comentarios=comentarios,
        supervisores=supervisores,
        get_label=get_personal_label
    )



# ---------------------------------------------------------
# [RUTA] Eliminar reporte (solo ADMIN)
# ---------------------------------------------------------
@reportes_bp.route("/reportes/<int:reporte_id>/eliminar", methods=["POST"])
@roles_required("ADMIN")
def eliminar_reporte(reporte_id):
    confirmar = (request.form.get("confirmar") or "").strip()
    esperado = f"ELIMINAR {reporte_id}"

    if confirmar != esperado:
        # si usas flash en el proyecto, esto es ideal
        try:
            flash(f"Confirmación incorrecta para eliminar el reporte {reporte_id}.", "danger")
        except:
            pass
        return redirect(url_for("reportes.ver_reportes"))

    with get_conn() as conn:
        conn.execute("DELETE FROM reportes WHERE id = ?", (reporte_id,))
    
    try:
        flash(f"Reporte {reporte_id} eliminado exitosamente.", "success")
    except:
        pass
    return redirect(url_for("reportes.ver_reportes"))
