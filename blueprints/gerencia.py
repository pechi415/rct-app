from flask import Blueprint, render_template, request, flash, redirect, url_for, make_response
from database import get_conn
from blueprints.reportes import fetch_reporte, build_reporte_context
from config import MINAS
from blueprints.auth import login_required
import gc

gerencia_bp = Blueprint("gerencia", __name__)

@gerencia_bp.route("/gerencia", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        fecha = request.form.get("fecha")
        turno = request.form.get("turno")

        if not fecha or not turno:
            flash("Fecha y Turno son requeridos.", "danger")
            return redirect(url_for("gerencia.index"))

        with get_conn() as conn:
            # Buscar Reporte ED
            rep_ed = conn.execute(
                "SELECT id, estado FROM reportes WHERE mina = ? AND fecha = ? AND turno = ?",
                ("ED", fecha, turno)
            ).fetchone()

            # Buscar Reporte PB
            rep_prb = conn.execute(
                "SELECT id, estado FROM reportes WHERE mina = ? AND fecha = ? AND turno = ?",
                ("PB", fecha, turno)
            ).fetchone()

            if not rep_ed or not rep_prb:
                flash(f"Falta reporte para la misma fecha y turno. No se puede consolidar.", "danger")
                return redirect(url_for("gerencia.index"))

            if rep_ed["estado"] != "CERRADO" or rep_prb["estado"] != "CERRADO":
                flash(f"Ambos reportes deben estar en estado CERRADO para consolidar los datos finales.", "warning")
                return redirect(url_for("gerencia.index"))

            # Ambos existen y cerrados -> redigir a la vista del dashboard consolidado
            return redirect(url_for("gerencia.dashboard", fecha=fecha, turno=turno))

    return render_template("gerencia_index.html")


@gerencia_bp.route("/gerencia/dashboard/<fecha>/<turno>")
@login_required
def dashboard(fecha, turno):
    with get_conn() as conn:
        rep_ed = conn.execute(
            "SELECT id FROM reportes WHERE mina = ? AND fecha = ? AND turno = ?",
            ("ED", fecha, turno)
        ).fetchone()

        rep_prb = conn.execute(
            "SELECT id FROM reportes WHERE mina = ? AND fecha = ? AND turno = ?",
            ("PB", fecha, turno)
        ).fetchone()

        if not rep_ed or not rep_prb:
            flash("No existen los dos reportes CERRADOS necesarios para consolidar.", "danger")
            return redirect(url_for("gerencia.index"))

        # Obtener los contextos individuales completos
        ctx_ed = build_reporte_context(conn, rep_ed["id"])
        ctx_prb = build_reporte_context(conn, rep_prb["id"])

        # =========================================================
        # Algoritmo de Consolidación
        # =========================================================
        
        # 1. Distribución de Camiones
        dist_cam_dict = {}
        for item in ctx_ed["dist_camiones"]:
            t = item["tipo"]
            dist_cam_dict[t] = dist_cam_dict.get(t, 0) + float(item["cantidad"])
        for item in ctx_prb["dist_camiones"]:
            t = item["tipo"]
            dist_cam_dict[t] = dist_cam_dict.get(t, 0) + float(item["cantidad"])

        distribucion_camiones = [{"tipo": k, "cantidad": int(v)} for k, v in dist_cam_dict.items()]
        
        # 2. Contactos Operativos
        # El usuario pidió desglose exacto (la tabla como la veíamos) pero consolidada.
        contactos_consolidado = []
        for x in ctx_ed["contactos"]:
            contactos_consolidado.append({
                "mina": "El Descanso", "tipo_contacto": x["tipo_contacto"], "operador": x["operador"]
            })
        for x in ctx_prb["contactos"]:
            contactos_consolidado.append({
                "mina": "Pribbenow", "tipo_contacto": x["tipo_contacto"], "operador": x["operador"]
            })
            
        total_contactos = len(contactos_consolidado)

        # 3. Personal Disposición (roster, presentes, ausentes, etc)
        # Sumamos los conteos base
        def merge_personal(p1, p2):
            result = {}
            for row in p1:
                result[row["categoria"]] = result.get(row["categoria"], 0) + row["cantidad"]
            for row in p2:
                result[row["categoria"]] = result.get(row["categoria"], 0) + row["cantidad"]
            return [{"categoria": k, "cantidad": v} for k, v in result.items()]

        personal = merge_personal(ctx_ed["personal"], ctx_prb["personal"])
        
        roster_p = ctx_ed["roster_p"] + ctx_prb["roster_p"]
        disponible_p = ctx_ed["disponible_p"] + ctx_prb["disponible_p"]

        # 4. First / Last (No se suman, se muestran en paralelo)
        fl_ed = ctx_ed["operacion"]
        fl_prb = ctx_prb["operacion"]

        # 5. Fatiga (Nueva Sección)
        fatiga_sueno_total = ctx_ed.get("fatiga_total_sueno", 0) + ctx_prb.get("fatiga_total_sueno", 0)
        fatiga_pausas_total = ctx_ed.get("fatiga_total_pausas", 0) + ctx_prb.get("fatiga_total_pausas", 0)

        # =========================================================
        
        gerencia_context = {
            "fecha": fecha,
            "turno": turno,
            "distribucion_camiones": distribucion_camiones,
            "total_camiones": ctx_ed["total_camiones"] + ctx_prb["total_camiones"],
            "camiones_disponibles": ctx_ed["camiones_disponibles"] + ctx_prb["camiones_disponibles"],
            
            "contactos": contactos_consolidado,
            "total_contactos": total_contactos,
            
            "personal": personal,
            "roster_p": roster_p,
            "disponible_p": disponible_p,
            
            "fl_ed": fl_ed,
            "fl_prb": fl_prb,

            "fatiga_sueno_total": fatiga_sueno_total,
            "fatiga_pausas_total": fatiga_pausas_total
        }

    # Si nos piden PDF:
    if request.args.get("pdf") == "1":
        html = render_template("pdf/gerencia_pdf.html", **gerencia_context)
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
            # Ejecutar weasyprint como subproceso CLI completamente aislado para evitar
            # cruce de memoria y OOM Killer en el worker Gunicorn de Render.
            subprocess.run(
                ["python", "-m", "weasyprint", in_name, out_name, "--base-url", str(base_dir)],
                check=True,
                timeout=55
            )
            with open(out_name, "rb") as f:
                pdf_bytes = f.read()
        except subprocess.TimeoutExpired:
            flash("Error: Tiempo de espera agotado al generar el PDF. El servidor está saturado.", "danger")
            return redirect(url_for("gerencia.index"))
        except subprocess.CalledProcessError:
            flash("Error interno al renderizar PDF. La tarea consumió demasiada memoria del servidor.", "danger")
            return redirect(url_for("gerencia.index"))
        finally:
            if os.path.exists(in_name): os.remove(in_name)
            if os.path.exists(out_name): os.remove(out_name)
            gc.collect()

        resp = make_response(pdf_bytes)
        resp.headers["Content-Type"] = "application/pdf"
        resp.headers["Content-Disposition"] = f'inline; filename="GERENCIAL_{fecha}_T{turno}.pdf"'
        return resp

    return render_template("gerencia_dashboard.html", **gerencia_context)

