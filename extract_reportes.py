import re

with open('app.py', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Extraer Bloque 4 y 5
b4_5 = re.search(r'# =========================================================\n# Bloque 4.*?# =========================================================\n# Bloque 6', text, flags=re.DOTALL)
if b4_5:
    bloque_4_5_code = b4_5.group(0).replace('# =========================================================\n# Bloque 6', '')
else:
    print("Error: No se encontro el Bloque 4 o 5.")
    bloque_4_5_code = ""

# 2. Extraer Resumen
resumen = re.search(r'# ---------------------------------------------------------\n@app\.route\("/reportes/<int:reporte_id>/resumen"\).*?# =========================================================\n# \[ADMIN\]', text, flags=re.DOTALL)
if resumen:
    resumen_code = resumen.group(0).replace('# =========================================================\n# [ADMIN]', '')
else:
    print("Error: No se encontro resumen.")
    resumen_code = ""

# 3. Extraer Eliminar
eliminar = re.search(r'# ---------------------------------------------------------\n# \[RUTA\] Eliminar reporte \(solo ADMIN\).*?conn\.execute\("DELETE FROM reportes WHERE id = \?", \(reporte_id,\)\)', text, flags=re.DOTALL)
if eliminar:
    # also add the return redirect that comes right after it
    # Find the remainder of the function
    idx = text.find(eliminar.group(0))
    if idx != -1:
        # Find exactly where the next def or app.route begins
        end_idx = text.find('\n@app', idx + len(eliminar.group(0)))
        if end_idx == -1: end_idx = len(text)
        eliminar_code = text[idx:end_idx]
else:
    print("Error: No se encontro eliminar.")
    eliminar_code = ""


# Escribir a blueprints/reportes.py
imports = """
import os
import gc
from datetime import date, datetime
from flask import Blueprint, render_template, request, redirect, url_for, g, flash, abort, make_response
from weasyprint import HTML
from database import get_conn, get_db_connection
from config import MINAS, CAMIONETAS_POR_MINA
from utils import mina_label, calc_disponible_personal
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

"""

# Reemplazar @app.route por @reportes_bp.route
full_code = imports + "\n\n" + bloque_4_5_code + "\n\n" + resumen_code + "\n\n" + eliminar_code
full_code = full_code.replace('@app.route', '@reportes_bp.route')
full_code = full_code.replace('@app.post', '@reportes_bp.post')
full_code = full_code.replace('@app.get', '@reportes_bp.get')

# Corregir urls
full_code = full_code.replace('url_for("reportes")', 'url_for("reportes.ver_reportes")')
full_code = full_code.replace("url_for('reportes')", "url_for('reportes.ver_reportes')")
full_code = full_code.replace('url_for("ver_reportes")', 'url_for("reportes.ver_reportes")')
full_code = full_code.replace("url_for('ver_reportes')", "url_for('reportes.ver_reportes')")
full_code = full_code.replace('url_for("reporte_inicio"', 'url_for("reportes.reporte_inicio"')
full_code = full_code.replace("url_for('reporte_inicio'", "url_for('reportes.reporte_inicio'")

with open('blueprints/reportes.py', 'w', encoding='utf-8') as f:
    f.write(full_code)

print("Reportes extraido a blueprints/reportes.py")

# Quitarlo de app.py
if b4_5:
    text = text.replace(b4_5.group(0), '# =========================================================\n# Bloque 6')
if resumen:
    text = text.replace(resumen.group(0), '# =========================================================\n# [ADMIN]')
if eliminar:
    text = text.replace(eliminar_code, '')

# Remover también el viejo fetch_reporte y reporte_mina_required de app.py ya que lo pasamos manual a reportes.py
text = re.sub(r'# ---------------------------------------------------------\n# \[HELPER\] Traer reporte o 404.*?return r', '', text, flags=re.DOTALL)
text = re.sub(r'# ---------------------------------------------------------\n# \[PERMISOS\] Decorador por mina.*?return wrapped', '', text, flags=re.DOTALL)

# Inyectar registro de reportes_bp
if 'app.register_blueprint(reportes_bp)\nfrom blueprints.reportes import fetch_reporte, reporte_mina_required' not in text:
    text = text.replace(
        'app.register_blueprint(admin_bp)',
        'app.register_blueprint(admin_bp)\nfrom blueprints.reportes import reportes_bp\napp.register_blueprint(reportes_bp)\nfrom blueprints.reportes import fetch_reporte, reporte_mina_required'
    )

with open('app.py', 'w', encoding='utf-8') as f:
    f.write(text)

print("app.py limpiado de reportes base.")
