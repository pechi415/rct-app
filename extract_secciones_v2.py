import os

with open('app.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

start_idx = 831
end_idx = 3211

secciones_code = "".join(lines[start_idx:end_idx])

imports = """
import os
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, g, flash, abort
from database import get_conn, insert_and_get_id
from utils import norm_text
from blueprints.auth import roles_required
from blueprints.reportes import fetch_reporte, reporte_mina_required

secciones_bp = Blueprint("secciones", __name__)
"""

full_code = imports + "\n" + secciones_code

# Replace @app.route with @secciones_bp.route
full_code = full_code.replace('@app.route', '@secciones_bp.route')
full_code = full_code.replace('@app.post', '@secciones_bp.post')
full_code = full_code.replace('@app.get', '@secciones_bp.get')

# Fix url_for references
full_code = full_code.replace('url_for("reporte_inicio"', 'url_for("reportes.reporte_inicio"')
full_code = full_code.replace("url_for('reporte_inicio'", "url_for('reportes.reporte_inicio'")
full_code = full_code.replace('url_for("gestion_areas"', 'url_for("secciones.gestion_areas"')
full_code = full_code.replace('url_for("auth.login")', 'url_for("auth.login")')

with open('blueprints/secciones.py', 'w', encoding='utf-8') as f:
    f.write(full_code)

print("secciones_bp creado y poblado!")

# Ahora limpiar app.py
base_app = lines[:start_idx]
# Todo desde 3212 a 3488 son admin, login y cosas repetidas.
# PERO DEBEMOS CHEQUEAR el INIT. 
# Si el INIT esta al final (alrededor de 3491 en adelante)
init_idx = -1
for i, line in enumerate(lines):
    if "# [INIT]" in line:
        init_idx = i - 2
        break

if init_idx != -1:
    tail = lines[init_idx:]
else:
    print("NO SE ENCONTRO INIT")
    tail = []

new_app_lines = base_app + tail
new_app_text = "".join(new_app_lines)

if 'app.register_blueprint(secciones_bp)' not in new_app_text:
    new_app_text = new_app_text.replace(
        'app.register_blueprint(reportes_bp)',
        'app.register_blueprint(reportes_bp)\\nfrom blueprints.secciones import secciones_bp\\napp.register_blueprint(secciones_bp)'
    )

with open('app.py', 'w', encoding='utf-8') as f:
    f.write(new_app_text)

print("app.py limpiado con exito!!")
