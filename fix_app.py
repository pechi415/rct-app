import re

with open('app.py', 'r', encoding='utf-8') as f:
    text = f.read()

# Borrar [AUTH] Cargar usuario logueado en cada request
text = re.sub(
    r'# -{57}\n# \[AUTH\] Cargar usuario logueado.*?# -{57}\n@app\.before_request.*?# ---------------------------------------------------------',
    '# ---------------------------------------------------------',
    text, flags=re.DOTALL
)

# Borrar [HELPER] Cambio de contraseña hasta [HELPER] Permisos ADMIN
text = re.sub(
    r'# -{57}\n# \[HELPER\] Cambio de contraseña.*?# ---------------------------------------------------------',
    '# ---------------------------------------------------------',
    text, flags=re.DOTALL
)

# Borrar [HELPER] Permisos ADMIN
text = re.sub(
    r'# -{57}\n# \[HELPER\] Permisos ADMIN.*?# ---------------------------------------------------------',
    '# ---------------------------------------------------------',
    text, flags=re.DOTALL
)

# Borrar [PERMISOS] Decorador por roles
text = re.sub(
    r'# -{57}\n# \[PERMISOS\] Decorador por roles.*?# ---------------------------------------------------------',
    '# ---------------------------------------------------------',
    text, flags=re.DOTALL
)

# Borrar [AUTH] Login / Logout (hasta Ruta Eliminar reporte)
text = re.sub(
    r'# -{57}\n# \[AUTH\] Login / Logout.*?# ---------------------------------------------------------',
    '# ---------------------------------------------------------',
    text, flags=re.DOTALL
)

# Reemplazar url_for
text = text.replace('url_for("login")', 'url_for("auth.login")')
text = text.replace("url_for('login')", "url_for('auth.login')")
text = text.replace('url_for("logout")', 'url_for("auth.logout")')
text = text.replace("url_for('logout')", "url_for('auth.logout')")
text = text.replace('url_for("cambiar_password")', 'url_for("auth.cambiar_password")')
text = text.replace("url_for('cambiar_password')", "url_for('auth.cambiar_password')")

# Limpiar posibles dobles imports
if 'app.register_blueprint(auth_bp)' not in text:
    text = text.replace(
        'init_db_app(app)',
        'init_db_app(app)\n\nfrom blueprints.auth import auth_bp\napp.register_blueprint(auth_bp)\n'
    )

with open('app.py', 'w', encoding='utf-8') as f:
    f.write(text)

print('app.py modificado correctamente.')
