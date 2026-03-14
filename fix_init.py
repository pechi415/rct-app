with open('app.py', 'a', encoding='utf-8') as f:
    f.write('''
# ---------------------------------------------------------
# [INIT] Ejecutar inicialización (ORDEN CORRECTO)
# ---------------------------------------------------------
try:
    init_auth_tables()
    init_db()
    seed_admin_once()
    seed_user_minas_once()
    print("INFO: Base de datos inicializada correctamente.", flush=True)
except Exception as e:
    print(f"ERROR: No se pudo inicializar la base de datos: {e}", flush=True)
    print("WARNING: La app iniciará, pero las operaciones de BD fallarán hasta corregir la conexión.", flush=True)

# =========================================================
# RUN
# =========================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
''')
