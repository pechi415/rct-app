# =========================================================
# app.py — Reporte de Cambio de Turno (RCT)
# Bloque 1: Imports, App, Configuración base y Catálogos
# =========================================================

from __future__ import annotations

import os
import re
import gc
import sqlite3
import psycopg2
from psycopg2.extras import DictCursor
from datetime import date, datetime
import time
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, abort, make_response, session, g, flash
)

try:
    from weasyprint import HTML
except OSError:
    HTML = None
from werkzeug.security import generate_password_hash, check_password_hash



# =========================================================
# [APP] Flask
# =========================================================
app = Flask(__name__)

from database import init_app as init_db_app, get_conn, is_postgres, sql_params, get_db_connection
init_db_app(app)

from blueprints.auth import auth_bp, login_required, admin_required, roles_required
app.register_blueprint(auth_bp)
from blueprints.admin import admin_bp
app.register_blueprint(admin_bp)
from blueprints.reportes import reportes_bp
app.register_blueprint(reportes_bp)
from blueprints.secciones import secciones_bp
app.register_blueprint(secciones_bp)
from blueprints.gerencia import gerencia_bp
app.register_blueprint(gerencia_bp)
from blueprints.reportes import fetch_reporte, reporte_mina_required


# En local: clave fija para que la sesión no se invalide al cambiar cómo ejecutas la app
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    app.secret_key = "rct-local-secret-2026-super-larga-y-unica-cambiala"



# =========================================================
# [CONFIG] Paths / DB
# =========================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Carpeta estándar de Flask para archivos locales (no se sube a GitHub)
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)

DB_PATH = os.path.join(INSTANCE_DIR, "rct.db")

# =========================================================
from config import (
    DB_PATH, BAHIAS_POR_MINA, ROLES, MINAS, CAMIONETAS_POR_MINA,
    ESTADOS_LIVIANO, TIPOS_DISTRIBUCION_CAMIONES, CATEGORIAS_PERSONAL,
    IMPACTO_PERSONAL, AREAS_OTRAS, ENTRENAMIENTOS_PERSONAL, TIPOS_CONTACTO,
    SUPERVISORES_POR_MINA, GRUPOS_SUP
)
from utils import mina_label, calc_disponible_personal, norm_text

@app.context_processor
def inject_helpers():
    return dict(mina_label=mina_label)






# =========================================================
# Bloque 2: Auth, carga de usuario (g.user / g.user_minas) y permisos
# =========================================================













# =========================================================
# Bloque 3: Inicialización DB (Auth + RCT) + Seeds
# =========================================================

# ---------------------------------------------------------
# [DB] Tablas de autenticación / autorización
# ---------------------------------------------------------
def init_auth_tables():
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        if is_postgres():
            # PostgreSQL
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                  id BIGSERIAL PRIMARY KEY,
                  username TEXT NOT NULL UNIQUE,
                  password_hash TEXT NOT NULL,
                  rol TEXT NOT NULL CHECK (rol IN ('ADMIN','SUPERVISOR','DIGITADOR','LECTOR')),
                  is_active SMALLINT NOT NULL DEFAULT 1,
                  debe_cambiar_pass SMALLINT NOT NULL DEFAULT 0,
                  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
            """)

            # ✅ Auto-migración si la tabla ya existía antes de este update
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS debe_cambiar_pass SMALLINT NOT NULL DEFAULT 0;")

            cur.execute("""
                CREATE TABLE IF NOT EXISTS user_minas (
                  user_id BIGINT NOT NULL,
                  mina TEXT NOT NULL,
                  PRIMARY KEY (user_id, mina),
                  CONSTRAINT fk_user_minas_user
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            """)
        else:
            # SQLite
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT NOT NULL UNIQUE,
                  password_hash TEXT NOT NULL,
                  rol TEXT NOT NULL,
                  is_active INTEGER NOT NULL DEFAULT 1,
                  debe_cambiar_pass INTEGER NOT NULL DEFAULT 0,
                  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            try:
                cur.execute("ALTER TABLE users ADD COLUMN debe_cambiar_pass INTEGER NOT NULL DEFAULT 0;")
            except Exception:
                pass

            cur.execute("""
                CREATE TABLE IF NOT EXISTS user_minas (
                  user_id INTEGER NOT NULL,
                  mina TEXT NOT NULL,
                  PRIMARY KEY (user_id, mina),
                  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)

        conn.commit()
    finally:
        try:
            cur.close()
        except Exception:
            pass
        conn.close()



# ---------------------------------------------------------
# [DB] Tablas principales del RCT
# ---------------------------------------------------------
def init_db():

    with get_conn() as conn:
        if is_postgres():

            # =========================================================
            # POSTGRESQL (Render)
            # =========================================================

            conn.execute("""
                CREATE TABLE IF NOT EXISTS reportes (
                    id BIGSERIAL PRIMARY KEY,
                    fecha TEXT NOT NULL,
                    turno TEXT NOT NULL,
                    mina TEXT NOT NULL DEFAULT 'ED',
                    estado TEXT NOT NULL DEFAULT 'ABIERTO'
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS gestion_areas (
                    id BIGSERIAL PRIMARY KEY,
                    reporte_id BIGINT NOT NULL,
                    hora TEXT NOT NULL,
                    hallazgo TEXT NOT NULL,
                    accion TEXT NOT NULL,
                    corregido SMALLINT NOT NULL,
                    responsable TEXT NOT NULL,
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id)
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS buses_bahias (
                    id BIGSERIAL PRIMARY KEY,
                    reporte_id BIGINT NOT NULL,
                    bahia TEXT NOT NULL,
                    hora TEXT NOT NULL,
                    observacion TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id)
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS equipos_varados (
                    id BIGSERIAL PRIMARY KEY,
                    reporte_id BIGINT NOT NULL,
                    equipo INTEGER NOT NULL,
                    ubicacion TEXT NOT NULL,
                    motivo TEXT NOT NULL,
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id)
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS ausentismo (
                    id BIGSERIAL PRIMARY KEY,
                    reporte_id BIGINT NOT NULL,
                    nombre TEXT NOT NULL,
                    motivo TEXT NOT NULL,
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id)
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS bombas (
                    id BIGSERIAL PRIMARY KEY,
                    reporte_id BIGINT NOT NULL,
                    numero TEXT NOT NULL,
                    estado TEXT NOT NULL,
                    ubicacion TEXT NOT NULL,
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id)
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS distribucion_camiones (
                    id BIGSERIAL PRIMARY KEY,
                    reporte_id BIGINT NOT NULL,
                    tipo TEXT NOT NULL,
                    cantidad DOUBLE PRECISION NOT NULL,
                    creado_en TIMESTAMPTZ DEFAULT NOW()
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS equipo_liviano (
                    id BIGSERIAL PRIMARY KEY,
                    reporte_id BIGINT NOT NULL,
                    camioneta INTEGER NOT NULL,
                    estado TEXT NOT NULL DEFAULT 'OK',
                    comentario TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id)
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS distribucion_personal (
                    id BIGSERIAL PRIMARY KEY,
                    reporte_id BIGINT NOT NULL,
                    categoria TEXT NOT NULL,
                    cantidad INTEGER NOT NULL,
                    creado_en TIMESTAMPTZ DEFAULT NOW(),
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id),
                    UNIQUE(reporte_id, categoria)
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS operadores_otras_areas (
                    id BIGSERIAL PRIMARY KEY,
                    reporte_id BIGINT NOT NULL,
                    nombre TEXT NOT NULL,
                    area TEXT NOT NULL,
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id)
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS entrenamiento_personal (
                    id BIGSERIAL PRIMARY KEY,
                    reporte_id BIGINT NOT NULL,
                    entrenamiento TEXT NOT NULL,
                    cantidad INTEGER NOT NULL,
                    creado_en TIMESTAMPTZ DEFAULT NOW(),
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id),
                    UNIQUE(reporte_id, entrenamiento)
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS luminarias (
                    id BIGSERIAL PRIMARY KEY,
                    reporte_id BIGINT NOT NULL,
                    numero TEXT NOT NULL,
                    ubicacion TEXT NOT NULL,
                    creado_en TIMESTAMPTZ DEFAULT NOW(),
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id),
                    UNIQUE(reporte_id, numero)
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS contactos_operadores (
                    id BIGSERIAL PRIMARY KEY,
                    reporte_id BIGINT NOT NULL,
                    tipo TEXT NOT NULL,
                    operador TEXT NOT NULL,
                    creado_en TIMESTAMPTZ DEFAULT NOW(),
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id)
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS seguridad_observaciones (
                    id BIGSERIAL PRIMARY KEY,
                    reporte_id BIGINT NOT NULL,
                    lugar TEXT NOT NULL,
                    lugar_norm TEXT NOT NULL,
                    hallazgos INTEGER NOT NULL,
                    divulgada SMALLINT NOT NULL,
                    creado_en TIMESTAMPTZ DEFAULT NOW(),
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id),
                    UNIQUE(reporte_id, lugar_norm, hallazgos, divulgada)
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS seguridad_charlas (
                    id BIGSERIAL PRIMARY KEY,
                    reporte_id BIGINT NOT NULL,
                    tema TEXT NOT NULL,
                    tema_norm TEXT NOT NULL,
                    personas INTEGER NOT NULL,
                    lugar TEXT NOT NULL,
                    lugar_norm TEXT NOT NULL,
                    creado_en TIMESTAMPTZ DEFAULT NOW(),
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id),
                    UNIQUE(reporte_id, tema_norm, personas, lugar_norm)
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS first_last (
                    id BIGSERIAL PRIMARY KEY,
                    reporte_id BIGINT NOT NULL UNIQUE,

                    inicio_pit2 TEXT NOT NULL,
                    inicio_pit5 TEXT NOT NULL,
                    final_pit2  TEXT NOT NULL,
                    final_pit5  TEXT NOT NULL,

                    camiones_por_operador INTEGER NOT NULL DEFAULT 0,
                    razon TEXT NOT NULL DEFAULT '',

                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ DEFAULT NOW(),

                    FOREIGN KEY (reporte_id) REFERENCES reportes(id) ON DELETE CASCADE
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS pts_divulgacion (
                    id BIGSERIAL PRIMARY KEY,
                    reporte_id BIGINT NOT NULL UNIQUE,
                    texto TEXT NOT NULL DEFAULT '',
                    creado_en TIMESTAMPTZ DEFAULT NOW(),
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id)
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS comentarios_turno (
                    id BIGSERIAL PRIMARY KEY,
                    reporte_id BIGINT NOT NULL,
                    comentario TEXT NOT NULL,
                    creado_en TIMESTAMPTZ DEFAULT NOW(),
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id)
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS supervisores_turno (
                    id BIGSERIAL PRIMARY KEY,
                    reporte_id BIGINT NOT NULL,
                    grupo TEXT NOT NULL,
                    supervisor TEXT NOT NULL,
                    creado_en TIMESTAMPTZ DEFAULT NOW(),
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id),
                    UNIQUE(reporte_id, grupo, supervisor)
                );
            """)

        else:
            # =========================================================
            # SQLITE (Local)
            # =========================================================
            conn.execute("""
                CREATE TABLE IF NOT EXISTS reportes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fecha TEXT NOT NULL,
                    turno TEXT NOT NULL,
                    mina TEXT NOT NULL DEFAULT 'ED',
                    estado TEXT NOT NULL DEFAULT 'ABIERTO'
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS gestion_areas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporte_id INTEGER NOT NULL,
                    hora TEXT NOT NULL,
                    hallazgo TEXT NOT NULL,
                    accion TEXT NOT NULL,
                    corregido INTEGER NOT NULL,
                    responsable TEXT NOT NULL,
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS buses_bahias (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporte_id INTEGER NOT NULL,
                    bahia TEXT NOT NULL,
                    hora TEXT NOT NULL,
                    observacion TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS equipos_varados (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporte_id INTEGER NOT NULL,
                    equipo INTEGER NOT NULL,
                    ubicacion TEXT NOT NULL,
                    motivo TEXT NOT NULL,
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS ausentismo (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporte_id INTEGER NOT NULL,
                    nombre TEXT NOT NULL,
                    motivo TEXT NOT NULL,
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS bombas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporte_id INTEGER NOT NULL,
                    numero TEXT NOT NULL,
                    estado TEXT NOT NULL,
                    ubicacion TEXT NOT NULL,
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS distribucion_camiones (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporte_id INTEGER NOT NULL,
                    tipo TEXT NOT NULL,
                    cantidad REAL NOT NULL,
                    creado_en TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS equipo_liviano (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporte_id INTEGER NOT NULL,
                    camioneta INTEGER NOT NULL,
                    estado TEXT NOT NULL DEFAULT 'OK',
                    comentario TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS distribucion_personal (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporte_id INTEGER NOT NULL,
                    categoria TEXT NOT NULL,
                    cantidad INTEGER NOT NULL,
                    creado_en TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id),
                    UNIQUE(reporte_id, categoria)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS operadores_otras_areas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporte_id INTEGER NOT NULL,
                    nombre TEXT NOT NULL,
                    area TEXT NOT NULL,
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS entrenamiento_personal (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporte_id INTEGER NOT NULL,
                    entrenamiento TEXT NOT NULL,
                    cantidad INTEGER NOT NULL,
                    creado_en TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id),
                    UNIQUE(reporte_id, entrenamiento)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS luminarias (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporte_id INTEGER NOT NULL,
                    numero TEXT NOT NULL,
                    ubicacion TEXT NOT NULL,
                    creado_en TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id),
                    UNIQUE(reporte_id, numero)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS contactos_operadores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporte_id INTEGER NOT NULL,
                    tipo TEXT NOT NULL,
                    operador TEXT NOT NULL,
                    creado_en TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS seguridad_observaciones (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporte_id INTEGER NOT NULL,
                    lugar TEXT NOT NULL,
                    lugar_norm TEXT NOT NULL,
                    hallazgos INTEGER NOT NULL,
                    divulgada INTEGER NOT NULL,
                    creado_en TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id),
                    UNIQUE(reporte_id, lugar_norm, hallazgos, divulgada)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS seguridad_charlas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporte_id INTEGER NOT NULL,
                    tema TEXT NOT NULL,
                    tema_norm TEXT NOT NULL,
                    personas INTEGER NOT NULL,
                    lugar TEXT NOT NULL,
                    lugar_norm TEXT NOT NULL,
                    creado_en TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id),
                    UNIQUE(reporte_id, tema_norm, personas, lugar_norm)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS first_last (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporte_id INTEGER NOT NULL UNIQUE,

                    inicio_pit2 TEXT NOT NULL,
                    inicio_pit5 TEXT NOT NULL,
                    final_pit2  TEXT NOT NULL,
                    final_pit5  TEXT NOT NULL,

                    camiones_por_operador INTEGER NOT NULL DEFAULT 0,
                    razon TEXT NOT NULL DEFAULT "",

                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,

                    FOREIGN KEY (reporte_id) REFERENCES reportes(id) ON DELETE CASCADE
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS pts_divulgacion (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporte_id INTEGER NOT NULL UNIQUE,
                    texto TEXT NOT NULL DEFAULT '',
                    creado_en TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS comentarios_turno (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporte_id INTEGER NOT NULL,
                    comentario TEXT NOT NULL,
                    creado_en TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS supervisores_turno (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporte_id INTEGER NOT NULL,
                    grupo TEXT NOT NULL,
                    supervisor TEXT NOT NULL,
                    creado_en TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id),
                    UNIQUE(reporte_id, grupo, supervisor)
                )
            """)

            conn.commit()

        # [MIGRACIÓN] Trazabilidad visual de datos copiados vs nuevos vs editados
        tablas_trazabilidad = [
            'ausentismo', 'bombas', 'equipo_liviano', 'distribucion_personal',
            'operadores_otras_areas', 'luminarias', 'supervisores_turno'
        ]
        for tbl in tablas_trazabilidad:
            try:
                if is_postgres():
                    conn.execute(f"ALTER TABLE {tbl} ADD COLUMN IF NOT EXISTS origen TEXT DEFAULT 'NUEVO';")
                else:
                    conn.execute(f"ALTER TABLE {tbl} ADD COLUMN origen TEXT DEFAULT 'NUEVO';")
            except Exception:
                pass
        
        # Hacemos commit nuevamente por si acaso para SQLite
        if not is_postgres():
            conn.commit()



# ---------------------------------------------------------
# [SEED] Crear admin por única vez
# ---------------------------------------------------------
def seed_admin_once():
    # Asegura tablas antes de seed

    username = os.environ.get("SEED_ADMIN_USER", "admin").strip().lower()
    password = os.environ.get("SEED_ADMIN_PASS", "admin123")

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            sql_params("SELECT 1 FROM users WHERE LOWER(username) = ? LIMIT 1"),
            (username,)
        )
        existe = cur.fetchone()

        if not existe:
            pwd_hash = generate_password_hash(password)
            cur.execute(
                sql_params("""
                    INSERT INTO users (username, password_hash, rol, is_active)
                    VALUES (?, ?, 'ADMIN', 1)
                """),
                (username, pwd_hash)
            )
            conn.commit()
    finally:
        try:
            cur.close()
        except Exception:
            pass
        conn.close()



# ---------------------------------------------------------
# [SEED] Minas por única vez para admin
# ---------------------------------------------------------
def seed_user_minas_once():
    # Configurable por variables, con defaults razonables
    admin_username = os.environ.get("SEED_ADMIN_USER", "admin").strip().lower()
    minas_raw = os.environ.get("SEED_ADMIN_MINAS", "").strip()  # ej: "EL DESCANSO,OTRA"
    minas = [m.strip() for m in minas_raw.split(",") if m.strip()]

    # Si no definiste minas, no hacemos nada (evita ruido en producción)
    if not minas:
        return

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Buscar admin
        cur.execute(
            sql_params("SELECT id FROM users WHERE LOWER(username) = ? LIMIT 1"),
            (admin_username,)
        )
        admin = cur.fetchone()
        if not admin:
            return

        admin_id = admin["id"] if isinstance(admin, dict) else admin[0]

        # Insertar minas (idempotente)
        for mina in minas:
            cur.execute(
                sql_params("""
                    INSERT INTO user_minas (user_id, mina)
                    VALUES (?, ?)
                    ON CONFLICT (user_id, mina) DO NOTHING
                """),
                (admin_id, mina)
            )

        conn.commit()
    finally:
        try:
            cur.close()
        except Exception:
            pass
        conn.close()



# ---------------------------------------------------------
# [UTIL] Ruta para crear un usuario de pruebas rápido
# (Puedes eliminar esta ruta en producción)
# ---------------------------------------------------------
@app.route("/_seed_test_user")
def _seed_test_user():
    username = "digitador_ed"
    password = "1234"
    rol = "DIGITADOR"
    minas = ["ED"]

    with get_conn() as conn:
        u = conn.execute(
            "SELECT id FROM users WHERE username = ? LIMIT 1",
            (username,)
        ).fetchone()

        pw_hash = generate_password_hash(password)

        if not u:
            conn.execute("""
                INSERT INTO users (username, password_hash, rol, is_active)
                VALUES (?, ?, ?, 1)
            """, (username, pw_hash, rol))
            u = conn.execute(
                "SELECT id FROM users WHERE username = ? LIMIT 1",
                (username,)
            ).fetchone()
        else:
            conn.execute("""
                UPDATE users
                SET password_hash = ?, rol = ?, is_active = 1
                WHERE id = ?
            """, (pw_hash, rol, u["id"]))

        conn.execute("DELETE FROM user_minas WHERE user_id = ?", (u["id"],))
        for m in minas:
            conn.execute("""
                INSERT OR IGNORE INTO user_minas (user_id, mina)
                VALUES (?, ?)
            """, (u["id"], m))

    return {"ok": True, "user": username, "pass": password, "rol": rol, "minas": minas}





# =========================================================
# Bloque 6: Gestión + Buses + Varados (CRUD)
# =========================================================

@app.route("/__dbcheck")
def __dbcheck():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # 1) Identidad de la DB
        cur.execute("SELECT current_database() AS db, current_user AS usr;")
        ident = cur.fetchone()

        # 2) Qué tablas existen en public
        cur.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
            ORDER BY table_name;
        """)
        tablas = [r["table_name"] if isinstance(r, dict) else r[0] for r in cur.fetchall()]

        # 3) ¿Existe reportes?
        existe_reportes = "reportes" in tablas

        return {
            "database": ident,
            "tables_public": tablas,
            "reportes_exists": existe_reportes,
        }
    finally:
        try:
            cur.close()
        except Exception:
            pass
        conn.close()



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
