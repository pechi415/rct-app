# =========================================================
# app.py — Reporte de Cambio de Turno (RCT)
# Bloque 1: Imports, App, Configuración base y Catálogos
# =========================================================

from __future__ import annotations

import os
import re
import sqlite3
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import date, datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, abort, make_response, session, g
)
from weasyprint import HTML
from werkzeug.security import generate_password_hash, check_password_hash

def get_db_connection():
    database_url = os.environ.get("DATABASE_URL")

    if database_url:
        # Render / PostgreSQL
        return psycopg2.connect(
            database_url,
            cursor_factory=RealDictCursor
        )
    else:
        # Local / SQLite
        conn = sqlite3.connect("rct.db")
        conn.row_factory = sqlite3.Row
        return conn

def is_postgres() -> bool:
    return bool(os.environ.get("DATABASE_URL"))


def sql_params(query: str) -> str:
    """
    Convierte placeholders de SQLite (?) a psycopg2 (%s) cuando estamos en Postgres.
    En SQLite deja la query igual.
    """
    if is_postgres():
        return query.replace("?", "%s")
    return query

# =========================================================
# [APP] Flask
# =========================================================
app = Flask(__name__)

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
# [CATÁLOGOS] Listas fijas
# =========================================================
BAHIAS = [
    "bahía Draga",
    "bahía Platanal",
    "bahía Conveyor",
    "bahía 1.5",
    "bahía Banana 3 Norte",
    "bahía 5",
    "bahía 7A",
    "bahía Retro",
    "bahía 14",
    "bahía 15",
    "bahia 3 postes",
]

MINAS = [
    ("ED", "El Descanso"),
    ("PB", "Pribbenow"),
]

def mina_label(mina_code: str) -> str:
    """Devuelve etiqueta legible de la mina."""
    return dict(MINAS).get(mina_code, mina_code or "")

@app.context_processor
def inject_helpers():
    return dict(mina_label=mina_label)


CAMIONETAS_POR_MINA = {
    "ED": [2732, 2733, 2734, 2736, 2674, 2676, 2945],
    "PB": [2059, 2683, 2954, 3216, 3252, 3264],
}

ESTADOS_LIVIANO = ["OK", "PM", "DOWN"]

TIPOS_DISTRIBUCION_CAMIONES = [
    "Operativos",
    "Down",
    "Stand By con Operador",
    "Stand By sin Operador",
    "Carbon",
    "Stand By no programado",
]


# =========================================================
# [CONFIG] Distribución del personal
# =========================================================
CATEGORIAS_PERSONAL = [
    "ROSTER",
    "Ausentes",
    "Personal prestado a PB",
    "Personal recibido desde PB",
    "Personal prestado a Carbón",
    "Personal recibido desde Carbón",
    "Vacaciones",
    "Entrenamiento",
    "Trainer",
    "En otras áreas",
    "Auxiliares",
]

IMPACTO_PERSONAL = {
    "ROSTER": 0,
    "Ausentes": -1,
    "Personal prestado a PB": -1,
    "Personal recibido desde PB": +1,
    "Personal prestado a Carbón": -1,
    "Personal recibido desde Carbón": +1,
    "Trainer": +1,
    "Vacaciones": -1,
    "Entrenamiento": -1,
    "En otras áreas": -1,
    "Auxiliares": -1,
}

def calc_disponible_personal(items):
    """
    Calcula personal disponible.
    Retorna: (roster, disponible)
    """
    data = {row["categoria"]: int(row["cantidad"]) for row in items}
    roster = data.get("ROSTER", 0)

    disponible = roster
    for cat, sign in IMPACTO_PERSONAL.items():
        if cat != "ROSTER":
            disponible += sign * data.get(cat, 0)

    return roster, disponible


# =========================================================
# [CATÁLOGO] Áreas / Departamentos
# =========================================================
AREAS_OTRAS = sorted([
    "Botaderos",
    "Carbón",
    "C.A.S.F",
    "Despacho",
    "Dtech",
    "Dragalina",
    "Entrenamiento",
    "Perforación y voladura",
    "Producción bombas",
    "Producción palas",
    "Seguridad Industrial",
    "Vías",
], key=lambda x: x.lower())


# =========================================================
# [DB] Conexión SQLite
# =========================================================
from flask import g, has_app_context

def _open_sqlite_conn():
    conn = sqlite3.connect(
        DB_PATH,
        timeout=30,
        check_same_thread=False
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def get_conn():
    # Dentro de Flask (request): usar g
    if has_app_context():
        if "db" not in g:
            g.db = _open_sqlite_conn()
        return g.db

    # Fuera de Flask (inicio del programa / scripts)
    return _open_sqlite_conn()

@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()



# =========================================================
# Bloque 2: Auth, carga de usuario (g.user / g.user_minas) y permisos
# =========================================================

# ---------------------------------------------------------
# [AUTH] Cargar usuario logueado en cada request
# ---------------------------------------------------------
@app.before_request
def load_logged_in_user():
    """
    Carga en:
      - g.user: fila del usuario (id, username, rol, is_active)
      - g.user_minas: set con minas autorizadas (ej: {"ED","PB"})
    """
    user_id = session.get("user_id")

    if not user_id:
        g.user = None
        g.user_minas = set()
        return

    with get_conn() as conn:
        u = conn.execute("""
            SELECT id, username, rol, is_active
            FROM users
            WHERE id = ?
            LIMIT 1
        """, (user_id,)).fetchone()

        # Usuario inexistente o inactivo -> cerrar sesión
        if (not u) or (u["is_active"] != 1):
            session.clear()
            g.user = None
            g.user_minas = set()
            return

        g.user = u

        rows = conn.execute("""
            SELECT mina
            FROM user_minas
            WHERE user_id = ?
        """, (user_id,)).fetchall()

        g.user_minas = {r["mina"] for r in rows}


# ---------------------------------------------------------
# [HELPER] Cambio de contraseña
# ---------------------------------------------------------
from functools import wraps

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------
# [RUTA] Cambio de contraseña
# ---------------------------------------------------------
@app.route("/mi-cuenta/password", methods=["GET", "POST"])
@login_required
def cambiar_password():
    error = None

    # ✅ Lee el mensaje "ok" (si existe) y lo borra de la sesión
    ok = session.pop("flash_ok", None)

    if request.method == "POST":
        actual = request.form.get("actual", "")
        nueva = request.form.get("nueva", "")
        confirmar = request.form.get("confirmar", "")

        # Validaciones
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

                # Usuario no existe o inactivo
                if (not u) or (u["is_active"] != 1):
                    session.clear()
                    return redirect(url_for("login"))

                # Contraseña actual incorrecta
                if not check_password_hash(u["password_hash"], actual):
                    error = "La contraseña actual no es correcta."
                else:
                    # ✅ Actualizar contraseña
                    conn.execute("""
                        UPDATE users
                        SET password_hash = ?
                        WHERE id = ?
                    """, (generate_password_hash(nueva), g.user["id"]))

                    # ✅ Guardar mensaje y redirigir (POST-Redirect-GET)
                    session["flash_ok"] = "Contraseña actualizada correctamente."
                    return redirect(url_for("cambiar_password"))

    return render_template("cambiar_password.html", error=error, ok=ok)


# ---------------------------------------------------------
# [HELPER] Permisos ADMIN
# ---------------------------------------------------------
def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        if g.user["rol"] != "ADMIN":
            return ("No autorizado", 403)
        return view(*args, **kwargs)
    return wrapped



# ---------------------------------------------------------
# [HELPER] Traer reporte o 404
# ---------------------------------------------------------
def fetch_reporte(conn, reporte_id: int):
    r = conn.execute(
        "SELECT id, fecha, turno, mina, estado FROM reportes WHERE id = ?",
        (reporte_id,)
    ).fetchone()

    if r is None:
        abort(404)

    return r


# ---------------------------------------------------------
# [PERMISOS] Decorador por roles
# ---------------------------------------------------------
def roles_required(*roles):
    """
    Requiere usuario logueado y que su rol esté dentro de roles.
    """
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("login"))
            if g.user["rol"] not in roles:
                return ("No autorizado", 403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


# ---------------------------------------------------------
# [PERMISOS] Decorador por mina (reporte_id)
# ---------------------------------------------------------
def reporte_mina_required(view):
    """
    Bloquea acceso si el reporte NO pertenece a una mina autorizada para el usuario.
    - ADMIN: puede ver todo.
    - Otros roles: deben tener r["mina"] dentro de g.user_minas.
    """
    @wraps(view)
    def wrapped(reporte_id, *args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))

        # ADMIN bypass total
        if g.user["rol"] == "ADMIN":
            return view(reporte_id, *args, **kwargs)

        with get_conn() as conn:
            r = fetch_reporte(conn, reporte_id)

        if r["mina"] not in (g.user_minas or set()):
            return ("No autorizado para esta mina", 403)

        return view(reporte_id, *args, **kwargs)

    return wrapped


# ---------------------------------------------------------
# [HELPER] Normalizar texto (para evitar duplicados en seguridad)
# ---------------------------------------------------------
def norm_text(s: str) -> str:
    s = (s or "").strip()
    s = " ".join(s.split())
    return s.lower()


# =========================================================
# [CATÁLOGOS] Entrenamientos / Contactos / Supervisores
# =========================================================
ENTRENAMIENTOS_PERSONAL = ["Regular", "Brigada", "Equipos", "Especial"]

TIPOS_CONTACTO = [
    "Contacto Personal",
    "Contacto en Cabina",
    "Contacto en Oficina",
]

SUPERVISORES_POR_GRUPO = {
    "G1": ["A. Ramirez", "G. Hidalgo", "J. Diaz", "O. Araujo"],
    "G2": ["A. Morales", "S. Rodríguez", "L. Jiménez"],
    "G3": ["D. Tapias", "J. Hernández", "C. Daza", "E. Duran"],
}
GRUPOS_SUP = ["G1", "G2", "G3"]


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
                  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
            """)

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
                  rol TEXT NOT NULL CHECK (rol IN ('ADMIN','SUPERVISOR','DIGITADOR','LECTOR')),
                  is_active INTEGER NOT NULL DEFAULT 1,
                  created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """)

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
                hora TEXT NOT NULL,
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


# ---------------------------------------------------------
# [SEED] Crear admin por única vez
# ---------------------------------------------------------
def seed_admin_once():
    username = "admin"
    password = "admin123"
    rol = "ADMIN"

    with get_conn() as conn:
        existe = conn.execute(
            "SELECT 1 FROM users WHERE username = ? LIMIT 1",
            (username,)
        ).fetchone()

        if existe:
            return

        conn.execute("""
            INSERT INTO users (username, password_hash, rol, is_active)
            VALUES (?, ?, ?, 1)
        """, (username, generate_password_hash(password), rol))


# ---------------------------------------------------------
# [SEED] Minas por única vez para admin
# ---------------------------------------------------------
def seed_user_minas_once():
    with get_conn() as conn:
        admin = conn.execute(
            "SELECT id FROM users WHERE username = 'admin' LIMIT 1"
        ).fetchone()

        if not admin:
            return

        user_id = admin["id"]
        minas = ["ED", "PB"]  # ajusta si quieres

        for m in minas:
            conn.execute("""
                INSERT OR IGNORE INTO user_minas (user_id, mina)
                VALUES (?, ?)
            """, (user_id, m))


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


# ---------------------------------------------------------
# [INIT] Ejecutar inicialización (ORDEN CORRECTO)
# ---------------------------------------------------------
init_auth_tables()
init_db()

seed_admin_once()
seed_user_minas_once()


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
        SELECT tipo, ROUND(SUM(cantidad), 2) AS cantidad
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

    return dict(
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
        operacion=operacion,
        bahias=bahias,
        bahias_nota=bahias_nota,
        pts=pts,
        comentarios=comentarios,
        supervisores=supervisores,
    )


# ---------------------------------------------------------
# [RUTA] Reporte PDF
# ---------------------------------------------------------
@app.route("/reportes/<int:reporte_id>/pdf")
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

    html = render_template("pdf/reporte_pdf.html", **ctx)
    pdf_bytes = HTML(string=html, base_url=request.url_root).write_pdf()

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
@app.route("/")
def home():
    return redirect(url_for("ver_reportes"))


# ---------------------------------------------------------
# [RUTA] Ver reportes (filtrado por mina)
# ---------------------------------------------------------
@app.route("/reportes")
def ver_reportes():
    if g.user is None:
        return redirect(url_for("login"))

    with get_conn() as conn:
        if g.user["rol"] == "ADMIN":
            reportes = conn.execute("""
                SELECT id, fecha, turno, estado, mina
                FROM reportes
                ORDER BY id DESC
            """).fetchall()
        else:
            if not g.user_minas:
                reportes = []
            else:
                placeholders = ",".join(["?"] * len(g.user_minas))
                reportes = conn.execute(f"""
                    SELECT id, fecha, turno, estado, mina
                    FROM reportes
                    WHERE mina IN ({placeholders})
                    ORDER BY id DESC
                """, list(g.user_minas)).fetchall()

    return render_template("reportes.html", reportes=reportes)


# ---------------------------------------------------------
# [RUTA] Nuevo reporte
#   - ADMIN: puede crear en ED/PB
#   - SUPERVISOR: solo en sus minas (g.user_minas)
#   - DIGITADOR/LECTOR: bloqueado
# ---------------------------------------------------------
@app.route("/reportes/nuevo", methods=["GET", "POST"])
def nuevo_reporte():
    if g.user is None:
        return redirect(url_for("login"))

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
        # ✅ Si solo tiene 1 mina, se preselecciona y no hace falta escoger
        mina_sel = minas_permitidas[0]

        # En el template puedes ocultar el select si len(minas_permitidas)==1
        minas_ui = [(code, mina_label(code)) for code in minas_permitidas]

        return render_template(
            "reporte_nuevo.html",
            hoy=date.today().isoformat(),
            error=None,
            minas=minas_ui,
            mina_sel=mina_sel,
            mina_locked=(len(minas_permitidas) == 1)  # ✅ bandera para UI
        )

    # POST
    fecha = request.form.get("fecha", "").strip()
    turno = request.form.get("turno", "").strip().upper()
    mina = request.form.get("mina", "").strip().upper()

    # ✅ Validar mina contra permitidas (aquí está el blindaje real)
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

    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO reportes (fecha, turno, estado, mina) VALUES (?, ?, 'ABIERTO', ?)",
            (fecha, turno, mina)
        )
        reporte_id = cur.lastrowid

    return redirect(url_for("reporte_inicio", reporte_id=reporte_id))



# ---------------------------------------------------------
# [RUTA] Inicio del reporte
# ---------------------------------------------------------
@app.route("/reportes/<int:reporte_id>")
@reporte_mina_required
def reporte_inicio(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
    return render_template("reporte_inicio.html", r=r)


# ---------------------------------------------------------
# [RUTA] Cerrar reporte
# (nota: aquí también conviene validar mina con @reporte_mina_required)
# ---------------------------------------------------------
@app.route("/reportes/<int:reporte_id>/cerrar", methods=["POST"])
@reporte_mina_required
@roles_required("ADMIN", "SUPERVISOR")
def cerrar_reporte(reporte_id):
    with get_conn() as conn:
        conn.execute(
            "UPDATE reportes SET estado = 'CERRADO' WHERE id = ?",
            (reporte_id,)
        )
    return redirect(url_for("ver_reportes"))


# ---------------------------------------------------------
# [RUTA] Reabrir reporte
# ---------------------------------------------------------
@app.route("/reportes/<int:reporte_id>/reabrir", methods=["POST"])
@reporte_mina_required
@roles_required("ADMIN", "SUPERVISOR")
def reabrir_reporte(reporte_id):
    with get_conn() as conn:
        conn.execute(
            "UPDATE reportes SET estado = 'ABIERTO' WHERE id = ?",
            (reporte_id,)
        )
    return redirect(url_for("ver_reportes"))


# =========================================================
# Bloque 6: Gestión + Buses + Varados (CRUD)
# =========================================================

# ---------------------------------------------------------
# [RUTA] GESTIÓN
# ---------------------------------------------------------
@app.route("/reportes/<int:reporte_id>/gestion", methods=["GET", "POST"])
@reporte_mina_required
def gestion_areas(reporte_id):
    error = None

    with get_conn() as conn:
        reporte = fetch_reporte(conn, reporte_id)

        if request.method == "POST":
            if g.user is None:
                return redirect(url_for("login"))

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

                if hora == "" or hallazgo == "" or accion == "" or responsable == "":
                    error = "Todos los campos son obligatorios."
                else:
                    corregido_val = 1 if corregido == "1" else 0
                    conn.execute("""
                        INSERT INTO gestion_areas (reporte_id, hora, hallazgo, accion, corregido, responsable)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (reporte_id, hora, hallazgo, accion, corregido_val, responsable))
                    return redirect(url_for("gestion_areas", reporte_id=reporte_id))

        items = conn.execute(
            "SELECT * FROM gestion_areas WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()

    return render_template("gestion.html", reporte=reporte, r=reporte, items=items, error=error)


@app.route("/reportes/<int:reporte_id>/gestion/<int:item_id>/editar", methods=["GET", "POST"])
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

            return redirect(url_for("gestion_areas", reporte_id=reporte_id))

        return render_template("gestion_editar.html", r=r, reporte=r, item=item, error=None)


@app.route("/reportes/<int:reporte_id>/gestion/eliminar/<int:item_id>", methods=["POST"])
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

    return redirect(url_for("gestion_areas", reporte_id=reporte_id))


# ---------------------------------------------------------
# [RUTA] BUSES
# ---------------------------------------------------------
@app.route("/reportes/<int:reporte_id>/buses", methods=["GET", "POST"])
@reporte_mina_required
def buses_bahias(reporte_id):
    with get_conn() as conn:
        reporte = fetch_reporte(conn, reporte_id)
        error = None

        items = conn.execute(
            "SELECT * FROM buses_bahias WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()

        usadas = {it["bahia"] for it in items}
        bahias_disponibles = [b for b in BAHIAS if b not in usadas]

        if request.method == "POST":
            if g.user["rol"] == "LECTOR":
                error = "No tienes permisos para registrar información."
            elif reporte["estado"] == "CERRADO":
                error = "Este reporte está cerrado. No se puede editar."
            else:
                bahia = request.form.get("bahia", "").strip()
                hora = request.form.get("hora", "").strip()
                observacion = request.form.get("observacion", "").strip()

                if bahia == "" or hora == "":
                    error = "Bahía y Hora son obligatorios."
                elif bahia not in BAHIAS:
                    error = "Debes seleccionar una bahía válida."
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
        bahias_disponibles = [b for b in BAHIAS if b not in usadas]

    return render_template(
        "buses.html",
        reporte=reporte, r=reporte,
        items=items,
        error=error,
        bahias=bahias_disponibles
    )


@app.route("/reportes/<int:reporte_id>/buses/<int:item_id>/editar", methods=["GET", "POST"])
@reporte_mina_required
def editar_item_buses(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)

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
            observacion = request.form.get("observacion", "").strip()

            if bahia not in BAHIAS:
                error = "Debes seleccionar una bahía válida."
            elif bahia == "" or hora == "":
                error = "Bahía y Hora llegada son obligatorios."
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
            bahias=BAHIAS,
            error=error
        )


@app.route("/reportes/<int:reporte_id>/buses/eliminar/<int:item_id>", methods=["POST"])
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
@app.route("/reportes/<int:reporte_id>/varados", methods=["GET", "POST"])
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
                hora = request.form.get("hora", "").strip()
                motivo = request.form.get("motivo", "").strip()

                if equipo_raw == "" or ubicacion == "" or hora == "" or motivo == "":
                    error = "Todos los campos son obligatorios."
                elif not equipo_raw.isdigit():
                    error = "El equipo debe ser un número entero."
                else:
                    equipo = int(equipo_raw)
                    conn.execute("""
                        INSERT INTO equipos_varados (reporte_id, equipo, ubicacion, hora, motivo)
                        VALUES (?, ?, ?, ?, ?)
                    """, (reporte_id, equipo, ubicacion, hora, motivo))
                    return redirect(url_for("equipos_varados", reporte_id=reporte_id))

        items = conn.execute(
            "SELECT * FROM equipos_varados WHERE reporte_id = ? ORDER BY id DESC",
            (reporte_id,)
        ).fetchall()

    return render_template("varados.html", reporte=reporte, r=reporte, items=items, error=error)


@app.route("/reportes/<int:reporte_id>/varados/<int:item_id>/editar", methods=["GET", "POST"])
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
            hora = request.form.get("hora", "").strip()
            motivo = request.form.get("motivo", "").strip()

            if equipo_raw == "" or ubicacion == "" or hora == "" or motivo == "":
                error = "Todos los campos son obligatorios."
            elif not equipo_raw.isdigit():
                error = "El equipo debe ser un número entero."
            else:
                equipo = int(equipo_raw)
                conn.execute("""
                    UPDATE equipos_varados
                    SET equipo = ?, ubicacion = ?, hora = ?, motivo = ?
                    WHERE id = ? AND reporte_id = ?
                """, (equipo, ubicacion, hora, motivo, item_id, reporte_id))
                return redirect(url_for("equipos_varados", reporte_id=reporte_id))

        return render_template("varados_editar.html", r=r, reporte=r, it=it, error=error)


@app.route("/reportes/<int:reporte_id>/varados/eliminar/<int:item_id>", methods=["POST"])
@reporte_mina_required
def eliminar_item_varados(reporte_id, item_id):
    with get_conn() as conn:
        rep = conn.execute(
            "SELECT estado FROM reportes WHERE id = ?",
            (reporte_id,)
        ).fetchone()
        if rep is None:
            abort(404)

        if rep["estado"] == "CERRADO":
            return redirect(url_for("equipos_varados", reporte_id=reporte_id))

        if g.user["rol"] == "LECTOR":
            return ("No autorizado", 403)

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
@app.route("/reportes/<int:reporte_id>/ausentismo", methods=["GET", "POST"])
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


@app.route("/reportes/<int:reporte_id>/ausentismo/<int:item_id>/editar", methods=["GET", "POST"])
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


@app.route("/reportes/<int:reporte_id>/ausentismo/eliminar/<int:item_id>", methods=["POST"])
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
@app.route("/reportes/<int:reporte_id>/bombas", methods=["GET", "POST"])
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


@app.route("/reportes/<int:reporte_id>/bombas/<int:item_id>/editar", methods=["GET", "POST"])
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


@app.route("/reportes/<int:reporte_id>/bombas/eliminar/<int:item_id>", methods=["POST"])
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
@app.route("/reportes/<int:reporte_id>/dist_camiones", methods=["GET", "POST"])
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


@app.route("/reportes/<int:reporte_id>/dist_camiones/<int:item_id>/editar", methods=["GET", "POST"])
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


@app.route("/reportes/<int:reporte_id>/dist_camiones/<int:item_id>/eliminar", methods=["POST"])
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
@app.route("/reportes/<int:reporte_id>/equipo_liviano", methods=["GET", "POST"])
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
                camioneta = request.form.get("camioneta", "").strip()
                estado_l = request.form.get("estado", "OK").strip().upper()
                comentario = request.form.get("comentario", "").strip()

                if estado_l == "":
                    estado_l = "OK"

                if (not camioneta.isdigit()) or (int(camioneta) not in [int(x) for x in camionetas]):
                    error = "Debe seleccionar una camioneta válida."
                elif estado_l not in ESTADOS_LIVIANO:
                    error = "Estado inválido."
                else:
                    existe = conn.execute("""
                        SELECT 1
                        FROM equipo_liviano
                        WHERE reporte_id = ? AND camioneta = ?
                        LIMIT 1
                    """, (reporte_id, int(camioneta))).fetchone()

                    if existe:
                        error = f"La camioneta {camioneta} ya fue registrada en este reporte."
                    else:
                        conn.execute("""
                            INSERT INTO equipo_liviano (reporte_id, camioneta, estado, comentario)
                            VALUES (?, ?, ?, ?)
                        """, (reporte_id, int(camioneta), estado_l, comentario))
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
        camionetas_disponibles = [c for c in camionetas if int(c) not in ya_set]

    return render_template(
        "equipo_liviano.html",
        r=r, reporte=r,
        camionetas=camionetas_disponibles,
        estados=ESTADOS_LIVIANO,
        items=items,
        error=error
    )


@app.route("/reportes/<int:reporte_id>/equipo_liviano/<int:item_id>/editar", methods=["GET", "POST"])
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

            camioneta = request.form.get("camioneta", "").strip()
            estado = request.form.get("estado", "OK").strip().upper()
            comentario = request.form.get("comentario", "").strip()

            if camioneta == "" or camioneta not in camionetas:
                error = "Debes seleccionar una camioneta válida para esta mina."
            elif estado not in ESTADOS_LIVIANO:
                error = "Estado inválido."
            else:
                dup = conn.execute("""
                    SELECT 1
                    FROM equipo_liviano
                    WHERE reporte_id = ? AND camioneta = ? AND id <> ?
                """, (reporte_id, camioneta, item_id)).fetchone()

                if dup:
                    error = f"La camioneta {camioneta} ya está registrada en este reporte."
                else:
                    conn.execute("""
                        UPDATE equipo_liviano
                        SET camioneta = ?, estado = ?, comentario = ?
                        WHERE id = ? AND reporte_id = ?
                    """, (camioneta, estado, comentario, item_id, reporte_id))
                    return redirect(url_for("equipo_liviano", reporte_id=reporte_id))

    return render_template(
        "equipo_liviano_editar.html",
        r=r, reporte=r,
        it=it,
        camionetas=camionetas,
        error=error
    )


@app.route("/reportes/<int:reporte_id>/equipo_liviano/eliminar/<int:item_id>", methods=["POST"])
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


@app.route("/reportes/<int:reporte_id>/equipo_liviano/todas_ok", methods=["POST"])
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
@app.route("/reportes/<int:reporte_id>/personal", methods=["GET", "POST"])
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
                CASE categoria WHEN 'ROSTER' THEN 0 ELSE 1 END,
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
                CASE categoria WHEN 'ROSTER' THEN 0 ELSE 1 END,
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


@app.route("/reportes/<int:reporte_id>/personal/<int:item_id>/editar", methods=["GET", "POST"])
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


@app.route("/reportes/<int:reporte_id>/personal/eliminar/<int:item_id>", methods=["POST"])
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
@app.route("/reportes/<int:reporte_id>/otras_areas", methods=["GET", "POST"])
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


@app.route("/reportes/<int:reporte_id>/otras_areas/<int:item_id>/editar", methods=["GET", "POST"])
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


@app.route("/reportes/<int:reporte_id>/otras_areas/eliminar/<int:item_id>", methods=["POST"])
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
@app.route("/reportes/<int:reporte_id>/entrenamiento", methods=["GET", "POST"])
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


@app.route("/reportes/<int:reporte_id>/entrenamiento/<int:item_id>/editar", methods=["GET", "POST"])
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


@app.route("/reportes/<int:reporte_id>/entrenamiento/eliminar/<int:item_id>", methods=["POST"])
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
@app.route("/reportes/<int:reporte_id>/luminarias", methods=["GET", "POST"])
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


@app.route("/reportes/<int:reporte_id>/luminarias/<int:item_id>/editar", methods=["GET", "POST"])
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


@app.route("/reportes/<int:reporte_id>/luminarias/eliminar/<int:item_id>", methods=["POST"])
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
@app.route("/reportes/<int:reporte_id>/contactos", methods=["GET", "POST"])
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


@app.route("/reportes/<int:reporte_id>/contactos/<int:item_id>/editar", methods=["GET", "POST"])
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


@app.route("/reportes/<int:reporte_id>/contactos/eliminar/<int:item_id>", methods=["POST"])
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

@app.route("/reportes/<int:reporte_id>/seguridad", methods=["GET", "POST"])
@reporte_mina_required
def seguridad(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)

        error_obs = None
        error_charla = None

        if request.method == "POST":
            form_type = request.form.get("form_type", "").strip()

            if g.user is None:
                return redirect(url_for("login"))

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


@app.route("/reportes/<int:reporte_id>/seguridad/obs/<int:item_id>/editar", methods=["GET", "POST"])
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


@app.route("/reportes/<int:reporte_id>/seguridad/obs/<int:item_id>/eliminar", methods=["POST"])
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


@app.route("/reportes/<int:reporte_id>/seguridad/charla/<int:item_id>/editar", methods=["GET", "POST"])
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


@app.route("/reportes/<int:reporte_id>/seguridad/charla/<int:item_id>/eliminar", methods=["POST"])
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
@app.route("/reportes/<int:reporte_id>/first_last", methods=["GET", "POST"])
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
                    inicio_pit2 = request.form.get("inicio_pit2", "").strip()
                    inicio_pit5 = request.form.get("inicio_pit5", "").strip()
                    final_pit2  = request.form.get("final_pit2", "").strip()
                    final_pit5  = request.form.get("final_pit5", "").strip()

                    camiones_raw = request.form.get("camiones_por_operador", "").strip()
                    razon = request.form.get("razon", "").strip()

                    if inicio_pit2 == "" or inicio_pit5 == "" or final_pit2 == "" or final_pit5 == "":
                        error = "Todas las horas son obligatorias."
                    elif camiones_raw == "" or (not camiones_raw.isdigit()):
                        error = "La cantidad de camiones debe ser un número entero (0 o mayor)."
                    else:
                        camiones = int(camiones_raw)
                        if camiones > 0 and razon == "":
                            error = "Si camiones por operador es mayor que 0, la razón es obligatoria."
                        else:
                            conn.execute("""
                                INSERT INTO first_last
                                (reporte_id, inicio_pit2, inicio_pit5, final_pit2, final_pit5,
                                 camiones_por_operador, razon)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                            """, (reporte_id, inicio_pit2, inicio_pit5, final_pit2, final_pit5, camiones, razon))
                            return redirect(url_for("first_last", reporte_id=reporte_id))

        item = conn.execute(
            "SELECT * FROM first_last WHERE reporte_id = ?",
            (reporte_id,)
        ).fetchone()

    return render_template("first_last.html", r=r, reporte=r, item=item, error=error)


@app.route("/reportes/<int:reporte_id>/first_last/editar", methods=["GET", "POST"])
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

            inicio_pit2 = request.form.get("inicio_pit2", "").strip()
            inicio_pit5 = request.form.get("inicio_pit5", "").strip()
            final_pit2  = request.form.get("final_pit2", "").strip()
            final_pit5  = request.form.get("final_pit5", "").strip()

            camiones_raw = request.form.get("camiones_por_operador", "").strip()
            razon = request.form.get("razon", "").strip()

            if inicio_pit2 == "" or inicio_pit5 == "" or final_pit2 == "" or final_pit5 == "":
                error = "Todas las horas son obligatorias."
            else:
                if camiones_raw == "":
                    camiones_raw = "0"
                if not camiones_raw.isdigit():
                    error = "La cantidad de camiones debe ser un número entero (0 o mayor)."
                else:
                    camiones = int(camiones_raw)
                    if camiones > 0 and razon == "":
                        error = "Si camiones por operador es mayor que 0, la razón es obligatoria."
                    else:
                        conn.execute("""
                            UPDATE first_last
                            SET inicio_pit2 = ?, inicio_pit5 = ?, final_pit2 = ?, final_pit5 = ?,
                                camiones_por_operador = ?, razon = ?,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE reporte_id = ?
                        """, (inicio_pit2, inicio_pit5, final_pit2, final_pit5, camiones, razon, reporte_id))
                        return redirect(url_for("first_last", reporte_id=reporte_id))

    return render_template("first_last_editar.html", r=r, reporte=r, it=it, error=error)


@app.route("/reportes/<int:reporte_id>/first_last/eliminar", methods=["POST"])
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
@app.route("/reportes/<int:reporte_id>/pts", methods=["GET", "POST"])
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


@app.route("/reportes/<int:reporte_id>/pts/editar", methods=["GET", "POST"])
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


@app.route("/reportes/<int:reporte_id>/pts/eliminar", methods=["POST"])
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
@app.route("/reportes/<int:reporte_id>/comentarios", methods=["GET", "POST"])
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


@app.route("/reportes/<int:reporte_id>/comentarios/<int:item_id>/editar", methods=["GET", "POST"])
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


@app.route("/reportes/<int:reporte_id>/comentarios/eliminar/<int:item_id>", methods=["POST"])
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
@app.route("/reportes/<int:reporte_id>/supervisores", methods=["GET", "POST"])
@reporte_mina_required
def supervisores_turno(reporte_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
        error = None

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
                    validos = set(SUPERVISORES_POR_GRUPO.get(grupo, []))

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
        sup_por_grupo=SUPERVISORES_POR_GRUPO
    )


@app.route("/reportes/<int:reporte_id>/supervisores/<int:item_id>/editar", methods=["GET", "POST"])
@reporte_mina_required
def editar_supervisor_turno(reporte_id, item_id):
    with get_conn() as conn:
        r = fetch_reporte(conn, reporte_id)
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
                validos = set(SUPERVISORES_POR_GRUPO.get(grupo, []))
                if supervisor not in validos:
                    error = "Supervisor inválido para el grupo seleccionado."
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
        sup_por_grupo=SUPERVISORES_POR_GRUPO
    )


@app.route("/reportes/<int:reporte_id>/supervisores/eliminar/<int:item_id>", methods=["POST"])
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


# =========================================================
# Bloque 11: Resumen + PDF + Login/Logout + Init/Seeds + RUN
# =========================================================

# ---------------------------------------------------------
# [RUTA] Resumen
# ---------------------------------------------------------
@app.route("/reportes/<int:reporte_id>/resumen")
@reporte_mina_required
def resumen(reporte_id):
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

        dist_camiones = conn.execute("""
            SELECT tipo, ROUND(SUM(cantidad), 2) AS cantidad
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

        total_camiones = conn.execute(
            "SELECT COALESCE(SUM(cantidad), 0) FROM distribucion_camiones WHERE reporte_id = ?",
            (reporte_id,)
        ).fetchone()[0]
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
        supervisores=supervisores
    )


# =========================================================
# [ADMIN] Usuarios (solo ADMIN)
# =========================================================

@app.route("/admin/usuarios")
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
@app.route("/admin/usuarios/nuevo", methods=["GET", "POST"])
@admin_required
def admin_usuario_nuevo():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        rol = request.form.get("rol", "").strip().upper()
        minas = request.form.getlist("minas")  # lista de minas marcadas

        roles_validos = {"ADMIN", "SUPERVISOR", "DIGITADOR", "LECTOR"}
        minas_validas = {m[0] for m in MINAS}

        if not username or not password or rol not in roles_validos:
            error = "Usuario, contraseña y rol son obligatorios (rol válido)."
        elif len(password) < 6:
            error = "La contraseña debe tener al menos 6 caracteres."
        elif any(m not in minas_validas for m in minas):
            error = "Seleccionaste una mina inválida."
        else:
            with get_conn() as conn:
                try:
                    cur = conn.execute("""
                        INSERT INTO users (username, password_hash, rol, is_active)
                        VALUES (?, ?, ?, 1)
                    """, (username, generate_password_hash(password), rol))
                    user_id = cur.lastrowid
                except sqlite3.IntegrityError:
                    error = "Ese username ya existe."
                else:
                    # Asignar minas (si no se marca ninguna, queda sin minas)
                    for m in minas:
                        conn.execute("""
                            INSERT OR IGNORE INTO user_minas (user_id, mina)
                            VALUES (?, ?)
                        """, (user_id, m))

                    return redirect(url_for("admin_usuarios"))

    return render_template("admin_usuario_nuevo.html", error=error, roles=["ADMIN","SUPERVISOR","DIGITADOR","LECTOR"], minas=MINAS)


@app.route("/admin/usuarios/<int:user_id>/editar", methods=["GET", "POST"])
@admin_required
def admin_usuario_editar(user_id):
    error = None
    ok = None

    with get_conn() as conn:
        u = conn.execute("""
            SELECT id, username, rol, is_active
            FROM users
            WHERE id = ?
        """, (user_id,)).fetchone()

        if not u:
            abort(404)

        user_minas = conn.execute("""
            SELECT mina FROM user_minas WHERE user_id = ?
        """, (user_id,)).fetchall()
        user_minas_set = {r["mina"] for r in user_minas}

    if request.method == "POST":
        rol = request.form.get("rol", "").strip().upper()
        is_active = request.form.get("is_active", "1").strip()
        minas = request.form.getlist("minas")
        new_password = request.form.get("new_password", "").strip()

        roles_validos = {"ADMIN", "SUPERVISOR", "DIGITADOR", "LECTOR"}
        minas_validas = {m[0] for m in MINAS}

        if rol not in roles_validos:
            error = "Rol inválido."
        elif is_active not in ("0","1"):
            error = "Estado inválido."
        elif any(m not in minas_validas for m in minas):
            error = "Seleccionaste una mina inválida."
        elif new_password and len(new_password) < 6:
            error = "La nueva contraseña debe tener al menos 6 caracteres."
        else:
            with get_conn() as conn:
                # Actualizar rol/estado
                conn.execute("""
                    UPDATE users
                    SET rol = ?, is_active = ?
                    WHERE id = ?
                """, (rol, int(is_active), user_id))

                # Reset password (si vino)
                if new_password:
                    conn.execute("""
                        UPDATE users
                        SET password_hash = ?
                        WHERE id = ?
                    """, (generate_password_hash(new_password), user_id))

                # Actualizar minas: borrar y reinsertar
                conn.execute("DELETE FROM user_minas WHERE user_id = ?", (user_id,))
                for m in minas:
                    conn.execute("""
                        INSERT OR IGNORE INTO user_minas (user_id, mina)
                        VALUES (?, ?)
                    """, (user_id, m))

            ok = "Usuario actualizado."

            # Recargar datos para render
            with get_conn() as conn:
                u = conn.execute("""
                    SELECT id, username, rol, is_active
                    FROM users
                    WHERE id = ?
                """, (user_id,)).fetchone()

                user_minas = conn.execute("""
                    SELECT mina FROM user_minas WHERE user_id = ?
                """, (user_id,)).fetchall()
                user_minas_set = {r["mina"] for r in user_minas}

    return render_template(
        "admin_usuario_editar.html",
        u=u,
        minas=MINAS,
        user_minas_set=user_minas_set,
        roles=["ADMIN","SUPERVISOR","DIGITADOR","LECTOR"],
        error=error,
        ok=ok
    )


@app.post("/admin/usuarios/<int:user_id>/eliminar")
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

    return redirect(url_for("admin_usuarios"))



# ---------------------------------------------------------
# [AUTH] Login / Logout
# ---------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        # 🔴 normalizamos username
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            sql_params("""
                SELECT id, username, password_hash, rol, is_active
                FROM users
                WHERE LOWER(username) = ?
                LIMIT 1
            """),
            (username,)
        )

        user = cur.fetchone()
        cur.close()
        conn.close()

        if user is None:
            error = "Usuario o contraseña incorrectos."
        elif user["is_active"] != 1:
            error = "Usuario inactivo."
        elif not check_password_hash(user["password_hash"], password):
            error = "Usuario o contraseña incorrectos."
        else:
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("ver_reportes"))

    return render_template("login.html", error=error)




@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))



# ---------------------------------------------------------
# [INIT] Auth tables + seeds
# ---------------------------------------------------------
init_auth_tables()
# seed_admin_once()
# seed_user_minas_once()

# =========================================================
# RUN
# =========================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
