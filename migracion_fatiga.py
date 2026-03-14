import os
from database import get_db_connection, is_postgres

def create_table_fatiga():
    conn = get_db_connection()
    try:
        if is_postgres():
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS fatiga_pausas (
                    id SERIAL PRIMARY KEY,
                    reporte_id INTEGER REFERENCES reportes(id) ON DELETE CASCADE,
                    reportes_sueno INTEGER DEFAULT 0,
                    pausas_activas INTEGER DEFAULT 0
                )
            """)
            conn.commit()
            print("Tabla fatiga_pausas creada en PostgreSQL.")
        else:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS fatiga_pausas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporte_id INTEGER NOT NULL,
                    reportes_sueno INTEGER DEFAULT 0,
                    pausas_activas INTEGER DEFAULT 0,
                    FOREIGN KEY(reporte_id) REFERENCES reportes(id) ON DELETE CASCADE
                )
            """)
            conn.commit()
            print("Tabla fatiga_pausas creada en SQLite.")
        conn.close()
    except Exception as e:
        print(f"Error creando tabla: {e}")
        if not is_postgres():
            conn.close()
        else:
            conn.close()

if __name__ == '__main__':
    create_table_fatiga()
