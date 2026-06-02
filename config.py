import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)
DB_PATH = os.path.join(INSTANCE_DIR, "rct.db")

BAHIAS_POR_MINA = {
    "ED": [
        "bahía Banana 2", "bahía Platanal", "bahía Conveyor", "bahía 1.5",
        "bahía Banana 3", "bahía 5", "bahía 7A", "bahía Retro",
        "bahía 14", "bahía 15", "bahia 3 postes",
    ],
    "PB": [
        "Bahía Michoacán", "Bahía R39", "Bahía W3", "Bahía R24",
        "Bahía Cerrejones", "Bahía San Antonio", "Bahía Los Tupes",
    ],
}

ROLES = ["ADMIN", "SUPERVISOR", "DIGITADOR", "LECTOR"]

MINAS = [
    ("ED", "El Descanso"),
    ("PB", "Pribbenow"),
]

CAMIONETAS_POR_MINA = {
    "ED": [2732, 2733, 2734, 2736, 2674, 2676, 2945],
    "PB": [2059, 2683, 2954, 3216, 3252, 3264],
}

ESTADOS_LIVIANO = ["OK", "PM", "DOWN"]

TIPOS_DISTRIBUCION_CAMIONES = [
    "Operativos", "Down", "Stand By con Operador",
    "Stand By sin Operador", "Carbon", "Stand By no programado",
]

CATEGORIAS_PERSONAL = [
    "ROSTER", "Ausentes", "Personal prestado a PB",
    "Personal recibido desde PB", "Personal prestado a Carbón",
    "Personal recibido desde Carbón", "Personal solo día",
    "Vacaciones", "Entrenamiento", "Trainer", "En otras áreas", "Auxiliares",
]

IMPACTO_PERSONAL = {
    "ROSTER": 0,
    "Ausentes": -1,
    "Personal prestado a PB": -1,
    "Personal recibido desde PB": +1,
    "Personal prestado a Carbón": -1,
    "Personal recibido desde Carbón": +1,
    "Personal solo día": +1,
    "Trainer": +1,
    "Vacaciones": -1,
    "Entrenamiento": -1,
    "En otras áreas": -1,
    "Auxiliares": -1,
}

AREAS_OTRAS = sorted([
    "Botaderos", "Carbón", "C.A.S.F", "Despacho", "Dtech",
    "Dragalina", "Etto", "voladura", "Bombas", "Palas",
    "Seg. Ind", "Vías",
], key=lambda x: x.lower())

ENTRENAMIENTOS_PERSONAL = ["Regular", "Brigada", "Equipos", "Especial"]

TIPOS_CONTACTO = [
    "Contacto Personal",
    "Contacto en Cabina",
    "Contacto en Oficina",
]

SUPERVISORES_POR_MINA = {
    "ED": {
        "G1": ["A. Ramirez", "G. Hidalgo", "J. Diaz", "O. Araujo"],
        "G2": ["A. Morales", "S. Rodríguez", "L. Jiménez", "J. Vargas"],
        "G3": ["D. Tapias", "J. Hernández", "C. Daza", "E. Duran"],
    },
    "PB": {
        "G1": ["J. Ballesteros", "J. Reyes"],
        "G2": ["J. Hernández", "M. Maestre"],
        "G3": ["J. Daza", "Q. Muñoz"],
    },
}

GRUPOS_SUP = ["G1", "G2", "G3"]
