from config import MINAS, IMPACTO_PERSONAL

def mina_label(mina_code: str) -> str:
    """Devuelve etiqueta legible de la mina."""
    return dict(MINAS).get(mina_code, mina_code or "")

def get_personal_label(categoria: str, mina_code: str = None) -> str:
    """
    Devuelve la etiqueta visual para una categoría de personal.
    - ROSTER -> Roster del grupo
    - Si mina es PB, intercambia etiquetas de prestado/recibido.
    """
    if categoria == "ROSTER":
        return "Roster del grupo"
    
    if mina_code == "PB":
        if categoria == "Personal prestado a PB":
            return "Personal prestado a ED"
        if categoria == "Personal recibido desde PB":
            return "Personal recibido desde ED"
            
    return categoria

def calc_disponible_personal(items):
    """
    Calcula personal disponible.
    Retorna: (roster, disponible)

    REGLA:
      - roster = ROSTER + "Personal solo día"
      - "Personal solo día" NO se vuelve a aplicar en impactos (para no duplicar)
    """
    data = {row["categoria"]: int(row["cantidad"]) for row in items}

    roster = data.get("ROSTER", 0)

    disponible = roster
    for cat, sign in IMPACTO_PERSONAL.items():
        if cat != "ROSTER":
            disponible += sign * data.get(cat, 0)

    return roster, disponible

def norm_text(s: str) -> str:
    s = (s or "").strip()
    s = " ".join(s.split())
    return s.upper()

def get_boolean_val(form, key: str) -> int:
    val = form.get(key, "").strip().upper()
    return 1 if val in ["1", "TRUE", "SÍ", "SI", "YES", "ON"] else 0
