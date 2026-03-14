import glob

routes = [
    'editar_item_buses', 'eliminar_item_buses', 'buses_bahias',
    'editar_item_varados', 'eliminar_item_varados', 'equipos_varados'
]

for f in glob.glob('templates/*.html'):
    with open(f, 'r', encoding='utf-8') as file:
        content = file.read()
    
    new_content = content
    for r in routes:
        new_content = new_content.replace(f'url_for("{r}"', f'url_for("secciones.{r}"')
        new_content = new_content.replace(f"url_for('{r}'", f"url_for('secciones.{r}'")

    if new_content != content:
        with open(f, 'w', encoding='utf-8') as file:
            file.write(new_content)
        print(f"Reparado: {f}")
