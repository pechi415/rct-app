import glob

routes = [
    "ver_reportes",
    "nuevo_reporte",
    "reporte_inicio",
    "cerrar_reporte",
    "reabrir_reporte",
    "editar_fecha_reporte",
    "resumen",
    "reporte_pdf",
    "eliminar_reporte"
]

html_files = glob.glob('templates/*.html')
for f in html_files:
    with open(f, 'r', encoding='utf-8') as file:
        content = file.read()
    
    new_content = content
    for r in routes:
        # replace double quotes
        new_content = new_content.replace(f"url_for('{r}'", f"url_for('reportes.{r}'")
        new_content = new_content.replace(f'url_for("{r}"', f'url_for("reportes.{r}"')
    
    if new_content != content:
        with open(f, 'w', encoding='utf-8') as file:
            file.write(new_content)
        print(f"Actualizado {f}")
