import glob
import re
import os

files = glob.glob("templates/*.html")
ignore_files = ['base.html', 'macros.html', 'reportes.html', 'login.html', 'reporte_inicio.html', 'resumen.html']

# The start import to insert after {% block content %} or similar:
macro_import = "{% from 'macros.html' import render_header, render_alertas, acciones_td, btn_agregar %}\n"

for f in files:
    filename = os.path.basename(f)
    if filename in ignore_files or "editar" in filename or "nuevo" in filename or filename.startswith("_"):
        continue
    
    with open(f, 'r', encoding='utf-8') as file:
        content = file.read()
    
    original_content = content

    # 1. Insert import after {% block content %}
    if "{% from 'macros.html'" not in content:
        content = re.sub(r'({%\s*block content\s*%})', r'\1\n' + macro_import, content)

    # 2. Header replacement
    # Match:
    # <div class="d-flex justify-content-between ...">
    #   <div>
    #     <h1 class="mb-1">TÍTULO</h1>
    #     <div class="text-muted">
    #       Reporte #{{ r.id }} | {{ r.fecha }} | {{ r.turno }} | {{ r.mina }} | Estado: {{ r.estado }}
    #     </div>
    #   </div>
    #   {% include "_nav_reporte.html" %}
    # </div>
    header_regex = r'<div class="d-flex[^>]*>\s*<div>\s*<h1 class="mb-1">([^<]+)</h1>\s*<div class="text-muted">.*?</div>\s*</div>\s*{%\s*include "_nav_reporte\.html"\s*%}\s*</div>'
    def replace_header(match):
        title = match.group(1).strip()
        return f"{{{{ render_header('{title}', r) }}}}"
    
    content = re.sub(header_regex, replace_header, content, flags=re.DOTALL)

    # 3. Alertas replacement (combines error + cerrado check)
    alertas_regex = r'({%\s*if error\s*%}\s*<div class="alert alert-danger[^"]*">{{ error }}</div>\s*{%\s*endif\s*%}\s*)?{%\s*if r\.estado == "CERRADO"\s*%}\s*<div class="alert alert-warning[^"]*">\s*Este reporte está cerrado. No se puede editar.\s*</div>\s*{%\s*endif\s*%}'
    content = re.sub(alertas_regex, "{{ render_alertas(r, error) }}", content, flags=re.DOTALL)

    # 4. Btn agregar
    btn_agregar_regex = r'{%\s*if r\.estado != "CERRADO"\s*%}\s*<button class="btn btn-primary"[^>]*>✅ Agregar</button>\s*{%\s*else\s*%}\s*<button class="btn btn-secondary"[^>]*>Reporte cerrado</button>\s*{%\s*endif\s*%}'
    # if it's enclosed in a div with mt-3, let's replace the whole div? Let's just replace the btn part, but wait, the macro creates the div mt-3
    btn_agregar_full_regex = r'<div class="mt-3">\s*' + btn_agregar_regex + r'\s*</div>'
    content = re.sub(btn_agregar_full_regex, "{{ btn_agregar(r) }}", content, flags=re.DOTALL)
    # also try without the div
    content = re.sub(btn_agregar_regex, "{{ btn_agregar(r) }}", content, flags=re.DOTALL)

    # 5. Acciones td
    # This is trickier because we need the urls
    # <td class="acciones-td"> 
    #   <div class="d-flex gap-1 align-items-center">
    #     {% if r.estado == "CERRADO" %}
    #       <span class="reporte-cerrado">Reporte cerrado</span>
    #     {% else %}
    #       <a class="btn btn-sm btn-outline-primary" href="URL_EDIT"> ✏️ Editar </a>
    #       <form method="[pP][oO][sS][tT]" action="URL_DELETE" class="m-0">
    #         <button ...> 🗑 Eliminar </button>
    #       </form>
    #     {% endif %}
    #   </div>
    # </td>
    acciones_regex = r'<td class="acciones-td">\s*<div class="d-flex gap-1 align-items-center">\s*{%\s*if r\.estado == "CERRADO"\s*%}\s*<span class="reporte-cerrado">Reporte cerrado</span>\s*{%\s*else\s*%}\s*<a class="btn btn-sm btn-outline-primary"\s*href="([^"]+)">\s*✏️ Editar\s*</a>\s*<form method="[pP][oO][sS][tT]"\s*action="([^"]+)"\s*class="m-0">\s*<button class="btn btn-sm btn-outline-danger"\s*onclick="return confirm\(\'¿Eliminar este registro\?\'\);?">\s*🗑 Eliminar\s*</button>\s*</form>\s*{%\s*endif\s*%}\s*</div>\s*</td>'
    def replace_acciones(match):
        url_edit = match.group(1)
        url_delete = match.group(2)
        # Handle if the URL has quotes inside {{ URL }}
        # Wait, the macro parameter just accepts the value, so we pass it directly
        # Example: "{{ url_for('secciones.edit', item_id=it.id) }}" 
        # But wait, in the template, we are doing href="{{ url }}", so the regex captures {{ url }}.
        # In the macro call, we want: {{ acciones_td(r, url_for(...), url_for(...)) }}
        # So we need to strip the {{ }} from the captured group
        ue = url_edit.replace("{{", "").replace("}}", "").strip()
        ud = url_delete.replace("{{", "").replace("}}", "").strip()
        return f"{{{{ acciones_td(r, {ue}, {ud}) }}}}"

    content = re.sub(acciones_regex, replace_acciones, content, flags=re.DOTALL)

    if content != original_content:
        with open(f, 'w', encoding='utf-8') as file:
            file.write(content)
        print(f"Macros aplicados a {f}")
