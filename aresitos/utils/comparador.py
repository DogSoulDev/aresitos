#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comparador de herramientas: extrae listas desde `vista_herramientas_kali.py`
y busca coincidencias en el repositorio.

Este archivo reemplaza a `compare_tools.py` y corrige rutas relativas y errores
cuando las listas no están presentes.
"""
import ast
import os
import re
import json
import sys


def abspath_package_dir():
    # Directorio padre del paquete (este archivo está en aresitos/utils)
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


BASE = abspath_package_dir()  # apunta a .../aresitos/aresitos
VISTA = os.path.normpath(os.path.join(BASE, 'vista', 'vista_herramientas_kali.py'))


def extract_list_literal(text, keyword):
    i = text.find(keyword)
    if i == -1:
        return None
    i = text.find('[', i)
    if i == -1:
        return None
    depth = 0
    for j in range(i, len(text)):
        if text[j] == '[':
            depth += 1
        elif text[j] == ']':
            depth -= 1
            if depth == 0:
                snippet = text[i:j+1]
                try:
                    return ast.literal_eval(snippet)
                except Exception:
                    try:
                        code = '[]' if not snippet else snippet
                        return ast.literal_eval(code)
                    except Exception:
                        return None
    return None


if not os.path.exists(VISTA):
    print(json.dumps({'error': '`vista_herramientas_kali.py` no encontrada', 'path': VISTA}, ensure_ascii=False))
    sys.exit(1)


with open(VISTA, 'r', encoding='utf-8') as fh:
    text = fh.read()

# paquetes puede no existir; defensivamente usar lista vacía
paquetes = (
    extract_list_literal(text, '\n            paquetes = [')
    or extract_list_literal(text, '\n            paquetes =[')
    or extract_list_literal(text, 'paquetes = [')
)
if paquetes is None:
    paquetes = []

# Buscar la definición más grande de 'herramientas = [' en el archivo
herramientas_candidates = []
start = 0
while True:
    idx = text.find('herramientas = [', start)
    if idx == -1:
        break
    lst = extract_list_literal(text[idx:], 'herramientas = [')
    if lst:
        herramientas_candidates.append(lst)
    start = idx + 1

herramientas = []
if herramientas_candidates:
    herramientas = max(herramientas_candidates, key=lambda x: len(x))
if herramientas is None:
    herramientas = []

# extraer keys de bin_urls si existen
bin_urls = None
m = re.search(r"bin_urls\s*=\s*\{", text)
if m:
    start_idx = text.find('{', m.start())
    depth = 0
    for j in range(start_idx, len(text)):
        if text[j] == '{':
            depth += 1
        elif text[j] == '}':
            depth -= 1
            if depth == 0:
                snippet = text[start_idx:j+1]
                try:
                    obj = ast.literal_eval(snippet)
                    if isinstance(obj, dict):
                        bin_urls = list(obj.keys())
                except Exception:
                    pass
                break

extras = ['naabu', 'subfinder', 'sqlmap', 'wfuzz', 'httpx', 'gobuster', 'ffuf']

candidates = set()
for lst in (paquetes or []):
    if isinstance(lst, str):
        candidates.add(lst)
for lst in (herramientas or []):
    if isinstance(lst, str):
        candidates.add(lst)
if bin_urls:
    for k in bin_urls:
        name = os.path.splitext(k)[0]
        candidates.add(name)
for e in extras:
    candidates.add(e)

norm_map = {'pspy64': 'pspy', 'pspy32': 'pspy', 'linpeas.sh': 'linpeas'}
normalized = set()
for c in candidates:
    nc = norm_map.get(c, c)
    normalized.add(nc)

candidates = sorted(normalized)

ignore_ext = {'.png', '.jpg', '.db', '.sqlite', '.pyc', '.ico', '.bin'}
repo_matches = {c: {'count': 0, 'files': {}} for c in candidates}
for root, dirs, files in os.walk(os.path.abspath(os.path.join(BASE, '..'))):
    # recorrer desde la raíz del repo (un nivel arriba de package)
    if '.git' in dirs:
        dirs.remove('.git')
    for fname in files:
        if any(fname.endswith(ext) for ext in ignore_ext):
            continue
        fpath = os.path.join(root, fname)
        try:
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            continue
        for c in candidates:
            pattern = r'\b' + re.escape(c) + r'\b'
            found = re.findall(pattern, content)
            if found:
                repo_matches[c]['count'] += len(found)
                repo_matches[c]['files'].setdefault(fpath, 0)
                repo_matches[c]['files'][fpath] += len(found)

installer_tools = sorted(list(set([p for p in (paquetes or []) if isinstance(p, str)] + [h for h in (herramientas or []) if isinstance(h, str)])))
report = {
    'contador_herramientas_instalador': len(installer_tools),
    'muestra_instalador': installer_tools[:30],
    'candidatos_comprobados': candidates,
    'coincidencias': repo_matches,
}
repo_used = [t for t, info in repo_matches.items() if info['count'] > 0]
not_in_installer = [t for t in repo_used if t not in installer_tools]
not_used = [t for t in installer_tools if t not in repo_used]
report['herramientas_usadas_en_repo'] = sorted(repo_used)
report['no_en_instalador'] = sorted(not_in_installer)
report['instaladas_no_usadas_por_repo'] = sorted(not_used)

print(json.dumps(report, indent=2, ensure_ascii=False))
