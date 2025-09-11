#!/usr/bin/env python3
# Script para extraer listas de vista_herramientas_kali.py y comparar con referencias en el repo
import ast, os, re, json, sys

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
VISTA = os.path.join(BASE, 'aresitos', 'vista', 'vista_herramientas_kali.py')

def extract_list_literal(text, keyword):
    i = text.find(keyword)
    if i == -1:
        return None
    i = text.find('[', i)
    if i == -1:
        return None
    # find matching bracket
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
                    # fallback: try to sanitize lines and eval
                    try:
                        code = '[]' if not snippet else snippet
                        return ast.literal_eval(code)
                    except Exception:
                        return None
    return None

if not os.path.exists(VISTA):
    print(json.dumps({'error':'vista_herramientas_kali.py no encontrada', 'path': VISTA}))
    sys.exit(1)

text = open(VISTA, 'r', encoding='utf-8').read()
paquetes = extract_list_literal(text, '\n            paquetes = [') or extract_list_literal(text, '\n            paquetes =[') or extract_list_literal(text, 'paquetes = [')
herramientas_candidates = []
# encontrar todas las apariciones de "herramientas = [" y parsear
start = 0
while True:
    idx = text.find('herramientas = [', start)
    if idx == -1:
        break
    lst = extract_list_literal(text[idx:], 'herramientas = [')
    if lst:
        herramientas_candidates.append(lst)
    start = idx + 1

# elegir la lista más larga si hay varias
herramientas = []
if herramientas_candidates:
    herramientas = max(herramientas_candidates, key=lambda x: len(x))

# entradas especiales: bin_urls keys
bin_urls = None
m = re.search(r"bin_urls\s*=\s*\{", text)
if m:
    b = extract_list_literal(text[text.find('{', m.start()):], '{')
    if isinstance(b, dict):
        bin_urls = list(b.keys())

# herramientas adicionales a detectar (candidatos frecuentes)
extras = ['rustscan','naabu','subfinder','sqlmap','wfuzz','httpx','gobuster','ffuf']

candidates = set()
for lst in (paquetes or []):
    if isinstance(lst, str):
        candidates.add(lst)
for lst in (herramientas or []):
    if isinstance(lst, str):
        candidates.add(lst)
if bin_urls:
    for k in bin_urls:
        name = k
        # strip extension
        name = os.path.splitext(name)[0]
        candidates.add(name)
for e in extras:
    candidates.add(e)

# normalize some known aliases (pspy64 -> pspy)
norm_map = {'pspy64':'pspy', 'pspy32':'pspy', 'linpeas.sh':'linpeas', 'clamav-daemon':'clamav-daemon'}
normalized = set()
for c in candidates:
    nc = norm_map.get(c, c)
    normalized.add(nc)

candidates = sorted(normalized)

# walk repo and search occurrences
ignore_ext = {'.png','.jpg','.db','.sqlite','.pyc','.ico','.bin'}
repo_matches = {c:{'count':0,'files':{}} for c in candidates}
for root, dirs, files in os.walk(BASE):
    # skip .git
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
            # whole-word match (dash and underscore allowed)
            pattern = r'\\b' + re.escape(c) + r'\\b'
            found = re.findall(pattern, content)
            if found:
                repo_matches[c]['count'] += len(found)
                repo_matches[c]['files'].setdefault(fpath,0)
                repo_matches[c]['files'][fpath] += len(found)

# build report
installer_tools = sorted(list(set([p for p in paquetes if isinstance(p,str)] + [h for h in herramientas if isinstance(h,str)])))
report = {
    'installer_tools_count': len(installer_tools),
    'installer_tools_sample': installer_tools[:30],
    'candidates_checked': candidates,
    'matches': repo_matches
}
# tools in repo but not in installer
repo_used = [t for t,info in repo_matches.items() if info['count']>0]
not_in_installer = [t for t in repo_used if t not in installer_tools]
# installer tools not referenced
not_used = [t for t in installer_tools if t not in repo_used]
report['repo_used'] = sorted(repo_used)
report['not_in_installer'] = sorted(not_in_installer)
report['not_used_by_repo'] = sorted(not_used)

print(json.dumps(report, indent=2, ensure_ascii=False))
