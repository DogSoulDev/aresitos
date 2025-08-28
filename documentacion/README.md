# Documentación de Aresitos

Esta carpeta contiene la documentación técnica completa de **Aresitos - Herramienta de Ciberseguridad**.

## Archivos Principales

# Documentación de ARESITOS

Esta carpeta contiene la documentación técnica y de arquitectura de la suite ARESITOS.

## Índice de archivos

- `DOCUMENTACION_TECNICA_CONSOLIDADA.md`: Manual técnico completo
- `ARQUITECTURA_DESARROLLO.md`: Guía de arquitectura y desarrollo
- `REVISION_MVC_ARESITOS.md`: Revisión de la arquitectura MVC
- `AUDITORIA_SEGURIDAD_ARESITOS.md`: Auditoría de seguridad y vulnerabilidades
- `GUIA_INSTALACION.md`: Guía de instalación y configuración
- `TERMINAL_INTEGRADO.md`: Documentación del terminal integrado
- `SANITIZACION_ARCHIVOS.md`: Proceso de validación y sanitización de archivos

## Resumen

ARESITOS es una suite profesional de ciberseguridad para Kali Linux, con escaneador, SIEM, FIM, cuarentena y dashboard integrados. Arquitectura 100% Python nativo + herramientas Kali.

### Características principales
- Escáner de vulnerabilidades integrado
- SIEM y monitoreo de seguridad
- File Integrity Monitoring (FIM)
- Sistema de cuarentena automático
- Auditoría y reportes profesionales
- Arquitectura MVC y Python nativo


## Seguridad avanzada y protección anti-logout

ARESITOS implementa una doble capa de protección para evitar que cualquier acción de usuario (botón, terminal, herramienta forense) pueda provocar un cierre de sesión (logout), crash del entorno gráfico o ejecución de comandos peligrosos en Kali Linux.

**1. Protección anti-logout/crash en detención de procesos**
El sistema unificado de detención de procesos (`utils/detener_procesos.py`) filtra y protege explícitamente procesos de sesión, terminales, shells y servicios críticos. Ejemplo real:

```python
procesos_protegidos = [
	'systemd', 'init', 'login', 'sshd', 'Xorg', 'gdm', 'lightdm', 'NetworkManager',
	'dbus-daemon', 'udisksd', 'polkitd', 'upowerd', 'wpa_supplicant', 'gnome-shell',
	'plasmashell', 'xfce4-session', 'lxsession', 'openbox', 'kdeinit', 'kded', 'kdm',
	'sddm', 'agetty', 'bash', 'zsh', 'fish', 'pwsh', 'tmux', 'screen', 'python', 'python3',
	'konsole', 'gnome-terminal', 'xterm', 'tilix', 'alacritty', 'urxvt', 'mate-terminal',
	# ...otros procesos de sesión y shells...
]
if any(p in comando for p in procesos_protegidos):
	callback_actualizacion(f"PROTEGIDO: {comando} (PID: {pid}) no será terminado por seguridad\n")
	continue
# Protección extra: no matar procesos con DISPLAY/XDG_SESSION/TTY de usuario
try:
	environ = subprocess.check_output(['cat', f'/proc/{pid}/environ']).decode(errors='ignore')
	if 'DISPLAY=' in environ or 'XDG_SESSION' in environ or 'WAYLAND_DISPLAY' in environ or 'TTY=' in environ:
		callback_actualizacion(f"PROTEGIDO: {comando} (PID: {pid}) tiene entorno gráfico/terminal, no será terminado\n")
		continue
except Exception:
	pass
```

**2. Validación de comandos peligrosos en terminales y herramientas**
El validador de comandos (`utils/seguridad_comandos.py`) bloquea comandos peligrosos como:

```python
self.comandos_prohibidos = [
	'kill', 'pgrep', 'pkill', 'shutdown', 'reboot', 'poweroff', 'init', 'telinit',
	'bash', 'sh', 'zsh', 'fish', 'exec', 'eval', 'source', 'su', 'sudo', 'passwd',
	# ...otros comandos peligrosos...
]
```

**Ejemplo real de uso en la vista de reportes:**

```python
def ejecutar_comando_entry(self, event=None):
	comando = self.comando_entry.get().strip()
	from aresitos.utils.seguridad_comandos import validador_comandos
	es_valido, comando_sanitizado, mensaje = validador_comandos.validar_comando_completo(comando)
	if not es_valido:
		self.terminal_output.insert(tk.END, f"{mensaje}\n")
		return
	# ...ejecutar comando seguro...
```

**Resultado:**
- Ningún botón de "detener/cancelar" puede provocar logout ni crash de sesión.
- No es posible ejecutar comandos que puedan cerrar sesión, matar procesos críticos o comprometer la estabilidad del sistema desde ningún terminal integrado ni vista de ARESITOS.

---

**Proyecto desarrollado por DogSoulDev**
- **Herramientas Kali**: Integración con arsenal nativo
