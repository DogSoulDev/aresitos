# TERMINAL **TERMINAL INTEGRADO DE ARESITOS**

## LIST Descripción General

ARESITOS ahora incluye un **Terminal Integrado** en el Dashboard que captura y muestra en tiempo real toda la información de logs, escaneos, monitoreo, auditoría, FIM, SIEM y reportes directamente en la interfaz gráfica.

## LAUNCH Características Principales

### OK Captura de Logs en Tiempo Real
- Todos los logs de los módulos de ARESITOS se muestran automáticamente
- Información de escaneos, monitoreo, auditoría, etc.
- Timestamps precisos con emojis identificativos

### CONTROL Controles del Terminal
- **🔴 ACTIVAR CAPTURA LOGS**: Activa/desactiva la captura automática de logs
- **🧹 LIMPIAR**: Limpia el contenido del terminal
- **TERMINAL TERMINAL**: Abre un terminal externo de Kali Linux

### FAST Comandos Rápidos
Botones predefinidos para comandos frecuentes de ciberseguridad:
- WEB **Conexiones**: `netstat -tuln`
- CONFIG **Procesos**: `ps aux | head -20`
- 🔗 **Red**: `ifconfig`
- SCAN **Nmap**: `nmap --version`
- SAVE **Disco**: `df -h`
- MEMORY **Memoria**: `free -h`
- 👤 **Usuario**: `whoami`
- INFO **Sistema**: `uname -a`
- 🔌 **Sockets**: `ss -tuln`

### SYSTEM Línea de Comandos Personalizada
- Campo de entrada para ejecutar comandos personalizados
- Presiona **Enter** o **START Ejecutar** para ejecutar
- Salida formateada con análisis automático

## NOTE Uso del Terminal Integrado

### 1. Acceso al Terminal
1. Abre ARESITOS
2. Ve al **Dashboard**
3. Selecciona la pestaña **TERMINAL Terminal ARESITOS**

### 2. Activar Captura de Logs
1. Presiona **🔴 ACTIVAR CAPTURA LOGS**
2. El botón cambiará a **🟢 CAPTURA ACTIVA**
3. Ahora todos los logs aparecerán automáticamente

### 3. Realizar Escaneos
1. Ve a la pestaña **Escaneador**
2. Presiona **Escanear Sistema**
3. **¡NOVEDAD!** Verás los logs en tiempo real en el terminal:
   ```
   [11:32:14] LAUNCH [ESCANEADOR] Iniciando escaneo del sistema
   [11:32:15] SCAN [ESCANEADOR] Verificando herramientas de escaneo
   [11:32:16] OK [ESCANEADOR] Escaneo completado exitosamente
   ```

### 4. Monitoreo en Tiempo Real
- **Monitoreo**: Los logs de monitoreo aparecen automáticamente
- **Auditoría**: Eventos de auditoría en tiempo real
- **FIM**: Cambios en archivos monitoreados
- **SIEM**: Eventos de seguridad detectados
- **Reportes**: Generación de reportes en vivo

## TOOL Funcionalidades Técnicas

### Sistema de Logging Centralizado
```python
# Los módulos ahora registran actividad automáticamente:
self._log_terminal("LAUNCH Iniciando escaneo del sistema", "ESCANEADOR", "INFO")
self._log_terminal("OK Operación completada", "MONITOREO", "SUCCESS")
self._log_terminal("WARNING Advertencia detectada", "FIM", "WARNING")
self._log_terminal("ERROR Error en proceso", "SIEM", "ERROR")
```

### Tipos de Mensajes
- **INFO** INFO: Información general
- **SUCCESS** OK: Operaciones exitosas
- **WARNING** WARNING: Advertencias
- **ERROR** ERROR: Errores
- **DEBUG** SCAN: Información de depuración

### Redirección de Stdout/Stderr
- Captura automática de `print()` y errores
- Preserva la funcionalidad original
- Thread-safe para múltiples operaciones

## TARGET Casos de Uso

### 1. Debugging y Monitoreo
```
[14:30:15] LAUNCH [ESCANEADOR] Iniciando escaneo del sistema
[14:30:16] SCAN [ESCANEADOR] Verificando herramientas de escaneo
[14:30:17] OK [ESCANEADOR] Escaneo completado exitosamente
[14:30:20] SCAN [MONITOREO] Verificando servicios de red
[14:30:22] WARNING [FIM] Archivo modificado: /etc/passwd
[14:30:25] ERROR [SIEM] Evento de seguridad detectado
```

### 2. Auditoría Completa
- Registro cronológico de todas las operaciones
- Trazabilidad completa de acciones del usuario
- Logs estructurados con módulos identificables

### 3. Troubleshooting
- Información detallada de errores
- Contexto completo de operaciones fallidas
- Recomendaciones de solución automáticas

## TOOLS Comandos Avanzados

### Análisis de Red
```bash
netstat -tuln | grep LISTEN    # Puertos en escucha
ss -tulpn                     # Conexiones detalladas
nmap -sS -O localhost         # Escaneo de puertos
```

### Monitoreo del Sistema
```bash
ps aux --sort=-%cpu | head    # Procesos por CPU
free -h && df -h              # Memoria y disco
lsof -i                       # Archivos de red abiertos
```

### Seguridad
```bash
sudo netstat -tulpn | grep :22    # SSH activo
sudo ss -tulpn | grep :443        # HTTPS activo
sudo lsof -i :80                  # HTTP connections
```

## 🔐 Integración con Módulos ARESITOS

### Escaneador
- Logs de inicio/fin de escaneo
- Progreso de verificación de herramientas
- Resultados de análisis de vulnerabilidades

### Monitoreo
- Estado de servicios críticos
- Métricas de rendimiento
- Alertas de recursos

### FIM (File Integrity Monitoring)
- Cambios en archivos monitoreados
- Alertas de modificaciones sospechosas
- Baseline de integridad

### SIEM
- Eventos de seguridad en tiempo real
- Correlación de amenazas
- Alertas de patrones maliciosos

### Auditoría
- Registro de accesos
- Logs de configuración
- Historial de cambios

## DATA Ventajas del Terminal Integrado

### OK Ventajas
1. **Visibilidad Completa**: Todo en un solo lugar
2. **Tiempo Real**: Información instantánea
3. **Contexto Unificado**: Logs correlacionados
4. **Facilidad de Uso**: No need for external terminals
5. **Persistencia**: Historial completo de sesión
6. **Thread-Safe**: Múltiples operaciones simultáneas

### TARGET Comparación: Antes vs Ahora

#### ERROR ANTES
- Logs dispersos en terminal externo
- Información invisible para el usuario
- Sin correlación entre módulos
- Debugging complejo

#### OK AHORA
- Terminal integrado centralizado
- Logs visibles en tiempo real
- Contexto completo de operaciones
- Debugging simplificado

## LAUNCH Próximas Mejoras

1. **Filtros de Logs**: Por módulo, nivel, tiempo
2. **Exportar Logs**: Guardar sesiones completas
3. **Alertas Visuales**: Notificaciones emergentes
4. **Búsqueda**: Buscar en historial de logs
5. **Gráficos**: Visualización de métricas en tiempo real

---

## TIP **Tip de Uso**

**¡Activa la captura de logs antes de usar cualquier módulo de ARESITOS para ver toda la información en tiempo real!**

El Terminal Integrado es especialmente útil para:
- SCAN **Troubleshooting**: Ver exactamente qué está pasando
- DATA **Monitoring**: Seguimiento continuo de operaciones
- LOCK **Security**: Detectar actividades sospechosas
- NOTE **Auditing**: Registro completo de actividades
