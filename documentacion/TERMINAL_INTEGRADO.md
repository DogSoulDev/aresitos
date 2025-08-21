# 🖥️ TERMINAL INTEGRADO DE ARESITOS

## 📋 Descripción General

ARESITOS ahora incluye un **Terminal Integrado** en el Dashboard que captura y muestra en tiempo real toda la información de logs, escaneos, monitoreo, auditoría, FIM, SIEM y reportes directamente en la interfaz gráfica.

## 🚀 Características Principales

### ✅ Captura de Logs en Tiempo Real
- Todos los logs de los módulos de ARESITOS se muestran automáticamente
- Información de escaneos, monitoreo, auditoría, etc.
- Timestamps precisos con emojis identificativos

### 🎮 Controles del Terminal
- **🔴 ACTIVAR CAPTURA LOGS**: Activa/desactiva la captura automática de logs
- **🧹 LIMPIAR**: Limpia el contenido del terminal
- **🖥️ TERMINAL KALI**: Abre un terminal externo de Kali Linux

### ⚡ Comandos Rápidos
Botones predefinidos para comandos frecuentes de ciberseguridad:
- 🌐 **Conexiones**: `netstat -tuln`
- ⚙️ **Procesos**: `ps aux | head -20`
- 🔗 **Red**: `ifconfig`
- 🔍 **Nmap**: `nmap --version`
- 💾 **Disco**: `df -h`
- 🧠 **Memoria**: `free -h`
- 👤 **Usuario**: `whoami`
- ℹ️ **Sistema**: `uname -a`
- 🔌 **Sockets**: `ss -tuln`

### 💻 Línea de Comandos Personalizada
- Campo de entrada para ejecutar comandos personalizados
- Presiona **Enter** o **▶️ Ejecutar** para ejecutar
- Salida formateada con análisis automático

## 📝 Uso del Terminal Integrado

### 1. Acceso al Terminal
1. Abre ARESITOS
2. Ve al **Dashboard**
3. Selecciona la pestaña **🖥️ Terminal ARESITOS**

### 2. Activar Captura de Logs
1. Presiona **🔴 ACTIVAR CAPTURA LOGS**
2. El botón cambiará a **🟢 CAPTURA ACTIVA**
3. Ahora todos los logs aparecerán automáticamente

### 3. Realizar Escaneos
1. Ve a la pestaña **Escaneador**
2. Presiona **Escanear Sistema**
3. **¡NOVEDAD!** Verás los logs en tiempo real en el terminal:
   ```
   [11:32:14] 🚀 [ESCANEADOR] Iniciando escaneo del sistema
   [11:32:15] 🔍 [ESCANEADOR] Verificando herramientas de escaneo
   [11:32:16] ✅ [ESCANEADOR] Escaneo completado exitosamente
   ```

### 4. Monitoreo en Tiempo Real
- **Monitoreo**: Los logs de monitoreo aparecen automáticamente
- **Auditoría**: Eventos de auditoría en tiempo real
- **FIM**: Cambios en archivos monitoreados
- **SIEM**: Eventos de seguridad detectados
- **Reportes**: Generación de reportes en vivo

## 🔧 Funcionalidades Técnicas

### Sistema de Logging Centralizado
```python
# Los módulos ahora registran actividad automáticamente:
self._log_terminal("🚀 Iniciando escaneo del sistema", "ESCANEADOR", "INFO")
self._log_terminal("✅ Operación completada", "MONITOREO", "SUCCESS")
self._log_terminal("⚠️ Advertencia detectada", "FIM", "WARNING")
self._log_terminal("❌ Error en proceso", "SIEM", "ERROR")
```

### Tipos de Mensajes
- **INFO** ℹ️: Información general
- **SUCCESS** ✅: Operaciones exitosas
- **WARNING** ⚠️: Advertencias
- **ERROR** ❌: Errores
- **DEBUG** 🔍: Información de depuración

### Redirección de Stdout/Stderr
- Captura automática de `print()` y errores
- Preserva la funcionalidad original
- Thread-safe para múltiples operaciones

## 🎯 Casos de Uso

### 1. Debugging y Monitoreo
```
[14:30:15] 🚀 [ESCANEADOR] Iniciando escaneo del sistema
[14:30:16] 🔍 [ESCANEADOR] Verificando herramientas de escaneo
[14:30:17] ✅ [ESCANEADOR] Escaneo completado exitosamente
[14:30:20] 🔍 [MONITOREO] Verificando servicios de red
[14:30:22] ⚠️ [FIM] Archivo modificado: /etc/passwd
[14:30:25] ❌ [SIEM] Evento de seguridad detectado
```

### 2. Auditoría Completa
- Registro cronológico de todas las operaciones
- Trazabilidad completa de acciones del usuario
- Logs estructurados con módulos identificables

### 3. Troubleshooting
- Información detallada de errores
- Contexto completo de operaciones fallidas
- Recomendaciones de solución automáticas

## 🛠️ Comandos Avanzados

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

## 📊 Ventajas del Terminal Integrado

### ✅ Ventajas
1. **Visibilidad Completa**: Todo en un solo lugar
2. **Tiempo Real**: Información instantánea
3. **Contexto Unificado**: Logs correlacionados
4. **Facilidad de Uso**: No need for external terminals
5. **Persistencia**: Historial completo de sesión
6. **Thread-Safe**: Múltiples operaciones simultáneas

### 🎯 Comparación: Antes vs Ahora

#### ❌ ANTES
- Logs dispersos en terminal externo
- Información invisible para el usuario
- Sin correlación entre módulos
- Debugging complejo

#### ✅ AHORA
- Terminal integrado centralizado
- Logs visibles en tiempo real
- Contexto completo de operaciones
- Debugging simplificado

## 🚀 Próximas Mejoras

1. **Filtros de Logs**: Por módulo, nivel, tiempo
2. **Exportar Logs**: Guardar sesiones completas
3. **Alertas Visuales**: Notificaciones emergentes
4. **Búsqueda**: Buscar en historial de logs
5. **Gráficos**: Visualización de métricas en tiempo real

---

## 💡 Tip de Uso

**¡Activa la captura de logs antes de usar cualquier módulo de ARESITOS para ver toda la información en tiempo real!**

El Terminal Integrado es especialmente útil para:
- 🔍 **Troubleshooting**: Ver exactamente qué está pasando
- 📊 **Monitoring**: Seguimiento continuo de operaciones
- 🔒 **Security**: Detectar actividades sospechosas
- 📝 **Auditing**: Registro completo de actividades
