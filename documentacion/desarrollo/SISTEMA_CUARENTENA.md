# 🛡️ Sistema de Cuarentena Automática - Ares Aegis

## 📋 Descripción General

El sistema de cuarentena automática de Ares Aegis está diseñado para **aislar automáticamente cualquier amenaza, virus o vulnerabilidad** detectada por el escaneador, permitiendo al usuario decidir qué hacer con cada archivo de forma segura.

## 🔧 Componentes Implementados

### 1. 📦 Modelo de Cuarentena (`ares_aegis/modelo/cuarentena.py`)

**Clase `ArchivoEnCuarentena`:**
- Representa un archivo aislado con todos sus metadatos
- Incluye hash MD5 y SHA256 para verificación de integridad
- Almacena fecha, motivo, tipo de amenaza y severidad

**Clase `Cuarentena`:**
- Gestiona el directorio de cuarentena
- Índice JSON para seguimiento de archivos
- Verificación de integridad automática
- Funciones de limpieza y mantenimiento

### 2. 🎮 Controlador de Cuarentena (`ares_aegis/controladores/controlador_cuarentena.py`)

**Funcionalidades principales:**
- **Procesamiento automático** de amenazas detectadas
- **Categorización por severidad** (Crítica, Alta, Media, Baja)
- **Notificaciones** para amenazas críticas
- **Reportes detallados** del estado de cuarentena
- **Gestión completa** (restaurar, eliminar, limpiar)

### 3. 🔗 Integración con Escaneador (`ares_aegis/modelo/escaneador_avanzado.py`)

**Cuarentena automática activada para:**
- ✅ Configuraciones SSH inseguras
- ✅ Rootkits detectados por rkhunter
- ✅ Infecciones encontradas por chkrootkit  
- ✅ Malware identificado por ClamAV
- ✅ Archivos sospechosos de alto riesgo

### 4. 🎛️ Controlador Integrado (`ares_aegis/controladores/controlador_escaneador_cuarentena.py`)

**Orquesta todo el proceso:**
- Ejecuta escaneos con cuarentena automática
- Procesa vulnerabilidades según nivel de riesgo
- Genera reportes unificados
- Proporciona interfaz de gestión

## 🚀 Cómo Funciona

### Flujo Automático de Cuarentena

```
1. 🔍 ESCANEADOR DETECTA AMENAZA
   ↓
2. 📊 EVALUACIÓN DE SEVERIDAD
   ↓
3. 🔒 CUARENTENA AUTOMÁTICA (si es crítica/alta)
   ↓ 
4. 📝 REGISTRO COMPLETO
   ↓
5. 🚨 NOTIFICACIÓN AL USUARIO
```

### Criterios de Cuarentena Automática

| Tipo de Amenaza | Severidad | Acción |
|-----------------|-----------|---------|
| Malware detectado | Crítica | 🔒 Cuarentena inmediata |
| Rootkit encontrado | Crítica | 🔒 Cuarentena inmediata |
| Configuración insegura | Alta | 🔒 Cuarentena automática |
| Archivo sospechoso | Media | ⚠️ Alerta (no cuarentena) |
| Vulnerabilidad baja | Baja | ℹ️ Solo registro |

## 📁 Estructura de Archivos

```
ares_aegis/
├── modelo/
│   └── cuarentena.py              # Modelo de datos y gestión
├── controladores/
│   ├── controlador_cuarentena.py  # Lógica de negocio
│   └── controlador_escaneador_cuarentena.py  # Integración
└── tests/
    └── test_cuarentena.py         # Tests unitarios

Directorio de cuarentena (por defecto):
/tmp/ares_aegis_quarantine/
├── quarantine_index.json         # Índice de archivos
├── isolated_files/               # Archivos aislados
└── amenazas_sin_archivo.log      # Log de amenazas sin archivo
```

## 🎯 Características Principales

### ✨ Funcionalidades Implementadas

- **🔒 Aislamiento automático** de amenazas detectadas
- **🔍 Verificación de integridad** con hashes criptográficos
- **📊 Estadísticas detalladas** del estado de cuarentena
- **📋 Reportes completos** con recomendaciones
- **🧹 Limpieza automática** de archivos antiguos
- **↩️ Restauración segura** de falsos positivos
- **🗑️ Eliminación definitiva** de amenazas confirmadas
- **📝 Logging completo** de todas las operaciones
- **🚨 Notificaciones** para amenazas críticas
- **🔗 Integración transparente** con el escaneador

### 🛡️ Seguridad

- **Aislamiento completo** - Los archivos no pueden ejecutarse desde cuarentena
- **Verificación de integridad** - Detección de modificaciones
- **Metadatos protegidos** - Información completa de cada amenaza
- **Backup automático** - Opción de respaldo antes de aislar
- **Logs auditables** - Rastro completo de todas las acciones

## 🎮 Uso del Sistema

### Demostración Rápida

```bash
# Ejecutar demo del sistema
python demo_cuarentena.py
```

### Uso Programático

```python
from ares_aegis.controladores.controlador_escaneador_cuarentena import ControladorEscaneadorCuarentena

# Inicializar controlador integrado
controlador = ControladorEscaneadorCuarentena()

# Ejecutar escaneo con cuarentena automática
resultado = controlador.ejecutar_escaneo_con_cuarentena('completo')

# Ver resumen
print(f"Vulnerabilidades encontradas: {resultado['estadisticas']['total_vulnerabilidades']}")
print(f"Amenazas en cuarentena: {resultado['estadisticas']['en_cuarentena']}")

# Gestionar cuarentena
gestion = controlador.gestionar_cuarentena()
print(f"Archivos en cuarentena: {gestion['resumen']['total_archivos']}")
```

### Gestión Manual de Cuarentena

```python
from ares_aegis.controladores.controlador_cuarentena import ControladorCuarentena

cuarentena = ControladorCuarentena()

# Obtener resumen
resumen = cuarentena.obtener_resumen_cuarentena()

# Restaurar archivo
cuarentena.restaurar_archivo('/ruta/del/archivo')

# Eliminar definitivamente
cuarentena.eliminar_definitivamente('/ruta/del/archivo')

# Limpiar archivos antiguos (30 días)
cuarentena.limpiar_cuarentena_antigua(30)
```

## 📊 Reportes y Estadísticas

### Información Disponible

- **📈 Total de archivos** en cuarentena
- **📅 Fechas** de primer y último archivo
- **💾 Espacio utilizado** por archivos aislados
- **🔴 Amenazas críticas** que requieren atención inmediata
- **📋 Distribución por tipo** de amenaza y severidad
- **✅ Estado de integridad** de archivos en cuarentena

### Recomendaciones Automáticas

El sistema genera recomendaciones inteligentes:
- **🚨 Revisar amenazas críticas** inmediatamente
- **🧹 Limpiar cuarentena** si ocupa mucho espacio
- **🔍 Verificar integridad** si hay problemas detectados
- **📋 Generar reportes** para auditoría

## 🔧 Configuración

### Parámetros Configurables

```python
configuracion = {
    'cuarentena_automatica': True,           # Activar cuarentena automática
    'niveles_cuarentena': ['critico', 'alto'], # Niveles que van a cuarentena
    'notificar_cuarentena': True,            # Notificaciones activas
    'backup_antes_cuarentena': True,         # Backup antes de aislar
    'directorio_cuarentena': '/ruta/custom', # Directorio personalizado
    'dias_limpieza': 30                      # Días para limpieza automática
}
```

## 🧪 Testing

```bash
# Ejecutar tests de cuarentena
python -m pytest tests/test_cuarentena.py -v

# Test específicos
python -m pytest tests/test_cuarentena.py::TestCuarentena::test_poner_archivo_en_cuarentena -v
```

## 📈 Métricas y Monitoreo

### Logs Disponibles

- **🔍 Detección** - Cada amenaza detectada
- **🔒 Cuarentena** - Archivos puestos en cuarentena
- **↩️ Restauración** - Archivos restaurados
- **🗑️ Eliminación** - Archivos eliminados definitivamente
- **🧹 Limpieza** - Mantenimiento automático
- **❌ Errores** - Problemas y su resolución

### Integración con SIEM

El sistema está preparado para integrarse con:
- **📊 Sistemas SIEM** para correlación de eventos
- **📧 Notificaciones por email** para amenazas críticas
- **📱 Alertas móviles** para administradores
- **📋 Dashboards** en tiempo real

## 🎯 Resultado Final

**✅ OBJETIVO CUMPLIDO:** El escaneador ahora mueve automáticamente cualquier amenaza, virus o vulnerabilidad detectada a cuarentena, permitiendo al usuario decidir qué hacer con cada archivo de forma segura.

### Beneficios Implementados

1. **🛡️ Protección automática** - Aislamiento inmediato de amenazas
2. **🔍 Transparencia total** - El usuario ve todo lo que se detecta
3. **✋ Control del usuario** - Decisión final sobre cada archivo
4. **📊 Información completa** - Metadatos y contexto de cada amenaza
5. **🔒 Seguridad garantizada** - Archivos aislados no pueden causar daño
6. **↩️ Recuperación fácil** - Restauración simple de falsos positivos
7. **🧹 Mantenimiento automático** - Limpieza inteligente del sistema

**El sistema de cuarentena automática de Ares Aegis proporciona una capa adicional de seguridad que protege al usuario mientras mantiene el control total sobre las decisiones de seguridad.**
