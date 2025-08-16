# Mapa de Navegación - Escaneador Modular Ares Aegis

## Estructura del Sistema de Escaneo

### Archivos Principales

#### 1. `modelo_escaneador.py` (Punto de Entrada)
- **Propósito**: Mantiene compatibilidad con código existente
- **Contenido**: Importaciones y funciones de conveniencia
- **Uso**: `from ares_aegis.modelo import Escaneador`

#### 2. `modelo_escaneador_base.py` (Funcionalidad Base)
- **Propósito**: Implementa funcionalidades básicas de escaneo
- **Líneas**: 372 líneas de código
- **Componentes**:
  - Clase `EscaneadorBase`
  - Validaciones de seguridad básicas
  - Control de throttling
  - Configuración básica
  - Logging estructurado

#### 3. `modelo_escaneador_avanzado.py` (Funciones Avanzadas)
- **Propósito**: Implementa características avanzadas de seguridad
- **Líneas**: 573 líneas de código  
- **Componentes**:
  - Clase `EscaneadorAvanzado` (hereda de `EscaneadorBase`)
  - Sistema de detección de anomalías
  - Cache seguro con TTL
  - Sandbox para ejecución de comandos
  - Reportes de seguridad avanzados
  - Monitoreo de recursos

### Clases y Enumeraciones

#### Enumeraciones
- `TipoEscaneo`: Define tipos de escaneo disponibles
- `NivelCriticidad`: Niveles de criticidad para vulnerabilidades

#### Clases de Datos
- `VulnerabilidadEncontrada`: Estructura para vulnerabilidades
- `ResultadoEscaneo`: Resultado completo de escaneos

#### Excepciones
- `SecurityError`: Excepción personalizada para errores de seguridad

### Funciones de Conveniencia

#### `crear_escaneador(tipo="avanzado", **kwargs)`
```python
# Crear escaneador básico
escaneador_base = crear_escaneador("base")

# Crear escaneador avanzado (predeterminado)
escaneador_avanzado = crear_escaneador("avanzado")
```

#### `obtener_version()`
```python
info = obtener_version()
print(f"Versión: {info['version']}")
print(f"Módulos: {info['modulos']}")
```

### Flujo de Herencia

```
SecurityError (Exception)
    ↑
EscaneadorBase
    ↑
EscaneadorAvanzado
```

### Funcionalidades por Nivel

#### Nivel Base (EscaneadorBase)
- Escaneo básico de puertos
- Validaciones de entrada
- Control de throttling
- Logging básico
- Configuración desde archivos

#### Nivel Avanzado (EscaneadorAvanzado)
- Todas las funcionalidades base +
- Detección de anomalías
- Sistema de cache inteligente
- Sandbox de comandos
- Reportes de seguridad
- Monitoreo de recursos
- Análisis de patrones de tráfico

### Ejemplos de Uso

#### Uso Básico (Compatibilidad)
```python
from ares_aegis.modelo import Escaneador

# Uso tradicional - automáticamente usa EscaneadorAvanzado
escaneador = Escaneador()
resultado = escaneador.escanear_objetivo("192.168.1.1")
```

#### Uso Específico por Tipo
```python
from ares_aegis.modelo import crear_escaneador

# Escaneador básico para sistemas con recursos limitados
escaneador_ligero = crear_escaneador("base")

# Escaneador avanzado para análisis completo
escaneador_completo = crear_escaneador("avanzado")
```

#### Importación Directa
```python
from ares_aegis.modelo.modelo_escaneador_base import EscaneadorBase
from ares_aegis.modelo.modelo_escaneador_avanzado import EscaneadorAvanzado

# Uso directo de las clases
escaneador = EscaneadorAvanzado()
```

### Migración de Código Existente

#### Antes (Monolítico)
```python
from ares_aegis.modelo.modelo_escaneador import Escaneador
escaneador = Escaneador()
```

#### Después (Modular) - Sin Cambios Requeridos
```python
from ares_aegis.modelo.modelo_escaneador import Escaneador  # Funciona igual
# O usando el nuevo punto de entrada
from ares_aegis.modelo import Escaneador  # Recomendado
escaneador = Escaneador()
```

### Beneficios de la Modularización

1. **Mantenibilidad**: Código dividido en módulos lógicos
2. **Escalabilidad**: Fácil agregar nuevas funcionalidades
3. **Reutilización**: Componentes reutilizables
4. **Testing**: Pruebas más específicas por módulo
5. **Performance**: Carga bajo demanda de funcionalidades
6. **Claridad**: Separación clara de responsabilidades

### Ubicación de Archivos

```
ares_aegis/
└── modelo/
    ├── __init__.py (exporta las clases principales)
    ├── modelo_escaneador.py (punto de entrada y compatibilidad)
    ├── modelo_escaneador_base.py (funcionalidad base)
    └── modelo_escaneador_avanzado.py (funcionalidades avanzadas)
```

### Próximos Pasos Recomendados

1. **Testing**: Crear pruebas unitarias para cada módulo
2. **Documentación**: Generar documentación API automática
3. **Ejemplos**: Crear scripts de ejemplo para cada tipo de uso
4. **Optimización**: Perfilar y optimizar código según métricas
5. **Extensiones**: Considerar plugins para funcionalidades específicas

Esta estructura modular permite un mantenimiento más eficiente del código mientras mantiene total compatibilidad con el sistema existente.
