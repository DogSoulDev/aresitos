# HERRAMIENTAS FASE 3 - ACTUALIZACIÓN CONFIGURADOR

## Herramientas Agregadas al Configurador

### Nuevas Herramientas de Verificación

**Checksums Adicionales:**
- `sha1sum`, `sha512sum` - Para verificación múltiple de integridad

**Herramientas FIM Avanzadas:**
- `debsums` - Verificación de checksums de paquetes Debian/Kali
- `inotify-tools` - Monitoreo en tiempo real de archivos
- `tripwire`, `samhain` - Sistemas avanzados de integridad

**Análisis Forense Expandido:**
- `autopsy` - Plataforma de análisis forense digital (nativa Kali)
- `autopsy` - Suite forense completa
- `tcpdump`, `tshark` - Análisis de tráfico de red
- `strace`, `ltrace`, `gdb` - Debugging y análisis de procesos

**SIEM y Auditoría:**
- `rsyslog`, `logrotate`, `logwatch` - Gestión avanzada de logs
- `osquery` - Framework de consultas del sistema

**Antivirus Expandido:**
- `clamav-freshclam` - Actualizador de firmas antivirus

### Herramientas de Instalación Manual Actualizadas

Las siguientes herramientas requieren instalación manual y han sido documentadas:

1. **rustscan** - Escaneador rápido de puertos (requiere Rust)
2. **pspy32/pspy64** - Monitoreo de procesos sin root
3. **linpeas** - Script de escalamiento de privilegios
**ELIMINADO: volatility3** - Ya NO tiene soporte activo y no funciona correctamente en Kali 2025. Reemplazado por autopsy.
5. **httpx/nuclei** - Herramientas de ProjectDiscovery (requieren Go)

### Información Específica de Fase 3

El configurador ahora muestra información detallada sobre:

- **ESCANEADOR EXPANDIDO (Fase 3.1)**: 25+ herramientas integradas
- **SIEM AVANZADO (Fase 3.2)**: Análisis de patrones y correlación
- **FIM OPTIMIZADO (Fase 3.3)**: Monitoreo forense avanzado

### Comandos de Instalación Automática

Todas las herramientas principales se instalan automáticamente con:
```bash
sudo apt update && sudo apt install -y [lista_herramientas]
```

### Verificación de Herramientas

El sistema verifica **+50 herramientas** específicas para Kali Linux, incluyendo:
- Comandos básicos del sistema
- Herramientas de red y escaneo
- Análisis forense y malware
- Auditoría y monitoreo
- Editores y gestores de archivos

### Compatibilidad

- OK **Kali Linux 2025**: Funcionalidad completa
- WARNING **Otras distribuciones**: Verificación básica
- ERROR **Windows/macOS**: Solo verificación de Python

---

*Actualización realizada para soportar las expansiones de la Fase 3*
